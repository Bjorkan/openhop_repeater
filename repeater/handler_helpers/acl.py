import logging
import time
from typing import Callable, Dict, List, Optional

from openhop_core.protocol import Identity
from openhop_core.protocol.constants import PUB_KEY_SIZE

# ACL roles come from openhop_core, which mirrors firmware
# ``src/helpers/ClientACL.h``: the role is the LOW TWO BITS of the permissions
# byte and ADMIN is 3 — it is not "the 0x02 bit".
#
# This import is deliberately fail-closed. A core without these symbols still
# builds the login reply's is_admin byte from ``permissions & 0x02``, which
# also matches READ_WRITE (2); pairing it with this module would silently
# announce a room server's read-write clients as admins. Refusing to start is
# the safe failure.
try:
    from openhop_core.protocol.constants import (
        PERM_ACL_ADMIN,
        PERM_ACL_GUEST,
        PERM_ACL_READ_ONLY,
        PERM_ACL_READ_WRITE,
        PERM_ACL_ROLE_MASK,
    )
    from openhop_core.protocol.constants import acl_is_admin as is_admin_permissions
    from openhop_core.protocol.constants import acl_role as role_of
except ImportError as exc:  # pragma: no cover - exercised by the install, not tests
    raise ImportError(
        "openhop_core is too old: it does not export PERM_ACL_* / acl_is_admin. "
        "Install openhop_core with the ACL role fix (fix/login-perms or later) — "
        "an older core encodes admin as the 0x02 bit and would announce "
        "read-write clients as admins."
    ) from exc

logger = logging.getLogger("ACL")

_ROLE_NAMES = {
    PERM_ACL_GUEST: "guest",
    PERM_ACL_READ_ONLY: "read_only",
    PERM_ACL_READ_WRITE: "read_write",
    PERM_ACL_ADMIN: "admin",
}


def role_name(permissions: int) -> str:
    """Human-readable role name for logs and the web API."""
    return _ROLE_NAMES[role_of(permissions)]


def acl_identity_label(name: str, identity_type: str) -> str:
    """Stable label for an identity's stored ACL, independent of its key.

    There is one repeater identity whatever it is named, so its label is
    fixed. Room servers are told apart by their configured name.
    """
    if identity_type == "room_server":
        return f"room_server:{name}"
    return "repeater"


class ClientInfo:
    """Represents an authenticated client in the access control list."""

    def __init__(self, identity: Identity, permissions: int = 0):
        self.id = identity
        self.permissions = permissions
        self.shared_secret = b""
        self.last_timestamp = 0
        self.last_activity = 0
        self.last_login_success = 0
        self.out_path_len = -1
        self.out_path = bytearray()
        self.sync_since = 0  # For room servers - timestamp of last synced message

    def is_admin(self) -> bool:
        return is_admin_permissions(self.permissions)

    def is_guest(self) -> bool:
        return role_of(self.permissions) == PERM_ACL_GUEST

    def role_name(self) -> str:
        """Role name ("guest"/"read_only"/"read_write"/"admin") for logs and the API."""
        return role_name(self.permissions)


class ACL:
    """Per-identity access control list, firmware ``ClientACL``.

    With a ``store`` the entries firmware writes to ``/s_contacts`` survive a
    restart: every entry with non-zero permissions that ``persist_filter``
    accepts. The repeater passes no filter; a room server keeps admins only,
    as firmware's ``saveFilter``. Writes happen when an entry's stored
    permissions change, not on every login, so a returning admin costs no I/O.
    """

    def __init__(
        self,
        max_clients: int = 50,
        admin_password: Optional[str] = None,
        guest_password: Optional[str] = None,
        allow_read_only: bool = True,
        store=None,
        local_identity=None,
        identity_label: Optional[str] = None,
        persist_filter: Optional[Callable[["ClientInfo"], bool]] = None,
    ):
        self.max_clients = max_clients
        self.admin_password = admin_password or ""
        self.guest_password = guest_password or ""
        self.allow_read_only = allow_read_only
        self.clients: Dict[bytes, ClientInfo] = {}

        self._store = store
        self._local_identity = local_identity
        self._identity_label = identity_label or ""
        self._persist_filter = persist_filter
        # Permissions as last written to the store, keyed like ``clients``.
        self._persisted: Dict[bytes, int] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _identity_pubkey_hex(self) -> Optional[str]:
        if self._local_identity is None:
            return None
        return bytes(self._local_identity.get_public_key()[:PUB_KEY_SIZE]).hex()

    def _persistence_enabled(self) -> bool:
        return self._store is not None and self._identity_pubkey_hex() is not None

    def _derive_secret(self, pub_key: bytes) -> bytes:
        """Shared secret with a client, recomputed rather than read from disk."""
        if self._local_identity is None:
            return b""
        try:
            return Identity(pub_key).calc_shared_secret(self._local_identity.get_private_key())
        except Exception as e:
            logger.warning(f"Could not derive shared secret for {pub_key[:6].hex()}...: {e}")
            return b""

    def load(self) -> int:
        """Fill the table from the store. Returns the number of entries loaded.

        Loaded entries have ``last_activity`` 0, as in firmware: they are
        known, not active, until the client logs in again. The replay
        watermark also starts at 0, as firmware keeps it in RAM only.
        """
        if not self._persistence_enabled():
            return 0
        try:
            rows = self._store.load_acl_entries(self._identity_pubkey_hex(), self._identity_label)
        except Exception as e:
            logger.error(f"Failed to load ACL for '{self._identity_label}': {e}")
            return 0

        loaded = 0
        for row in rows:
            try:
                pub_key = bytes.fromhex(row["client_pubkey"])
                permissions = int(row["permissions"]) & 0xFF
                if len(pub_key) != PUB_KEY_SIZE or permissions == 0:
                    continue
                identity = Identity(pub_key)
            except Exception:
                logger.warning(f"Skipping malformed ACL row for '{self._identity_label}': {row}")
                continue
            client = ClientInfo(identity, permissions)
            client.shared_secret = self._derive_secret(pub_key)
            self.clients[pub_key] = client
            self._persisted[pub_key] = permissions
            loaded += 1

        if loaded:
            logger.info(
                f"Loaded {loaded} ACL entr{'y' if loaded == 1 else 'ies'} for '{self._identity_label}'"
            )
        return loaded

    def _should_persist(self, client: "ClientInfo") -> bool:
        if client.permissions == 0:
            return False
        return self._persist_filter is None or bool(self._persist_filter(client))

    def _sync_entry(self, pub_key: bytes) -> None:
        """Write one entry's current state to the store if it changed."""
        if not self._persistence_enabled():
            return
        client = self.clients.get(pub_key)
        wanted = client.permissions if client is not None and self._should_persist(client) else None
        if self._persisted.get(pub_key) == wanted:
            return

        identity_hex = self._identity_pubkey_hex()
        if wanted is None:
            ok = self._store.delete_acl_entry(identity_hex, pub_key.hex())
        else:
            ok = self._store.upsert_acl_entry(
                identity_hex, self._identity_label, pub_key.hex(), wanted
            )
        # On a failed write, leave the cache as it was so the next change retries.
        if ok is False:
            return
        if wanted is None:
            self._persisted.pop(pub_key, None)
        else:
            self._persisted[pub_key] = wanted

    # ------------------------------------------------------------------
    # Table management
    # ------------------------------------------------------------------

    def _put_client(self, identity: Identity) -> Optional["ClientInfo"]:
        """Find or add a client, firmware ``putClient``.

        When the table is full the least recently active non-admin is evicted.
        Firmware evicts its last slot, which may be an admin, when every entry
        is an admin; this refuses instead, so provisioned admins are never
        dropped to make room for a newcomer.
        """
        pub_key = bytes(identity.get_public_key()[:PUB_KEY_SIZE])
        client = self.clients.get(pub_key)
        if client is not None:
            return client

        if len(self.clients) >= self.max_clients:
            candidates = [(k, c) for k, c in self.clients.items() if not c.is_admin()]
            if not candidates:
                logger.warning("ACL full and every entry is an admin, cannot add client")
                return None
            evict_key, _ = min(candidates, key=lambda kc: kc[1].last_activity)
            del self.clients[evict_key]
            self._sync_entry(evict_key)
            logger.info(f"ACL full, evicted least active client {evict_key[:6].hex()}...")

        client = ClientInfo(identity, 0)
        self.clients[pub_key] = client
        return client

    def apply_permissions(self, pub_key: bytes, permissions: int) -> bool:
        """``setperm``, firmware ``ClientACL::applyPermissions``.

        A guest role deletes the first entry whose key starts with ``pub_key``,
        so a prefix is enough. Any other role needs the full key, finds or adds
        the entry, and stores the whole permissions byte, not just the role.
        """
        permissions &= 0xFF
        pub_key = bytes(pub_key)
        if role_of(permissions) == PERM_ACL_GUEST:
            # Firmware matches an empty prefix against the first entry and
            # deletes it. Refuse instead: "setperm  0" should not drop someone.
            if not pub_key:
                return False
            match = next((k for k in self.clients if k.startswith(pub_key)), None)
            if match is None:
                return False
            del self.clients[match]
            self._sync_entry(match)
            logger.info(f"setperm: removed {match[:6].hex()}... from ACL")
            return True

        if len(pub_key) < PUB_KEY_SIZE:
            return False
        pub_key = pub_key[:PUB_KEY_SIZE]
        try:
            identity = Identity(pub_key)
        except Exception:
            # Not a valid ed25519 key. Firmware stores any 32 bytes, but such
            # an entry could never log in, and Identity() refuses it.
            logger.info(f"setperm: {pub_key[:6].hex()}... is not a valid public key")
            return False
        client = self._put_client(identity)
        if client is None:
            return False
        client.permissions = permissions
        client.shared_secret = self._derive_secret(pub_key) or client.shared_secret
        self._sync_entry(pub_key)
        logger.info(f"setperm: {pub_key[:6].hex()}... permissions=0x{permissions:02X}")
        return True

    def format_acl_lines(self) -> List[str]:
        """Rows for ``get acl``: ``"%02X <pubkey>"`` for each entry with permissions."""
        return [
            f"{client.permissions:02X} {key.hex().upper()}"
            for key, client in self.clients.items()
            if client.permissions != 0
        ]

    def _is_replay(self, client: ClientInfo, timestamp: int) -> bool:
        if timestamp <= client.last_timestamp:
            logger.warning(
                f"Possible replay attack! timestamp={timestamp}, last={client.last_timestamp}"
            )
            return True
        return False

    def _touch_client_session(
        self,
        client: ClientInfo,
        shared_secret: bytes,
        timestamp: int,
        sync_since: int = None,
    ) -> None:
        now = int(time.time())
        # Monotonic: the replay watermark must never move backwards, even if
        # another accepted request advanced it between the replay check and
        # this write.
        client.last_timestamp = max(client.last_timestamp, timestamp)
        client.last_activity = now
        client.last_login_success = now
        client.shared_secret = shared_secret
        if sync_since is not None:
            client.sync_since = sync_since
            logger.debug(f"Stored sync_since={sync_since} for client")

    def authenticate_client(
        self,
        client_identity: Identity,
        shared_secret: bytes,
        password: str,
        timestamp: int,
        sync_since: int = None,
        target_identity_hash: int = None,
        target_identity_name: str = None,
        target_identity_config: dict = None,
    ) -> tuple[bool, int]:

        target_identity_config = target_identity_config or {}

        # Check for identity-specific passwords (required for room servers)
        identity_settings = target_identity_config.get("settings", {})

        # Determine if this is a room server by checking the type field
        identity_type = target_identity_config.get("type", "")
        is_room_server = identity_type == "room_server"

        # Log sync_since if provided (room server format)
        if sync_since is not None:
            logger.debug(f"Client sync_since timestamp: {sync_since}")

        if is_room_server:
            # Room servers use passwords from their settings section only
            # Empty strings are treated as "not set"
            admin_pwd = identity_settings.get("admin_password") or None
            guest_pwd = identity_settings.get("guest_password") or None

            if not admin_pwd and not guest_pwd:
                logger.error(
                    f"Room server '{target_identity_name}' has no passwords configured! Set admin_password and/or guest_password in settings."
                )
                return False, 0
        else:
            # Repeater uses global passwords from its own security section
            admin_pwd = self.admin_password
            guest_pwd = self.guest_password
            logger.debug(
                f"Repeater passwords - admin: {'SET' if admin_pwd else 'NONE'}, "
                f"guest: {'SET' if guest_pwd else 'NONE'}"
            )

        admin_pwd = admin_pwd or ""
        guest_pwd = guest_pwd or ""

        if target_identity_name:
            logger.debug(
                f"Authenticating for identity '{target_identity_name}' (room_server={is_room_server})"
            )

        pub_key = client_identity.get_public_key()[:PUB_KEY_SIZE]

        if not password:
            client = self.clients.get(pub_key)
            if client is None:
                if not self.allow_read_only:
                    logger.info("Blank password, sender not in ACL and read-only disabled")
                    return False, 0
                client = self._put_client(client_identity)
                if client is None:
                    return False, 0
                client.permissions = PERM_ACL_GUEST
                logger.info("Blank password, allowing read-only guest access")
            else:
                # Firmware skips the replay check and the session touch on this
                # path. We keep both: a replayed blank-password login from a
                # persisted admin must not be accepted.
                logger.info(f"ACL-based login for {pub_key[:6].hex()}...")

            if self._is_replay(client, timestamp):
                return False, 0
            self._touch_client_session(client, shared_secret, timestamp, sync_since=sync_since)
            # No role normalisation needed: PERM_ACL_GUEST *is* role 0, so a
            # client stored with no role bits already reads back as a guest.
            return True, client.permissions

        permissions = 0
        logger.debug(f"Comparing password (len={len(password)}) against admin/guest")
        logger.debug(
            f"Admin pwd len={len(admin_pwd) if admin_pwd else 0}, Guest pwd len={len(guest_pwd) if guest_pwd else 0}"
        )
        if admin_pwd and password == admin_pwd:
            permissions = PERM_ACL_ADMIN
            logger.info(f"Admin password validated for '{target_identity_name or 'unknown'}'")
        elif guest_pwd and password == guest_pwd:
            # Firmware splits the guest password by server type. simple_repeater
            # grants GUEST (may fetch base telemetry, may not change settings);
            # simple_room_server grants READ_WRITE (may post and read messages).
            permissions = PERM_ACL_READ_WRITE if is_room_server else PERM_ACL_GUEST
            logger.info(
                f"Guest password validated for '{target_identity_name or 'unknown'}' "
                f"(role={role_name(permissions)})"
            )
        else:
            logger.info(f"Invalid password for '{target_identity_name or 'unknown'}'")
            return False, 0

        is_new = pub_key not in self.clients
        client = self._put_client(client_identity)
        if client is None:
            return False, 0
        if is_new:
            logger.info(f"Added new client {pub_key[:6].hex()}...")

        if self._is_replay(client, timestamp):
            return False, 0
        self._touch_client_session(client, shared_secret, timestamp, sync_since=sync_since)
        client.permissions &= ~PERM_ACL_ROLE_MASK
        client.permissions |= permissions
        # Firmware saves after any non-guest password login. _sync_entry writes
        # only when the stored permissions changed, and a guest has none to store.
        self._sync_entry(pub_key)

        logger.info(f"Login success! Role: {client.role_name()}")
        return True, client.permissions

    def get_client(self, pub_key: bytes) -> Optional[ClientInfo]:
        return self.clients.get(pub_key[:PUB_KEY_SIZE])

    def get_num_clients(self) -> int:
        return len(self.clients)

    def get_all_clients(self):
        return list(self.clients.values())

    def remove_client(self, pub_key: bytes) -> bool:
        key = bytes(pub_key[:PUB_KEY_SIZE])
        if key in self.clients:
            del self.clients[key]
            self._sync_entry(key)
            return True
        return False
