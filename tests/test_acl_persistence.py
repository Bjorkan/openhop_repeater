"""Persistent ACL entries and ``setperm`` / ``get acl``, against firmware ClientACL.

Firmware keeps its ACL in ``/s_contacts``: an admin provisioned over serial with
``setperm <pubkey> 3`` logs in with a blank password forever after, across
reboots. These tests hold the repeater to that.
"""

import asyncio
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from openhop_core import LocalIdentity
from openhop_core.protocol import Identity

from repeater.data_acquisition.sqlite_handler import SQLiteHandler
from repeater.handler_helpers.acl import (
    ACL,
    PERM_ACL_ADMIN,
    PERM_ACL_GUEST,
    PERM_ACL_READ_ONLY,
    PERM_ACL_READ_WRITE,
    acl_identity_label,
)
from repeater.handler_helpers.login import LoginHelper
from repeater.handler_helpers.mesh_cli import MeshCLI

ROOM_CFG = {
    "type": "room_server",
    "settings": {"admin_password": "roomadmin", "guest_password": "roomguest"},
}


def _cli(acl):
    cfg = {"repeater": {"security": {}}, "mesh": {}}
    mgr = SimpleNamespace(save_to_file=MagicMock(return_value=True), live_update_daemon=MagicMock())
    return MeshCLI("/tmp/cfg.yaml", cfg, mgr, acl=acl)


def _repeater_acl(db, local, **kwargs):
    kwargs.setdefault("max_clients", 10)
    return ACL(
        admin_password="adminpw",
        guest_password="guestpw",
        allow_read_only=True,
        store=db,
        local_identity=local,
        identity_label="repeater",
        **kwargs,
    )


def _room_acl(db, local, name="room-a"):
    return ACL(
        max_clients=10,
        store=db,
        local_identity=local,
        identity_label=acl_identity_label(name, "room_server"),
        persist_filter=lambda c: c.is_admin(),
    )


def _login(acl, client, password, timestamp, config=None):
    return acl.authenticate_client(
        client_identity=Identity(client.get_public_key()),
        shared_secret=b"s" * 32,
        password=password,
        timestamp=timestamp,
        target_identity_config=config,
    )


def _acl_rows(db):
    with db._connect() as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM acl_entries").fetchall()]


@pytest.fixture
def db(tmp_path):
    return SQLiteHandler(tmp_path)


# ---------------------------------------------------------------------------
# setperm parsing and replies (firmware simple_repeater handleCommand)
# ---------------------------------------------------------------------------

FULL = LocalIdentity().get_public_key().hex()


@pytest.mark.parametrize(
    "command, reply",
    [
        ("setperm " + FULL, "Err - bad params"),  # no separator
        ("setperm zz" + FULL[2:] + " 3", "Err - bad pubkey"),  # not hex
        ("setperm abc 3", "Err - bad pubkey"),  # odd length
        ("setperm " + FULL + "ab 3", "Err - bad pubkey"),  # longer than a key
        ("setperm " + FULL[:4] + " 3", "Err - invalid params"),  # a role needs the full key
        ("setperm " + FULL[:4] + " 0", "Err - invalid params"),  # delete, but no match
        ("setperm " + "ab" * 32 + " 3", "Err - invalid params"),  # not an ed25519 key
        ("setperm " + FULL + " 3", "OK"),
    ],
)
def test_setperm_replies_match_firmware(command, reply):
    assert _cli(ACL())._cmd_setperm(command) == reply


def test_setperm_full_key_creates_an_entry_with_the_whole_byte():
    acl = ACL()
    cli = _cli(acl)

    assert cli._cmd_setperm("setperm " + FULL + " 3") == "OK"
    assert acl.get_client(bytes.fromhex(FULL)).permissions == PERM_ACL_ADMIN

    # Firmware stores the whole byte, not just the role bits.
    assert cli._cmd_setperm("setperm " + FULL + " 129") == "OK"
    client = acl.get_client(bytes.fromhex(FULL))
    assert client.permissions == 0x81
    assert client.permissions & 3 == PERM_ACL_READ_ONLY


def test_setperm_guest_role_deletes_by_prefix():
    acl = ACL()
    cli = _cli(acl)
    cli._cmd_setperm("setperm " + FULL + " 3")

    assert cli._cmd_setperm("setperm " + FULL[:4] + " 0") == "OK"
    assert acl.get_num_clients() == 0
    assert cli._cmd_setperm("setperm " + FULL[:4] + " 0") == "Err - invalid params"


def test_setperm_parses_perms_like_atoi():
    acl = ACL()
    cli = _cli(acl)
    cli._cmd_setperm("setperm " + FULL + " 2")

    # atoi("abc") is 0, the guest role: a delete, not an error.
    assert cli._cmd_setperm("setperm " + FULL + " abc") == "OK"
    assert acl.get_num_clients() == 0

    # atoi stops at the first non-digit; -1 wraps to 0xFF, an admin role.
    assert cli._cmd_setperm("setperm " + FULL + " 2x") == "OK"
    assert acl.get_client(bytes.fromhex(FULL)).permissions == PERM_ACL_READ_WRITE
    assert cli._cmd_setperm("setperm " + FULL + " -1") == "OK"
    assert acl.get_client(bytes.fromhex(FULL)).permissions == 0xFF


def test_setperm_with_an_empty_key_does_not_delete_anyone():
    # Firmware matches an empty prefix against its first entry; we refuse.
    acl = ACL()
    cli = _cli(acl)
    cli._cmd_setperm("setperm " + FULL + " 3")

    assert cli._cmd_setperm("setperm  0") == "Err - invalid params"
    assert acl.get_num_clients() == 1


def test_setperm_through_handle_command_echoes_the_prefix():
    cli = _cli(ACL())
    assert cli.handle_command(b"x", "07|setperm " + FULL + " 3", is_admin=True) == "07|OK"
    assert cli.handle_command(b"x", "setperm " + FULL + " 3", is_admin=False).startswith("Error:")


def test_setperm_without_an_acl_is_an_error_not_a_crash():
    assert _cli(None)._cmd_setperm("setperm " + FULL + " 3") == "Err - invalid params"


# ---------------------------------------------------------------------------
# get acl: the local console only
# ---------------------------------------------------------------------------


def test_get_acl_lists_entries_with_permissions_on_the_local_console_only():
    acl = ACL(allow_read_only=True)
    cli = _cli(acl)
    cli._cmd_setperm("setperm " + FULL + " 3")
    # A blank-password guest has permissions 0 and is left out, as in firmware.
    guest = LocalIdentity()
    _login(acl, guest, "", 1)

    assert cli.handle_command(b"x", "get acl", is_admin=True, local=True) == (
        "ACL:\n03 " + FULL.upper()
    )
    assert cli.handle_command(b"x", "get acl", is_admin=True) == (
        "Error: Use 'get acl' via serial console only"
    )


def test_get_acl_is_not_swallowed_by_get():
    cli = _cli(ACL())
    assert cli.handle_command(b"x", "get acl", is_admin=True, local=True) == "ACL:"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_setperm_admin_survives_a_restart_and_logs_in_with_a_blank_password(db):
    local = LocalIdentity()
    admin = LocalIdentity()

    before = _repeater_acl(db, local)
    assert _cli(before)._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3") == "OK"

    after = _repeater_acl(db, local)
    assert after.load() == 1
    loaded = after.get_client(admin.get_public_key())
    # Known but not active until it logs in, as firmware after a reboot.
    assert loaded.last_activity == 0
    assert loaded.last_timestamp == 0
    # The shared secret is derived, never stored.
    assert loaded.shared_secret == Identity(admin.get_public_key()).calc_shared_secret(
        local.get_private_key()
    )

    ok, perms = _login(after, admin, "", 100)
    assert (ok, perms) == (True, PERM_ACL_ADMIN)
    # Our blank-password path keeps the replay check firmware lacks.
    assert _login(after, admin, "", 100) == (False, 0)


def test_password_admin_login_persists_but_a_guest_login_does_not(db):
    local = LocalIdentity()
    admin, guest, reader = LocalIdentity(), LocalIdentity(), LocalIdentity()

    acl = _repeater_acl(db, local)
    assert _login(acl, admin, "adminpw", 1) == (True, PERM_ACL_ADMIN)
    assert _login(acl, guest, "guestpw", 1) == (True, PERM_ACL_GUEST)
    assert _login(acl, reader, "", 1) == (True, PERM_ACL_GUEST)

    reloaded = _repeater_acl(db, local)
    assert reloaded.load() == 1
    assert reloaded.get_client(admin.get_public_key()) is not None


def test_a_returning_admin_login_does_not_rewrite_its_entry(db):
    local = LocalIdentity()
    admin = LocalIdentity()
    acl = _repeater_acl(db, local)
    _login(acl, admin, "adminpw", 1)

    db.upsert_acl_entry = MagicMock(wraps=db.upsert_acl_entry)
    _login(acl, admin, "adminpw", 2)
    _login(acl, admin, "", 3)
    db.upsert_acl_entry.assert_not_called()


def test_room_server_persists_admins_only(db):
    local = LocalIdentity()
    admin, writer = LocalIdentity(), LocalIdentity()

    acl = _room_acl(db, local)
    assert _login(acl, admin, "roomadmin", 1, ROOM_CFG) == (True, PERM_ACL_ADMIN)
    assert _login(acl, writer, "roomguest", 1, ROOM_CFG) == (True, PERM_ACL_READ_WRITE)

    reloaded = _room_acl(db, local)
    assert reloaded.load() == 1
    assert reloaded.get_client(admin.get_public_key()) is not None
    assert reloaded.get_client(writer.get_public_key()) is None


def test_demoting_a_room_admin_drops_its_stored_entry(db):
    local = LocalIdentity()
    admin = LocalIdentity()
    acl = _room_acl(db, local)
    _login(acl, admin, "roomadmin", 1, ROOM_CFG)
    # Same key logs in with the room password: now read-write, not an admin.
    _login(acl, admin, "roomguest", 2, ROOM_CFG)

    assert _room_acl(db, local).load() == 0


def test_remove_client_deletes_the_stored_entry(db):
    local = LocalIdentity()
    admin = LocalIdentity()
    acl = _repeater_acl(db, local)
    _login(acl, admin, "adminpw", 1)

    assert acl.remove_client(admin.get_public_key()) is True
    assert _repeater_acl(db, local).load() == 0


def test_setperm_delete_removes_the_stored_entry(db):
    local = LocalIdentity()
    admin = LocalIdentity()
    acl = _repeater_acl(db, local)
    cli = _cli(acl)
    cli._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")
    cli._cmd_setperm(f"setperm {admin.get_public_key()[:4].hex()} 0")

    assert _repeater_acl(db, local).load() == 0


def test_identities_do_not_share_entries_even_when_their_hash_bytes_collide(db):
    first = LocalIdentity()
    second = LocalIdentity()
    while second.get_public_key()[0] != first.get_public_key()[0]:
        second = LocalIdentity()
    admin = LocalIdentity()

    _cli(_repeater_acl(db, first))._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")

    assert _room_acl(db, second).load() == 0
    assert _repeater_acl(db, first).load() == 1


def test_a_new_identity_key_keeps_the_acl(db):
    # Firmware's ACL survives a new private key; it recomputes secrets on load.
    old_key, new_key = LocalIdentity(), LocalIdentity()
    admin = LocalIdentity()
    _cli(_repeater_acl(db, old_key))._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")

    rotated = _repeater_acl(db, new_key)
    assert rotated.load() == 1
    assert rotated.get_client(admin.get_public_key()).shared_secret == Identity(
        admin.get_public_key()
    ).calc_shared_secret(new_key.get_private_key())
    # The rows moved; the old key has none left.
    assert [r["identity_pubkey"] for r in _acl_rows(db)] == [new_key.get_public_key().hex()]


def test_a_renamed_room_keeps_its_acl_and_a_later_key_change_still_finds_it(db):
    key, new_key = LocalIdentity(), LocalIdentity()
    admin = LocalIdentity()
    _cli(_room_acl(db, key, "old-name"))._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")

    assert _room_acl(db, key, "new-name").load() == 1
    assert _room_acl(db, new_key, "new-name").load() == 1


def test_deleting_an_identity_drops_its_acl(db):
    key = LocalIdentity()
    admin = LocalIdentity()
    _cli(_room_acl(db, key))._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")

    label = acl_identity_label("room-a", "room_server")
    assert db.delete_acl_identity(key.get_public_key().hex(), label) == 1
    # A room created later under the same name does not inherit the admins.
    assert _room_acl(db, LocalIdentity()).load() == 0


def test_a_failed_store_read_leaves_an_empty_acl():
    store = SimpleNamespace(load_acl_entries=MagicMock(side_effect=RuntimeError("db gone")))
    acl = ACL(store=store, local_identity=LocalIdentity(), identity_label="repeater")
    assert acl.load() == 0
    assert acl.get_num_clients() == 0


# ---------------------------------------------------------------------------
# A full table (firmware putClient)
# ---------------------------------------------------------------------------


def test_a_full_table_evicts_the_least_active_non_admin():
    acl = ACL(max_clients=3, admin_password="adminpw", allow_read_only=True)
    admin, old_guest, new_guest, newcomer = (LocalIdentity() for _ in range(4))
    _login(acl, admin, "adminpw", 1)
    _login(acl, old_guest, "", 1)
    _login(acl, new_guest, "", 1)
    acl.get_client(admin.get_public_key()).last_activity = 0  # admins are never picked
    acl.get_client(old_guest.get_public_key()).last_activity = 10
    acl.get_client(new_guest.get_public_key()).last_activity = 20

    assert _login(acl, newcomer, "", 1) == (True, PERM_ACL_GUEST)
    assert acl.get_client(old_guest.get_public_key()) is None
    assert acl.get_client(admin.get_public_key()) is not None
    assert acl.get_num_clients() == 3


def test_a_table_full_of_admins_refuses_rather_than_evicting_one():
    acl = ACL(max_clients=2, admin_password="adminpw", allow_read_only=True)
    cli = _cli(acl)
    first, second, newcomer = (LocalIdentity() for _ in range(3))
    cli._cmd_setperm(f"setperm {first.get_public_key().hex()} 3")
    cli._cmd_setperm(f"setperm {second.get_public_key().hex()} 3")

    assert _login(acl, newcomer, "", 1) == (False, 0)
    assert cli._cmd_setperm(f"setperm {newcomer.get_public_key().hex()} 3") == (
        "Err - invalid params"
    )
    assert acl.get_num_clients() == 2


def test_evicting_a_stored_entry_deletes_it(db):
    local = LocalIdentity()
    reader, newcomer = LocalIdentity(), LocalIdentity()
    acl = _repeater_acl(db, local, max_clients=1)
    _cli(acl)._cmd_setperm(f"setperm {reader.get_public_key().hex()} 1")
    _login(acl, newcomer, "", 1)

    assert _repeater_acl(db, local).load() == 0


# ---------------------------------------------------------------------------
# LoginHelper wiring
# ---------------------------------------------------------------------------


def _login_helper(db):
    return LoginHelper(identity_manager=MagicMock(), packet_injector=AsyncMock(), sqlite_handler=db)


def test_login_helper_loads_the_stored_acl_at_registration(db):
    local = LocalIdentity()
    admin = LocalIdentity()
    config = {"repeater": {"security": {"admin_password": "adminpw"}}}

    first = _login_helper(db)
    first.register_identity("repeater", local, identity_type="repeater", config=config)
    acl = first.get_acl_for_identity(local.get_public_key()[0])
    _cli(acl)._cmd_setperm(f"setperm {admin.get_public_key().hex()} 3")

    second = _login_helper(db)
    second.register_identity("repeater", local, identity_type="repeater", config=config)
    reloaded = second.get_acl_for_identity(local.get_public_key()[0])
    assert _login(reloaded, admin, "", 5) == (True, PERM_ACL_ADMIN)


def test_login_helper_room_acl_keeps_admins_only(db):
    local = LocalIdentity()
    admin, writer = LocalIdentity(), LocalIdentity()

    helper = _login_helper(db)
    helper.register_identity("room-a", local, identity_type="room_server", config=ROOM_CFG)
    acl = helper.get_acl_for_identity(local.get_public_key()[0])
    _login(acl, admin, "roomadmin", 1, ROOM_CFG)
    _login(acl, writer, "roomguest", 1, ROOM_CFG)

    again = _login_helper(db)
    again.register_identity("room-a", local, identity_type="room_server", config=ROOM_CFG)
    reloaded = again.get_acl_for_identity(local.get_public_key()[0])
    assert [c.id.get_public_key() for c in reloaded.get_all_clients()] == [admin.get_public_key()]


# ---------------------------------------------------------------------------
# Room server: loaded admins are neither pushed to nor evicted
# ---------------------------------------------------------------------------


def _room_server(acl, db):
    from repeater.handler_helpers.room_server import RoomServer

    return RoomServer(
        room_hash=0x34,
        room_name="room-a",
        local_identity=LocalIdentity(),
        sqlite_handler=db,
        packet_injector=AsyncMock(return_value=True),
        acl=acl,
    )


@pytest.mark.asyncio
async def test_room_eviction_keeps_a_stored_admin():
    acl = ACL(max_clients=5, admin_password="roomadmin")
    admin, writer = LocalIdentity(), LocalIdentity()
    _login(acl, admin, "roomadmin", 1, ROOM_CFG)
    _login(acl, writer, "roomguest", 1, ROOM_CFG)

    stale = time.time() - 10_000
    db = SimpleNamespace(
        get_all_room_clients=MagicMock(
            return_value=[
                {
                    "client_pubkey": c.get_public_key().hex(),
                    "push_failures": 0,
                    "last_activity": stale,
                }
                for c in (admin, writer)
            ]
        ),
        upsert_client_sync=MagicMock(),
    )
    await _room_server(acl, db)._evict_failed_clients()

    assert acl.get_client(admin.get_public_key()) is not None
    assert acl.get_client(writer.get_public_key()) is None


@pytest.mark.asyncio
async def test_room_sync_loop_does_not_push_to_an_entry_that_has_not_logged_in(monkeypatch):
    monkeypatch.setattr("repeater.handler_helpers.room_server.secrets.randbelow", lambda n: 0)
    monkeypatch.setattr("repeater.handler_helpers.room_server.SYNC_PUSH_INTERVAL_MS", 10)
    acl = ACL(max_clients=5)
    acl.apply_permissions(LocalIdentity().get_public_key(), PERM_ACL_ADMIN)

    db = SimpleNamespace(
        get_client_sync=MagicMock(return_value=None),
        upsert_client_sync=MagicMock(),
        get_unsynced_messages=MagicMock(return_value=[]),
        get_all_room_clients=MagicMock(return_value=[]),
        cleanup_old_messages=MagicMock(return_value=0),
    )
    rs = _room_server(acl, db)
    rs.next_push_time = 0
    rs._running = True

    task = asyncio.create_task(rs._sync_loop())
    await asyncio.sleep(0.3)
    rs._running = False
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    db.get_client_sync.assert_not_called()
    db.get_unsynced_messages.assert_not_called()

    # Once it logs in it is pushed to as before.
    acl.get_all_clients()[0].last_activity = int(time.time())
    rs.next_push_time = 0  # skip the back-off after a round with no one to push to
    rs._running = True
    task = asyncio.create_task(rs._sync_loop())
    await asyncio.sleep(0.3)
    rs._running = False
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    db.get_unsynced_messages.assert_called()
