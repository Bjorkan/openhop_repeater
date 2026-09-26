"""ACL management over the web API: listing, setting, removing, and identity changes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import cherrypy
import pytest
from openhop_core import LocalIdentity
from openhop_core.protocol import Identity

from repeater.data_acquisition.sqlite_handler import SQLiteHandler
from repeater.handler_helpers.login import LoginHelper
from repeater.handler_helpers.mesh_cli import MeshCLI
from repeater.web.api_endpoints import APIEndpoints

ROOM_SETTINGS = {"admin_password": "roomadmin", "guest_password": "roomguest"}


@pytest.fixture
def request_ctx(monkeypatch):
    request = SimpleNamespace(method="GET", params={}, json={})
    response = SimpleNamespace(headers={}, status=200)
    monkeypatch.setattr(cherrypy, "request", request, raising=False)
    monkeypatch.setattr(cherrypy, "response", response, raising=False)
    return request


class _Daemon:
    """The parts of the daemon the ACL endpoints read, backed by a real store."""

    def __init__(self, db, rooms):
        self.local_identity = LocalIdentity()
        self.login_helper = LoginHelper(
            identity_manager=MagicMock(), packet_injector=AsyncMock(), sqlite_handler=db
        )
        self.login_helper.register_identity(
            "repeater",
            self.local_identity,
            identity_type="repeater",
            config={"repeater": {"security": {"admin_password": "adminpw"}}},
        )
        self.rooms = []
        for name, identity in rooms:
            self.add_room(name, identity)
        self.identity_manager = SimpleNamespace(get_identities_by_type=self._by_type)
        self.repeater_handler = SimpleNamespace(storage=SimpleNamespace(sqlite_handler=db))

    def add_room(self, name, identity):
        cfg = {"name": name, "type": "room_server", "settings": dict(ROOM_SETTINGS)}
        self.login_helper.register_identity(name, identity, identity_type="room_server", config=cfg)
        self.rooms.append((name, identity, cfg))

    def _by_type(self, kind):
        return list(self.rooms) if kind == "room_server" else []


def _api(daemon, config=None):
    api = APIEndpoints.__new__(APIEndpoints)
    api.config = config or {}
    api.daemon_instance = daemon
    api.config_manager = MagicMock()
    api.config_manager.save_to_file.return_value = True
    return api


def _post(request, api_method, body):
    request.method = "POST"
    request.json = body
    return api_method()


@pytest.fixture
def db(tmp_path):
    return SQLiteHandler(tmp_path)


def test_set_list_and_remove_an_entry(db, request_ctx):
    daemon = _Daemon(db, [])
    api = _api(daemon)
    admin = LocalIdentity().get_public_key().hex()

    result = _post(
        request_ctx,
        api.acl_set_permissions,
        {"identity_name": "repeater", "client_pubkey": admin, "permissions": 3},
    )
    assert result["success"] is True
    assert result["data"]["persisted"] is True
    assert result["data"]["permissions"] == "admin"

    request_ctx.method = "GET"
    listed = api.acl_clients(identity_name="repeater")["data"]["clients"]
    assert [(c["public_key_full"], c["permissions_value"], c["persisted"]) for c in listed] == [
        (admin, 3, True)
    ]
    assert listed[0]["identity_pubkey"] == daemon.local_identity.get_public_key().hex()
    info = api.acl_info()["data"]["acls"][0]
    # Provisioned, not logged in: an entry, stored, but not a session.
    assert (info["acl_entries"], info["stored_entries"], info["authenticated_clients"]) == (1, 1, 0)

    removed = _post(
        request_ctx,
        api.acl_remove_client,
        {"client_pubkey": admin, "identity_name": "repeater"},
    )
    assert removed["success"] is True
    assert removed["data"]["removed_from"] == ["repeater"]
    assert db.load_acl_entries(daemon.local_identity.get_public_key().hex()) == []


def test_remove_accepts_the_legacy_public_key_field(db, request_ctx):
    daemon = _Daemon(db, [])
    api = _api(daemon)
    admin = LocalIdentity().get_public_key()
    daemon.login_helper.get_acl_by_name("repeater").apply_permissions(admin, 3)

    removed = _post(request_ctx, api.acl_remove_client, {"public_key": admin.hex()})
    assert removed["success"] is True


@pytest.mark.parametrize(
    "body, message",
    [
        ({"client_pubkey": "aa" * 32, "permissions": 3}, "identity_name"),
        ({"identity_name": "repeater", "client_pubkey": "aa" * 16, "permissions": 3}, "64"),
        ({"identity_name": "repeater", "client_pubkey": "zz" * 32, "permissions": 3}, "hex"),
        ({"identity_name": "repeater", "client_pubkey": "aa" * 32, "permissions": "3"}, "integer"),
        ({"identity_name": "repeater", "client_pubkey": "aa" * 32, "permissions": True}, "integer"),
        ({"identity_name": "repeater", "client_pubkey": "aa" * 32, "permissions": 0}, "remove"),
        ({"identity_name": "repeater", "client_pubkey": "aa" * 32, "permissions": 128}, "remove"),
        ({"identity_name": "nope", "client_pubkey": "aa" * 32, "permissions": 3}, "not found"),
        ({"identity_name": "repeater", "client_pubkey": "ab" * 32, "permissions": 3}, "valid"),
    ],
)
def test_set_permissions_validates_its_input(db, request_ctx, body, message):
    api = _api(_Daemon(db, []))
    result = _post(request_ctx, api.acl_set_permissions, body)
    assert result["success"] is False
    assert message in result["error"]


def test_a_room_read_write_entry_is_reported_as_not_stored(db, request_ctx):
    daemon = _Daemon(db, [("room-a", LocalIdentity())])
    api = _api(daemon)
    result = _post(
        request_ctx,
        api.acl_set_permissions,
        {
            "identity_name": "room-a",
            "client_pubkey": LocalIdentity().get_public_key().hex(),
            "permissions": 2,
        },
    )
    assert result["success"] is True
    assert result["data"]["persisted"] is False
    assert "until restart" in result["message"]


def test_identities_that_share_a_hash_byte_are_listed_separately(db, request_ctx):
    daemon = _Daemon(db, [])
    twin = LocalIdentity()
    while twin.get_public_key()[0] != daemon.local_identity.get_public_key()[0]:
        twin = LocalIdentity()
    daemon.add_room("room-a", twin)
    api = _api(daemon)
    for name in ("repeater", "room-a"):
        _post(
            request_ctx,
            api.acl_set_permissions,
            {
                "identity_name": name,
                "client_pubkey": LocalIdentity().get_public_key().hex(),
                "permissions": 3,
            },
        )

    request_ctx.method = "GET"
    listed = api.acl_clients()["data"]["clients"]
    assert sorted(c["identity_name"] for c in listed) == ["repeater", "room-a"]


def test_update_identity_moves_a_room_acl_when_renamed_and_rekeyed(db, request_ctx):
    old_seed = "11" * 32
    old_identity = LocalIdentity(seed=bytes.fromhex(old_seed))
    daemon = _Daemon(db, [("room-a", old_identity)])
    config = {
        "identities": {
            "room_servers": [
                {"name": "room-a", "identity_key": old_seed, "settings": dict(ROOM_SETTINGS)}
            ]
        }
    }
    api = _api(daemon, config)
    admin = LocalIdentity()
    daemon.login_helper.get_acl_by_name("room-a").apply_permissions(admin.get_public_key(), 3)

    new_seed = "22" * 32
    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "room-b", "identity_key": new_seed}
    assert api.update_identity()["success"] is True

    new_identity = LocalIdentity(seed=bytes.fromhex(new_seed))
    rows = db.load_acl_entries(new_identity.get_public_key().hex())
    assert [r["client_pubkey"] for r in rows] == [admin.get_public_key().hex()]
    assert db.load_acl_entries(old_identity.get_public_key().hex()) == []


def test_delete_identity_drops_the_room_acl(db, request_ctx):
    seed = "33" * 32
    identity = LocalIdentity(seed=bytes.fromhex(seed))
    daemon = _Daemon(db, [("room-a", identity)])
    daemon.identity_manager.named_identities = {}
    config = {"identities": {"room_servers": [{"name": "room-a", "identity_key": seed}]}}
    api = _api(daemon, config)
    daemon.login_helper.get_acl_by_name("room-a").apply_permissions(
        LocalIdentity().get_public_key(), 3
    )

    request_ctx.method = "DELETE"
    assert api.delete_identity(name="room-a", type="room_server")["success"] is True
    assert db.load_acl_entries(identity.get_public_key().hex()) == []


def test_web_cli_get_acl_is_local(db, request_ctx):
    daemon = _Daemon(db, [])
    acl = daemon.login_helper.get_acl_by_name("repeater")
    admin = LocalIdentity().get_public_key()
    acl.apply_permissions(admin, 3)
    cli = MeshCLI(
        "/tmp/cfg.yaml",
        {"repeater": {}},
        SimpleNamespace(save_to_file=MagicMock(return_value=True), live_update_daemon=MagicMock()),
        acl=acl,
    )
    daemon.text_helper = SimpleNamespace(cli=cli)
    api = _api(daemon)

    # Past the auth decorator: authentication is not what this covers.
    reply = _post(request_ctx, lambda: APIEndpoints.cli.__wrapped__(api), {"command": "get acl"})
    assert reply["data"]["reply"] == "ACL:\n03 " + admin.hex().upper()
    # The mesh path passes no local flag.
    assert cli.handle_command(b"x", "get acl", is_admin=True).startswith("Error:")


def test_a_loaded_admin_has_a_secret_for_the_current_key(db):
    # The UI's "stored" entries must be usable straight after a restart.
    daemon = _Daemon(db, [])
    admin = LocalIdentity()
    daemon.login_helper.get_acl_by_name("repeater").apply_permissions(admin.get_public_key(), 3)

    restarted = LoginHelper(
        identity_manager=MagicMock(), packet_injector=AsyncMock(), sqlite_handler=db
    )
    restarted.register_identity(
        "repeater", daemon.local_identity, identity_type="repeater", config={"repeater": {}}
    )
    client = restarted.get_acl_by_name("repeater").get_client(admin.get_public_key())
    assert client.shared_secret == Identity(admin.get_public_key()).calc_shared_secret(
        daemon.local_identity.get_private_key()
    )


def _room_update_setup(db):
    old_seed, other_seed = "11" * 32, "44" * 32
    old_identity = LocalIdentity(seed=bytes.fromhex(old_seed))
    daemon = _Daemon(db, [("room-a", old_identity)])
    config = {
        "identities": {
            "room_servers": [
                {"name": "room-a", "identity_key": old_seed, "settings": dict(ROOM_SETTINGS)},
                {"name": "room-b", "identity_key": other_seed, "settings": dict(ROOM_SETTINGS)},
            ]
        }
    }
    admin = LocalIdentity()
    daemon.login_helper.get_acl_by_name("room-a").apply_permissions(admin.get_public_key(), 3)
    return daemon, config, old_identity, admin


def test_update_identity_refuses_a_key_another_identity_uses(db, request_ctx):
    daemon, config, old_identity, admin = _room_update_setup(db)
    api = _api(daemon, config)

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "renamed", "identity_key": "44" * 32}
    result = api.update_identity()

    assert result["success"] is False
    assert "already used" in result["error"]
    room = config["identities"]["room_servers"][0]
    assert (room["name"], room["identity_key"]) == ("room-a", "11" * 32)
    api.config_manager.save_to_file.assert_not_called()
    assert len(db.load_acl_entries(old_identity.get_public_key().hex())) == 1


def test_update_identity_does_not_save_a_key_whose_acl_did_not_move(db, request_ctx):
    daemon, config, old_identity, admin = _room_update_setup(db)
    api = _api(daemon, config)
    daemon.login_helper.move_room_acl = MagicMock(side_effect=RuntimeError("disk full"))

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "identity_key": "22" * 32}
    result = api.update_identity()

    assert result["success"] is False
    api.config_manager.save_to_file.assert_not_called()
    assert config["identities"]["room_servers"][0]["identity_key"] == "11" * 32


def test_a_failed_config_save_moves_the_acl_back(db, request_ctx):
    daemon, config, old_identity, admin = _room_update_setup(db)
    api = _api(daemon, config)
    api.config_manager.save_to_file.return_value = False

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "identity_key": "22" * 32}
    assert api.update_identity()["success"] is False

    assert len(db.load_acl_entries(old_identity.get_public_key().hex())) == 1
    new_identity = LocalIdentity(seed=bytes.fromhex("22" * 32))
    assert db.load_acl_entries(new_identity.get_public_key().hex()) == []


def test_acl_info_uses_the_right_acl_when_hashes_collide(db, request_ctx):
    daemon = _Daemon(db, [])
    twin = LocalIdentity()
    while twin.get_public_key()[0] != daemon.local_identity.get_public_key()[0]:
        twin = LocalIdentity()
    daemon.add_room("room-a", twin)
    daemon.login_helper.get_acl_by_name("room-a").apply_permissions(
        LocalIdentity().get_public_key(), 3
    )
    api = _api(daemon)

    acls = {a["name"]: a for a in api.acl_info()["data"]["acls"]}
    assert acls["repeater"]["acl_entries"] == 0
    assert acls["room-a"]["acl_entries"] == 1
    assert acls["room-a"]["has_admin_password"] is True
    assert acls["repeater"]["store_error"] is None


def test_a_refused_update_leaves_the_live_config_unchanged(db, request_ctx):
    daemon, config, old_identity, admin = _room_update_setup(db)
    api = _api(daemon, config)
    before = dict(config["identities"]["room_servers"][0], settings=dict(ROOM_SETTINGS))

    request_ctx.method = "PUT"
    request_ctx.json = {
        "name": "room-a",
        "new_name": "renamed",
        "settings": {"admin_password": "same", "guest_password": "same"},
    }
    assert api.update_identity()["success"] is False
    assert config["identities"]["room_servers"][0] == before


def test_a_key_change_with_no_store_is_refused(request_ctx):
    config = {
        "identities": {
            "room_servers": [{"name": "room-a", "identity_key": "11" * 32, "settings": {}}]
        }
    }
    api = _api(SimpleNamespace(), config)
    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "identity_key": "22" * 32}
    result = api.update_identity()
    assert result["success"] is False
    assert "no ACL store" in result["error"]
    api.config_manager.save_to_file.assert_not_called()


def test_a_room_without_an_acl_does_not_borrow_one_by_hash(db, request_ctx):
    daemon = _Daemon(db, [])
    twin = LocalIdentity()
    while twin.get_public_key()[0] != daemon.local_identity.get_public_key()[0]:
        twin = LocalIdentity()
    # Registered with the identity manager but, having no passwords, not for logins.
    daemon.rooms.append(("room-b", twin, {"name": "room-b", "settings": {}}))
    api = _api(daemon)

    names = [a["name"] for a in api.acl_info()["data"]["acls"]]
    assert names == ["repeater"]
    result = _post(
        request_ctx,
        api.acl_set_permissions,
        {
            "identity_name": "room-b",
            "client_pubkey": LocalIdentity().get_public_key().hex(),
            "permissions": 3,
        },
    )
    assert result["success"] is False


def test_acl_clients_reports_an_unreadable_store(db, request_ctx):
    daemon = _Daemon(db, [])
    daemon.login_helper.get_acl_by_name("repeater").load_error = "database is locked"
    api = _api(daemon)
    data = api.acl_clients()["data"]
    assert data["store_errors"] == {"repeater": "database is locked"}


def test_remove_from_every_acl_reports_which_failed(db, request_ctx):
    from repeater.handler_helpers.acl import ACLStoreError

    daemon = _Daemon(db, [("room-a", LocalIdentity())])
    key = LocalIdentity().get_public_key()
    for name in ("repeater", "room-a"):
        daemon.login_helper.get_acl_by_name(name).apply_permissions(key, 3)
    daemon.login_helper.get_acl_by_name("room-a").remove_client = MagicMock(
        side_effect=ACLStoreError("disk full")
    )
    api = _api(daemon)

    result = _post(request_ctx, api.acl_remove_client, {"client_pubkey": key.hex()})
    assert result["success"] is False
    assert "room-a (disk full)" in result["error"]
    assert "removed from repeater" in result["error"]


class _LiveDaemon:
    """A daemon whose hot reload goes through the real IdentityManager, as main.py's does."""

    def __init__(self, db, room_name, room_seed):
        from repeater.identity_manager import IdentityManager

        self.identity_manager = IdentityManager({})
        self.local_identity = LocalIdentity()
        self.login_helper = LoginHelper(
            identity_manager=self.identity_manager, packet_injector=AsyncMock(), sqlite_handler=db
        )
        self.repeater_handler = SimpleNamespace(storage=SimpleNamespace(sqlite_handler=db))
        self.login_helper.register_identity(
            "repeater", self.local_identity, identity_type="repeater", config={"repeater": {}}
        )
        cfg = {"name": room_name, "identity_key": room_seed, "settings": dict(ROOM_SETTINGS)}
        self._register_identity_everywhere(
            room_name, LocalIdentity(seed=bytes.fromhex(room_seed)), cfg, "room_server"
        )
        self.config = {"identities": {"room_servers": [cfg]}}

    def _register_identity_everywhere(
        self, name, identity, config, identity_type, previous_name=None
    ):
        if not self.identity_manager.register_identity(
            name=name, identity=identity, config=config, identity_type=identity_type
        ):
            return False
        self.login_helper.register_identity(
            name=name, identity=identity, identity_type=identity_type, config=config
        )
        return True


def test_a_rename_applies_live_and_the_room_stays_manageable(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)
    acl = daemon.login_helper.get_acl_by_name("room-a")
    acl.apply_permissions(LocalIdentity().get_public_key(), 3)

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "room-b"}
    result = api.update_identity()
    assert "applied immediately" in result["message"]

    assert daemon.login_helper.get_acl_by_name("room-b") is acl
    assert daemon.login_helper.get_acl_by_name("room-a") is None
    added = _post(
        request_ctx,
        api.acl_set_permissions,
        {
            "identity_name": "room-b",
            "client_pubkey": LocalIdentity().get_public_key().hex(),
            "permissions": 3,
        },
    )
    assert added["success"] is True


def test_a_rename_then_a_rekey_leaves_one_live_acl(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)
    daemon.login_helper.get_acl_by_name("room-a").apply_permissions(
        LocalIdentity().get_public_key(), 3
    )

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "room-b"}
    api.update_identity()
    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-b", "identity_key": "22" * 32}
    assert "applied immediately" in api.update_identity()["message"]

    attached = [a for a in set(daemon.login_helper.acls_by_name.values()) if not a.detached]
    assert len(attached) == 2  # the repeater and the room
    assert [n for n, *_ in daemon.identity_manager.get_identities_by_type("room_server")] == [
        "room-b"
    ]
    new_pubkey = LocalIdentity(seed=bytes.fromhex("22" * 32)).get_public_key().hex()
    assert daemon.login_helper.get_acl_by_name("room-b").store_key == new_pubkey
    assert len(db.load_acl_entries(new_pubkey)) == 1


def test_a_refused_hot_reload_keeps_the_room_registered(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)
    daemon._register_identity_everywhere = MagicMock(return_value=False)

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "room-b"}
    assert "Restart required" in api.update_identity()["message"]
    assert [n for n, *_ in daemon.identity_manager.get_identities_by_type("room_server")] == [
        "room-a"
    ]


def test_a_hot_reload_that_raises_keeps_the_room_registered(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)
    daemon._register_identity_everywhere = MagicMock(side_effect=RuntimeError("boom"))

    request_ctx.method = "PUT"
    request_ctx.json = {"name": "room-a", "new_name": "room-b"}
    assert "Restart required" in api.update_identity()["message"]
    assert [n for n, *_ in daemon.identity_manager.get_identities_by_type("room_server")] == [
        "room-a"
    ]


def test_a_rename_that_clears_the_passwords_waits_for_a_restart(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)

    request_ctx.method = "PUT"
    request_ctx.json = {
        "name": "room-a",
        "new_name": "room-b",
        "settings": {"admin_password": "", "guest_password": ""},
    }
    assert "Restart required" in api.update_identity()["message"]
    # Nothing half-applied: the running room keeps its registration and ACL.
    assert [n for n, *_ in daemon.identity_manager.get_identities_by_type("room_server")] == [
        "room-a"
    ]
    assert daemon.login_helper.get_acl_by_name("room-a") is not None


def test_delete_identity_frees_the_name_and_hash(db, request_ctx):
    daemon = _LiveDaemon(db, "room-a", "11" * 32)
    api = _api(daemon, daemon.config)

    request_ctx.method = "DELETE"
    assert api.delete_identity(name="room-a", type="room_server")["success"] is True
    identity = LocalIdentity(seed=bytes.fromhex("11" * 32))
    # Re-creating the room registers at once instead of conflicting until a restart.
    assert daemon.identity_manager.registration_error("room-a", identity, "room_server") is None
