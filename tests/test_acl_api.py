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
