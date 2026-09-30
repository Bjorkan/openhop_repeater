"""Re-registering a room identity (hot reload) must not leave a second sync loop."""

import asyncio
import threading
from unittest.mock import MagicMock

import pytest

from repeater.handler_helpers.text import TextHelper


class _FakeIdentity:
    def __init__(self, pubkey: bytes):
        self._pubkey = pubkey

    def get_public_key(self):
        return self._pubkey


class _FakeACL:
    def get_all_clients(self):
        return []


def _make_helper(acl_dict):
    helper = TextHelper(
        identity_manager=MagicMock(),
        acl_dict=acl_dict,
        sqlite_handler=MagicMock(),
    )
    helper._loop = asyncio.get_running_loop()
    return helper


def _running_sync_tasks():
    return [
        t
        for t in asyncio.all_tasks()
        if not t.done() and t.get_coro().__qualname__ == "RoomServer._sync_loop"
    ]


async def _settle(helper):
    for _ in range(5):
        if helper._pending_tasks:
            await asyncio.gather(*list(helper._pending_tasks), return_exceptions=True)
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_reregister_same_hash_leaves_one_sync_loop():
    old_acl, new_acl = _FakeACL(), _FakeACL()
    acl_dict = {0x41: old_acl}
    helper = _make_helper(acl_dict)
    identity = _FakeIdentity(b"A" * 32)

    helper.register_identity("room", identity, "room_server")
    await _settle(helper)
    old_room = helper.room_servers[0x41]
    assert len(_running_sync_tasks()) == 1

    acl_dict[0x41] = new_acl
    helper.register_identity("room-renamed", identity, "room_server", previous_name="room")
    await _settle(helper)

    new_room = helper.room_servers[0x41]
    assert new_room is not old_room
    assert new_room.acl is new_acl
    assert old_room._running is False
    assert old_room._sync_task.done()
    assert _running_sync_tasks() == [new_room._sync_task]

    await helper.cleanup()


@pytest.mark.asyncio
async def test_reregister_new_key_stops_room_under_old_hash():
    acl_dict = {0x41: _FakeACL(), 0x42: _FakeACL()}
    helper = _make_helper(acl_dict)

    helper.register_identity("room", _FakeIdentity(b"A" * 32), "room_server")
    await _settle(helper)
    old_room = helper.room_servers[0x41]

    helper.register_identity(
        "room-renamed", _FakeIdentity(b"B" * 32), "room_server", previous_name="room"
    )
    await _settle(helper)

    assert set(helper.room_servers) == {0x42}
    assert old_room._running is False
    assert _running_sync_tasks() == [helper.room_servers[0x42]._sync_task]

    await helper.cleanup()


@pytest.mark.asyncio
async def test_reregister_from_request_thread_stops_old_before_starting_new():
    acl_dict = {0x41: _FakeACL()}
    helper = _make_helper(acl_dict)
    identity = _FakeIdentity(b"A" * 32)

    helper.register_identity("room", identity, "room_server")
    await _settle(helper)
    old_room = helper.room_servers[0x41]

    # CherryPy request threads have no running loop: the swap is handed to
    # helper._loop with run_coroutine_threadsafe.
    thread = threading.Thread(
        target=helper.register_identity, args=("room", identity, "room_server")
    )
    thread.start()
    await asyncio.to_thread(thread.join)
    for _ in range(20):
        if helper.room_servers[0x41]._sync_task is not None:
            break
        await asyncio.sleep(0.01)

    new_room = helper.room_servers[0x41]
    assert new_room is not old_room
    assert old_room._running is False
    assert _running_sync_tasks() == [new_room._sync_task]

    await helper.cleanup()
