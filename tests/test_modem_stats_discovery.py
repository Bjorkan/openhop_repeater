import json
import urllib.error

import pytest

from repeater.sensors.manager import SensorManager
from repeater.sensors.openhop_modem import OpenHopModemSensor


class Response:
    status = 200

    def __init__(self, payload):
        self.body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def sensor(name="modem", **settings):
    return OpenHopModemSensor(name, {"settings": {"host": "example.test", **settings}})


def test_environment_and_agc_descriptors_from_single_read(monkeypatch):
    payload = {
        "system": {"die_temperature_c": "51.2"},
        "environment": {
            "available": True,
            "temperature_c": 23.4,
            "humidity_pct": 0,
            "pressure_hpa": 1008.2,
            "new_measure": -3,
            "flag": False,
            "numeric_string": "12",
        },
        "radio": {
            "agc_reset_count": 0,
            "last_agc_reset_ms_ago": None,
            "agc_reset_interval_sec": 30,
        },
    }
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen", lambda *_a, **_k: Response(payload)
    )
    result = sensor().read()
    assert result["ok"] is True
    assert result["data"]["temperature_c"] == 51.2
    assert result["data"]["modem:/environment/temperature_c"] == 23.4
    assert result["data"]["modem:/environment/flag"] is False
    assert result["data"]["modem:/environment/humidity_pct"] == 0
    assert "modem:/environment/numeric_string" not in result["data"]
    assert result["data"]["modem:/radio/last_agc_reset_ms_ago"] is None
    descriptors = {d["id"]: d for d in result["metrics"]}
    assert descriptors["/environment/temperature_c"]["unit"] == "°C"
    assert descriptors["/radio/agc_reset_count"]["category"] == "diagnostic"
    assert descriptors["/radio/last_agc_reset_ms_ago"]["available"] is False
    assert descriptors["/environment/new_measure"]["unit"] is None
    assert len([d for d in result["metrics"] if d["id"] == "/environment/temperature_c"]) == 1


def test_path_policy_bounds_and_availability(monkeypatch):
    payloads = [
        {
            "environment": {
                "available": False,
                "temperature_c": 100,
                "nested": {"a/b": 0},
                "token": {"value": 99},
                "gps": {"latitude": 10},
                "settings": {"voltage": 2},
                "untyped": None,
            },
            "counters": {"rx_packets": 5, "new": float("nan")},
            "network": {"new": 3},
            "radio": {"unknown": 2},
        },
        {
            "environment": {
                "available": True,
                "temperature_c": 22,
                "nested": {"a/b": -1},
                "untyped": False,
            }
        },
        {"environment": {"available": False}},
    ]
    instance = sensor()
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen",
        lambda *_a, **_k: Response(payloads.pop(0)),
    )
    first = instance.read()
    assert first["data"]["modem:/environment/temperature_c"] is None
    assert first["data"]["modem:/environment/nested/a~1b"] is None
    assert "modem:/environment/untyped" not in first["data"]
    assert not any("token" in key or "gps" in key or "settings" in key for key in first["data"])
    assert "modem:/network/new" not in first["data"]
    assert "modem:/counters/rx_packets" not in first["data"]  # compatibility key only
    second = instance.read()
    assert second["data"]["modem:/environment/untyped"] is False
    assert second["data"]["modem:/environment/nested/a~1b"] == -1
    third = instance.read()
    assert third["data"]["modem:/environment/nested/a~1b"] is None
    assert (
        next(d for d in third["metrics"] if d["id"] == "/environment/nested/a~1b")["reason"]
        == "source_unavailable"
    )


def test_failure_clears_previous_values_and_redacts_url(monkeypatch):
    instance = sensor(base_url="http://user:password@example.test")
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen",
        lambda *_a, **_k: Response({"environment": {"temperature_c": 20}}),
    )
    assert instance.read()["ok"]

    def fail(*_a, **_k):
        raise urllib.error.URLError("http://user:password@example.test/secret")

    monkeypatch.setattr("repeater.sensors.openhop_modem.urllib.request.urlopen", fail)
    result = instance.read()
    assert result["ok"] is False
    assert result["data"] == {}
    assert "password" not in str(result)
    assert result["metrics"][0]["reason"] == "read_failed"


@pytest.mark.parametrize(
    "settings",
    [
        {"endpoint": "/api/private-token/api/stats?token=query-secret"},
        {"base_url": "https://user:password@example.test/private-token/", "endpoint": "/stats"},
    ],
)
def test_published_url_is_origin_only_while_request_uses_configured_path(monkeypatch, settings):
    requested = []

    def fetch(request, **_kwargs):
        requested.append(request.full_url)
        return Response({"environment": {"available": True}})

    monkeypatch.setattr("repeater.sensors.openhop_modem.urllib.request.urlopen", fetch)
    instance = sensor(**settings)
    result = instance.read()
    assert result["ok"] is True
    assert result["data"]["url"] in {"http://example.test", "https://example.test"}
    assert "private-token" in requested[0]
    assert "private-token" not in str(result)
    assert "query-secret" not in str(result)
    assert "password" not in str(result)


def test_oversized_response_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen",
        lambda *_a, **_k: Response(b" " * 131073),
    )
    result = sensor().read()
    assert result["ok"] is False
    assert "too large" in result["error"]


def test_discovery_caps_and_exclusion(monkeypatch):
    payload = {"environment": {f"field_{i:03}": i for i in range(100)}}
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen", lambda *_a, **_k: Response(payload)
    )
    result = sensor(discovery_exclude_paths="/environment/field_000").read()
    keys = [key for key in result["data"] if key.startswith("modem:")]
    assert len(keys) <= 64
    assert "modem:/environment/field_000" not in keys
    assert result["data"]["modem:/environment/field_001"] == 1
    assert result["data"].get("modem:/environment/field_099") is None
    assert result["data"]["modem_discovery_truncated"] is True


def test_known_environment_fields_and_agc_survive_dynamic_path_cap(monkeypatch):
    payload = {
        "environment": {
            **{f"field_{i:03}": i for i in range(100)},
            "available": True,
            "temperature_c": 21,
            "humidity_pct": 54,
            "pressure_hpa": 1012,
        },
        "radio": {"agc_reset_count": 3, "last_agc_reset_ms_ago": 12, "agc_reset_interval_sec": 30},
    }
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen", lambda *_a, **_k: Response(payload)
    )
    result = sensor().read()
    assert result["ok"] is True
    assert len(result["metrics"]) == 64
    for path in (
        "/environment/available",
        "/environment/temperature_c",
        "/environment/humidity_pct",
        "/environment/pressure_hpa",
        "/radio/agc_reset_count",
        "/radio/last_agc_reset_ms_ago",
        "/radio/agc_reset_interval_sec",
    ):
        assert "modem:" + path in result["data"]
    assert result["data"]["modem_discovery_truncated"] is True


def test_priority_fields_survive_node_cap_before_generic_sorted_leaves():
    from repeater.sensors.modem_stats_discovery import MAX_NODES, ModemDiscovery

    payload = {
        "counters": {f"a_{i:04}": i for i in range(MAX_NODES + 100)},
        "environment": {"available": True, "temperature_c": 22, "humidity_pct": None},
        "radio": {"reviewed": 7, "agc_reset_count": 4},
    }
    discovery = ModemDiscovery(include="/radio/reviewed")
    data, metrics = discovery.select(payload)
    assert data["modem:/environment/available"] is True
    assert data["modem:/environment/temperature_c"] == 22
    assert data["modem:/environment/humidity_pct"] is None
    assert data["modem:/radio/agc_reset_count"] == 4
    assert data["modem:/radio/reviewed"] == 7
    assert len(metrics) <= 64
    assert data["modem_discovery_truncated"] is True


def test_later_priority_field_is_not_starved_by_prior_generic_admissions():
    from repeater.sensors.modem_stats_discovery import ModemDiscovery

    discovery = ModemDiscovery(include="/radio/reviewed")
    first, _ = discovery.select({"environment": {f"field_{i:03}": i for i in range(100)}})
    assert first["modem_discovery_truncated"] is True
    later, _ = discovery.select(
        {
            "environment": {"available": True, "temperature_c": 23},
            "radio": {"reviewed": 7, "agc_reset_count": 5},
        }
    )
    assert later["modem:/environment/temperature_c"] == 23
    assert later["modem:/radio/reviewed"] == 7
    assert later["modem:/radio/agc_reset_count"] == 5


def test_huge_integer_leaf_does_not_fail_other_sensor_values(monkeypatch):
    payload = {"environment": {"huge": 10**400, "temperature_c": 24}}
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen", lambda *_a, **_k: Response(payload)
    )
    result = sensor().read()
    assert result["ok"] is True
    assert result["data"]["modem:/environment/temperature_c"] == 24
    assert "modem:/environment/huge" not in result["data"]


def test_include_cannot_duplicate_compatibility_counter():
    from repeater.sensors.modem_stats_discovery import ModemDiscovery

    data, metrics = ModemDiscovery(include="/counters/rx_packets").select(
        {"counters": {"rx_packets": 5}}
    )
    assert "modem:/counters/rx_packets" not in data
    assert not metrics


def test_invalid_include_paths_rejected():
    from repeater.sensors.modem_stats_discovery import parse_paths

    with pytest.raises(ValueError, match="discovery_include_paths"):
        parse_paths("/network/token,not-a-pointer", "discovery_include_paths")
    with pytest.raises(ValueError, match="discovery_include_paths"):
        parse_paths("/environment/bad~2escape", "discovery_include_paths")


def test_invalid_policy_does_not_unload_configured_sensor():
    config = {
        "sensors": {
            "enabled": True,
            "definitions": [
                {
                    "type": "openhop_modem",
                    "name": "modem",
                    "settings": {
                        "host": "example.test",
                        "discovery_include_paths": "not-a-pointer",
                    },
                }
            ],
        }
    }
    manager = SensorManager(config)
    assert len(manager.sensors) == 1
    assert manager.sensors[0].discovery.include == frozenset()


def test_two_instances_and_cached_summary_match_reading_contract(monkeypatch):
    calls = []

    def fetch(request, **_kwargs):
        calls.append(request.full_url)
        return Response({"environment": {"temperature_c": 0, "available": True}})

    monkeypatch.setattr("repeater.sensors.openhop_modem.urllib.request.urlopen", fetch)
    config = {
        "sensors": {
            "enabled": True,
            "definitions": [
                {"type": "openhop_modem", "name": name, "settings": {"host": name + ".test"}}
                for name in ("north", "south")
            ],
        }
    }
    manager = SensorManager(config)
    readings = manager.read_all()
    assert len(calls) == 2
    assert [r["name"] for r in readings] == ["north", "south"]
    assert all(r["data"]["modem:/environment/temperature_c"] == 0 for r in readings)
    assert all(r["metrics"][0]["source_path"].startswith("/environment/") for r in readings)
    with manager._readings_lock:
        manager._latest_readings = readings
    assert manager.get_summary()["readings"] == readings
    assert len(calls) == 2  # stats uses the cache, not an extra HTTP fetch


def test_include_policy_cannot_override_denied_or_excluded_paths(monkeypatch):
    payload = {
        "radio": {"reviewed": 7},
        "network": {"address": 9},
        "environment": {"api_token": 4, "good": 3},
    }
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen", lambda *_a, **_k: Response(payload)
    )
    result = sensor(
        discovery_include_paths="/radio/reviewed,/network/address",
        discovery_exclude_paths="/environment/good",
    ).read()
    assert result["data"]["modem:/radio/reviewed"] == 7
    assert not any(
        key.startswith(("modem:/network/", "modem:/environment/")) for key in result["data"]
    )


@pytest.mark.parametrize("excluded", ["/environment", "/radio"])
def test_ancestor_exclusion_blocks_known_fallback(excluded):
    from repeater.sensors.modem_stats_discovery import ModemDiscovery

    discovery = ModemDiscovery(exclude=excluded)
    data, metrics = discovery.select(
        {
            "environment": {"available": True, "temperature_c": None},
            "radio": {"agc_reset_count": 3},
        }
    )
    assert not any(key.startswith("modem:" + excluded + "/") for key in data)
    assert not any(metric["source_path"].startswith(excluded + "/") for metric in metrics)


def test_reserved_or_control_keys_and_type_changes_are_never_current(monkeypatch):
    payloads = [
        {"environment": {"ok": 2, "<script>": 4, "control\nkey": 3}},
        {"environment": {"ok": True}},
    ]
    monkeypatch.setattr(
        "repeater.sensors.openhop_modem.urllib.request.urlopen",
        lambda *_a, **_k: Response(payloads.pop(0)),
    )
    instance = sensor()
    first = instance.read()
    assert first["data"]["modem:/environment/ok"] == 2
    assert not any("script" in key or "control" in key for key in first["data"])
    changed = instance.read()
    assert changed["data"]["modem:/environment/ok"] is None
    descriptor = next(d for d in changed["metrics"] if d["id"] == "/environment/ok")
    assert descriptor["available"] is False
    assert descriptor["reason"] == "invalid"
