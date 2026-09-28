"""Actual CherryPy routing: the legacy root sensor URLs must not bypass /api auth."""

import json
import subprocess
import sys


def test_sensor_endpoints_only_exist_under_authenticated_api(tmp_path):
    script = r"""
import json, pathlib, socket, sys, urllib.request, urllib.error
import yaml
from repeater.web import http_server as hs

root = pathlib.Path(sys.argv[1])
(root / "index.html").write_text("<html>UI</html>")
config = {"repeater": {"security": {"jwt_secret": "test-secret-only"}},
          "storage": {"storage_dir": str(root / "storage")},
          "web": {"web_path": str(root)},
          "sensors": {"enabled": True, "definitions": [{"name": "modem", "type": "openhop_modem",
              "settings": {"password": "synthetic-secret"}}]}}
path = root / "config.yaml"
path.write_text(yaml.safe_dump(config))
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
hs.WEBSOCKET_AVAILABLE = False
server = hs.HTTPStatsServer(host="127.0.0.1", port=port, config=config, config_path=str(path))
base = f"http://127.0.0.1:{port}"
def status(route, data=None, headers=None):
    req = urllib.request.Request(base + route, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
try:
    server.start()
    before = path.read_bytes()
    roots = [status("/" + name)[0] for name in
             ("sensors_config", "sensors_types", "sensors_read", "sensors_config_update")]
    roots.append(status("/sensors_config_update", data=b'{"enabled":false}',
                        headers={"Content-Type":"application/json"})[0])
    unauth = status("/api/sensors_config")[0]
    token = server.jwt_handler.create_jwt("admin", "test-client")
    authorized, payload = status("/api/sensors_config", headers={"Authorization": "Bearer " + token})
    parsed = json.loads(payload) if authorized == 200 else {}
    password = parsed.get("data", {}).get("definitions", [{}])[0].get("settings", {}).get("password")
    print(json.dumps({"roots":roots, "unauth":unauth, "authorized":authorized,
                      "masked":password == "*****", "disk_untouched":path.read_bytes() == before}))
finally:
    server.stop()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    facts = json.loads(result.stdout.strip().splitlines()[-1])
    assert facts == {
        "roots": [404, 404, 404, 404, 404],
        "unauth": 401,
        "authorized": 200,
        "masked": True,
        "disk_untouched": True,
    }


def test_authenticated_http_sensor_config_round_trip_and_stats_json(tmp_path):
    script = r"""
import json, pathlib, socket, sys, urllib.request, urllib.error
import yaml
from repeater.web import http_server as hs
from repeater.sensors.modem_stats_discovery import ModemDiscovery

root = pathlib.Path(sys.argv[1])
(root / "index.html").write_text("<html>UI</html>")
config = {"repeater": {"security": {"jwt_secret": "test-only-key"}},
          "storage": {"storage_dir": str(root / "storage")},
          "web": {"web_path": str(root)},
          "sensors": {"enabled": True, "definitions": [
              {"name": "legacy", "type": "pymc_modem", "settings": {
                  "host": "legacy.test", "password": "synthetic-legacy"}},
              {"name": "modern", "type": "openhop_modem", "settings": {
                  "host": "modern.test", "password": "synthetic-modern"}}]}}
path = root / "config.yaml"
path.write_text(yaml.safe_dump(config))
discovery = ModemDiscovery()
data, metrics = discovery.select({"environment": {"available": False,
                                                       "temperature_c": 18, "flag": False},
                                  "radio": {"last_agc_reset_ms_ago": None}})
reading = {"name": "modern", "type": "openhop_modem", "ok": True,
           "data": data, "metrics": metrics}
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
hs.WEBSOCKET_AVAILABLE = False
server = hs.HTTPStatsServer(host="127.0.0.1", port=port, config=config,
                            config_path=str(path), stats_getter=lambda: {
                                "sensors": {"readings": [reading]}})
base = f"http://127.0.0.1:{port}"
def call(route, token=None, body=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + route, headers=headers,
              data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, None
try:
    server.start()
    token = server.jwt_handler.create_jwt("admin", "test-client")
    denied = call("/api/sensors_config_update", body={"enabled": False})[0]
    status, public = call("/api/sensors_config", token)
    body = public["data"]
    masked = [d["settings"]["password"] for d in body["definitions"]]
    body["definitions"][1]["name"] = "renamed"
    body["definitions"].reverse()
    saved_status, saved_response = call("/api/sensors_config_update", token, body)
    on_disk = yaml.safe_load(path.read_text())["sensors"]["definitions"]
    stats_status, stats = call("/api/stats", token)
    measured = stats["sensors"]["readings"][0]
    print(json.dumps({"denied": denied, "get_status": status, "masked": masked,
                      "save_status": saved_status, "saved": saved_response["success"],
                      "names": [d["name"] for d in on_disk],
                      "types": [d["type"] for d in on_disk],
                      "secrets_preserved": [d["settings"]["password"] for d in on_disk]
                           == ["synthetic-modern", "synthetic-legacy"],
                      "origins_stripped": all("_original_name" not in d for d in on_disk),
                      "stats_status": stats_status,
                      "false_value": measured["data"]["modem:/environment/available"] is False,
                      "null_value": measured["data"]["modem:/environment/temperature_c"] is None,
                      "agc_null": measured["data"]["modem:/radio/last_agc_reset_ms_ago"] is None,
                      "metrics_list": isinstance(measured["metrics"], list)}))
finally:
    server.stop()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    facts = json.loads(result.stdout.strip().splitlines()[-1])
    assert facts == {
        "denied": 401,
        "get_status": 200,
        "masked": ["*****", "*****"],
        "save_status": 200,
        "saved": True,
        "names": ["renamed", "legacy"],
        "types": ["openhop_modem", "pymc_modem"],
        "secrets_preserved": True,
        "origins_stripped": True,
        "stats_status": 200,
        "false_value": True,
        "null_value": True,
        "agc_null": True,
        "metrics_list": True,
    }
