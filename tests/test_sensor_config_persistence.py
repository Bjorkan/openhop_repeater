"""Sensor config write failure and route contract regressions."""

import copy
import errno
import os
import stat

import cherrypy
import pytest
import yaml

from repeater.web.api_endpoints import APIEndpoints


def _request(api):
    cherrypy.request.method = "POST"
    cherrypy.request.json = {
        "enabled": False,
        "poll_interval_seconds": 45,
        "definitions": [{"name": "new", "type": "bme280"}],
    }
    return api.sensors_config_update()


@pytest.mark.parametrize(
    "setting,value",
    [
        ("discovery_include_paths", "not-a-pointer"),
        ("discovery_exclude_paths", "/environment/bad~2escape"),
        ("discovery_include_paths", ["/radio/reviewed"]),
    ],
)
def test_sensor_update_rejects_invalid_modem_policy_without_persisting(tmp_path, setting, value):
    path = tmp_path / "config.yaml"
    original = b"sensors: {enabled: true}\n"
    path.write_bytes(original)
    config = {"sensors": {"enabled": True}}
    api = APIEndpoints(config=config, config_path=str(path))
    cherrypy.request.method = "POST"
    cherrypy.request.json = {
        "enabled": True,
        "definitions": [
            {
                "name": "modem",
                "type": "openhop_modem",
                "settings": {"host": "example.test", setting: value},
            }
        ],
    }
    result = api.sensors_config_update()
    assert result["success"] is False
    assert setting in str(result)
    assert path.read_bytes() == original
    assert config == {"sensors": {"enabled": True}}


@pytest.mark.parametrize("failure", ["dump", "fsync", "replace"])
def test_sensor_update_failure_preserves_file_and_memory(tmp_path, monkeypatch, failure):
    from repeater import config_manager

    path = tmp_path / "config.yaml"
    path.write_bytes(b"# preserve this exact text\nsensors: {enabled: true}\nother: 1\n")
    path.chmod(0o640)
    config = {"sensors": {"enabled": True}, "other": 1}
    api = APIEndpoints(config=config, config_path=str(path))
    previous = path.read_bytes()
    memory = copy.deepcopy(api.config)
    identity = api.config["sensors"]

    def fail(*_args, **_kwargs):
        raise OSError("injected " + failure)

    target, name = {
        "dump": (config_manager.yaml, "safe_dump"),
        "fsync": (config_manager.os, "fsync"),
        "replace": (config_manager.os, "replace"),
    }[failure]
    monkeypatch.setattr(target, name, fail)
    assert _request(api)["success"] is False
    assert path.read_bytes() == previous
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert api.config == memory
    assert api.config["sensors"] is identity
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.yaml"]


def test_sensor_update_atomic_success_preserves_metadata_and_symlink(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text("sensors: {enabled: true}\nother: 1\n")
    target.chmod(0o640)
    link = tmp_path / "current.yaml"
    link.symlink_to(target)
    before = target.stat()
    config = {"sensors": {"enabled": True}, "other": 1}
    api = APIEndpoints(config=config, config_path=str(link))
    result = _request(api)
    assert result["success"] is True
    assert result["data"]["restart_required"] is True
    assert link.is_symlink()
    assert (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode)) == (
        before.st_uid,
        before.st_gid,
        0o640,
    )
    assert yaml.safe_load(target.read_text())["sensors"] == api.config["sensors"]
    assert yaml.safe_load(target.read_text())["other"] == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.yaml", "current.yaml"]


def test_sensor_update_preserves_existing_xattrs_on_symlink_target(tmp_path):
    if not all(hasattr(os, name) for name in ("listxattr", "getxattr", "setxattr")):
        pytest.skip("extended attributes unavailable")
    target = tmp_path / "config.yaml"
    target.write_text("sensors: {enabled: true}\n")
    link = tmp_path / "current.yaml"
    link.symlink_to(target)
    try:
        os.setxattr(target, "user.review_marker", b"retain-across-replace")
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("filesystem does not support user extended attributes")
        raise
    api = APIEndpoints(config={"sensors": {"enabled": True}}, config_path=str(link))

    assert _request(api)["success"] is True
    assert link.is_symlink()
    assert os.getxattr(target, "user.review_marker") == b"retain-across-replace"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.yaml", "current.yaml"]


def test_sensor_update_read_failure_preserves_memory(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("sensors: {enabled: true}\n")
    api = APIEndpoints(config={"sensors": {"enabled": True}}, config_path=str(path))
    previous = copy.deepcopy(api.config)
    original_open = open

    def fail_read(file, mode="r", *args, **kwargs):
        if str(file) == str(path) and mode == "r":
            raise OSError("injected read failure")
        return original_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_read)
    assert _request(api)["success"] is False
    assert api.config == previous
    assert path.read_text() == "sensors: {enabled: true}\n"


@pytest.mark.parametrize(
    "original",
    [
        b"orphaned scalar # keep exact bytes\n",
        b"- existing\n- entries\n",
        b"null # explicit null\n",
        b"# empty YAML document\n",
    ],
    ids=["scalar", "list", "null", "empty"],
)
def test_sensor_update_rejects_non_mapping_yaml_root_without_changing_state(tmp_path, original):
    path = tmp_path / "config.yaml"
    path.write_bytes(original)
    config = {"sensors": {"enabled": True}, "other": {"kept": True}}
    api = APIEndpoints(config=config, config_path=str(path))
    previous = copy.deepcopy(config)
    section = config["sensors"]

    result = _request(api)

    assert result["success"] is False
    assert path.read_bytes() == original
    assert config == previous
    assert api.config == previous
    assert config["sensors"] is section
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.yaml"]


def test_sensor_openapi_update_route_only():
    from pathlib import Path

    from repeater.web import api_endpoints

    spec = yaml.safe_load((Path(api_endpoints.__file__).parent / "openapi.yaml").read_text())
    assert set(spec["paths"]["/sensors_config"]) == {"get"}
    assert "post" in spec["paths"]["/sensors_config_update"]
    assert spec["paths"]["/sensors_config_update"]["post"]["security"]
