# Adding a New Sensor Plug-in

Sensors in openhop-repeater are self-contained modules that live in `repeater/sensors/`. The subsystem is plug-in based: adding a new sensor requires only one new file. The manager discovers and loads it automatically at runtime by importing the module named after the sensor type.

---

## How the sensor subsystem works

| Component | File | Role |
|-----------|------|------|
| `SensorBase` | `repeater/sensors/base.py` | Abstract base class all sensors inherit from |
| `SensorRegistry` | `repeater/sensors/registry.py` | Maps type strings → sensor classes via `@SensorRegistry.register` |
| `SensorManager` | `repeater/sensors/manager.py` | Reads config, imports sensor modules, polls sensors in background |

When `SensorManager` loads a configured sensor of type `"foo"`, it imports `repeater.sensors.foo`. The Sensor Manager API also imports installed sensor modules before enumerating `SensorRegistry`, so the UI's Add Sensor menu discovers new types without a hardcoded frontend list. Give the class a `_settings_schema` for its dynamic form; installing a module does not automatically create a sensor definition or detect physical hardware. Restart the backend after installing code, then add/configure the sensor in the UI.

---

## Step-by-step guide

### 1. Create `repeater/sensors/<type>.py`

Name the file after the sensor type string (lowercase, underscores for hyphens). The type string is what operators write in `config.yaml`.

Minimal template:

```python
"""
<SensorName> sensor plug-in.

Requires: pip install <package>

Config example:
  - type: <type>
    name: "my-sensor"
    enabled: true
    auto_install_packages: false
    settings:
      some_option: value
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import SensorBase
from .registry import SensorRegistry


@SensorRegistry.register("<type>")
class MySensor(SensorBase):
    sensor_type = "<type>"
    _settings_schema = [
        {"key": "some_option", "type": "string", "label": "Some Option", "default": "default"},
    ]

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None, log=None):
        super().__init__(name=name, config=config, log=log)

        # Read settings with safe defaults
        self.some_option = self.settings.get("some_option", "default")

        self.available = False
        if not self.ensure_python_modules(
            [
                ("import_name", "pip-package-name"),
            ]
        ):
            return  # logs a warning; sensor will report unavailable

        try:
            import import_name  # type: ignore[import-not-found]

            # Initialise hardware here
            self.device = import_name.Device(...)
            self.available = True
            self.log.info("MySensor initialized")
        except Exception as exc:
            self.log.warning("MySensor init failed: %s", exc)
            self.available = False

    def _read(self) -> Dict[str, Any]:
        if not self.available:
            raise RuntimeError("device not available")
        try:
            return {
                "field_one": ...,
                "field_two": ...,
            }
        except Exception as exc:
            raise RuntimeError(f"read failed: {exc}") from exc
```

Key rules:

- **`sensor_type`** class attribute must match the string passed to `@SensorRegistry.register`.
- Multiple definitions may use the same sensor type (for example two `openhop_modem` instances), but each must have a unique name: the poller caches readings by name. The `pymc_modem` alias remains loadable for old configurations but is not offered as a new type in Sensor Manager.
- **`self.settings`** is the `settings:` block from the sensor's config entry (a plain dict).
- **`ensure_python_modules`** handles missing dependencies gracefully. Pass a multi-line list of `(import_name, pip_package)` tuples. Returns `False` and logs a warning if any are missing and `auto_install_packages` is `false`; installs them via pip if `true`. Sensor-specific packages belong here — do **not** add them to `pyproject.toml`.
- **`_read`** must return a flat `dict[str, Any]`. The base class wraps it in a standard envelope (`name`, `type`, `ok`, `timestamp`, `data`, optional `error`). Plug-ins may override `_reading_metrics(ok)` to attach optional `metrics` beside `data`, using only metadata captured during the same read.
- **`_read`** must raise `RuntimeError` on failure — the base class catches it, marks `ok=False`, and logs it without crashing the polling loop.
- All hardware initialisation belongs in `__init__`, not in `_read`. Keep `_read` fast.
- Lazy-import third-party packages inside `__init__` (after `ensure_python_modules` returns `True`) so the module can be imported on hosts that don't have the package installed.

### 2. Add a commented example to `config.yaml.example`

Find the `sensors.definitions` block and add your sensor alongside the existing examples:

```yaml
    # Example MySensor (commented out by default)
    # - type: <type>
    #   name: my-sensor
    #   enabled: true
    #   auto_install_packages: true
    #   settings:
    #     some_option: value
```

Use hex notation for I2C addresses (e.g. `0x43`) as this matches how addresses are listed in datasheets and tools like `i2cdetect`.

### 3. Test locally

Add a test to `tests/test_sensors.py` that:

1. Registers a lightweight mock of your sensor (or stubs the hardware import).
2. Verifies that `SensorManager` loads it and `read_all()` returns the expected structure.
3. Verifies that a hardware failure in `_read` produces an `ok=False` result rather than raising.

Example pattern from the existing test suite:

```python
class _MockMySensor(SensorBase):
    sensor_type = "<type>"

    def _read(self):
        return {"field_one": 42.0, "field_two": 55.0}


SensorRegistry.register("<type>", _MockMySensor)


def test_my_sensor_loads_and_reads():
    config = {
        "sensors": {
            "enabled": True,
            "definitions": [
                {"name": "test-sensor", "type": "<type>", "settings": {}},
            ],
        }
    }
    manager = SensorManager(config)
    readings = manager.read_all()
    assert readings[0]["ok"] is True
    assert readings[0]["data"]["field_one"] == 42.0
```

---

## Checklist

- [ ] `repeater/sensors/<type>.py` created
- [ ] `sensor_type` class attribute matches the `@SensorRegistry.register` key
- [ ] All settings read from `self.settings` with sensible defaults
- [ ] `ensure_python_modules` called before any third-party import
- [ ] Hardware initialised in `__init__`, not `_read`
- [ ] `_read` raises `RuntimeError` on failure (never returns `None` or partial data silently)
- [ ] Commented example added to `config.yaml.example`
- [ ] Unit test added to `tests/test_sensors.py`

---

## Existing sensors

### Networked openHop Modem discovery

Configure each modem's HTTP host, optional Basic authentication, and a unique sensor name once; no LAN or hardware auto-detection occurs. Besides the historical flat keys (including `temperature_c` as the MCU die-temperature alias), the modem sensor discovers finite JSON numbers and booleans under `environment`, `counters`, `measurements`, and `telemetry` dictionaries. Known AGC diagnostics under `radio` are handled explicitly. Generic values use `data["modem:/environment/temperature_c"]`-style keys and optional `metrics` descriptors beside `data`; environmental temperature never replaces the die temperature. Known counter aliases are not duplicated as discovered entities. Numeric strings, arrays, and unknown root/radio/network/config/GPS leaves are not discovered. Credential and location subtrees remain denied even under approved branches.

To admit a *reviewed* extra numeric/boolean leaf outside the approved roots, set `discovery_include_paths` to comma-separated exact JSON Pointers (for example `/radio/reviewed_diagnostic`); `discovery_exclude_paths` can narrow the policy and wins over inclusion. Neither setting grants access to forbidden credential, network, GPS, configuration or location segments. These are string settings, not lists. IDs are RFC6901-escaped source paths; an entity's identity is configured sensor name plus ID, so renaming a sensor or changing a firmware path changes its identity. Descriptors have category, kind, nullable unit and per-snapshot availability; unknown null-only fields wait for a typed sample before admission, while known null fields remain visible. `environment.available=false` invalidates environmental values without marking the whole HTTP modem offline; a missing section means unsupported capability, and an HTTP failure sets the reading `ok=false`. No stale number is reused as current.

Limits per modem: response 128 KiB, dictionary depth four below a root, 512 inspected generic nodes, 64 admitted paths for the instance lifetime, and segment/pointer limits of 64/256 characters. Known fields and reviewed exact included leaves are checked before the generic node budget; included leaves take priority over generic leaves for admission. Truncation is reported as `modem_discovery_truncated` in flat data. Invalid path policies are rejected by the sensor config save API; a pre-existing invalid policy is ignored at load time (default conservative discovery), so it does not disable the modem sensor. The historical `data.url` remains present but contains only the origin, never an endpoint path, credentials, query or fragment. Reload resets admission, and readings refresh at the configured modem poll cadence (default 60 seconds), not the dashboard refresh cadence. These diagnostics do **not** create RRD history or CayenneLPP/RF telemetry. Additions to those boundaries require a separate design and review.

| Type | File | Hardware |
|------|------|----------|
| `hardware_stats` | `repeater/sensors/hardware_stats.py` | Host CPU / memory / disk / network (via `psutil`) |
| `ina219` | `repeater/sensors/ina219.py` | INA219 I²C current/voltage/power monitor |
| `ens210` | `repeater/sensors/ens210.py` | ENS210 I²C relative humidity and temperature sensor |
| `bme280` | `repeater/sensors/bme280.py` | BME280 I²C temperature, humidity and barometric pressure sensor |
