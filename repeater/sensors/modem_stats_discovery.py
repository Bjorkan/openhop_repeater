"""Bounded, conservative selection of modem HTTP diagnostic leaves."""

from __future__ import annotations

import math
from typing import Any

ROOTS = frozenset({"environment", "counters", "measurements", "telemetry"})
DENIED = frozenset(
    {
        "auth",
        "authentication",
        "token",
        "password",
        "secret",
        "credential",
        "credentials",
        "private",
        "key",
        "gps",
        "position",
        "location",
        "network",
        "config",
        "configuration",
        "calibration",
        "settings",
        "nmea",
        "address",
        "latitude",
        "longitude",
    }
)
KNOWN = {
    "/environment/temperature_c": ("Environmental temperature", "°C", "number", "measurement"),
    "/environment/humidity_pct": ("Relative humidity", "%", "number", "measurement"),
    "/environment/pressure_hpa": ("Station pressure", "hPa", "number", "measurement"),
    "/environment/available": ("Environment available", None, "boolean", "status"),
    "/radio/agc_reset_count": ("AGC resets", None, "number", "diagnostic"),
    "/radio/last_agc_reset_ms_ago": ("Last AGC reset age", "ms", "number", "diagnostic"),
    "/radio/agc_reset_interval_sec": ("AGC reset interval", "s", "number", "configuration"),
}
# These already have compatibility keys; avoid duplicate entities for a single source leaf.
COMPAT_COUNTERS = frozenset(
    {"rx_packets", "tx_packets", "crc_errors", "last_rssi_dbm", "last_snr_db", "noise_floor_dbm"}
)
MAX_NODES = 512
MAX_PATHS = 64


def pointer(parts: tuple[str, ...]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def parse_paths(value: Any, setting: str) -> frozenset[str]:
    if not isinstance(value, str):
        raise TypeError(f"{setting} must be comma-separated JSON Pointers")
    paths = [s.strip() for s in value.split(",") if s.strip()]
    if len(paths) > 32 or any(
        not p.startswith("/")
        or len(p) > 256
        or "//" in p
        or any("~" in segment.replace("~0", "").replace("~1", "") for segment in p.split("/"))
        for p in paths
    ):
        raise ValueError(f"{setting} contains an invalid JSON Pointer")
    return frozenset(paths)


def _denied(parts: tuple[str, ...]) -> bool:
    return any(
        len(segment) > 64
        or not segment
        or any(ord(char) < 32 or char in "<>" for char in segment)
        or any(word in segment.lower() for word in DENIED)
        for segment in parts
    )


def _scalar(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


class ModemDiscovery:
    """Admitted paths live only for this configured sensor instance."""

    def __init__(self, include: str = "", exclude: str = ""):
        self.include = parse_paths(include, "discovery_include_paths")
        self.exclude = parse_paths(exclude, "discovery_exclude_paths")
        self.admitted: dict[str, tuple[str, str]] = {}

    def _excluded(self, path: str) -> bool:
        return any(path == parent or path.startswith(parent + "/") for parent in self.exclude)

    def select(self, payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        candidates: dict[str, Any] = {}
        inspected = 0
        truncated = False
        # Resolve the small, fixed priority set before generic traversal consumes
        # the node budget. Never recurse through arbitrary branches for this pass.
        priority = set()
        for path in KNOWN.keys() | self.include:
            parts = tuple(
                segment.replace("~1", "/").replace("~0", "~") for segment in path[1:].split("/")
            )
            if (
                2 <= len(parts) <= 5
                and not self._excluded(path)
                and not _denied(parts)
                and not (parts[0] == "counters" and len(parts) == 2 and parts[1] in COMPAT_COUNTERS)
            ):
                priority.add(path)
        for path in sorted(priority):
            parts = tuple(
                segment.replace("~1", "/").replace("~0", "~") for segment in path[1:].split("/")
            )
            if len(parts) < 2 or len(parts) > 5:
                continue
            node: Any = payload
            for part in parts:
                if not isinstance(node, dict) or part not in node:
                    break
                node = node[part]
            else:
                if _scalar(node) or (node is None and (path in KNOWN or path in self.admitted)):
                    candidates[path] = node
        roots = sorted(ROOTS | {p.split("/")[1] for p in self.include if p.count("/") >= 2})
        stack = [(root, (root,)) for root in reversed(roots) if isinstance(payload.get(root), dict)]
        # Sorting at every branch yields deterministic admission independently of JSON member order.
        while stack:
            _, parts = stack.pop()
            inspected += 1
            if inspected > MAX_NODES:
                truncated = True
                break
            if _denied(parts) or len(parts) > 5 or len(pointer(parts)) > 256:
                continue
            path = pointer(parts)
            if self._excluded(path):
                continue
            node: Any = payload
            for part in parts:
                node = node[part]
            if isinstance(node, dict):
                if len(parts) == 5:
                    continue
                for child in sorted(node, reverse=True):
                    if isinstance(child, str):
                        stack.append((child, (*parts, child)))
                continue
            if len(parts) < 2 or (parts[0] not in ROOTS and path not in self.include):
                continue
            if parts[0] == "counters" and len(parts) == 2 and parts[1] in COMPAT_COUNTERS:
                continue
            if _scalar(node):
                candidates[path] = node
            elif node is None and (path in KNOWN or path in self.admitted):
                candidates[path] = None
        environment = payload.get("environment")
        # Reserve slots for firmware's known fields before admitting arbitrary leaves.
        for path in sorted(
            candidates, key=lambda path: (path not in KNOWN, path not in self.include, path)
        ):
            if path not in self.admitted:
                limit = (
                    MAX_PATHS
                    if path in priority
                    else MAX_PATHS - len(priority - self.admitted.keys())
                )
                if len(self.admitted) >= limit:
                    truncated = True
                    continue
                kind = (
                    KNOWN[path][2]
                    if path in KNOWN
                    else ("boolean" if isinstance(candidates[path], bool) else "number")
                )
                self.admitted[path] = (
                    kind,
                    path.split("/")[-1].replace("~1", "/").replace("~0", "~"),
                )
        data: dict[str, Any] = {}
        descriptors: list[dict[str, Any]] = []
        for path, (kind, fallback_label) in sorted(self.admitted.items()):
            value = candidates.get(path)
            invalid = False
            section_off = (
                path.startswith("/environment/")
                and isinstance(environment, dict)
                and environment.get("available") is False
                and path != "/environment/available"
            )
            if section_off:
                value = None
            if value is not None and (
                (kind == "boolean" and not isinstance(value, bool))
                or (
                    kind == "number"
                    and (isinstance(value, bool) or not isinstance(value, (int, float)))
                )
            ):
                value = None
                invalid = True
            label, unit, _, category = KNOWN.get(
                path, (fallback_label.replace("_", " ").title(), None, kind, "measurement")
            )
            data_key = "modem:" + path
            data[data_key] = value
            descriptors.append(
                {
                    "id": path,
                    "source_path": path,
                    "data_key": data_key,
                    "label": label,
                    "unit": unit,
                    "kind": kind,
                    "category": category,
                    "available": value is not None,
                    **(
                        {
                            "reason": "source_unavailable"
                            if section_off
                            else "invalid"
                            if invalid
                            else "null"
                            if path in candidates
                            else "missing"
                        }
                        if value is None
                        else {}
                    ),
                }
            )
        if truncated:
            data["modem_discovery_truncated"] = True
        return data, descriptors

    def failed(self) -> list[dict[str, Any]]:
        return [
            {
                "id": path,
                "source_path": path,
                "data_key": "modem:" + path,
                "label": KNOWN.get(path, (label.replace("_", " ").title(),))[0],
                "unit": KNOWN.get(path, (None, None))[1],
                "kind": kind,
                "category": KNOWN.get(path, (None, None, None, "measurement"))[3],
                "available": False,
                "reason": "read_failed",
            }
            for path, (kind, label) in sorted(self.admitted.items())
        ]
