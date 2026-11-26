"""Remember the router MAC the user confirmed. Nothing else is stored."""

from __future__ import annotations

import json
import os
from pathlib import Path

from netwatch.engine import TrustedGateway
from netwatch.parse import normalize_mac, unicast_ip, valid_iface


def default_state_path() -> Path:
    override = os.environ.get("NETWATCH_STATE_PATH")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home()
        return root / "NetWatch" / "trusted-gateway.json"
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "netwatch" / "trusted-gateway.json"


def load_state(path: Path) -> tuple[TrustedGateway | None, tuple[str, str, str] | None]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None, None
    if not isinstance(raw, dict):
        return None, None
    trusted = _trusted(raw.get("gateway_ip"), raw.get("gateway_mac"), raw.get("iface"))
    locked = _locked(raw.get("locked_ip"), raw.get("locked_mac"), raw.get("locked_iface"))
    return trusted, locked


def write_state(
    path: Path,
    trusted: TrustedGateway | None,
    locked: tuple[str, str, str] | None,
) -> None:
    payload: dict[str, str] = {}
    if trusted is not None:
        payload.update(
            gateway_ip=trusted.ip,
            gateway_mac=trusted.mac,
            iface=trusted.iface,
        )
    if locked is not None:
        payload.update(locked_ip=locked[0], locked_mac=locked[1], locked_iface=locked[2])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(path)


def clear_state(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def _trusted(ip: object, mac: object, iface: object) -> TrustedGateway | None:
    if not isinstance(ip, str) or not isinstance(mac, str):
        return None
    normalized = normalize_mac(mac)
    interface = iface if isinstance(iface, str) else ""
    if not unicast_ip(ip) or not normalized:
        return None
    if interface and not _iface_ok(interface):
        return None
    return TrustedGateway(ip, normalized, interface)


def _locked(ip: object, mac: object, iface: object) -> tuple[str, str, str] | None:
    trusted = _trusted(ip, mac, iface)
    if trusted is None:
        return None
    return trusted.ip, trusted.mac, trusted.iface


def _iface_ok(iface: str) -> bool:
    return valid_iface(iface, windows=False) or valid_iface(iface, windows=True)
