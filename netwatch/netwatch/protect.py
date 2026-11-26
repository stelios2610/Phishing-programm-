"""Pin or release the confirmed router MAC on this computer. Never sends frames."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from netwatch.parse import normalize_mac, unicast_ip, valid_iface


@dataclass
class ProtectResult:
    applied: bool
    reason: str
    message: str
    command: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def apply_permanent_neighbor(ip: str, mac: str, iface: str) -> ProtectResult:
    target = _checked(ip, mac, iface)
    if os.name == "nt":
        return _run(windows_lock_command(*target), reason_ok="applied")
    tool = _linux_tool()
    if tool is None:
        return _unsupported(_suggested_lock(*target))
    kind, binary = tool
    if kind == "ip" and not target[2]:
        return _unsupported(_suggested_lock(*target))
    return _run(linux_lock_command(kind, binary, *target), reason_ok="applied")


def delete_permanent_neighbor(ip: str, mac: str, iface: str) -> ProtectResult:
    target = _checked(ip, mac, iface)
    if os.name == "nt":
        return _run(windows_unlock_command(target[0], target[2]), reason_ok="cleared")
    tool = _linux_tool()
    if tool is None:
        return _unsupported(_suggested_unlock(target[0], target[2]))
    kind, binary = tool
    if kind == "ip" and not target[2]:
        return _unsupported(_suggested_unlock(target[0], target[2]))
    return _run(linux_unlock_command(kind, binary, target[0], target[2]), reason_ok="cleared")


def linux_lock_command(kind: str, binary: str, ip: str, mac: str, iface: str) -> list[str]:
    if kind == "ip":
        return [binary, "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", iface]
    if iface:
        return [binary, "-i", iface, "-s", ip, mac]
    return [binary, "-s", ip, mac]


def linux_unlock_command(kind: str, binary: str, ip: str, iface: str) -> list[str]:
    if kind == "ip":
        return [binary, "neigh", "del", ip, "dev", iface]
    if iface:
        return [binary, "-i", iface, "-d", ip]
    return [binary, "-d", ip]


def windows_lock_command(ip: str, mac: str, iface: str) -> list[str]:
    return [
        "netsh",
        "interface",
        "ipv4",
        "add",
        "neighbors",
        iface,
        ip,
        mac.replace(":", "-"),
        "store=active",
    ]


def windows_unlock_command(ip: str, iface: str) -> list[str]:
    return ["netsh", "interface", "ipv4", "delete", "neighbors", iface, ip]


def _checked(ip: str, mac: str, iface: str) -> tuple[str, str, str]:
    normalized = normalize_mac(mac)
    windows = os.name == "nt"
    if not unicast_ip(ip) or not normalized:
        raise ValueError("invalid")
    if iface and not valid_iface(iface, windows=windows):
        raise ValueError("invalid")
    if windows and not iface:
        raise ValueError("invalid")
    return ip, normalized, iface


def _linux_tool() -> tuple[str, str] | None:
    ip_bin = _tool("ip", ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"])
    if ip_bin:
        return "ip", ip_bin
    arp_bin = _tool("arp", ["/usr/sbin/arp", "/sbin/arp", "/usr/bin/arp"])
    if arp_bin:
        return "arp", arp_bin
    return None


def _tool(name: str, fallbacks: list[str]) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in fallbacks:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def _run(command: list[str], *, reason_ok: str) -> ProtectResult:
    shown = " ".join(shlex.quote(part) for part in command)
    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ProtectResult(False, "failed", _fail(exc.__class__.__name__), shown)
    if completed.returncode == 0:
        if reason_ok == "cleared":
            return ProtectResult(
                True,
                "cleared",
                "The static router ARP entry was removed.",
                shown,
            )
        return ProtectResult(
            True,
            "applied",
            "The router MAC is now pinned on this computer. It lasts until reboot or until you forget it. It does not stop an attack outside the local network.",
            shown,
        )
    detail = _clean((completed.stderr or completed.stdout or b"").decode("utf-8", "replace"))
    return ProtectResult(False, "failed", _fail(detail), shown)


def _unsupported(command: str) -> ProtectResult:
    return ProtectResult(
        False,
        "unsupported",
        "No ARP tool was found. The command was not run.",
        command,
    )


def _suggested_lock(ip: str, mac: str, iface: str) -> str:
    dev = f" dev {shlex.quote(iface)}" if iface else ""
    return f"ip neigh replace {shlex.quote(ip)} lladdr {shlex.quote(mac)} nud permanent{dev}"


def _suggested_unlock(ip: str, iface: str) -> str:
    dev = f" dev {shlex.quote(iface)}" if iface else ""
    return f"ip neigh del {shlex.quote(ip)}{dev}"


def _fail(detail: str) -> str:
    base = "The ARP table was not changed. Administrator rights are required."
    return f"{base} {detail}".strip()


def _clean(text: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())[:180]
