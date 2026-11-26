"""Read this computer's route, ARP table, and ICMP counters. Never sends a packet."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from netwatch.model import Snapshot
from netwatch.parse import parse_proc_arp, parse_proc_route, parse_proc_snmp_icmp, parse_windows_report

_WINDOWS_SCRIPT = """
$ErrorActionPreference = 'Stop'
$sep = [char]31
$icmp = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetIcmpV4Statistics()
Write-Output ("ICMP" + $sep + $icmp.EchoRequestsReceived + $sep + $icmp.RedirectsReceived)
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 1
if ($route) { Write-Output ("GW" + $sep + $route.NextHop + $sep + $route.InterfaceAlias) }
Get-NetNeighbor -AddressFamily IPv4 | ForEach-Object {
  Write-Output ("NEI" + $sep + $_.IPAddress + $sep + $_.LinkLayerAddress + $sep + $_.InterfaceAlias + $sep + $_.State)
}
"""


def collect_snapshot() -> Snapshot:
    if os.name == "nt":
        return collect_windows()
    return collect_linux()


def collect_linux() -> Snapshot:
    route_text = _read("/proc/net/route")
    arp_text = _read("/proc/net/arp")
    snmp_text = _read("/proc/net/snmp")
    notes: list[str] = []
    if route_text is None:
        gateway_ip, gateway_iface = None, None
        notes.append("no-route")
    else:
        gateway_ip, gateway_iface = parse_proc_route(route_text)
    neighbors = parse_proc_arp(arp_text) if arp_text is not None else ()
    if arp_text is None:
        notes.append("no-arp")
    echos, redirects = parse_proc_snmp_icmp(snmp_text) if snmp_text is not None else (None, None)
    if snmp_text is None:
        notes.append("no-icmp")
    return Snapshot(
        neighbors=neighbors,
        gateway_ip=gateway_ip,
        gateway_iface=gateway_iface,
        in_echos=echos,
        in_redirects=redirects,
        note=",".join(notes),
    )


def collect_windows() -> Snapshot:
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _WINDOWS_SCRIPT,
            ],
            capture_output=True,
            timeout=8,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Snapshot((), None, None, None, None, note="windows-collect-failed")
    text = completed.stdout.decode("utf-8", "replace")
    if completed.returncode != 0 and not text.strip():
        return Snapshot((), None, None, None, None, note="windows-collect-failed")
    return parse_windows_report(text)


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
