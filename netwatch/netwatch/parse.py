"""Pure parsers for local network tables. No sockets and no subprocesses."""

from __future__ import annotations

import re
import sys

from netwatch.model import Neighbor, Snapshot

_MAC_CHARS = re.compile(r"[^0-9a-f]")


def normalize_mac(value: str) -> str:
    hexdigits = _MAC_CHARS.sub("", value.lower())
    if len(hexdigits) != 12 or hexdigits == "0" * 12:
        return ""
    mac = ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))
    if mac == "ff:ff:ff:ff:ff:ff":
        return ""
    return mac


def valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


def unicast_ip(ip: str) -> bool:
    if not valid_ip(ip):
        return False
    first = int(ip.split(".")[0])
    if ip == "0.0.0.0" or ip == "255.255.255.255" or first == 0 or first == 127:
        return False
    if 224 <= first <= 239:
        return False
    return True


def valid_iface(iface: str, *, windows: bool) -> bool:
    if not iface or any(ch in iface for ch in "\r\n\"'`$|&;<>"):
        return False
    if windows:
        return bool(re.fullmatch(r"[A-Za-z0-9_.: \-]{1,64}", iface))
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", iface))


def proc_ipv4(hex_value: str) -> str:
    raw = bytes.fromhex(hex_value)
    if len(raw) != 4:
        raise ValueError(hex_value)
    # /proc/net/route prints the address in host byte order.
    ordered = raw if sys.byteorder == "big" else raw[::-1]
    return ".".join(str(byte) for byte in ordered)


def parse_proc_route(text: str) -> tuple[str | None, str | None]:
    best: tuple[int, str, str] | None = None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        iface, destination, gateway, flags, _ref, _use, metric = parts[:7]
        if destination != "00000000":
            continue
        try:
            flag_bits = int(flags, 16)
            metric_n = int(metric)
            gateway_ip = proc_ipv4(gateway)
        except ValueError:
            continue
        if flag_bits & 0x2 == 0 or gateway_ip == "0.0.0.0":
            continue
        if not valid_iface(iface, windows=False) or not unicast_ip(gateway_ip):
            continue
        if best is None or metric_n < best[0]:
            best = (metric_n, iface, gateway_ip)
    if best is None:
        return None, None
    return best[2], best[1]


def parse_proc_arp(text: str) -> tuple[Neighbor, ...]:
    rows: list[Neighbor] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hwtype, flags, mac, _mask, device = parts[:6]
        if flags == "0x0":
            continue
        normalized = normalize_mac(mac)
        if not unicast_ip(ip) or not normalized or not valid_iface(device, windows=False):
            continue
        state = "reachable" if flags == "0x2" else flags
        rows.append(Neighbor(ip, normalized, device, state))
    return tuple(rows)


def parse_proc_snmp_icmp(text: str) -> tuple[int | None, int | None]:
    header: list[str] | None = None
    for line in text.splitlines():
        if not line.startswith("Icmp:"):
            continue
        parts = line.split()[1:]
        if header is None:
            header = parts
            continue
        if len(parts) < len(header):
            continue
        values = dict(zip(header, parts))
        try:
            return int(values["InEchos"]), int(values["InRedirects"])
        except (KeyError, ValueError):
            return None, None
    return None, None


def parse_windows_report(text: str) -> Snapshot:
    gateway_ip: str | None = None
    gateway_iface: str | None = None
    echos: int | None = None
    redirects: int | None = None
    neighbors: list[Neighbor] = []
    for line in text.splitlines():
        parts = line.split("\x1f")
        kind = parts[0].strip()
        if kind == "ICMP" and len(parts) >= 3:
            try:
                echos = int(parts[1].strip())
                redirects = int(parts[2].strip())
            except ValueError:
                continue
        elif kind == "GW" and len(parts) >= 3:
            ip = parts[1].strip()
            iface = parts[2].strip()
            if unicast_ip(ip) and valid_iface(iface, windows=True):
                gateway_ip = ip
                gateway_iface = iface
        elif kind == "NEI" and len(parts) >= 5:
            ip = parts[1].strip()
            mac = normalize_mac(parts[2])
            iface = parts[3].strip()
            state = parts[4].strip()
            if state.lower() in {"incomplete", "uninitialized"}:
                continue
            if not unicast_ip(ip) or not mac or not valid_iface(iface, windows=True):
                continue
            neighbors.append(Neighbor(ip, mac, iface, state))
    return Snapshot(tuple(neighbors), gateway_ip, gateway_iface, echos, redirects)


def icmp_echo_source(packet: bytes) -> str | None:
    """Return the source of an IPv4 ICMP echo request. Ignore every other packet."""
    if len(packet) < 21 or (packet[0] >> 4) != 4:
        return None
    header_len = (packet[0] & 0x0F) * 4
    if header_len < 20 or len(packet) < header_len + 1:
        return None
    if packet[header_len] != 8:
        return None
    source = packet[12:16]
    if len(source) != 4:
        return None
    ip = ".".join(str(byte) for byte in source)
    if not unicast_ip(ip):
        return None
    return ip
