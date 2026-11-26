"""Snapshots of this computer's local network view."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str
    iface: str
    state: str = ""


@dataclass(frozen=True)
class Snapshot:
    neighbors: tuple[Neighbor, ...]
    gateway_ip: str | None
    gateway_iface: str | None
    in_echos: int | None
    in_redirects: int | None
    ping_sources: tuple[str, ...] = ()
    simulated: bool = False
    taken_at: str = ""
    note: str = ""

    def gateway_mac(self) -> str | None:
        if not self.gateway_ip:
            return None
        same_iface = [
            n for n in self.neighbors if n.ip == self.gateway_ip and n.iface == self.gateway_iface
        ]
        chosen = same_iface or [n for n in self.neighbors if n.ip == self.gateway_ip]
        return chosen[0].mac if chosen else None
