"""Fixed laboratory snapshots. Building these does not transmit anything."""

from __future__ import annotations

from dataclasses import replace

from netwatch.model import Neighbor, Snapshot

GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "02:11:22:33:44:55"
ATTACK_MAC = "02:de:ad:be:ef:01"
PING_FROM = "192.168.1.50"


def baseline() -> Snapshot:
    return Snapshot(
        neighbors=(
            Neighbor(GATEWAY_IP, GATEWAY_MAC, "eth0", "reachable"),
            Neighbor("192.168.1.20", "02:11:22:33:44:20", "eth0", "reachable"),
        ),
        gateway_ip=GATEWAY_IP,
        gateway_iface="eth0",
        in_echos=0,
        in_redirects=0,
        simulated=True,
    )


def with_ping(prev: Snapshot) -> Snapshot:
    return replace(
        prev,
        in_echos=(prev.in_echos or 0) + 1,
        ping_sources=(PING_FROM,),
        simulated=True,
    )


def with_mitm(prev: Snapshot) -> Snapshot:
    gateway = prev.gateway_ip
    neighbors = tuple(
        Neighbor(item.ip, ATTACK_MAC if item.ip == gateway else item.mac, item.iface, item.state)
        for item in prev.neighbors
    )
    if gateway and all(item.ip != gateway for item in neighbors):
        neighbors = neighbors + (
            Neighbor(gateway, ATTACK_MAC, prev.gateway_iface or "eth0", "reachable"),
        )
    return replace(prev, neighbors=neighbors, ping_sources=(), simulated=True)


def with_redirect(prev: Snapshot) -> Snapshot:
    return replace(
        prev,
        in_redirects=(prev.in_redirects or 0) + 1,
        ping_sources=(),
        simulated=True,
    )
