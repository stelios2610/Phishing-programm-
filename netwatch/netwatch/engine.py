"""Turn network snapshots into alerts. This module never touches the network."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from netwatch.model import Neighbor, Snapshot
from netwatch.parse import normalize_mac, unicast_ip, valid_iface

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TrustedGateway:
    ip: str
    mac: str
    iface: str

    def to_dict(self) -> dict[str, str]:
        return {"ip": self.ip, "mac": self.mac, "iface": self.iface}


@dataclass
class Alert:
    id: int
    at: str
    severity: str
    code: str
    title: str
    detail: str
    simulated: bool
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class Engine:
    def __init__(self, clock: Clock | None = None, *, prompt_confirm: bool = True) -> None:
        self._clock = clock or _utcnow
        self._prompt_confirm = prompt_confirm
        self.trusted: TrustedGateway | None = None
        self.session_pings = 0
        self.session_redirects = 0
        self._alerts: list[Alert] = []
        self._next_id = 1
        self._open: set[str] = set()
        self._once: set[str] = set()
        self._prev_mac: dict[str, str] = {}
        self._prev_echo: int | None = None
        self._prev_redirect: int | None = None
        self._prev_gateway_ip: str | None = None
        self._prev_gateway_mac: str | None = None
        self._coalesce_at: dict[str, datetime] = {}
        self._coalesce_id: dict[str, int] = {}
        self._window_sources: dict[str, list[str]] = {}

    def has_open(self, code: str) -> bool:
        return code in self._open

    def alerts(self) -> list[Alert]:
        return list(reversed(self._alerts))

    def confirm(self, ip: str, mac: str, iface: str) -> TrustedGateway:
        normalized = normalize_mac(mac)
        if not unicast_ip(ip) or not normalized:
            raise ValueError("invalid")
        if iface and not valid_iface(iface, windows=False) and not valid_iface(iface, windows=True):
            raise ValueError("invalid")
        self.trusted = TrustedGateway(ip, normalized, iface)
        self._open.discard("gateway_mac_changed")
        self._alerts = [alert for alert in self._alerts if alert.code != "confirm_gateway"]
        return self.trusted

    def forget(self) -> None:
        self.trusted = None
        self._open.discard("gateway_mac_changed")

    def observe(self, snap: Snapshot) -> list[Alert]:
        fresh: list[Alert] = []
        by_ip, conflicts = _index(snap.neighbors)
        fresh.extend(self._conflicts(snap, conflicts))
        fresh.extend(self._gateway(snap))
        fresh.extend(self._neighbors(snap, by_ip, {ip for ip, _a, _b in conflicts}))
        fresh.extend(self._clones(snap))
        fresh.extend(self._counter(snap, "ping"))
        fresh.extend(self._counter(snap, "redirect"))
        conflict_ips = {ip for ip, _first, _second in conflicts}
        self._prev_mac = {ip: item.mac for ip, item in by_ip.items() if ip not in conflict_ips}
        self._prev_gateway_ip = snap.gateway_ip
        self._prev_gateway_mac = snap.gateway_mac()
        return fresh

    def _conflicts(self, snap: Snapshot, conflicts: list[tuple[str, str, str]]) -> list[Alert]:
        emitted: list[Alert] = []
        for ip, first, second in conflicts:
            key = f"conflict:{ip}:{first}:{second}"
            if key in self._once:
                continue
            self._once.add(key)
            emitted.append(
                self._emit(
                    snap,
                    "critical",
                    "arp_conflict",
                    "Two MAC addresses for one IP",
                    f"{ip} is announced as both {first} and {second}.",
                )
            )
        return emitted

    def _gateway(self, snap: Snapshot) -> list[Alert]:
        emitted: list[Alert] = []
        current = snap.gateway_mac()
        trusted = self.trusted
        contradicts = bool(
            trusted and snap.gateway_ip == trusted.ip and current and current != trusted.mac
        )
        if contradicts and trusted is not None and current is not None:
            if "gateway_mac_changed" not in self._open:
                self._open.add("gateway_mac_changed")
                emitted.append(
                    self._emit(
                        snap,
                        "critical",
                        "gateway_mac_changed",
                        "The router MAC changed",
                        (
                            f"Router {trusted.ip} was confirmed as {trusted.mac} and now appears "
                            f"as {current}. On a local network that is the usual picture of ARP "
                            "spoofing: someone is pretending to be the router. Do not enter "
                            "passwords. Compare the MAC with the sticker on the router. If it "
                            "does not match, disconnect. Pinning writes the previous MAC back "
                            "on this computer only."
                        ),
                    )
                )
        elif (
            trusted
            and snap.gateway_ip == trusted.ip
            and current == trusted.mac
            and "gateway_mac_changed" in self._open
        ):
            self._open.discard("gateway_mac_changed")
            emitted.append(
                self._emit(
                    snap,
                    "info",
                    "gateway_restored",
                    "The router MAC is back",
                    f"Router {trusted.ip} is showing the MAC you confirmed ({trusted.mac}) again.",
                )
            )
        elif (
            current
            and self._prev_gateway_mac
            and self._prev_gateway_ip
            and snap.gateway_ip == self._prev_gateway_ip
            and current != self._prev_gateway_mac
        ):
            token = f"flip:{snap.gateway_ip}:{current}"
            if token not in self._once:
                self._once.add(token)
                emitted.append(
                    self._emit(
                        snap,
                        "warning",
                        "gateway_mac_changed",
                        "The gateway MAC changed",
                        (
                            f"Default gateway {snap.gateway_ip} had MAC {self._prev_gateway_mac} and "
                            f"now appears as {current}. It is not confirmed yet, so there is no way "
                            "to know which one is your router. Do not confirm it unless you compared "
                            "it with the device."
                        ),
                    )
                )

        if trusted and snap.gateway_ip and snap.gateway_ip != trusted.ip:
            token = f"gw-ip:{snap.gateway_ip}"
            if token not in self._once:
                self._once.add(token)
                emitted.append(
                    self._emit(
                        snap,
                        "warning",
                        "gateway_ip_changed",
                        "The router address changed",
                        (
                            f"The default gateway was {trusted.ip} and is now {snap.gateway_ip}. "
                            "That happens when you change networks or DHCP hands out another gateway. "
                            "It is not an attack by itself. Confirm the router again only on your own "
                            "network, and only if the MAC matches the device."
                        ),
                    )
                )
        elif (
            self._prompt_confirm
            and trusted is None
            and snap.gateway_ip
            and current
            and "confirm_gateway" not in self._once
        ):
            self._once.add("confirm_gateway")
            iface = snap.gateway_iface or "-"
            emitted.append(
                self._emit(
                    snap,
                    "info",
                    "confirm_gateway",
                    "Confirm the router",
                    (
                        f"The current gateway is {snap.gateway_ip} with MAC {current} on {iface}. "
                        "Confirm it only if that MAC matches your router."
                    ),
                )
            )
        return emitted

    def _neighbors(
        self,
        snap: Snapshot,
        by_ip: dict[str, Neighbor],
        conflict_ips: set[str],
    ) -> list[Alert]:
        changes: list[tuple[str, str, str]] = []
        for ip, item in by_ip.items():
            if ip in conflict_ips or ip == snap.gateway_ip:
                continue
            previous = self._prev_mac.get(ip)
            if previous and previous != item.mac:
                changes.append((ip, previous, item.mac))
        if len(changes) >= 3:
            listed = ", ".join(ip for ip, _old, _new in changes[:8])
            return [
                self._emit(
                    snap,
                    "critical",
                    "arp_storm",
                    "Many MAC addresses changed at once",
                    (
                        f"One reading changed the MAC of {len(changes)} addresses ({listed}). "
                        "That looks like an ARP flood, not a normal device change."
                    ),
                )
            ]
        emitted: list[Alert] = []
        for ip, previous, mac in changes:
            emitted.append(
                self._emit(
                    snap,
                    "warning",
                    "neighbor_mac_changed",
                    "A device MAC changed",
                    (
                        f"{ip} had MAC {previous} and now has {mac}. That can be a different device "
                        "on the same address, or someone answering in its place."
                    ),
                )
            )
        return emitted

    def _clones(self, snap: Snapshot) -> list[Alert]:
        trusted = self.trusted
        if trusted is None:
            return []
        emitted: list[Alert] = []
        seen: set[str] = set()
        for item in snap.neighbors:
            if item.ip == trusted.ip or item.mac != trusted.mac:
                continue
            seen.add(item.ip)
            key = f"clone:{item.ip}"
            if key in self._open:
                continue
            self._open.add(key)
            emitted.append(
                self._emit(
                    snap,
                    "critical",
                    "gateway_mac_cloned",
                    "The router MAC also appeared elsewhere",
                    (
                        f"Confirmed router MAC {trusted.mac} of {trusted.ip} is also present on "
                        f"{item.ip}. Someone may be copying the router."
                    ),
                )
            )
        for key in list(self._open):
            if key.startswith("clone:") and key.split(":", 1)[1] not in seen:
                self._open.discard(key)
        return emitted

    def _counter(self, snap: Snapshot, kind: str) -> list[Alert]:
        if kind == "ping":
            value = snap.in_echos
            previous = self._prev_echo
        else:
            value = snap.in_redirects
            previous = self._prev_redirect
        if value is None:
            return []
        if previous is None or value < previous:
            if kind == "ping":
                self._prev_echo = value
            else:
                self._prev_redirect = value
            return []
        delta = value - previous
        if kind == "ping":
            self._prev_echo = value
        else:
            self._prev_redirect = value
        if delta <= 0:
            return []
        if kind == "ping":
            self.session_pings += delta
            return [self._ping(snap, delta)]
        self.session_redirects += delta
        return [self._redirect(snap, delta)]

    def _ping(self, snap: Snapshot, delta: int) -> Alert:
        def fill(alert: Alert, *, fresh: bool) -> None:
            alert.count = delta if fresh else alert.count + delta
            sources = self._window_sources.get("ping", [])
            shown = ", ".join(sources[:8])
            if shown:
                alert.detail = (
                    f"{alert.count} ICMP echo requests came from: {shown}. A ping only shows that "
                    "someone is checking whether this computer is up. By itself it is not a break-in."
                )
            else:
                alert.detail = (
                    f"{alert.count} ICMP echo requests arrived. Without administrator rights the "
                    "sender address is not visible. A ping by itself is not a break-in."
                )

        return self._coalesce(
            snap,
            "ping",
            20,
            "warning",
            "ping",
            "Ping to this computer",
            fill,
        )

    def _redirect(self, snap: Snapshot, delta: int) -> Alert:
        def fill(alert: Alert, *, fresh: bool) -> None:
            alert.count = delta if fresh else alert.count + delta
            alert.detail = (
                f"This computer accepted {alert.count} ICMP redirects. A device on the network is "
                "telling it to send traffic somewhere else. That is a classic man-in-the-middle sign. "
                "Avoid signing in to accounts until you have checked the network."
            )

        return self._coalesce(
            snap,
            "redirect",
            30,
            "critical",
            "icmp_redirect",
            "ICMP redirect — possible route hijack",
            fill,
        )

    def _remember_sources(self, key: str, sources: tuple[str, ...]) -> None:
        bucket = self._window_sources.setdefault(key, [])
        for source in sources:
            if unicast_ip(source) and source not in bucket and len(bucket) < 8:
                bucket.append(source)

    def _coalesce(
        self,
        snap: Snapshot,
        key: str,
        window_s: int,
        severity: str,
        code: str,
        title: str,
        fill: Callable[..., None],
    ) -> Alert:
        now = self._clock()
        previous_at = self._coalesce_at.get(key)
        previous_id = self._coalesce_id.get(key)
        continued = (
            previous_at is not None
            and previous_id is not None
            and now - previous_at <= timedelta(seconds=window_s)
        )
        if not continued:
            self._window_sources[key] = []
        if code == "ping":
            self._remember_sources(key, snap.ping_sources)
        if continued and previous_id is not None:
            alert = next(item for item in self._alerts if item.id == previous_id)
            fill(alert, fresh=False)
            alert.at = now.isoformat()
            self._coalesce_at[key] = now
            self._alerts = [item for item in self._alerts if item.id != alert.id] + [alert]
            return alert
        alert = self._emit(snap, severity, code, title, "")
        fill(alert, fresh=True)
        self._coalesce_at[key] = now
        self._coalesce_id[key] = alert.id
        return alert

    def _emit(
        self,
        snap: Snapshot,
        severity: str,
        code: str,
        title: str,
        detail: str,
    ) -> Alert:
        alert = Alert(
            id=self._next_id,
            at=self._clock().isoformat(),
            severity=severity,
            code=code,
            title=title,
            detail=detail,
            simulated=snap.simulated,
        )
        self._next_id += 1
        self._alerts.append(alert)
        if len(self._alerts) > 200:
            self._alerts = self._alerts[-200:]
        return alert


def _index(neighbors: tuple[Neighbor, ...]) -> tuple[dict[str, Neighbor], list[tuple[str, str, str]]]:
    by_ip: dict[str, Neighbor] = {}
    macs: dict[str, set[str]] = {}
    for item in neighbors:
        macs.setdefault(item.ip, set()).add(item.mac)
        by_ip.setdefault(item.ip, item)
    conflicts = [
        (ip, sorted(seen)[0], sorted(seen)[1]) for ip, seen in macs.items() if len(seen) >= 2
    ]
    return by_ip, conflicts
