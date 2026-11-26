"""Hold the live reading and the separate simulation. The simulation never touches the OS."""

from __future__ import annotations

import os
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from netwatch import __version__
from netwatch.capture import IcmpEchoTap
from netwatch.collect import collect_snapshot
from netwatch.demo import baseline, with_mitm, with_ping, with_redirect
from netwatch.engine import Engine
from netwatch.model import Snapshot
from netwatch.protect import ProtectResult, apply_permanent_neighbor, delete_permanent_neighbor
from netwatch.store import clear_state, load_state, write_state

_DEMO = "This is a simulation. Computer settings were not changed and no packet was sent."


class MonitorError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Monitor:
    def __init__(self, state_path: Path, *, poll: bool, interval: float = 2.0) -> None:
        self.state_path = state_path
        self.interval = interval
        self.poll = poll
        self.live_engine = Engine()
        self.live_snap: Snapshot | None = None
        self.demo_engine: Engine | None = None
        self.demo_snap: Snapshot | None = None
        self.mode = "live"
        self.capture_mode = "unavailable"
        self.live_error = ""
        self.last_protect: ProtectResult | None = None
        self.lock_record: tuple[str, str, str] | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tap: IcmpEchoTap | None = None
        trusted, locked = load_state(state_path)
        if trusted is not None:
            self.live_engine.confirm(trusted.ip, trusted.mac, trusted.iface)
        self.lock_record = locked

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._tap = IcmpEchoTap()
        if self._tap.mode == "icmp-echo":
            self.capture_mode = "icmp-echo"
        self._thread = threading.Thread(target=self._loop, name="netwatch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        tap = self._tap
        self._tap = None
        if tap is not None:
            tap.close()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=2)

    def tick(self) -> None:
        sources: list[str] = []
        tap = self._tap
        if tap is not None:
            sources = tap.drain()
        try:
            snap = collect_snapshot()
        except Exception as exc:
            with self._lock:
                self.live_error = exc.__class__.__name__
            return
        snap = replace(snap, ping_sources=tuple(sources[:20]), taken_at=_iso())
        with self._lock:
            self.live_error = ""
            self.live_snap = snap
            self.live_engine.observe(snap)
            if tap is not None and tap.mode == "icmp-echo":
                self.capture_mode = "icmp-echo"
            elif snap.in_echos is not None:
                self.capture_mode = "counters"
            else:
                self.capture_mode = "unavailable"

    def state_dict(self) -> dict:
        with self._lock:
            return self._state_unlocked()

    def confirm(self, accept_change: bool) -> dict:
        with self._lock:
            self._confirm_unlocked(accept_change)
            if accept_change:
                message = "The new MAC was accepted. Do that only after checking it on the device."
            else:
                message = "The router MAC is confirmed. Pinning writes only that one."
            return self._response(ok=True, message=message)

    def forget(self) -> dict:
        with self._lock:
            demo = self._demo_active()
            record = None if demo else self.lock_record
            engine, _snap = self._active()
            engine.forget()
            if not demo:
                self.lock_record = None
                clear_state(self.state_path)
        unlock: ProtectResult | None = None
        if record is not None:
            try:
                unlock = delete_permanent_neighbor(*record)
            except ValueError:
                unlock = None
        with self._lock:
            if demo:
                message = "The simulation no longer has a confirmed router."
            elif unlock is not None and not unlock.applied:
                message = "The confirmation was forgotten. " + unlock.message
            else:
                message = "The router confirmation was forgotten."
            if unlock is not None:
                self.last_protect = unlock
            return self._response(ok=True, message=message, result=unlock)

    def protect(self) -> dict:
        with self._lock:
            denial = self._protect_denial()
            if denial is not None:
                self.last_protect = denial
                return self._response(ok=False, message=denial.message, result=denial)
            trusted = self.live_engine.trusted
            snap = self.live_snap
            if trusted is None or snap is None:
                raise MonitorError("no_gateway")
            iface = trusted.iface or snap.gateway_iface or ""
            target = (trusted.ip, trusted.mac, iface)
        try:
            result = apply_permanent_neighbor(*target)
        except ValueError:
            result = ProtectResult(
                False,
                "invalid",
                "Invalid router address. Nothing was changed.",
                "",
            )
        with self._lock:
            self.last_protect = result
            if result.applied:
                self.lock_record = target
                self._persist()
            return self._response(ok=result.applied, message=result.message, result=result)

    def demo_ping(self) -> dict:
        with self._lock:
            engine, snap = self._ensure_demo()
            updated = with_ping(snap)
            engine.observe(updated)
            self.demo_snap = updated
            return self._response(ok=True, message="Simulated ping. No packet was sent.")

    def demo_mitm(self) -> dict:
        with self._lock:
            engine, snap = self._ensure_demo()
            mac = snap.gateway_mac()
            if engine.trusted is None and snap.gateway_ip and mac:
                engine.confirm(snap.gateway_ip, mac, snap.gateway_iface or "")
            updated = with_mitm(snap)
            engine.observe(updated)
            self.demo_snap = updated
            return self._response(
                ok=True,
                message="Simulated man-in-the-middle. No packet was sent on the network.",
            )

    def demo_redirect(self) -> dict:
        with self._lock:
            engine, snap = self._ensure_demo()
            updated = with_redirect(snap)
            engine.observe(updated)
            self.demo_snap = updated
            return self._response(ok=True, message="Simulated ICMP redirect. No packet was sent.")

    def demo_reset(self) -> dict:
        with self._lock:
            self.mode = "live"
            self.demo_engine = None
            self.demo_snap = None
            return self._response(ok=True, message="Back to this computer's real network view.")

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            if self._stop.is_set():
                return
            try:
                self.tick()
            except Exception as exc:
                with self._lock:
                    self.live_error = exc.__class__.__name__

    def _confirm_unlocked(self, accept_change: bool) -> None:
        engine, snap = self._active()
        if snap is None or not snap.gateway_ip:
            raise MonitorError("no_gateway")
        mac = snap.gateway_mac()
        if not mac:
            raise MonitorError("no_mac")
        if engine.has_open("gateway_mac_changed") and not accept_change:
            raise MonitorError("mismatch")
        engine.confirm(snap.gateway_ip, mac, snap.gateway_iface or "")
        if not self._demo_active():
            self._persist()

    def _protect_denial(self) -> ProtectResult | None:
        if self._demo_active():
            return ProtectResult(False, "demo", _DEMO, "")
        trusted = self.live_engine.trusted
        snap = self.live_snap
        if trusted is None:
            return ProtectResult(
                False,
                "unconfirmed",
                "Confirm the router MAC first, and only if it matches the device.",
                "",
            )
        if snap is None or not snap.gateway_ip:
            return ProtectResult(
                False,
                "no_gateway",
                "No default gateway has been read yet.",
                "",
            )
        if snap.gateway_ip != trusted.ip:
            return ProtectResult(
                False,
                "gateway_moved",
                "The current gateway is not the confirmed one. A different address was not locked.",
                "",
            )
        return None

    def _ensure_demo(self) -> tuple[Engine, Snapshot]:
        if self.demo_engine is None or self.demo_snap is None:
            self.demo_engine = Engine(prompt_confirm=False)
            self.demo_snap = baseline()
            self.demo_engine.observe(self.demo_snap)
        self.mode = "demo"
        return self.demo_engine, self.demo_snap

    def _demo_active(self) -> bool:
        return self.mode == "demo" and self.demo_engine is not None and self.demo_snap is not None

    def _active(self) -> tuple[Engine, Snapshot | None]:
        if self._demo_active():
            assert self.demo_engine is not None
            return self.demo_engine, self.demo_snap
        return self.live_engine, self.live_snap

    def _persist(self) -> None:
        write_state(self.state_path, self.live_engine.trusted, self.lock_record)

    def _response(
        self,
        *,
        ok: bool,
        message: str,
        result: ProtectResult | None = None,
    ) -> dict:
        body: dict[str, object] = {
            "ok": ok,
            "message": message,
            "state": self._state_unlocked(),
        }
        if result is not None:
            body["result"] = result.to_dict()
        return body

    def _state_unlocked(self) -> dict:
        engine, snap = self._active()
        demo = self._demo_active()
        trusted = engine.trusted.to_dict() if engine.trusted else None
        mismatch = engine.has_open("gateway_mac_changed")
        gateway_mac = snap.gateway_mac() if snap else None
        neighbors = []
        if snap is not None:
            for item in snap.neighbors:
                role = "device"
                if snap.gateway_ip and item.ip == snap.gateway_ip:
                    role = "gateway"
                elif engine.trusted and item.mac == engine.trusted.mac and item.ip != engine.trusted.ip:
                    role = "clone"
                neighbors.append(
                    {
                        "ip": item.ip,
                        "mac": item.mac,
                        "iface": item.iface,
                        "state": item.state,
                        "role": role,
                    }
                )
        return {
            "version": __version__,
            "view": "demo" if demo else "live",
            "capture": self.capture_mode,
            "os": os.name,
            "error": self.live_error,
            "simulated": bool(snap and snap.simulated),
            "taken_at": snap.taken_at if snap else "",
            "note": snap.note if snap else "",
            "gateway": {
                "ip": snap.gateway_ip if snap else None,
                "mac": gateway_mac,
                "iface": snap.gateway_iface if snap else None,
                "trusted": trusted,
                "mismatch": mismatch,
            },
            "icmp": {
                "in_echos": snap.in_echos if snap else None,
                "in_redirects": snap.in_redirects if snap else None,
                "session_pings": engine.session_pings,
                "session_redirects": engine.session_redirects,
            },
            "neighbors": neighbors,
            "alerts": [alert.to_dict() for alert in engine.alerts()],
            "flags": {
                "can_confirm": bool(snap and gateway_mac and not mismatch),
                "can_accept": bool(mismatch and snap and gateway_mac),
                "can_protect": bool(
                    not demo
                    and engine.trusted
                    and snap
                    and snap.gateway_ip == engine.trusted.ip
                ),
                "can_forget": engine.trusted is not None,
            },
            "locked": self.lock_record is not None and not demo,
            "protection": self.last_protect.to_dict() if self.last_protect else None,
        }


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()
