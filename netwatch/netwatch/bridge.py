"""Helper process for the Windows desktop window. Reads commands, writes text."""

from __future__ import annotations

import sys

from netwatch.monitor import Monitor, MonitorError
from netwatch.report import format_frame
from netwatch.store import default_state_path

_ERRORS = {
    "no_gateway": "No default gateway is visible.",
    "no_mac": "The router has not answered ARP yet, so there is no MAC to confirm.",
    "mismatch": (
        "The router MAC does not match the one you confirmed. Pinning keeps the old one. "
        "Accept the new one only after checking it on the device."
    ),
    "invalid": "Invalid address. Nothing was changed.",
}


def main() -> int:
    monitor = Monitor(state_path=default_state_path(), poll=True, interval=2.0)
    monitor.tick()
    monitor.start()
    try:
        for raw in sys.stdin:
            op = raw.strip().lower()
            if not op:
                continue
            if op == "quit":
                break
            frame = _run(monitor, op)
            sys.stdout.write(frame)
            sys.stdout.flush()
    finally:
        monitor.stop()
    return 0


def _run(monitor: Monitor, op: str) -> str:
    try:
        if op == "state":
            return format_frame({"ok": True, "message": "", "state": monitor.state_dict()})
        if op == "confirm":
            return format_frame(monitor.confirm(False))
        if op == "accept":
            return format_frame(monitor.confirm(True))
        if op == "protect":
            return format_frame(monitor.protect())
        if op == "forget":
            return format_frame(monitor.forget())
        if op == "ping":
            return format_frame(monitor.demo_ping())
        if op == "mitm":
            return format_frame(monitor.demo_mitm())
        if op == "redirect":
            return format_frame(monitor.demo_redirect())
        if op == "reset":
            return format_frame(monitor.demo_reset())
    except MonitorError as exc:
        return format_frame(
            {
                "ok": False,
                "message": _ERRORS.get(exc.code, "That could not be completed."),
                "state": monitor.state_dict(),
            }
        )
    return format_frame(
        {
            "ok": False,
            "message": "Unknown command.",
            "state": monitor.state_dict(),
        }
    )


if __name__ == "__main__":
    raise SystemExit(main())
