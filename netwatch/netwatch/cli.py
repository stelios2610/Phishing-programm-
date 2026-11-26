"""netwatch: watch this computer for pings and LAN man-in-the-middle signs."""

from __future__ import annotations

import argparse
import json
import os
import sys

from netwatch.collect import collect_snapshot
from netwatch.demo import baseline, with_mitm, with_ping, with_redirect
from netwatch.engine import Engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Watch this computer for incoming pings and LAN man-in-the-middle signs.",
    )
    parser.add_argument("--serve", action="store_true", help="Open the optional local web page instead of the window")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8840)
    parser.add_argument("--once", action="store_true", help="Print one reading as JSON and exit")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Print a simulated ping and MITM. Sends nothing.",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow binding outside localhost. The page can pin the router MAC.",
    )
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between readings")
    args = parser.parse_args(argv)

    if args.demo:
        return _print_demo()
    if args.once:
        return _print_once()
    if not args.serve:
        from netwatch.desktop import main as desktop_main

        return desktop_main()

    host = args.host.strip()
    if not args.allow_remote and host.strip("[]") not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "Refusing to listen outside localhost. The page can pin the router MAC. "
            "Pass --allow-remote only if you accept that.",
            file=sys.stderr,
        )
        return 2
    interval = min(30.0, max(0.5, args.interval))
    os.environ["NETWATCH_INTERVAL"] = str(interval)
    import uvicorn

    uvicorn.run("netwatch.api:app", host=host, port=args.port, reload=False)
    return 0


def _print_once() -> int:
    snap = collect_snapshot()
    engine = Engine()
    alerts = engine.observe(snap)
    payload = {
        "gateway_ip": snap.gateway_ip,
        "gateway_iface": snap.gateway_iface,
        "gateway_mac": snap.gateway_mac(),
        "neighbors": [
            {"ip": item.ip, "mac": item.mac, "iface": item.iface, "state": item.state}
            for item in snap.neighbors
        ],
        "in_echos": snap.in_echos,
        "in_redirects": snap.in_redirects,
        "note": snap.note,
        "alerts": [alert.to_dict() for alert in alerts],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _print_demo() -> int:
    engine = Engine(prompt_confirm=False)
    current = baseline()
    engine.observe(current)
    mac = current.gateway_mac()
    if current.gateway_ip and mac:
        engine.confirm(current.gateway_ip, mac, current.gateway_iface or "")
    alerts = []
    current = with_ping(current)
    alerts.extend(engine.observe(current))
    current = with_mitm(current)
    alerts.extend(engine.observe(current))
    current = with_redirect(current)
    alerts.extend(engine.observe(current))
    print(json.dumps([alert.to_dict() for alert in alerts], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
