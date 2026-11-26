"""English text for the desktop window. No Greek copy lives here."""

from __future__ import annotations


def render_report(state: dict) -> str:
    gateway = state.get("gateway") or {}
    icmp = state.get("icmp") or {}
    flags = state.get("flags") or {}
    lines: list[str] = []
    if state.get("view") == "demo":
        lines.append(
            "SIMULATION. These numbers are not your real network, and no packet was sent."
        )
        lines.append("")
    lines.append("Router")
    lines.append(f"  {gateway.get('ip') or 'No gateway visible'}")
    mac = gateway.get("mac") or "No MAC yet"
    iface = gateway.get("iface") or ""
    lines.append(f"  {mac}" + (f"  {iface}" if iface else ""))
    trusted = gateway.get("trusted")
    if not state.get("taken_at") and state.get("view") != "demo":
        lines.append("  No reading yet.")
    elif gateway.get("mismatch"):
        confirmed = trusted.get("mac") if isinstance(trusted, dict) else ""
        extra = f" Confirmed MAC: {confirmed}." if confirmed else ""
        lines.append("  The MAC does not match the confirmed one." + extra)
    elif isinstance(trusted, dict):
        locked = " A static ARP entry is active on this computer." if state.get("locked") else ""
        lines.append(f"  Confirmed: {trusted.get('mac')}.{locked}")
    else:
        lines.append("  Not confirmed. Compare the MAC with the router before you confirm.")
    lines.append("")
    lines.append(f"New pings since opening: {icmp.get('session_pings') or 0}")
    if icmp.get("in_echos") is None:
        lines.append("ICMP counters were not read.")
    elif state.get("view") == "demo":
        lines.append(f"Counter inside the simulation: {icmp.get('in_echos')}")
    else:
        lines.append(f"Pings since system boot: {icmp.get('in_echos')}")
    lines.append(f"New ICMP redirects since opening: {icmp.get('session_redirects') or 0}")
    lines.append("")
    capture = state.get("capture")
    if capture == "icmp-echo":
        lines.append("The address that sends a ping (ICMP echo) is visible.")
    elif capture == "counters":
        lines.append(
            "The count of incoming pings is visible, not the sender. "
            "The sender needs administrator rights."
        )
    else:
        lines.append("This system's ICMP counters were not read.")
    if state.get("taken_at"):
        lines.append(f"Last reading: {state.get('taken_at')}")
    lines.append("")
    lines.append("Alerts")
    alerts = state.get("alerts") or []
    if not alerts:
        lines.append("  No alerts since opening.")
    for alert in alerts:
        kind = "simulation" if alert.get("simulated") else "live"
        count = alert.get("count") or 1
        suffix = f" x{count}" if count > 1 else ""
        lines.append(f"  [{alert.get('severity')}] {alert.get('title')} ({kind}{suffix})")
        detail = alert.get("detail") or ""
        if detail:
            lines.append(f"    {detail}")
    lines.append("")
    lines.append("Devices in the ARP table")
    neighbors = state.get("neighbors") or []
    if not neighbors:
        lines.append("  No ARP entries yet.")
    else:
        lines.append(f"  {'IP':<16} {'MAC':<18} {'IFACE':<12} {'ROLE'}")
        for row in neighbors:
            lines.append(
                f"  {row.get('ip', ''):<16} {row.get('mac', ''):<18} "
                f"{row.get('iface', ''):<12} {row.get('role', '')}"
            )
    lines.append("")
    lines.append(
        "This is not a file antivirus. It cannot see an attack at your provider, "
        "or a fake Wi-Fi that is itself the router. Without administrator rights it "
        "can see that pings arrived, not who sent them. Pinning applies only to the "
        "confirmed router MAC on this computer."
    )
    if flags:
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_frame(payload: dict) -> str:
    state = payload.get("state") or {}
    flags = state.get("flags") or {}
    message = " ".join(str(payload.get("message") or "").split())
    report = render_report(state).rstrip("\n")
    return "\n".join(
        [
            "BEGIN",
            f"OK {1 if payload.get('ok') else 0}",
            f"MESSAGE {message}",
            f"CONFIRM {1 if flags.get('can_confirm') else 0}",
            f"ACCEPT {1 if flags.get('can_accept') else 0}",
            f"PROTECT {1 if flags.get('can_protect') else 0}",
            f"FORGET {1 if flags.get('can_forget') else 0}",
            f"VIEW {state.get('view') or 'live'}",
            "REPORT",
            report,
            "END",
            "",
        ]
    )
