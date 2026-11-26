import os

import pytest

from netwatch.report import format_frame, render_report


def _greek(text: str) -> bool:
    return any("\u0370" <= char <= "\u03ff" or "\u1f00" <= char <= "\u1fff" for char in text)


def test_report_and_window_protocol_are_english():
    state = {
        "view": "demo",
        "capture": "counters",
        "taken_at": "2026-11-26T10:00:00+00:00",
        "locked": False,
        "gateway": {
            "ip": "192.168.1.1",
            "mac": "02:de:ad:be:ef:01",
            "iface": "eth0",
            "trusted": {"ip": "192.168.1.1", "mac": "02:11:22:33:44:55", "iface": "eth0"},
            "mismatch": True,
        },
        "icmp": {"in_echos": 1, "in_redirects": 0, "session_pings": 1, "session_redirects": 0},
        "neighbors": [
            {"ip": "192.168.1.1", "mac": "02:de:ad:be:ef:01", "iface": "eth0", "state": "reachable", "role": "gateway"}
        ],
        "alerts": [
            {
                "severity": "critical",
                "title": "The router MAC changed",
                "detail": "Someone is pretending to be the router.",
                "simulated": True,
                "count": 1,
            }
        ],
        "flags": {"can_confirm": False, "can_accept": True, "can_protect": False, "can_forget": True},
    }
    report = render_report(state)
    frame = format_frame({"ok": True, "message": "Simulated man-in-the-middle.", "state": state})
    assert "SIMULATION" in report
    assert "The router MAC changed" in report
    assert "192.168.1.1" in report
    assert frame.startswith("BEGIN\n")
    assert "\nACCEPT 1\n" in frame
    assert "\nVIEW demo\n" in frame
    assert frame.rstrip().endswith("END")
    assert not _greek(report)
    assert not _greek(frame)


def test_desktop_window_shows_an_english_reading(tmp_path, monkeypatch):
    monkeypatch.setenv("NETWATCH_STATE_PATH", str(tmp_path / "trusted.json"))
    monkeypatch.setenv("DISPLAY", os.environ.get("DISPLAY") or ":1")
    tkinter = pytest.importorskip("tkinter")
    from netwatch.desktop import NetWatchApp

    try:
        app = NetWatchApp()
    except tkinter.TclError:
        pytest.skip("no desktop display")
    try:
        app.root.update_idletasks()
        text = app.report.get("1.0", "end")
        assert "Router" in text
        assert not _greek(text)
        app._mitm()
        text = app.report.get("1.0", "end")
        assert "SIMULATION" in text
        assert "The router MAC changed" in text
        assert app.status.cget("text").startswith("Simulated man-in-the-middle")
    finally:
        app.close()
