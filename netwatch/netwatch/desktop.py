"""Desktop window. Run this on your own computer; it reads that computer's network."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

from netwatch import __version__
from netwatch.monitor import Monitor, MonitorError
from netwatch.report import render_report
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


class NetWatchApp:
    def __init__(self) -> None:
        self.monitor = Monitor(state_path=default_state_path(), poll=True, interval=2.0)
        self.monitor.tick()
        self.monitor.start()
        self.root = tk.Tk()
        self.root.title(f"NetWatch {_version_label()}")
        self.root.geometry("920x720")
        self.root.minsize(720, 520)
        self.root.configure(bg="#f3f0e8")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        self.refresh()
        self.root.after(2000, self._tick)

    def _build(self) -> None:
        header = tk.Frame(self.root, bg="#0f5c56")
        header.pack(fill="x")
        tk.Label(
            header,
            text="NetWatch",
            bg="#0f5c56",
            fg="#f6f3ec",
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        ).pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(
            header,
            text="Desktop app for this computer. It watches pings and LAN man-in-the-middle signs.",
            bg="#0f5c56",
            fg="#f6f3ec",
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x", padx=16, pady=(0, 12))

        actions = tk.Frame(self.root, bg="#f3f0e8")
        actions.pack(fill="x", padx=12, pady=8)
        self.confirm = self._button(actions, "Confirm router", self._confirm)
        self.accept = self._button(actions, "Accept the new MAC", self._accept)
        self.protect = self._button(actions, "Pin the MAC", self._protect)
        self.forget = self._button(actions, "Forget it", self._forget)
        demo = tk.Frame(self.root, bg="#f3f0e8")
        demo.pack(fill="x", padx=12)
        tk.Label(
            demo,
            text="Simulation, no packets sent",
            bg="#f3f0e8",
            fg="#5f594f",
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 8))
        self._button(demo, "Simulate ping", self._ping)
        self._button(demo, "Simulate MITM", self._mitm)
        self._button(demo, "Simulate redirect", self._redirect)
        self.reset = self._button(demo, "End simulation", self._reset)

        self.status = tk.Label(
            self.root,
            text="",
            bg="#f3f0e8",
            fg="#083f3b",
            anchor="w",
            font=("Segoe UI", 10),
        )
        self.status.pack(fill="x", padx=16, pady=(6, 0))

        body = tk.Frame(self.root, bg="#f3f0e8")
        body.pack(fill="both", expand=True, padx=12, pady=8)
        scroll = ttk.Scrollbar(body)
        scroll.pack(side="right", fill="y")
        self.report = tk.Text(
            body,
            wrap="word",
            bg="#fffdf8",
            fg="#1c1915",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=8,
            yscrollcommand=scroll.set,
        )
        self.report.pack(side="left", fill="both", expand=True)
        scroll.config(command=self.report.yview)
        self.report.configure(state="disabled")

    def _button(self, parent: tk.Widget, label: str, command) -> tk.Button:
        button = tk.Button(
            parent,
            text=label,
            command=command,
            bg="#fffdf8",
            fg="#1c1915",
            activebackground="#0f5c56",
            activeforeground="#f6f3ec",
            relief="flat",
            padx=10,
            pady=4,
        )
        button.pack(side="left", padx=4, pady=2)
        return button

    def refresh(self) -> None:
        state = self.monitor.state_dict()
        flags = state.get("flags") or {}
        self.confirm.configure(state="normal" if flags.get("can_confirm") else "disabled")
        self.accept.configure(state="normal" if flags.get("can_accept") else "disabled")
        self.protect.configure(state="normal" if flags.get("can_protect") else "disabled")
        self.forget.configure(state="normal" if flags.get("can_forget") else "disabled")
        self.reset.configure(state="normal" if state.get("view") == "demo" else "disabled")
        self.report.configure(state="normal")
        self.report.delete("1.0", "end")
        self.report.insert("1.0", render_report(state))
        self.report.configure(state="disabled")

    def _tick(self) -> None:
        if not self.root.winfo_exists():
            return
        self.refresh()
        self.root.after(2000, self._tick)

    def _act(self, call) -> None:
        try:
            result = call()
        except MonitorError as exc:
            self.status.configure(text=_ERRORS.get(exc.code, "That could not be completed."))
            self.refresh()
            return
        self.status.configure(text=str(result.get("message") or ""))
        self.refresh()

    def _confirm(self) -> None:
        self._act(lambda: self.monitor.confirm(False))

    def _accept(self) -> None:
        self._act(lambda: self.monitor.confirm(True))

    def _protect(self) -> None:
        self._act(self.monitor.protect)

    def _forget(self) -> None:
        self._act(self.monitor.forget)

    def _ping(self) -> None:
        self._act(self.monitor.demo_ping)

    def _mitm(self) -> None:
        self._act(self.monitor.demo_mitm)

    def _redirect(self) -> None:
        self._act(self.monitor.demo_redirect)

    def _reset(self) -> None:
        self._act(self.monitor.demo_reset)

    def close(self) -> None:
        self.monitor.stop()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def _version_label() -> str:
    return __version__


def main() -> int:
    try:
        NetWatchApp().run()
    except tk.TclError as exc:
        print(f"NetWatch could not open a window: {exc}", file=sys.stderr)
        return 2
    return 0
