"""Native desktop window (tkinter) — same engine as the CLI, never fetches URLs."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import ttk

from phishguard.engine import analyze

EXAMPLES = [
    ("Microsoft official", "https://login.microsoftonline.com/"),
    ("Subdomain trap", "https://login.microsoft.com.secure-auth.xyz/signin"),
    ("Typosquat", "https://micros0ft-online.com/login"),
    ("@ trick", "https://login.microsoftonline.com@evil.example/login"),
    ("gov.gr kit", "https://gov-gr-taxisnet.web.app/login"),
    ("PayPal IP", "http://185.22.10.4/paypal/webscr?cmd=_login"),
]

COPY = {
    "el": {
        "title": "PhishGuard",
        "subtitle": "Τοπική ανάλυση · ο σύνδεσμος δεν ανοίγεται",
        "analyze": "Ανάλυση",
        "hint": "Επικολλήστε URL και πατήστε Ανάλυση",
        "risk": "Κίνδυνος",
        "official": "Επίσημο",
        "looks": "Μοιάζει με",
        "findings": "Ευρήματα",
    },
    "en": {
        "title": "PhishGuard",
        "subtitle": "Local analysis · the link is never opened",
        "analyze": "Analyze",
        "hint": "Paste a URL and click Analyze",
        "risk": "Risk",
        "official": "Official",
        "looks": "Looks like",
        "findings": "Findings",
    },
}

COLORS = {
    "bg": "#07090f",
    "panel": "#10141e",
    "text": "#e8edf7",
    "muted": "#93a0b8",
    "accent": "#6ea8ff",
    "good": "#3dd68c",
    "warn": "#f5c542",
    "bad": "#ff5d6c",
    "line": "#243049",
}


class PhishGuardApp:
    def __init__(self) -> None:
        self.lang = "el"
        self.root = tk.Tk()
        self.root.title("PhishGuard")
        self.root.geometry("920x720")
        self.root.minsize(720, 560)
        self.root.configure(bg=COLORS["bg"])
        self._logo_img = None
        self._build()

    def _t(self, key: str) -> str:
        return COPY[self.lang][key]

    def _build(self) -> None:
        pad = {"padx": 20, "pady": 6}
        header = tk.Frame(self.root, bg=COLORS["bg"])
        header.pack(fill="x", **pad)
        logo_path = Path(__file__).resolve().parent / "static" / "logo-64.png"
        self._logo_img = None
        if logo_path.exists():
            try:
                self._logo_img = tk.PhotoImage(file=str(logo_path))
                tk.Label(header, image=self._logo_img, bg=COLORS["bg"], bd=0).pack(side="left", padx=(0, 10))
                self.root.iconphoto(True, self._logo_img)
            except tk.TclError:
                self._logo_img = None
        tk.Label(
            header,
            text="PhishGuard",
            fg=COLORS["accent"],
            bg=COLORS["bg"],
            font=("Segoe UI", 22, "bold"),
        ).pack(side="left")
        self.sub = tk.Label(header, fg=COLORS["muted"], bg=COLORS["bg"], font=("Segoe UI", 10))
        self.sub.pack(side="left", padx=12)
        langf = tk.Frame(header, bg=COLORS["bg"])
        langf.pack(side="right")
        tk.Button(langf, text="EL", command=lambda: self._set_lang("el"), width=4).pack(side="left")
        tk.Button(langf, text="EN", command=lambda: self._set_lang("en"), width=4).pack(side="left")

        self.hint = tk.Label(self.root, fg=COLORS["muted"], bg=COLORS["bg"], font=("Segoe UI", 10))
        self.hint.pack(anchor="w", padx=20)

        row = tk.Frame(self.root, bg=COLORS["bg"])
        row.pack(fill="x", padx=20, pady=8)
        self.url_var = tk.StringVar()
        self.entry = tk.Entry(
            row,
            textvariable=self.url_var,
            font=("Segoe UI", 12),
            bg="#0b0f18",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self.entry.bind("<Return>", lambda _e: self.analyze())
        self.btn = tk.Button(
            row,
            command=self.analyze,
            bg=COLORS["accent"],
            fg="#071018",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            padx=16,
            pady=8,
        )
        self.btn.pack(side="right")

        chips = tk.Frame(self.root, bg=COLORS["bg"])
        chips.pack(fill="x", padx=20, pady=(0, 8))
        for label, url in EXAMPLES:
            tk.Button(
                chips,
                text=label,
                command=lambda u=url: self._example(u),
                bg=COLORS["panel"],
                fg=COLORS["text"],
                relief="flat",
                padx=8,
                pady=4,
            ).pack(side="left", padx=4, pady=2)

        self.verdict = tk.Label(self.root, bg=COLORS["bg"], fg=COLORS["text"], font=("Segoe UI", 16, "bold"))
        self.verdict.pack(anchor="w", padx=20, pady=(8, 0))
        self.meta = tk.Label(self.root, bg=COLORS["bg"], fg=COLORS["muted"], font=("Segoe UI", 10), wraplength=860, justify="left")
        self.meta.pack(anchor="w", padx=20)

        wrap = tk.Frame(self.root, bg=COLORS["panel"])
        wrap.pack(fill="both", expand=True, padx=20, pady=12)
        self.text = tk.Text(
            wrap,
            bg="#0b0f18",
            fg=COLORS["text"],
            font=("Consolas", 11),
            relief="flat",
            wrap="word",
            padx=12,
            pady=12,
        )
        scroll = ttk.Scrollbar(wrap, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set, state="disabled")
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._refresh_copy()
        self.entry.focus_set()

    def _set_lang(self, lang: str) -> None:
        self.lang = lang
        self._refresh_copy()

    def _refresh_copy(self) -> None:
        self.sub.configure(text=self._t("subtitle"))
        self.hint.configure(text=self._t("hint"))
        self.btn.configure(text=self._t("analyze"))

    def _example(self, url: str) -> None:
        self.url_var.set(url)
        self.analyze()

    def analyze(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            return
        result = analyze(url)
        label = result.verdict_el if self.lang == "el" else result.verdict.replace("_", " ")
        color = {
            "official": COLORS["good"],
            "likely_safe": COLORS["good"],
            "suspicious": COLORS["warn"],
        }.get(result.verdict, COLORS["bad"])
        self.verdict.configure(text=f"{label}  ·  {self._t('risk')} {result.risk_percent}/100", fg=color)
        bits = [result.normalized or result.url]
        if result.official_brand:
            bits.append(f"{self._t('official')}: {result.official_brand}")
        if result.impersonated_brand:
            bits.append(f"{self._t('looks')}: {result.impersonated_brand}")
        self.meta.configure(text="  ·  ".join(bits))
        lines = [self._t("findings") + ":", ""]
        for f in result.findings:
            title = f.title_el if self.lang == "el" else f.title
            detail = f.detail_el if self.lang == "el" else f.detail
            lines.append(f"[{f.severity.upper()}] {title}")
            lines.append(f"    {detail}")
            lines.append("")
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "\n".join(lines) if lines else "")
        self.text.configure(state="disabled")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    PhishGuardApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
