"""Inspect fetched HTML for login kits without executing scripts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from phishguard.brands import BRANDS
from phishguard.confusables import fold_confusables
from phishguard.lures import lure_hits


@dataclass
class PageSignals:
    title: str = ""
    password: bool = False
    email: bool = False
    brands: list[str] = field(default_factory=list)
    form_hosts: list[str] = field(default_factory=list)
    lures: list[str] = field(default_factory=list)
    iframe: bool = False


class _HtmlSig(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.signals = PageSignals()
        self._in_title = False
        self._title_buf: list[str] = []
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "input":
            typ = d.get("type", "text").lower()
            name = (d.get("name", "") + d.get("id", "") + d.get("autocomplete", "")).lower()
            if typ == "password" or "password" in name or name in {"passwd", "pwd"}:
                self.signals.password = True
            if typ in {"email", "tel"} or "email" in name or "user" in name:
                self.signals.email = True
        if tag == "iframe":
            self.signals.iframe = True
        if tag == "form" and d.get("action"):
            host = (urlparse(d["action"]).hostname or "").lower()
            if host:
                self.signals.form_hosts.append(host)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            self.signals.title = " ".join(self._title_buf).strip()

    def handle_data(self, data):
        if self._in_title:
            self._title_buf.append(data)
        if data.strip():
            self._text.append(data)


def inspect_html(html: str) -> PageSignals:
    parser = _HtmlSig()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    blob = fold_confusables((parser.signals.title + " " + " ".join(parser._text[:400])).lower())
    compact = re.sub(r"[^a-z0-9α-ωάέήίόύώ]+", " ", blob)
    brands: list[str] = []
    for brand in BRANDS:
        for alias in brand.aliases:
            a = fold_confusables(alias)
            if len(a) >= 5 and a in compact.replace(" ", ""):
                brands.append(brand.name)
                break
    parser.signals.brands = brands
    parser.signals.lures = lure_hits(blob)
    if re.search(r'type\s*=\s*["\']password["\']', html or "", re.I):
        parser.signals.password = True
    return parser.signals
