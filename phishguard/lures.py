"""SharePoint / OneDrive / email lure detection (PhishScan rules).

Real microsoft.com / sharepoint.com hosts can still carry phishing files.
The giveaway is the filename and hidden characters — not the domain.
"""

from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import parse_qs, unquote, urlparse

LURE_PHRASES: tuple[str, ...] = (
    "ασφαλές μήνυμα",
    "ασφαλεσ μηνυμα",
    "προστατευμένο μήνυμα",
    "προστατευμενο μηνυμα",
    "κρυπτογραφημένο μήνυμα",
    "κρυπτογραφημενο μηνυμα",
    "κάντε κλικ",
    "καντε κλικ",
    "λήψη εγγράφου",
    "ληψη εγγραφου",
    "για να το δείτε",
    "για να το δειτε",
    "για να το ανοίξετε",
    "πατήστε εδώ",
    "πατηστε εδω",
    "κατεβάστε το έγγραφο",
    "secure message",
    "encrypted message",
    "protected message",
    "protected file",
    "click to view",
    "click to open",
    "click to download",
    "click the download",
    "download document",
    "download the document",
    "view the document",
    "open the document",
    "shared a file with you",
    "sent you a secure",
    "sent you a protected",
)

INVISIBLE_CHARS = (
    "\u00a0",
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u2060",
    "\u202f",
    "\u00ad",
    "\u180e",
)

CLOUD_SHARE_HOSTS: tuple[str, ...] = (
    "sharepoint.com",
    "onedrive.live.com",
    "1drv.ms",
    "onedrive.com",
    "docs.google.com",
    "drive.google.com",
    "dropbox.com",
    "dropboxusercontent.com",
    "box.com",
    "wetransfer.com",
    "we.tl",
    "icloud.com",
)

UNWRAP_HOST_SUFFIXES: tuple[str, ...] = (
    "safelinks.protection.outlook.com",
    "linkprotect.cudasvc.com",
    "urldefense.proofpoint.com",
)

HOST_CREDENTIAL_TOKENS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "passwd",
    "auth",
    "oauth",
    "update",
    "confirm",
    "billing",
    "invoice",
    "recover",
    "unlock",
    "support",
    "alert",
    "limited",
)


def fully_unquote(s: str) -> str:
    prev = s or ""
    for _ in range(4):
        nxt = unquote(prev.replace("+", " "))
        if nxt == prev:
            break
        prev = nxt
    return html.unescape(prev)


def filename_from_path(path: str) -> str:
    if not path:
        return ""
    return path.rstrip("/").split("/")[-1]


def normalize_for_match(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    for ch in INVISIBLE_CHARS:
        s = s.replace(ch, " ")
    s = s.replace("ς", "σ")
    s = s.casefold()
    return re.sub(r"\s+", " ", s)


def lure_hits(text: str) -> list[str]:
    norm = normalize_for_match(text)
    return [p for p in LURE_PHRASES if normalize_for_match(p) in norm]


def has_invisible(text: str) -> bool:
    return any(ch in (text or "") for ch in INVISIBLE_CHARS)


def sentence_filename(filename: str) -> bool:
    if not filename:
        return False
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    if len(stem) < 35:
        return False
    spaces = stem.count(" ") + stem.count("\u00a0")
    punct = sum(stem.count(c) for c in ".!?;:")
    low = stem.lower()
    return spaces >= 5 and (punct >= 1 or "κλικ" in low or "click" in low)


def is_cloud_share_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in CLOUD_SHARE_HOSTS)


def dangerous_share_ext(filename: str) -> str:
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext in {"html", "htm", "xhtml", "js", "vbs", "lnk"}:
        return ext
    return ""


def unwrap_security_wrapper(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower() if parsed.hostname else ""
    qs = parse_qs(parsed.query)
    if host.endswith("safelinks.protection.outlook.com") or host.endswith("linkprotect.cudasvc.com"):
        inner = (qs.get("url") or [""])[0]
        if inner:
            return unquote(inner), host
    if host.endswith("urldefense.proofpoint.com"):
        inner = (qs.get("u") or [""])[0]
        if inner:
            inner = inner.replace("-3A", ":").replace("-2F", "/").replace("_", "/")
            return inner, host
    return url, ""


def looks_like_html_or_email(text: str) -> bool:
    t = text.lstrip()[:4000].lower()
    if "<a " in t or "<html" in t or "href=" in t:
        return True
    if t.startswith("from:") or "\nsubject:" in t or t.startswith("mime-version"):
        return True
    if text.count("http://") + text.count("https://") >= 2 and "\n" in text:
        return True
    return False
