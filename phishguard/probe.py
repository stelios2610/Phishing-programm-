"""Safe, limited HTTP GET for HTML inspection. Never logs in or runs JavaScript."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

MAX_BYTES = 262_144
TIMEOUT = 5
UA = "PhishGuard/1.1 (phishing detector; read-only HTML)"


def fetch_html(url: str) -> tuple[str | None, str | None, int | None]:
    """Return (html, error, http_status). html may be empty on error."""
    if not url.lower().startswith(("http://", "https://")):
        return None, "unsupported-scheme", None
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            ctype = (resp.headers.get("Content-Type") or "").lower()
            html = raw.decode("utf-8", errors="replace")
            if "html" not in ctype and "<" not in html[:400]:
                return html, None, status
            return html, None, status
    except ssl.SSLError as exc:
        return None, f"ssl:{exc}", None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_BYTES).decode("utf-8", errors="replace")
        except Exception:
            body = None
        return body, f"http:{exc.code}", exc.code
    except Exception as exc:
        return None, type(exc).__name__, None
