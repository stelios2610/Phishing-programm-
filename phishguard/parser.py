"""URL parsing helpers. Analysis is local — we never fetch the URL."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

from phishguard.lures import fully_unquote, unwrap_security_wrapper

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass(frozen=True, slots=True)
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    userinfo: str | None
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    host_unicode: str
    is_ip: bool
    ip_version: int | None
    labels: tuple[str, ...]
    etld_plus_one: str
    tld: str
    punycode_used: bool
    decode_notes: tuple[str, ...]


def _hxxp_to_http(url: str) -> str:
    return re.sub(r"(?i)^hxxps://", "https://", re.sub(r"(?i)^hxxp://", "http://", url))


def ensure_scheme(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    if raw.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
        return raw
    if _SCHEME_RE.match(raw):
        return raw
    if raw.startswith("//"):
        return "https:" + raw
    return "https://" + raw


def _decode_host(host: str) -> tuple[str, bool, tuple[str, ...]]:
    notes: list[str] = []
    puny = False
    host = host.strip(".").lower()
    if "%" in host:
        try:
            decoded = unquote(host)
            if decoded != host:
                notes.append("percent-encoded-host")
                host = decoded
        except Exception:
            pass
    unicode_host = host
    try:
        # idna decode each label
        parts = []
        for label in host.split("."):
            if label.startswith("xn--"):
                puny = True
                parts.append(label.encode("ascii").decode("idna"))
            else:
                try:
                    parts.append(label.encode("ascii").decode("idna"))
                except Exception:
                    parts.append(label)
        unicode_host = ".".join(parts)
    except Exception:
        unicode_host = host
    return unicode_host, puny, tuple(notes)


def _etld_plus_one(host: str) -> tuple[str, str]:
    labels = [l for l in host.lower().strip(".").split(".") if l]
    if not labels:
        return "", ""
    tld = labels[-1]
    if len(labels) == 1:
        return host, tld
    # naive eTLD+1: last two labels, except common two-part public suffixes
    two_part = {
        "co.uk",
        "com.au",
        "co.nz",
        "co.jp",
        "com.br",
        "com.gr",
        "com.tr",
        "co.in",
        "com.mx",
        "co.za",
        "com.cn",
        "gov.uk",
        "ac.uk",
        "org.uk",
        "net.au",
        "gov.gr",
        "com.cy",
    }
    last_two = ".".join(labels[-2:])
    if last_two in two_part and len(labels) >= 3:
        return ".".join(labels[-3:]), last_two
    return last_two, tld


def _ip_info(host: str) -> tuple[bool, int | None]:
    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ip = ipaddress.ip_address(candidate)
        return True, ip.version
    except ValueError:
        pass
    # decimal / hex / octal IPv4 tricks
    if re.fullmatch(r"0x[0-9a-f]+", candidate, re.I):
        try:
            ipaddress.IPv4Address(int(candidate, 16))
            return True, 4
        except Exception:
            return False, None
    if re.fullmatch(r"\d+", candidate) and len(candidate) <= 10:
        try:
            ipaddress.IPv4Address(int(candidate, 10))
            return True, 4
        except Exception:
            return False, None
    return False, None


def parse_url(raw: str) -> ParsedURL:
    original = raw.strip()
    if not original:
        raise ValueError("empty URL")

    notes: list[str] = []
    working = original
    # Strip wrapping quotes/brackets commonly copied from emails
    working = _hxxp_to_http(working.strip("<>\"'"))
    inner, via = unwrap_security_wrapper(working)
    if via:
        notes.append("unwrapped:" + via)
        working = inner

    lowered = working.lower()
    if lowered.startswith(("javascript:", "data:", "vbscript:")):
        scheme = lowered.split(":", 1)[0]
        return ParsedURL(
            original=original,
            normalized=working,
            scheme=scheme,
            userinfo=None,
            host="",
            port=None,
            path=working,
            query="",
            fragment="",
            host_unicode="",
            is_ip=False,
            ip_version=None,
            labels=(),
            etld_plus_one="",
            tld="",
            punycode_used=False,
            decode_notes=("dangerous-scheme",),
        )

    with_scheme = ensure_scheme(working)
    parsed = urlparse(with_scheme)

    userinfo = None
    host = parsed.hostname or ""
    if parsed.netloc and "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0]
        notes.append("userinfo")

    host = (host or "").rstrip(".")
    unicode_host, puny, host_notes = _decode_host(host) if host else ("", False, ())
    notes.extend(host_notes)

    is_ip, ip_ver = _ip_info(host) if host else (False, None)
    labels = tuple(l for l in unicode_host.split(".") if l) if not is_ip else ()
    etld1, tld = ("", "") if is_ip else _etld_plus_one(unicode_host)

    path = fully_unquote(parsed.path or "")
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    port = parsed.port
    scheme = (parsed.scheme or "").lower()

    normalized = f"{scheme}://{unicode_host or host}"
    if port:
        normalized += f":{port}"
    normalized += parsed.path or ""
    if query:
        normalized += "?" + query
    if fragment:
        normalized += "#" + fragment

    return ParsedURL(
        original=original,
        normalized=normalized,
        scheme=scheme,
        userinfo=userinfo,
        host=host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        host_unicode=unicode_host,
        is_ip=is_ip,
        ip_version=ip_ver,
        labels=labels,
        etld_plus_one=etld1,
        tld=tld,
        punycode_used=puny,
        decode_notes=tuple(notes),
    )


def query_pairs(query: str) -> dict[str, list[str]]:
    return parse_qs(query, keep_blank_values=True)
