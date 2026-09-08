"""Phishing scoring engine. Local heuristics only — never fetches the URL."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from phishguard.brands import (
    BRANDS,
    CREDENTIAL_KEYWORDS,
    SHORTENER_HOSTS,
    SUSPICIOUS_TLDS,
    Brand,
    host_matches_suffix,
    is_user_content_host,
    official_brand_for_host,
)
from phishguard.confusables import fold_confusables, has_invisible, has_mixed_scripts
from phishguard.parser import ParsedURL, parse_url, query_pairs

KEYBOARD_ADJACENT = {
    "q": "wa",
    "w": "qes",
    "e": "wrd",
    "r": "etf",
    "t": "ryg",
    "y": "tuh",
    "u": "yij",
    "i": "uok",
    "o": "ipl",
    "p": "o",
    "a": "qsz",
    "s": "awdx",
    "d": "sefc",
    "f": "drgv",
    "g": "fthb",
    "h": "gyjn",
    "j": "hku",
    "k": "jli",
    "l": "ko",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "nk",
}


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    title: str
    title_el: str
    detail: str
    detail_el: str
    severity: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Analysis:
    url: str
    normalized: str
    host: str
    host_unicode: str
    verdict: str
    verdict_el: str
    score: int
    risk_percent: int
    impersonated_brand: str | None
    official_brand: str | None
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "normalized": self.normalized,
            "host": self.host,
            "host_unicode": self.host_unicode,
            "verdict": self.verdict,
            "verdict_el": self.verdict_el,
            "score": self.score,
            "risk_percent": self.risk_percent,
            "impersonated_brand": self.impersonated_brand,
            "official_brand": self.official_brand,
            "findings": [f.to_dict() for f in self.findings],
            "signals": self.signals,
        }


VERDICT_EL = {
    "official": "Επίσημο",
    "likely_safe": "Πιθανώς ασφαλές",
    "suspicious": "Ύποπτο",
    "phishing": "Phishing",
    "dangerous": "Επικίνδυνο",
    "invalid": "Άκυρο",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = prev[j] + 1
            delete = cur[j - 1] + 1
            sub = prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _is_typo_of(candidate: str, brand: str) -> bool:
    if candidate == brand:
        return True
    if abs(len(candidate) - len(brand)) > 2:
        return False
    dist = _levenshtein(candidate, brand)
    if len(brand) <= 4:
        return dist == 0
    if len(brand) <= 6:
        return dist <= 1
    return dist <= 2


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


def _deleet(s: str) -> str:
    return s.translate(_LEET)


def _brand_token_hits(text: str) -> list[tuple[Brand, str]]:
    folded = fold_confusables(text.lower())
    compact = re.sub(r"[^a-z0-9]", "", folded)
    hits: list[tuple[Brand, str]] = []
    seen: set[str] = set()
    for brand in BRANDS:
        for alias in brand.aliases:
            alias_f = fold_confusables(alias)
            if len(alias_f) < 4:
                continue
            if alias_f in compact or alias_f in folded:
                key = brand.name
                if key not in seen:
                    hits.append((brand, alias))
                    seen.add(key)
                break
            # typosquat of alias inside compact host
            # compare eTLD-like labels later; here only substring of close aliases
    return hits


def _typosquat_label(label: str) -> list[tuple[Brand, str]]:
    folded = fold_confusables(label.lower())
    parts = [p for p in re.split(r"[-_]", folded) if p]
    candidates = {
        folded,
        folded.replace("-", ""),
        _deleet(folded.replace("-", "")),
        *parts,
        *(_deleet(p) for p in parts),
    }
    hits: list[tuple[Brand, str]] = []
    for brand in BRANDS:
        for alias in brand.aliases:
            alias_f = fold_confusables(alias)
            if len(alias_f) < 5:
                continue
            matched = False
            for cand in candidates:
                if cand == alias_f:
                    matched = True
                    break
                if _is_typo_of(cand, alias_f):
                    matched = True
                    break
                if cand.startswith(alias_f) and len(cand) - len(alias_f) <= 8:
                    suffix = cand[len(alias_f) :]
                    if suffix in {
                        "login",
                        "secure",
                        "verify",
                        "support",
                        "online",
                        "onlinecom",
                        "com",
                        "365",
                        "account",
                    }:
                        matched = True
                        break
            if matched:
                hits.append((brand, alias))
                break
    return hits


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _findings_for(parsed: ParsedURL) -> tuple[list[Finding], str | None, str | None, dict[str, Any]]:
    findings: list[Finding] = []
    impersonated: str | None = None
    official: Brand | None = None
    host = parsed.host_unicode or parsed.host
    host_l = host.lower()
    folded_host = fold_confusables(host_l)
    etld = parsed.etld_plus_one.lower() if parsed.etld_plus_one else ""
    sld = etld.split(".")[0] if etld else (parsed.labels[0] if parsed.labels else "")

    if parsed.scheme in {"javascript", "data", "vbscript"}:
        findings.append(
            Finding(
                "dangerous_scheme",
                "Dangerous URL scheme",
                "Επικίνδυνο σχήμα URL",
                f"Scheme '{parsed.scheme}:' can execute code in the browser.",
                f"Το σχήμα '{parsed.scheme}:' μπορεί να εκτελέσει κώδικα στον browser.",
                "critical",
                100,
            )
        )
        return findings, None, None, {"scheme": parsed.scheme}

    if parsed.scheme == "file":
        findings.append(
            Finding(
                "file_scheme",
                "Local file URL",
                "Τοπικό αρχείο",
                "file:// links are not web login pages.",
                "Οι σύνδεσμοι file:// δεν είναι σελίδες σύνδεσης στο διαδίκτυο.",
                "high",
                70,
            )
        )

    official = official_brand_for_host(host_l) if host_l and not parsed.is_ip else None

    if parsed.userinfo:
        findings.append(
            Finding(
                "userinfo_at",
                "Credentials / @ trick in host",
                "Κόλπο @ στο host",
                "The '@' hides the real destination. Browsers use the host after '@'.",
                "Το '@' κρύβει τον πραγματικό προορισμό. Ο browser χρησιμοποιεί το host μετά το '@'.",
                "critical",
                90,
            )
        )
        ui = fold_confusables(parsed.userinfo.lower())
        for brand in BRANDS:
            for alias in brand.aliases:
                if len(alias) >= 5 and fold_confusables(alias) in ui:
                    impersonated = impersonated or brand.name
                    findings.append(
                        Finding(
                            "brand_in_userinfo",
                            f"{brand.name} name before @",
                            f"Όνομα {brand.name} πριν το @",
                            "The brand appears only in the fake userinfo prefix, not on the real host.",
                            "Το brand εμφανίζεται μόνο στο ψεύτικο πρόθεμα πριν το @, όχι στο πραγματικό host.",
                            "critical",
                            88,
                        )
                    )
                    break
            else:
                continue
            break

    if parsed.is_ip:
        findings.append(
            Finding(
                "ip_host",
                "IP address instead of domain",
                "Διεύθυνση IP αντί για domain",
                "Login pages for major brands never use a raw IP as the host.",
                "Οι σελίδες σύνδεσης μεγάλων εταιρειών δεν χρησιμοποιούν raw IP ως host.",
                "high",
                75,
            )
        )

    if parsed.punycode_used or has_mixed_scripts(host) or (host != fold_confusables(host) and not host.isascii()):
        findings.append(
            Finding(
                "homograph",
                "Homograph / IDN lookalike",
                "Homograph / IDN απομίμηση",
                f"Decoded host: {parsed.host_unicode}. Characters may look like Latin letters.",
                f"Αποκωδικοποιημένο host: {parsed.host_unicode}. Χαρακτήρες μπορεί να μοιάζουν με λατινικά.",
                "critical",
                85,
            )
        )

    if has_invisible(parsed.original) or has_invisible(host):
        findings.append(
            Finding(
                "invisible_chars",
                "Invisible / RTL override characters",
                "Αόρατοι χαρακτήρες / RTL override",
                "Zero-width or direction-override characters are a classic phishing obfuscation.",
                "Αόρατοι χαρακτήρες ή αλλαγή κατεύθυνσης κειμένου είναι κλασική τεχνική phishing.",
                "critical",
                90,
            )
        )

    if parsed.tld in SUSPICIOUS_TLDS and official is None:
        findings.append(
            Finding(
                "suspicious_tld",
                "Suspicious top-level domain",
                "Ύποπτο TLD",
                f"TLD '.{parsed.tld}' is frequently abused in phishing kits.",
                f"Το TLD '.{parsed.tld}' χρησιμοποιείται συχνά σε phishing kits.",
                "medium",
                18,
            )
        )

    if host_l in SHORTENER_HOSTS or any(host_matches_suffix(host_l, h) for h in SHORTENER_HOSTS):
        # aka.ms is official Microsoft — lower severity
        sev, sc = ("low", 12) if host_matches_suffix(host_l, "aka.ms") else ("medium", 28)
        findings.append(
            Finding(
                "shortener",
                "URL shortener hides destination",
                "Shortener κρύβει τον προορισμό",
                "Short links conceal the real host. Expand them before trusting.",
                "Τα short links κρύβουν τον πραγματικό host. Ανοίξτε τα μόνο αφού επεκταθούν.",
                sev,
                sc,
            )
        )

    if is_user_content_host(host_l):
        findings.append(
            Finding(
                "user_content_host",
                "Free / user-content hosting",
                "Δωρεάν / user-content hosting",
                "Anyone can publish a site on this host. Brand logos here are not proof of authenticity.",
                "Οποιοσδήποτε μπορεί να δημοσιεύσει σελίδα εδώ. Τα λογότυπα δεν αποδεικνύουν αυθεντικότητα.",
                "medium",
                25,
            )
        )

    # Brand in subdomain while registrable domain is unrelated
    labels_for_brand = parsed.labels[:-1] if len(parsed.labels) > 1 else parsed.labels
    subdomain = ".".join(parsed.labels[:-2]) if len(parsed.labels) >= 3 else ""
    haystack = folded_host
    compact_host = re.sub(r"[^a-z0-9]", "", folded_host)

    brand_hits: list[tuple[Brand, str, str]] = []
    for brand in BRANDS:
        is_official_this = official is not None and official.name == brand.name
        for alias in brand.aliases:
            alias_f = fold_confusables(alias)
            if len(alias_f) < 5:
                continue
            labels = [fold_confusables(l) for l in parsed.labels]
            compact_labels = [l.replace("-", "") for l in labels]
            if alias_f in labels or alias_f in compact_labels:
                brand_hits.append((brand, alias, "host"))
                break
            if len(alias_f) >= 6 and (alias_f in compact_host or alias_f in haystack):
                brand_hits.append((brand, alias, "host"))
                break

    # typosquat on SLD
    typo_hits = _typosquat_label(sld) if sld else []
    for brand, alias in typo_hits:
        if official and official.name == brand.name:
            continue
        brand_hits.append((brand, alias, "typosquat"))

    # unique brands
    seen_brands: set[str] = set()
    unique_hits: list[tuple[Brand, str, str]] = []
    for brand, alias, kind in brand_hits:
        if brand.name in seen_brands:
            continue
        seen_brands.add(brand.name)
        unique_hits.append((brand, alias, kind))

    for brand, alias, kind in unique_hits:
        is_off = official is not None and official.name == brand.name
        if is_off:
            continue
        impersonated = brand.name
        if kind == "typosquat":
            findings.append(
                Finding(
                    "typosquat",
                    f"Typosquat of {brand.name}",
                    f"Typosquat της {brand.name}",
                    f"Domain label looks like '{alias}' ({brand.name}) but is not an official domain.",
                    f"Το domain μοιάζει με '{alias}' ({brand.name}) αλλά δεν είναι επίσημο.",
                    "critical",
                    88,
                )
            )
        elif parsed.is_ip:
            findings.append(
                Finding(
                    "brand_on_ip",
                    f"{brand.name} mentioned on an IP host",
                    f"{brand.name} σε IP host",
                    f"Brand token '{alias}' on a raw IP is phishing.",
                    f"Το όνομα '{alias}' σε raw IP είναι phishing.",
                    "critical",
                    92,
                )
            )
        elif is_user_content_host(host_l):
            findings.append(
                Finding(
                    "brand_on_user_host",
                    f"{brand.name} impersonation on free hosting",
                    f"Απομίμηση {brand.name} σε δωρεάν hosting",
                    f"Token '{alias}' on a user-content host is a common kit pattern.",
                    f"Το '{alias}' σε user-content host είναι κοινό μοτίβο phishing kit.",
                    "critical",
                    86,
                )
            )
        else:
            # brand in subdomain of unrelated domain: login.microsoft.com.evil.xyz
            official_suffix_in_host = any(host_matches_suffix(host_l, d) for d in brand.domains)
            if not official_suffix_in_host:
                findings.append(
                    Finding(
                        "brand_impersonation",
                        f"Impersonates {brand.name}",
                        f"Απομίμηση {brand.name}",
                        f"Uses '{alias}' but the registrable domain is '{etld or host}', not an official {brand.name} property.",
                        f"Χρησιμοποιεί '{alias}' αλλά το domain είναι '{etld or host}', όχι επίσημη ιδιοκτησία της {brand.name}.",
                        "critical",
                        90,
                    )
                )

    # Path / query brand + keywords
    path_q = fold_confusables((parsed.path + "?" + parsed.query).lower())
    compact_path = re.sub(r"[^a-z0-9]", "", path_q)
    path_brand: str | None = None
    for brand in BRANDS:
        for alias in brand.aliases:
            alias_f = fold_confusables(alias)
            if len(alias_f) >= 5 and alias_f in compact_path:
                path_brand = brand.name
                if official is None or official.name != brand.name:
                    impersonated = impersonated or brand.name
                    findings.append(
                        Finding(
                            "brand_in_path",
                            f"{brand.name} named in path/query",
                            f"{brand.name} στο path/query",
                            "Phishing kits put the real brand in the path while the domain is unrelated.",
                            "Τα kits βάζουν το πραγματικό brand στο path ενώ το domain είναι άσχετο.",
                            "high",
                            55,
                        )
                    )
                break
        if path_brand:
            break

    keyword_hits = [k for k in CREDENTIAL_KEYWORDS if k in path_q or k in compact_path]
    if keyword_hits and official is None:
        findings.append(
            Finding(
                "credential_keywords",
                "Login / account keywords",
                "Λέξεις σύνδεσης / λογαριασμού",
                "Path or query contains: " + ", ".join(sorted(set(keyword_hits))[:8]),
                "Το path ή το query περιέχει: " + ", ".join(sorted(set(keyword_hits))[:8]),
                "medium",
                22,
            )
        )

    qs = query_pairs(parsed.query)
    sensitive_q = {"password", "passwd", "pwd", "user", "username", "email", "token", "otp", "ssn"}
    leaked = [k for k in qs if k.lower() in sensitive_q]
    if leaked:
        findings.append(
            Finding(
                "secrets_in_query",
                "Sensitive fields in query string",
                "Ευαίσθητα πεδία στο query",
                "Query keys: " + ", ".join(leaked),
                "Κλειδιά query: " + ", ".join(leaked),
                "high",
                40,
            )
        )

    if parsed.scheme == "http" and (official or impersonated or keyword_hits):
        findings.append(
            Finding(
                "plain_http",
                "Unencrypted HTTP",
                "HTTP χωρίς κρυπτογράφηση",
                "Login pages for major brands require HTTPS.",
                "Οι σελίδες σύνδεσης μεγάλων εταιρειών απαιτούν HTTPS.",
                "high" if (official or impersonated) else "medium",
                35 if (official or impersonated) else 18,
            )
        )

    if parsed.port and parsed.port not in {80, 443, 8080, 8443}:
        findings.append(
            Finding(
                "odd_port",
                "Unusual port",
                "Ασυνήθιστο port",
                f"Port {parsed.port} is uncommon for official brand sites.",
                f"Το port {parsed.port} είναι ασυνήθιστο για επίσημες σελίδες.",
                "low",
                12,
            )
        )

    if len(parsed.labels) >= 5:
        findings.append(
            Finding(
                "deep_subdomains",
                "Excessive subdomain depth",
                "Υπερβολικό βάθος subdomain",
                f"{len(parsed.labels)} labels. Deep trees are used to fake 'microsoft.com' as a prefix.",
                f"{len(parsed.labels)} labels. Βαθιά δέντρα χρησιμοποιούνται για να φαίνεται 'microsoft.com' ως prefix.",
                "medium",
                20,
            )
        )

    # microsoft.com.evil.com pattern: consecutive official labels not at the end
    for brand in BRANDS:
        for domain in brand.domains:
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            needle = "." + domain
            # host like a.microsoft.com.evil.com
            if host_l.endswith("." + domain):
                continue
            if domain in host_l and not host_matches_suffix(host_l, domain):
                if host_l.startswith(domain + ".") or f".{domain}." in f".{host_l}.":
                    if official is None or official.name != brand.name:
                        impersonated = impersonated or brand.name
                        findings.append(
                            Finding(
                                "domain_as_subdomain",
                                f"Official {brand.name} domain used as subdomain",
                                f"Επίσημο domain {brand.name} ως subdomain",
                                f"'{domain}' appears inside '{host}' but the real registrable domain is '{etld}'.",
                                f"Το '{domain}' εμφανίζεται μέσα στο '{host}' αλλά το πραγματικό domain είναι '{etld}'.",
                                "critical",
                                92,
                            )
                        )
                        break

    sld_entropy = _shannon(sld) if sld else 0
    if len(sld) >= 16 and sld_entropy > 3.8 and official is None:
        findings.append(
            Finding(
                "high_entropy_domain",
                "Random-looking domain",
                "Domain που μοιάζει τυχαίο",
                f"Second-level label entropy {sld_entropy:.2f} often indicates generated phishing domains.",
                f"Εντροπία {sld_entropy:.2f} συχνά δείχνει αυτόματα generated phishing domains.",
                "low",
                10,
            )
        )

    hyphen_count = sld.count("-") if sld else 0
    if hyphen_count >= 3 and official is None:
        findings.append(
            Finding(
                "many_hyphens",
                "Many hyphens in domain",
                "Πολλά ενωτικά στο domain",
                "Patterns like 'microsoft-office365-login-secure.xyz' are kit defaults.",
                "Μοτίβα όπως 'microsoft-office365-login-secure.xyz' είναι defaults των kits.",
                "medium",
                16,
            )
        )

    if len(parsed.original) > 180:
        findings.append(
            Finding(
                "very_long_url",
                "Very long URL",
                "Πολύ μεγάλο URL",
                "Long URLs bury the real host and tracking payloads.",
                "Τα μεγάλα URL κρύβουν το πραγματικό host.",
                "low",
                8,
            )
        )

    # official domain extra trust finding
    if official and not any(f.severity == "critical" for f in findings):
        findings.insert(
            0,
            Finding(
                "official_domain",
                f"Official {official.name} domain",
                f"Επίσημο domain {official.name}",
                f"Host matches known {official.name} property '{etld or host}'. Still check the path and HTTPS.",
                f"Το host ταιριάζει με γνωστή ιδιοκτησία {official.name} ('{etld or host}'). Ελέγξτε path και HTTPS.",
                "info",
                0,
            ),
        )

    signals = {
        "scheme": parsed.scheme,
        "host": host,
        "etld_plus_one": etld,
        "tld": parsed.tld,
        "is_ip": parsed.is_ip,
        "punycode": parsed.punycode_used,
        "userinfo": bool(parsed.userinfo),
        "official": official.name if official else None,
        "impersonated": impersonated,
        "keyword_hits": keyword_hits[:12],
        "sld_entropy": round(sld_entropy, 3),
        "label_count": len(parsed.labels),
    }
    return findings, impersonated, official.name if official else None, signals


def _verdict(score: int, findings: list[Finding], official: str | None) -> str:
    critical = any(f.severity == "critical" for f in findings)
    if any(f.code == "dangerous_scheme" for f in findings):
        return "dangerous"
    if critical or score >= 70:
        return "phishing"
    if score >= 35:
        return "suspicious"
    if official and score < 20:
        return "official"
    return "likely_safe"


def analyze(url: str) -> Analysis:
    raw = (url or "").strip()
    if not raw:
        f = Finding(
            "empty",
            "Empty input",
            "Κενή είσοδος",
            "Paste a URL to analyze.",
            "Επικολλήστε ένα URL για ανάλυση.",
            "info",
            0,
        )
        return Analysis(
            url="",
            normalized="",
            host="",
            host_unicode="",
            verdict="invalid",
            verdict_el=VERDICT_EL["invalid"],
            score=0,
            risk_percent=0,
            impersonated_brand=None,
            official_brand=None,
            findings=(f,),
            signals={},
        )

    try:
        parsed = parse_url(raw)
    except Exception as exc:
        f = Finding(
            "parse_error",
            "Could not parse URL",
            "Αδυναμία ανάλυσης URL",
            str(exc),
            str(exc),
            "high",
            50,
        )
        return Analysis(
            url=raw,
            normalized="",
            host="",
            host_unicode="",
            verdict="invalid",
            verdict_el=VERDICT_EL["invalid"],
            score=50,
            risk_percent=50,
            impersonated_brand=None,
            official_brand=None,
            findings=(f,),
            signals={"error": str(exc)},
        )

    findings, impersonated, official_name, signals = _findings_for(parsed)
    # de-dupe by code+title
    uniq: list[Finding] = []
    seen: set[str] = set()
    for f in findings:
        key = f.code + f.title
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    raw_score = sum(f.score for f in uniq)
    # cap + boost if multiple independent high signals
    score = min(100, raw_score)
    if sum(1 for f in uniq if f.severity in {"high", "critical"}) >= 3:
        score = min(100, max(score, 85))

    verdict = _verdict(score, uniq, official_name)
    return Analysis(
        url=raw,
        normalized=parsed.normalized,
        host=parsed.host,
        host_unicode=parsed.host_unicode,
        verdict=verdict,
        verdict_el=VERDICT_EL[verdict],
        score=score,
        risk_percent=score,
        impersonated_brand=impersonated,
        official_brand=official_name,
        findings=tuple(uniq),
        signals=signals,
    )
