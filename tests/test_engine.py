from __future__ import annotations

from phishguard.engine import analyze
from phishguard.parser import parse_url


def test_official_microsoft():
    r = analyze("https://login.microsoftonline.com/")
    assert r.verdict == "official"
    assert r.official_brand == "Microsoft"
    assert r.score < 20


def test_subdomain_trap():
    r = analyze("https://login.microsoft.com.secure-auth.xyz/signin")
    assert r.verdict == "phishing"
    assert r.impersonated_brand == "Microsoft"
    codes = {f.code for f in r.findings}
    assert "domain_as_subdomain" in codes or "brand_impersonation" in codes


def test_typosquat_leet():
    r = analyze("https://micros0ft-online.com/login")
    assert r.verdict == "phishing"
    assert r.impersonated_brand == "Microsoft"


def test_at_trick():
    r = analyze("https://login.microsoftonline.com@evil.example/login")
    assert r.verdict == "phishing"
    codes = {f.code for f in r.findings}
    assert "userinfo_at" in codes
    assert r.host in {"evil.example", "evil.example."}


def test_ip_paypal():
    r = analyze("http://185.22.10.4/paypal/webscr?cmd=_login")
    assert r.verdict == "phishing"
    assert r.impersonated_brand == "PayPal"
    codes = {f.code for f in r.findings}
    assert "ip_host" in codes
    assert "plain_http" in codes


def test_user_content_gov():
    r = analyze("https://gov-gr-taxisnet.web.app/login")
    assert r.verdict == "phishing"
    assert r.impersonated_brand in {"gov.gr", None} or any(
        "gov" in (r.impersonated_brand or "").lower() for _ in [0]
    )
    codes = {f.code for f in r.findings}
    assert "user_content_host" in codes


def test_javascript_scheme():
    r = analyze("javascript:alert(1)")
    assert r.verdict == "dangerous"
    assert any(f.code == "dangerous_scheme" for f in r.findings)


def test_empty():
    r = analyze("   ")
    assert r.verdict == "invalid"


def test_punycode_homograph():
    # xn--pple-43d.com is a classic IDN example (apple lookalike)
    r = analyze("https://xn--pple-43d.com/login")
    assert any(f.code == "homograph" for f in r.findings)


def test_parse_adds_scheme():
    p = parse_url("office.com")
    assert p.scheme == "https"
    assert p.host == "office.com"


def test_cli_json_exit(tmp_path):
    from phishguard.cli import main

    assert main(["https://www.microsoft.com"]) == 0
    assert main(["https://login.microsoft.com.phish.xyz/"]) == 1


def test_greek_bank():
    r = analyze("https://www.nbg.gr/")
    assert r.official_brand == "National Bank of Greece"
    r2 = analyze("https://nbg-login.xyz/account")
    assert r2.verdict in {"phishing", "suspicious"}
