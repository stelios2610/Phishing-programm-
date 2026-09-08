from unittest.mock import patch

from fastapi.testclient import TestClient

from phishguard.api import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_index():
    r = client.get("/")
    assert r.status_code == 200
    assert "PhishGuard" in r.text


@patch("phishguard.engine.fetch_html", return_value=(None, "timeout", None))
def test_analyze_api(_fetch):
    r = client.post("/api/analyze", json={"url": "https://login.microsoft.com.evil.xyz/"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "phishing"
    assert body["impersonated_brand"] == "Microsoft"
