import json

import pytest
from fastapi.testclient import TestClient

from netwatch.api import app
from netwatch.cli import main
from netwatch.monitor import Monitor
from netwatch.protect import ProtectResult


@pytest.fixture
def client(tmp_path, monkeypatch):
    path = tmp_path / "trusted.json"
    monkeypatch.setenv("NETWATCH_STATE_PATH", str(path))
    monkeypatch.setenv("NETWATCH_DISABLE_POLL", "1")
    with TestClient(app) as test_client:
        test_client.app.state.monitor.stop()
        test_client.app.state.monitor = Monitor(state_path=path, poll=False)
        yield test_client
        test_client.app.state.monitor.stop()


def test_health_and_index(client):
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["service"] == "netwatch"
    page = client.get("/")
    assert page.status_code == 200
    assert "NetWatch" in page.text
    assert 'id="demo-mitm"' in page.text
    assert "PhishGuard" not in page.text


def test_demo_ping_and_mitm_are_marked_simulated(client, tmp_path):
    ping = client.post("/api/demo/ping")
    assert ping.status_code == 200
    body = ping.json()
    assert body["state"]["view"] == "demo"
    assert body["state"]["alerts"][0]["code"] == "ping"
    assert body["state"]["alerts"][0]["simulated"] is True
    assert "192.168.1.50" in body["state"]["alerts"][0]["detail"]

    attack = client.post("/api/demo/mitm")
    assert attack.status_code == 200
    state = attack.json()["state"]
    codes = [item["code"] for item in state["alerts"]]
    assert "gateway_mac_changed" in codes
    critical = next(item for item in state["alerts"] if item["code"] == "gateway_mac_changed")
    assert critical["severity"] == "critical"
    assert critical["simulated"] is True
    assert state["gateway"]["mismatch"] is True
    assert state["gateway"]["trusted"]["mac"] == "02:11:22:33:44:55"
    assert state["gateway"]["mac"] == "02:de:ad:be:ef:01"
    assert not (tmp_path / "trusted.json").exists()


def test_demo_protect_does_not_touch_the_os(client, monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("simulation must not change ARP")

    monkeypatch.setattr("netwatch.monitor.apply_permanent_neighbor", boom)
    client.post("/api/demo/mitm")
    response = client.post("/api/protect")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["result"]["reason"] == "demo"


def test_accepting_simulated_change_does_not_persist(client, tmp_path):
    client.post("/api/demo/mitm")
    refused = client.post("/api/gateway/confirm", json={})
    assert refused.status_code == 409
    assert refused.json()["error"] == "mismatch"
    accepted = client.post("/api/gateway/confirm", json={"accept_change": True})
    assert accepted.status_code == 200
    assert accepted.json()["state"]["gateway"]["mismatch"] is False
    assert accepted.json()["state"]["gateway"]["trusted"]["mac"] == "02:de:ad:be:ef:01"
    assert not (tmp_path / "trusted.json").exists()
    reset = client.post("/api/demo/reset")
    assert reset.json()["state"]["view"] == "live"


def test_live_confirm_and_protect_use_the_real_gateway(client, tmp_path, monkeypatch):
    client.app.state.monitor.tick()
    state = client.get("/api/state").json()
    if not state["gateway"]["mac"]:
        pytest.skip("this machine has no gateway MAC")
    confirmed = client.post("/api/gateway/confirm", json={})
    assert confirmed.status_code == 200
    trusted = confirmed.json()["state"]["gateway"]["trusted"]
    assert trusted["ip"] == state["gateway"]["ip"]
    assert trusted["mac"] == state["gateway"]["mac"]
    assert "confirm_gateway" not in [item["code"] for item in confirmed.json()["state"]["alerts"]]
    saved = json.loads((tmp_path / "trusted.json").read_text(encoding="utf-8"))
    assert saved["gateway_mac"] == state["gateway"]["mac"]

    seen = {}

    def fake(ip, mac, iface):
        seen["args"] = (ip, mac, iface)
        return ProtectResult(True, "applied", "done", "ip neigh replace")

    monkeypatch.setattr("netwatch.monitor.apply_permanent_neighbor", fake)

    def fake_delete(ip, mac, iface):
        seen["deleted"] = (ip, mac, iface)
        return ProtectResult(True, "cleared", "cleared", "ip neigh del")

    monkeypatch.setattr("netwatch.monitor.delete_permanent_neighbor", fake_delete)
    protected = client.post("/api/protect")
    assert protected.status_code == 200
    assert protected.json()["ok"] is True
    assert seen["args"][0] == state["gateway"]["ip"]
    assert seen["args"][1] == state["gateway"]["mac"]
    forgotten = client.post("/api/gateway/forget")
    assert seen["deleted"][0] == state["gateway"]["ip"]
    assert forgotten.json()["state"]["gateway"]["trusted"] is None
    assert not (tmp_path / "trusted.json").exists()


def test_protect_before_confirm_does_nothing(client, monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("unconfirmed protect must not run")

    monkeypatch.setattr("netwatch.monitor.apply_permanent_neighbor", boom)
    client.app.state.monitor.tick()
    state = client.get("/api/state").json()
    response = client.post("/api/protect")
    assert response.status_code == 200
    assert response.json()["ok"] is False
    expected = "unconfirmed" if state["gateway"]["ip"] else "no_gateway"
    assert response.json()["result"]["reason"] == expected


def test_redirect_demo(client):
    response = client.post("/api/demo/redirect")
    alerts = response.json()["state"]["alerts"]
    assert alerts[0]["code"] == "icmp_redirect"
    assert alerts[0]["simulated"] is True


def test_cli_demo_sends_nothing_and_remote_bind_is_refused(capsys):
    assert main(["--demo"]) == 0
    text = capsys.readouterr().out
    assert "gateway_mac_changed" in text
    assert "ping" in text
    assert main(["--serve", "--host", "0.0.0.0", "--port", "9"]) == 2


def test_cli_once_prints_json(capsys):
    assert main(["--once"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "gateway_ip" in payload
    assert "neighbors" in payload
