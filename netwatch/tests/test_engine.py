from datetime import datetime, timedelta, timezone

from netwatch.engine import Engine
from netwatch.model import Neighbor, Snapshot

GW = "192.168.1.1"
REAL = "02:11:22:33:44:55"
FAKE = "02:de:ad:be:ef:01"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 26, 8, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def snap(
    mac: str = REAL,
    echos: int = 0,
    redirects: int = 0,
    extra: tuple[Neighbor, ...] = (),
    sources: tuple[str, ...] = (),
    gateway: str = GW,
    simulated: bool = False,
) -> Snapshot:
    neighbors = (Neighbor(gateway, mac, "eth0", "reachable"),) + extra
    return Snapshot(neighbors, gateway, "eth0", echos, redirects, sources, simulated)


def test_historical_pings_are_not_alerts():
    engine = Engine(prompt_confirm=False)
    assert engine.observe(snap(echos=10, redirects=4)) == []
    assert engine.session_pings == 0
    alerts = engine.observe(snap(echos=12))
    assert [item.code for item in alerts] == ["ping"]
    assert alerts[0].count == 2
    assert "administrator" in alerts[0].detail
    assert engine.session_pings == 2


def test_ping_names_sources_and_coalesces():
    clock = Clock()
    engine = Engine(clock=clock, prompt_confirm=False)
    engine.observe(snap())
    engine.observe(snap(echos=1, sources=("192.0.2.10",)))
    clock.advance(5)
    engine.observe(snap(echos=2, sources=("192.0.2.11",)))
    alerts = [item for item in engine.alerts() if item.code == "ping"]
    assert len(alerts) == 1
    assert alerts[0].count == 2
    assert "192.0.2.10" in alerts[0].detail
    assert "192.0.2.11" in alerts[0].detail
    clock.advance(25)
    engine.observe(snap(echos=3, sources=("192.0.2.12",)))
    assert len([item for item in engine.alerts() if item.code == "ping"]) == 2


def test_counter_reset_does_not_alert():
    engine = Engine(prompt_confirm=False)
    engine.observe(snap(echos=5))
    assert engine.observe(snap(echos=1)) == []
    assert engine.session_pings == 0


def test_redirect_is_critical_and_coalesced():
    clock = Clock()
    engine = Engine(clock=clock, prompt_confirm=False)
    engine.observe(snap())
    first = engine.observe(snap(redirects=1))
    assert first[0].code == "icmp_redirect"
    assert first[0].severity == "critical"
    clock.advance(10)
    engine.observe(snap(redirects=2))
    alerts = [item for item in engine.alerts() if item.code == "icmp_redirect"]
    assert len(alerts) == 1
    assert alerts[0].count == 2


def test_confirmed_gateway_mac_change_is_critical_once():
    engine = Engine(prompt_confirm=False)
    engine.observe(snap())
    engine.confirm(GW, REAL, "eth0")
    alerts = engine.observe(snap(FAKE))
    assert [item.code for item in alerts] == ["gateway_mac_changed"]
    assert alerts[0].severity == "critical"
    assert engine.has_open("gateway_mac_changed")
    assert engine.observe(snap(FAKE)) == []
    restored = engine.observe(snap(REAL))
    assert restored[0].code == "gateway_restored"
    assert not engine.has_open("gateway_mac_changed")


def test_unconfirmed_gateway_change_is_only_a_warning():
    engine = Engine(prompt_confirm=False)
    engine.observe(snap())
    alerts = engine.observe(snap(FAKE))
    assert alerts[0].severity == "warning"
    assert alerts[0].code == "gateway_mac_changed"
    assert not engine.has_open("gateway_mac_changed")


def test_saved_mismatch_alerts_on_first_reading():
    engine = Engine(prompt_confirm=False)
    engine.confirm(GW, REAL, "eth0")
    alerts = engine.observe(snap(FAKE))
    assert alerts[0].severity == "critical"


def test_clone_and_neighbor_change_and_storm():
    engine = Engine(prompt_confirm=False)
    laptop = Neighbor("192.168.1.20", "02:11:22:33:44:20", "eth0", "reachable")
    engine.observe(snap(extra=(laptop,)))
    engine.confirm(GW, REAL, "eth0")
    cloned = engine.observe(
        snap(
            extra=(
                laptop,
                Neighbor("192.168.1.77", REAL, "eth0", "reachable"),
            )
        )
    )
    assert cloned[0].code == "gateway_mac_cloned"
    changed = engine.observe(
        snap(
            extra=(
                Neighbor("192.168.1.20", "02:11:22:33:44:99", "eth0", "reachable"),
                Neighbor("192.168.1.77", REAL, "eth0", "reachable"),
            )
        )
    )
    assert [item.code for item in changed] == ["neighbor_mac_changed"]
    assert (
        engine.observe(
            snap(
                extra=(
                    Neighbor("192.168.1.20", "02:11:22:33:44:99", "eth0", "reachable"),
                    Neighbor("192.168.1.77", REAL, "eth0", "reachable"),
                )
            )
        )
        == []
    )

    hosts = tuple(
        Neighbor(f"192.168.1.{index}", "02:11:22:33:44:10", "eth0", "reachable")
        for index in (21, 22, 23)
    )
    engine.observe(snap(extra=hosts))
    moved = tuple(
        Neighbor(f"192.168.1.{index}", "02:11:22:33:44:90", "eth0", "reachable")
        for index in (21, 22, 23)
    )
    storm = engine.observe(snap(extra=moved))
    assert [item.code for item in storm] == ["arp_storm"]


def test_same_snapshot_two_macs_conflict():
    engine = Engine(prompt_confirm=False)
    both = Snapshot(
        (
            Neighbor("192.168.1.40", REAL, "eth0", "reachable"),
            Neighbor("192.168.1.40", FAKE, "eth0", "reachable"),
        ),
        GW,
        "eth0",
        0,
        0,
    )
    alerts = engine.observe(both)
    assert alerts[0].code == "arp_conflict"
    assert alerts[0].severity == "critical"


def test_gateway_ip_change_is_not_called_mitm():
    engine = Engine(prompt_confirm=False)
    engine.observe(snap())
    engine.confirm(GW, REAL, "eth0")
    alerts = engine.observe(snap(gateway="10.0.0.1"))
    assert alerts[0].code == "gateway_ip_changed"
    assert alerts[0].severity == "warning"


def test_prompt_asks_once_and_simulation_flag_sticks():
    engine = Engine()
    first = engine.observe(snap(simulated=True))
    assert first[0].code == "confirm_gateway"
    assert first[0].simulated is True
    assert engine.observe(snap(simulated=True)) == []
