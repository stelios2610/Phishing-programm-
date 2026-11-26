import sys
from pathlib import Path

from netwatch.collect import collect_linux
from netwatch.parse import (
    icmp_echo_source,
    normalize_mac,
    parse_proc_arp,
    parse_proc_route,
    parse_proc_snmp_icmp,
    parse_windows_report,
    proc_ipv4,
)

ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp0s3\t00000000\t01001EAC\t0003\t0\t0\t0\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""

ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
172.30.0.1       0x1         0x2         FA-58-8B-42-AC-27     *        enp0s3
192.168.1.5      0x1         0x0         00:00:00:00:00:00     *        enp0s3
10.0.0.9         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
255.255.255.255  0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
"""

WINDOWS = (
    "ICMP\x1f7\x1f2\n"
    "GW\x1f192.168.1.1\x1fWi-Fi\n"
    "NEI\x1f192.168.1.1\x1fAA-BB-CC-DD-EE-FF\x1fWi-Fi\x1fReachable\n"
    "NEI\x1f192.168.1.50\x1f\x1fWi-Fi\x1fIncomplete\n"
)


def test_proc_route_picks_lowest_metric_gateway():
    if sys.byteorder != "little":
        return
    assert proc_ipv4("01001EAC") == "172.30.0.1"
    assert parse_proc_route(ROUTE) == ("172.30.0.1", "enp0s3")


def test_proc_arp_skips_incomplete_and_broadcast():
    rows = parse_proc_arp(ARP)
    assert [(row.ip, row.mac, row.iface) for row in rows] == [
        ("172.30.0.1", "fa:58:8b:42:ac:27", "enp0s3"),
        ("10.0.0.9", "aa:bb:cc:dd:ee:ff", "eth0"),
    ]


def test_snmp_icmp_uses_names_not_column_guesses():
    header = (
        "InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds "
        "InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps"
    )
    text = f"Icmp: {header}\nIcmp: 1 0 0 0 0 0 0 4 9 0\nIcmpMsg: ignore me\n"
    assert parse_proc_snmp_icmp(text) == (9, 4)


def test_windows_report_is_independent_of_translated_headers():
    snap = parse_windows_report(WINDOWS)
    assert snap.gateway_ip == "192.168.1.1"
    assert snap.gateway_iface == "Wi-Fi"
    assert snap.in_echos == 7
    assert snap.in_redirects == 2
    assert len(snap.neighbors) == 1
    assert snap.neighbors[0].mac == "aa:bb:cc:dd:ee:ff"


def test_icmp_echo_source_ignores_replies():
    request = bytearray(28)
    request[0] = 0x45
    request[12:16] = bytes((203, 0, 113, 9))
    request[20] = 8
    assert icmp_echo_source(bytes(request)) == "203.0.113.9"
    request[20] = 0
    assert icmp_echo_source(bytes(request)) is None
    assert normalize_mac("00-00-00-00-00-00") == ""


def test_linux_collector_matches_proc_files():
    route = Path("/proc/net/route")
    if not route.exists():
        return
    snap = collect_linux()
    assert (snap.gateway_ip, snap.gateway_iface) == parse_proc_route(route.read_text(encoding="utf-8"))
    assert snap.in_echos is not None
