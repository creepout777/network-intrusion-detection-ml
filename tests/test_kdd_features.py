"""Live NSL-KDD feature extraction (no capture privileges needed)."""

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from monitoring.kdd_features import FEATURE_NAMES, ConnectionTracker, service_name

CLIENT, SERVER = "10.0.0.5", "10.0.0.80"


def handshake(tracker, t, sport, dport, payload=b"GET / HTTP/1.1\r\n\r\n", reply=b"HTTP/1.1 200 OK\r\n\r\nhello",
              client=CLIENT, server=SERVER):
    c2s = IP(src=client, dst=server)
    s2c = IP(src=server, dst=client)
    tracker.add_packet(c2s / TCP(sport=sport, dport=dport, flags="S"), now=t)
    tracker.add_packet(s2c / TCP(sport=dport, dport=sport, flags="SA"), now=t + 0.01)
    tracker.add_packet(c2s / TCP(sport=sport, dport=dport, flags="A"), now=t + 0.02)
    tracker.add_packet(c2s / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload), now=t + 0.03)
    tracker.add_packet(s2c / TCP(sport=dport, dport=sport, flags="PA") / Raw(reply), now=t + 0.04)
    tracker.add_packet(c2s / TCP(sport=sport, dport=dport, flags="FA"), now=t + 0.05)
    tracker.add_packet(s2c / TCP(sport=dport, dport=sport, flags="FA"), now=t + 0.06)


def test_normal_http_connection():
    tracker = ConnectionTracker()
    handshake(tracker, 100.0, 50000, 80)
    [(_, f)] = tracker.expired(now=101.0)
    assert set(FEATURE_NAMES) <= set(f)
    assert (f["protocol_type"], f["service"], f["flag"]) == ("tcp", "http", "SF")
    assert f["src_bytes"] == 18 and f["dst_bytes"] == 24
    assert f["logged_in"] == 1 and f["count"] == 1


def test_rejected_port_scan_raises_rerror_rate():
    tracker = ConnectionTracker()
    for i, port in enumerate(range(1, 41)):
        t = 200.0 + i * 0.01
        tracker.add_packet(IP(src=CLIENT, dst=SERVER) / TCP(sport=60000, dport=port, flags="S"), now=t)
        tracker.add_packet(IP(src=SERVER, dst=CLIENT) / TCP(sport=port, dport=60000, flags="RA"), now=t + 0.001)
    records = [f for _, f in tracker.expired(now=210.0)]
    last = records[-1]
    assert {r["flag"] for r in records} == {"REJ"}
    assert last["count"] == 40 and last["rerror_rate"] == 1.0
    assert 0 < last["diff_srv_rate"] < 1 and last["dst_host_same_src_port_rate"] == 1.0


def test_unanswered_syn_flood_is_s0():
    tracker = ConnectionTracker()
    for i in range(50):
        tracker.add_packet(IP(src=CLIENT, dst=SERVER) / TCP(sport=1000 + i, dport=80, flags="S"), now=300.0 + i * 0.01)
    records = [f for _, f in tracker.expired(now=305.0)]
    assert {r["flag"] for r in records} == {"S0"}
    assert records[-1]["serror_rate"] == 1.0 and records[-1]["srv_count"] == 50


def test_failed_ftp_login_is_counted():
    tracker = ConnectionTracker()
    handshake(tracker, 400.0, 50001, 21, payload=b"PASS hunter2\r\n", reply=b"530 Login incorrect.\r\n")
    [(_, f)] = tracker.expired(now=401.0)
    assert f["service"] == "ftp" and f["num_failed_logins"] == 1


def test_icmp_and_service_names():
    tracker = ConnectionTracker()
    tracker.add_packet(IP(src=CLIENT, dst=SERVER) / ICMP(type=8), now=500.0)
    [(_, f)] = tracker.expired(now=503.0)
    assert (f["protocol_type"], f["service"], f["flag"]) == ("icmp", "eco_i", "SF")
    assert service_name(6, 443) == "http_443"
    assert service_name(17, 53) == "domain_u"
    assert service_name(6, 31337) == "private"
    assert service_name(6, 6001) == "X11"
