"""
Feed crafted packet streams through the live detector and count alerts.
No capture privileges needed. Run from the repository root:

    python scripts/simulate_traffic.py
"""

import os
import random
import sys

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from monitoring.packet_sniffer import RealtimeIDS  # noqa: E402
from test_kdd_features import handshake  # noqa: E402

THRESHOLD = 0.8


def report(ids, label, records):
    scores = [ids.score(f) for _, f in records]
    flagged = sum(1 for pred, conf in scores if pred == 1 and conf >= THRESHOLD)
    mean = sum(conf for _, conf in scores) / max(1, len(scores))
    print(f"{label:30} {len(scores):4} connections   flagged {flagged:4}   mean p(attack) = {mean:.2f}")


def main():
    random.seed(1)
    ids = RealtimeIDS(alert_threshold=THRESHOLD)
    tr = ids.tracker
    t = 1000.0

    # Normal browsing: full HTTP/HTTPS sessions to a handful of servers
    for i in range(60):
        server = f"93.184.216.{i % 6}"
        sport, dport = 50000 + i, random.choice([80, 443, 443])
        c2s, s2c = IP(src="10.0.0.5", dst=server), IP(src=server, dst="10.0.0.5")
        tr.add_packet(c2s / TCP(sport=sport, dport=dport, flags="S"), now=t)
        tr.add_packet(s2c / TCP(sport=dport, dport=sport, flags="SA"), now=t + .01)
        tr.add_packet(c2s / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"x" * 300), now=t + .02)
        tr.add_packet(s2c / TCP(sport=dport, dport=sport, flags="PA") / Raw(b"y" * 4000), now=t + .05)
        tr.add_packet(c2s / TCP(sport=sport, dport=dport, flags="FA"), now=t + .06)
        tr.add_packet(s2c / TCP(sport=dport, dport=sport, flags="FA"), now=t + .07)
        t += 0.7
    report(ids, "Normal web browsing", tr.expired(now=t + 5))

    # Normal DNS lookups
    t += 10
    for i in range(30):
        c2s, s2c = IP(src="10.0.0.5", dst="1.1.1.1"), IP(src="1.1.1.1", dst="10.0.0.5")
        tr.add_packet(c2s / UDP(sport=40000 + i, dport=53) / Raw(b"q" * 40), now=t)
        tr.add_packet(s2c / UDP(sport=53, dport=40000 + i) / Raw(b"a" * 90), now=t + .02)
        t += 0.5
    report(ids, "Normal DNS", tr.expired(now=t + 5))

    # SYN port scan answered with RSTs (closed ports)
    t += 10
    for port in range(1, 300):
        tr.add_packet(IP(src="10.6.6.6", dst="10.0.0.80") / TCP(sport=61000, dport=port, flags="S"), now=t)
        tr.add_packet(IP(src="10.0.0.80", dst="10.6.6.6") / TCP(sport=port, dport=61000, flags="RA"), now=t + .001)
        t += 0.005
    report(ids, "SYN port scan (RST replies)", tr.expired(now=t + 5))

    # SYN flood from spoofed sources, never answered
    t += 10
    for i in range(400):
        tr.add_packet(IP(src=f"10.9.{i % 200}.{i % 250}", dst="10.0.0.80") / TCP(sport=1024 + i, dport=80, flags="S"), now=t)
        t += 0.002
    report(ids, "SYN flood (no replies)", tr.expired(now=t + 5))

    # FTP password guessing
    t += 10
    for i in range(20):
        handshake(tr, t, 52000 + i, 21, payload=b"PASS x\r\n", reply=b"530 Login incorrect.\r\n")
        t += 0.2
    report(ids, "FTP password guessing", tr.expired(now=t + 5))


if __name__ == "__main__":
    main()
