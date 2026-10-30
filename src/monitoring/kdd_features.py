"""
Live NSL-KDD feature extraction.

Turns captured packets into connection records with the same 41 features the
model was trained on:

* basic features      duration, protocol_type, service, flag, src/dst bytes, land, ...
* content features    a few cheap payload checks (failed logins, logged_in)
* traffic features    computed over the connections seen in the last 2 seconds
* host features       computed over the last 100 connections

The definitions follow the original KDD Cup 99 feature description. Content
features that need full protocol parsing (root shells, file creations, ...)
stay at 0.
"""

import threading
import time
from collections import deque

import numpy as np
import pandas as pd

try:  # scapy is only needed for live capture
    from scapy.layers.inet import ICMP, IP, TCP, UDP
except Exception:  # pragma: no cover
    IP = TCP = UDP = ICMP = None


FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERICAL_FEATURES = [c for c in FEATURE_NAMES if c not in CATEGORICAL_FEATURES]

# Destination port -> NSL-KDD service name (TCP unless noted).
TCP_SERVICES = {
    7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat", 20: "ftp_data",
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 42: "name", 43: "whois",
    53: "domain", 57: "mtp", 70: "gopher", 71: "remote_job", 77: "rje", 79: "finger",
    80: "http", 84: "ctf", 87: "link", 95: "supdup", 101: "hostnames", 102: "iso_tsap",
    105: "csnet_ns", 109: "pop_2", 110: "pop_3", 111: "sunrpc", 113: "auth", 117: "uucp_path",
    119: "nntp", 137: "netbios_ns", 138: "netbios_dgm", 139: "netbios_ssn", 143: "imap4",
    150: "sql_net", 175: "vmnet", 179: "bgp", 194: "IRC", 210: "Z39_50", 389: "ldap",
    433: "nnsp", 443: "http_443", 512: "exec", 513: "login", 514: "shell", 515: "printer",
    520: "efs", 530: "courier", 540: "uucp", 543: "klogin", 544: "kshell", 2784: "http_2784",
    5190: "aol", 6667: "IRC", 8001: "http_8001",
}
UDP_SERVICES = {53: "domain_u", 69: "tftp_u", 123: "ntp_u"}
ICMP_SERVICES = {0: "ecr_i", 3: "urp_i", 5: "red_i", 8: "eco_i", 13: "tim_i", 14: "tim_i"}

SERROR_FLAGS = {"S0", "S1", "S2", "S3"}
REJ_FLAGS = {"REJ"}
FAILED_LOGIN_MARKERS = (b"530 ", b"Login incorrect", b"Authentication failed", b"Permission denied")

PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}


def service_name(proto, dport, icmp_type=None):
    """Map a destination port (or ICMP type) to the NSL-KDD service vocabulary."""
    if proto == 1:
        return ICMP_SERVICES.get(icmp_type, "other")
    if proto == 17:
        return UDP_SERVICES.get(dport, "private" if dport < 49152 else "other")
    if 6000 <= dport <= 6063:
        return "X11"
    return TCP_SERVICES.get(dport, "private" if dport < 49152 else "other")


def connection_flag(conn):
    """Derive the KDD/Bro connection state from the TCP flags seen on both sides."""
    if conn["proto"] != 6:
        return "SF"
    o, r = conn["orig"], conn["resp"]
    if not o["syn"]:
        return "OTH"
    if not r["synack"]:
        if r["rst"]:
            return "REJ"
        if o["rst"]:
            return "RSTOS0"
        if o["fin"]:
            return "SH"
        return "S0"
    if o["rst"]:
        return "RSTO"
    if r["rst"]:
        return "RSTR"
    if o["fin"] and r["fin"]:
        return "SF"
    if o["fin"]:
        return "S2"
    if r["fin"]:
        return "S3"
    return "S1"


def _new_side():
    return {"syn": False, "synack": False, "fin": False, "rst": False, "bytes": 0, "packets": 0}


class ConnectionTracker:
    """Groups packets into bidirectional connections and emits KDD records."""

    def __init__(self, idle_timeout=2.0, closed_grace=0.5, host_window=100, time_window=2.0):
        self.idle_timeout = idle_timeout
        self.closed_grace = closed_grace
        self.time_window = time_window
        self.connections = {}
        self.history = deque(maxlen=5000)       # finished connections, for the 2-second features
        self.host_history = deque(maxlen=host_window)
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ capture
    def add_packet(self, packet, now=None):
        if IP is None or IP not in packet:
            return
        now = now or time.time()
        ip = packet[IP]
        proto = int(ip.proto)
        sport = dport = 0
        icmp_type = None
        payload = b""
        tcp_flags = ""
        if TCP in packet:
            sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            icmp_type = int(packet[ICMP].type)
            payload = bytes(packet[ICMP].payload)

        fwd = (ip.src, sport, ip.dst, dport, proto)
        rev = (ip.dst, dport, ip.src, sport, proto)
        with self.lock:
            if fwd in self.connections:
                conn, side = self.connections[fwd], "orig"
            elif rev in self.connections:
                conn, side = self.connections[rev], "resp"
            else:
                # A SYN-ACK without a SYN means we joined mid-handshake: the sender is the responder.
                if "S" in tcp_flags and "A" in tcp_flags:
                    key, side = rev, "resp"
                else:
                    key, side = fwd, "orig"
                conn = {
                    "key": key, "proto": proto, "start": now, "last": now, "closed_at": None,
                    "icmp_type": icmp_type, "orig": _new_side(), "resp": _new_side(),
                    "wrong_fragment": 0, "urgent": 0, "failed_logins": 0,
                }
                self.connections[key] = conn

            s = conn[side]
            conn["last"] = now
            s["packets"] += 1
            s["bytes"] += len(payload)
            if ip.frag or (int(ip.flags) & 0x1):
                conn["wrong_fragment"] += 1
            if tcp_flags:
                if "S" in tcp_flags:
                    if "A" in tcp_flags:
                        conn["resp"]["synack"] = True
                    else:
                        s["syn"] = True
                if "F" in tcp_flags:
                    s["fin"] = True
                if "R" in tcp_flags:
                    s["rst"] = True
                if "U" in tcp_flags:
                    conn["urgent"] += 1
                o, r = conn["orig"], conn["resp"]
                if conn["closed_at"] is None and (o["rst"] or r["rst"] or (o["fin"] and r["fin"])):
                    conn["closed_at"] = now
            if side == "resp" and payload and any(m in payload for m in FAILED_LOGIN_MARKERS):
                conn["failed_logins"] += 1

    # ------------------------------------------------------------------ records
    def expired(self, now=None):
        """Return (connection, features) for every connection that is finished or idle."""
        now = now or time.time()
        done = []
        with self.lock:
            for key, conn in list(self.connections.items()):
                closed = conn["closed_at"] is not None and now - conn["closed_at"] >= self.closed_grace
                idle = now - conn["last"] >= self.idle_timeout
                if closed or idle:
                    done.append(conn)
                    del self.connections[key]
        done.sort(key=lambda c: c["start"])
        return [(conn, self._features(conn)) for conn in done]

    def _features(self, conn):
        src_ip, sport, dst_ip, dport, proto = conn["key"]
        flag = connection_flag(conn)
        service = service_name(proto, dport, conn["icmp_type"])
        o, r = conn["orig"], conn["resp"]
        f = dict.fromkeys(NUMERICAL_FEATURES, 0.0)
        f.update({
            "duration": int(max(0.0, conn["last"] - conn["start"])),
            "protocol_type": PROTO_NAMES.get(proto, "tcp"),
            "service": service,
            "flag": flag,
            "src_bytes": o["bytes"],
            "dst_bytes": r["bytes"],
            "land": int(src_ip == dst_ip and sport == dport),
            "wrong_fragment": min(conn["wrong_fragment"], 3),
            "urgent": conn["urgent"],
            "num_failed_logins": min(conn["failed_logins"], 5),
            "logged_in": int(flag in ("SF", "S1") and o["bytes"] > 0 and r["bytes"] > 0 and proto == 6),
        })

        record = {"time": conn["last"], "dst": dst_ip, "service": service, "flag": flag, "sport": sport}

        # Traffic features: connections in the past 2 seconds.
        recent = [h for h in self.history if conn["last"] - h["time"] <= self.time_window] + [record]
        same_host = [h for h in recent if h["dst"] == dst_ip]
        same_srv = [h for h in recent if h["service"] == service]
        f["count"] = len(same_host)
        f["srv_count"] = len(same_srv)
        f["serror_rate"] = _rate(same_host, lambda h: h["flag"] in SERROR_FLAGS)
        f["rerror_rate"] = _rate(same_host, lambda h: h["flag"] in REJ_FLAGS)
        f["same_srv_rate"] = _rate(same_host, lambda h: h["service"] == service)
        f["diff_srv_rate"] = _rate(same_host, lambda h: h["service"] != service)
        f["srv_serror_rate"] = _rate(same_srv, lambda h: h["flag"] in SERROR_FLAGS)
        f["srv_rerror_rate"] = _rate(same_srv, lambda h: h["flag"] in REJ_FLAGS)
        f["srv_diff_host_rate"] = _rate(same_srv, lambda h: h["dst"] != dst_ip)

        # Host features: the last 100 connections.
        last100 = list(self.host_history) + [record]
        host = [h for h in last100 if h["dst"] == dst_ip]
        host_srv = [h for h in last100 if h["service"] == service]
        f["dst_host_count"] = len(host)
        f["dst_host_srv_count"] = len(host_srv)
        f["dst_host_same_srv_rate"] = _rate(host, lambda h: h["service"] == service)
        f["dst_host_diff_srv_rate"] = _rate(host, lambda h: h["service"] != service)
        f["dst_host_same_src_port_rate"] = _rate(host, lambda h: h["sport"] == sport)
        f["dst_host_srv_diff_host_rate"] = _rate(host_srv, lambda h: h["dst"] != dst_ip)
        f["dst_host_serror_rate"] = _rate(host, lambda h: h["flag"] in SERROR_FLAGS)
        f["dst_host_srv_serror_rate"] = _rate(host_srv, lambda h: h["flag"] in SERROR_FLAGS)
        f["dst_host_rerror_rate"] = _rate(host, lambda h: h["flag"] in REJ_FLAGS)
        f["dst_host_srv_rerror_rate"] = _rate(host_srv, lambda h: h["flag"] in REJ_FLAGS)

        self.history.append(record)
        self.host_history.append(record)
        return f


def _rate(items, predicate):
    if not items:
        return 0.0
    return round(sum(1 for i in items if predicate(i)) / len(items), 2)


class KDDEncoder:
    """Applies the saved label encoders and scaler to raw feature dicts."""

    FALLBACK = {"protocol_type": "tcp", "service": "other", "flag": "OTH"}

    def __init__(self, encoders, scaler):
        self.encoders = encoders
        self.scaler = scaler
        self.known = {col: set(enc.classes_) for col, enc in encoders.items()}

    def transform(self, rows):
        df = pd.DataFrame(rows, columns=FEATURE_NAMES)
        for col in CATEGORICAL_FEATURES:
            values = df[col].astype(str).where(df[col].astype(str).isin(self.known[col]), self.FALLBACK[col])
            df[col] = self.encoders[col].transform(values)
        df[NUMERICAL_FEATURES] = df[NUMERICAL_FEATURES].astype(np.float64).fillna(0.0)
        df[NUMERICAL_FEATURES] = self.scaler.transform(df[NUMERICAL_FEATURES])
        return df
