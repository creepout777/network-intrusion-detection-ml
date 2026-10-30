"""
Real-Time Packet Monitoring Module

This module captures live network traffic, extracts NSL-KDD features,
and applies the trained ML model for real-time attack detection.
"""

import scapy.all as scapy
import joblib
import threading
import logging
import structlog
from datetime import datetime, timedelta
from collections import deque, defaultdict
import time
import os
import sys
import platform
import socket
import argparse
import ipaddress

SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)
from common.config_utils import cfg_get, load_runtime_config
from monitoring.kdd_features import ConnectionTracker, KDDEncoder  # noqa: E402

os.makedirs('logs', exist_ok=True)

# Enterprise-grade logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s","module":"%(module)s","line":"%(lineno)d"}',
    handlers=[
        logging.FileHandler('logs/ids_alerts.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Structlog for structured logging with correlation IDs
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="%Y-%m-%dT%H:%M:%S", utc=False),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True
)
struct_logger = structlog.get_logger()
DEFAULT_CONFIG_PATH = os.path.join("config", "ids_config.json")


class RealtimeIDS:
    """Real-time Intrusion Detection System."""
    
    def __init__(self, model_path='models/svm_model.pkl', 
                 scaler_path='data/processed/scaler.pkl',
                 encoders_path='data/processed/label_encoders.pkl',
                 alert_threshold=0.8,
                 loopback_window_seconds=5,
                 loopback_min_distinct_ports_for_scan=15):
        """
        Initialize IDS system.
        
        Args:
            model_path: Path to trained ML model
            scaler_path: Path to feature scaler
            encoders_path: Path to categorical encoders
            alert_threshold: Confidence threshold for alerts (critical-only default: 0.8)
        """
        logger.info("Loading trained model from %s", model_path)
        self._ensure_artifact_exists(model_path, "model")
        self._ensure_artifact_exists(scaler_path, "scaler")
        self._ensure_artifact_exists(encoders_path, "label encoders")
        try:
            self.model = joblib.load(model_path)
        except (joblib.exceptions.PicklingError, EOFError) as e:
            logger.error("Model file corrupted at %s: %s", model_path, e)
            raise RuntimeError(f"Corrupted model file: {model_path}") from e
        self.scaler = joblib.load(scaler_path)
        self.encoders = joblib.load(encoders_path)
        self.alert_threshold = alert_threshold
        self.suppressed_loopback_ports = set()
        self.loopback_port_activity = defaultdict(deque)
        self.loopback_window_seconds = int(loopback_window_seconds)
        self.loopback_min_distinct_ports_for_scan = int(loopback_min_distinct_ports_for_scan)
        self.attack_group_merge_window_seconds = 120
        self.local_ips = self._get_local_ips()
        self._state_lock = threading.RLock()
        
        self.tracker = ConnectionTracker()
        self.feature_encoder = KDDEncoder(self.encoders, self.scaler)
        self.alerts = deque(maxlen=1000)  # Keep last 1000 alerts
        self.stats = {
            'packets_processed': 0,
            'packet_processing_errors': 0,
            'flows_analyzed': 0,
            'flow_analysis_errors': 0,
            'attacks_detected': 0,
            'start_time': datetime.now()
        }
        
        print("[OK] IDS System initialized")

    @staticmethod
    def _ensure_artifact_exists(path, label):
        """Fail fast with actionable messages for missing runtime artifacts."""
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Missing {label} artifact: '{path}'. "
                "Provide the required runtime artifact file or pass explicit runtime paths."
            )
    
    def process_packet(self, packet):
        """Process individual packet."""
        try:
            self.tracker.add_packet(packet)
            with self._state_lock:
                self.stats['packets_processed'] += 1
        except Exception:
            with self._state_lock:
                self.stats['packet_processing_errors'] += 1
                packet_processing_errors = self.stats['packet_processing_errors']
            if packet_processing_errors % 50 == 0:
                logger.warning(
                    "Packet processing errors: %s",
                    packet_processing_errors
                )
    
    def analyze_flows(self):
        """Score every finished connection and raise alerts for confident detections."""
        for conn, features in self.tracker.expired():
            flow_key = conn["key"]
            try:
                with self._state_lock:
                    self.stats['flows_analyzed'] += 1
                    flows_analyzed = self.stats['flows_analyzed']

                # Suppress known benign localhost dashboard traffic to reduce false positives.
                if self._is_suppressed_benign_flow(flow_key):
                    continue

                # On localhost traffic, only consider scan-like behavior as suspicious.
                if self._is_loopback_flow(flow_key) and not self._is_scan_like_loopback_flow(flow_key):
                    continue

                prediction, confidence = self.score(features)

                if flows_analyzed % 50 == 0:
                    logger.info(
                        "Flow analyzed: %s %s flag=%s pred=%s conf=%.3f",
                        features['protocol_type'], features['service'], features['flag'], prediction, confidence,
                    )

                # Create alert only for critical-confidence detections.
                if prediction == 1 and confidence >= self.alert_threshold:
                    new_alert = {
                        'timestamp': datetime.now(),
                        'src_ip': flow_key[0],
                        'src_port': flow_key[1],
                        'dst_ip': flow_key[2],
                        'dst_port': flow_key[3],
                        'protocol': flow_key[4],
                        'confidence': float(confidence),
                        'packets': conn['orig']['packets'] + conn['resp']['packets'],
                        'bytes': conn['orig']['bytes'] + conn['resp']['bytes'],
                        'service': features['service'],
                        'flag': features['flag'],
                    }
                    event = self._build_event(new_alert)
                    attacker_ip = self._resolve_attacker_ip(new_alert['src_ip'], new_alert['dst_ip'])
                    target_ip = self._resolve_target_ip(
                        new_alert['src_ip'],
                        new_alert['dst_ip'],
                        attacker_ip,
                    )

                    with self._state_lock:
                        existing_alert = self._find_existing_attack_group(
                            attacker_ip=attacker_ip,
                            target_ip=target_ip,
                            event_time=new_alert['timestamp'],
                        )

                        if existing_alert is not None:
                            existing_alert.setdefault('events', [])
                            existing_alert.setdefault('target_ips', [existing_alert.get('dst_ip')])
                            existing_target_port = existing_alert.get('dst_port', 0)
                            try:
                                existing_target_port_int = int(existing_target_port)
                            except (TypeError, ValueError):
                                existing_target_port_int = 0
                            existing_alert.setdefault('target_ports', [existing_target_port_int])
                            existing_alert.setdefault('event_count', 1)
                            existing_alert.setdefault('first_seen', existing_alert.get('timestamp'))

                            # Merge repeated events for a bounded attacker-target pair.
                            existing_alert['timestamp'] = new_alert['timestamp']
                            existing_alert['last_seen'] = new_alert['timestamp']
                            existing_alert['confidence'] = max(existing_alert['confidence'], new_alert['confidence'])
                            existing_alert['packets'] += new_alert['packets']
                            existing_alert['bytes'] += new_alert['bytes']
                            existing_alert['src_port'] = new_alert['src_port']
                            existing_alert['dst_port'] = new_alert['dst_port']
                            existing_alert['protocol'] = new_alert['protocol']
                            existing_alert['event_count'] = existing_alert.get('event_count', 1) + 1
                            existing_alert['events'].append(event)
                            existing_alert['attacker_ip'] = attacker_ip

                            if target_ip and target_ip not in existing_alert['target_ips']:
                                existing_alert['target_ips'].append(target_ip)
                            if int(new_alert['dst_port']) not in existing_alert['target_ports']:
                                existing_alert['target_ports'].append(int(new_alert['dst_port']))
                        else:
                            new_alert['events'] = [event]
                            new_alert['event_count'] = 1
                            new_alert['attacker_ip'] = attacker_ip
                            new_alert['target_ips'] = [target_ip] if target_ip else [new_alert['dst_ip']]
                            new_alert['target_ports'] = [int(new_alert['dst_port'])]
                            new_alert['first_seen'] = new_alert['timestamp']
                            new_alert['last_seen'] = new_alert['timestamp']
                            self.alerts.append(new_alert)
                            self.stats['attacks_detected'] += 1

                    logger.warning(f"ATTACK DETECTED: {new_alert['src_ip']}:{new_alert['src_port']} "
                                 f"-> {new_alert['dst_ip']}:{new_alert['dst_port']} "
                                 f"{features['service']}/{features['flag']} (Confidence: {confidence:.2%})")
            
            except Exception as e:
                with self._state_lock:
                    self.stats['flow_analysis_errors'] += 1
                logger.error(f"Error analyzing flow: {e}")

    def score(self, features):
        """Return (prediction, attack probability) for one NSL-KDD feature dict."""
        X = self.feature_encoder.transform([features])
        prediction = int(self.model.predict(X)[0])
        confidence = float(self.model.predict_proba(X)[0, 1])
        return prediction, confidence

    def set_dashboard_port(self, port):
        """Mark dashboard port as benign on localhost loopback traffic."""
        try:
            self.suppressed_loopback_ports.add(int(port))
        except Exception:
            return

    def _is_suppressed_benign_flow(self, flow_key):
        """
        Suppress loopback dashboard traffic that would otherwise trigger false alerts.
        Keeps localhost port-scan detection on other ports intact.
        """
        src_ip, src_port, dst_ip, dst_port, _protocol = flow_key

        if not self.suppressed_loopback_ports:
            return False

        is_loopback = src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1")
        if not is_loopback:
            return False

        return int(src_port) in self.suppressed_loopback_ports or int(dst_port) in self.suppressed_loopback_ports

    @staticmethod
    def _is_loopback_flow(flow_key):
        src_ip, _src_port, dst_ip, _dst_port, _protocol = flow_key
        return src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1")

    def _is_scan_like_loopback_flow(self, flow_key):
        """
        Treat localhost traffic as malicious only when it resembles a port scan:
        many distinct destination ports in a short window from the same source.
        """
        src_ip, _src_port, _dst_ip, dst_port, _protocol = flow_key
        now = time.time()
        key = src_ip
        history = self.loopback_port_activity[key]

        history.append((now, int(dst_port)))
        cutoff = now - self.loopback_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct_ports = {port for _ts, port in history}
        return len(distinct_ports) >= self.loopback_min_distinct_ports_for_scan

    def _find_existing_attack_group(self, attacker_ip, target_ip, event_time):
        """
        Find an existing attack group using a bounded attacker-target key.
        Merge only when attacker and target match and the prior activity is recent.
        """
        if not attacker_ip or not target_ip:
            return None

        cutoff = event_time - timedelta(seconds=max(1, int(self.attack_group_merge_window_seconds)))
        for alert in reversed(self.alerts):
            alert_attacker = alert.get('attacker_ip') or self._resolve_attacker_ip(
                alert.get('src_ip'),
                alert.get('dst_ip'),
            )
            if alert_attacker != attacker_ip:
                continue

            raw_targets = alert.get('target_ips')
            if isinstance(raw_targets, list):
                alert_targets = {str(ip) for ip in raw_targets if ip}
            else:
                fallback_target = alert.get('dst_ip')
                alert_targets = {str(fallback_target)} if fallback_target else set()
            if target_ip not in alert_targets:
                continue

            last_seen = alert.get('last_seen', alert.get('timestamp'))
            if isinstance(last_seen, datetime) and last_seen < cutoff:
                continue
            return alert
        return None

    @staticmethod
    def _build_event(alert):
        """Build a compact event record for drill-down in dashboard."""
        return {
            'timestamp': alert['timestamp'],
            'src_ip': alert['src_ip'],
            'src_port': int(alert['src_port']),
            'dst_ip': alert['dst_ip'],
            'dst_port': int(alert['dst_port']),
            'protocol': int(alert['protocol']),
            'confidence': float(alert['confidence']),
            'packets': int(alert['packets']),
            'bytes': int(alert['bytes'])
        }

    @staticmethod
    def _normalize_ip(value):
        """Normalize IPv4/IPv6 strings so comparisons are stable."""
        text = str(value).strip()
        if not text:
            return ""
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text

    def _collect_scapy_interface_ips(self, interface_names=None):
        """Collect IP addresses bound to scapy-visible interfaces."""
        ips = set()
        names = interface_names
        if not names:
            try:
                names = scapy.get_if_list()
            except Exception:
                names = []
        for iface in names:
            iface_name = str(iface)
            try:
                addr_v4 = self._normalize_ip(scapy.get_if_addr(iface_name))
                if addr_v4 and addr_v4 not in {"0.0.0.0", "0"}:
                    ips.add(addr_v4)
            except Exception:
                pass
            try:
                get_if_addr6 = getattr(scapy, "get_if_addr6", None)
                if callable(get_if_addr6):
                    addr_v6 = self._normalize_ip(get_if_addr6(iface_name))
                    if addr_v6 and addr_v6 not in {"::", "::0"}:
                        ips.add(addr_v6)
            except Exception:
                pass
        return ips

    def _get_local_ips(self, interface_names=None):
        """Collect local machine IPs to avoid marking them as attackers."""
        ips = {"127.0.0.1", "::1", "0.0.0.0"}
        try:
            hostname = socket.gethostname()
            for entry in socket.getaddrinfo(hostname, None):
                addr = self._normalize_ip(entry[4][0])
                if addr:
                    ips.add(addr)
        except Exception:
            pass

        try:
            for entry in socket.getaddrinfo(socket.getfqdn(), None):
                addr = self._normalize_ip(entry[4][0])
                if addr:
                    ips.add(addr)
        except Exception:
            pass

        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.connect(("8.8.8.8", 53))
            addr = self._normalize_ip(udp.getsockname()[0])
            if addr:
                ips.add(addr)
            udp.close()
        except Exception:
            pass

        ips.update(self._collect_scapy_interface_ips(interface_names=interface_names))
        return {self._normalize_ip(ip) for ip in ips if self._normalize_ip(ip)}

    def _resolve_attacker_ip(self, src_ip, dst_ip):
        """
        Resolve attacker-centric IP for display.
        Preference:
        1) non-local endpoint (your IP is never attacker)
        2) source IP as fallback
        """
        normalized_src = self._normalize_ip(src_ip)
        normalized_dst = self._normalize_ip(dst_ip)
        src_is_local = normalized_src in self.local_ips
        dst_is_local = normalized_dst in self.local_ips

        if src_is_local and not dst_is_local:
            return dst_ip
        if dst_is_local and not src_is_local:
            return src_ip
        if not src_is_local and not dst_is_local:
            try:
                src_obj = ipaddress.ip_address(normalized_src)
                dst_obj = ipaddress.ip_address(normalized_dst)
                src_is_private = bool(getattr(src_obj, "is_private", False))
                dst_is_private = bool(getattr(dst_obj, "is_private", False))
                if src_is_private and not dst_is_private:
                    return dst_ip
                if dst_is_private and not src_is_private:
                    return src_ip
            except ValueError:
                pass
        return src_ip

    @staticmethod
    def _resolve_target_ip(src_ip, dst_ip, attacker_ip):
        if attacker_ip == src_ip:
            return dst_ip
        if attacker_ip == dst_ip:
            return src_ip
        return dst_ip
    
    def start_monitoring(self, interface=None, packet_count=0):
        """
        Start real-time packet monitoring.
        
        Args:
            interface: Network interface to monitor (default: auto-detect)
            packet_count: Number of packets to capture (0=infinite)
        """
        print(f"\n{'='*60}")
        print("Starting Real-Time IDS Monitoring...")
        print(f"{'='*60}")
        
        interfaces = self._resolve_interfaces(interface)
        self.local_ips = self._get_local_ips(interface_names=interfaces)
        print(f"Monitoring interface(s): {', '.join(interfaces)}")
        print(f"Alert threshold: {self.alert_threshold:.2f}")
        print(
            "Loopback scan heuristic: "
            f"{self.loopback_min_distinct_ports_for_scan}+ distinct ports in "
            f"{self.loopback_window_seconds}s"
        )
        logger.info(f"Started monitoring on interface(s): {interfaces}")
        
        try:
            # Start analysis thread
            analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
            analysis_thread.start()
            
            # Start packet capture on one or more interfaces.
            sniffers = []
            for iface in interfaces:
                sniffer = scapy.AsyncSniffer(
                    prn=self.process_packet,
                    iface=iface,
                    store=False
                )
                sniffer.start()
                sniffers.append(sniffer)

            # Keep monitor alive until interrupted or packet target reached.
            if packet_count and packet_count > 0:
                while self.stats['packets_processed'] < packet_count:
                    time.sleep(0.5)
            else:
                while True:
                    time.sleep(1)
        
        except PermissionError:
            logger.error("ERROR: Administrator/root privileges required for packet capture!")
            print("⚠️  Please run with administrator privileges (sudo on Linux, Run as Admin on Windows)")
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
            self._print_summary()
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
            print(f"⚠️  Error: {e}")
        finally:
            if 'sniffers' in locals():
                for sniffer in sniffers:
                    try:
                        if sniffer.running:
                            sniffer.stop()
                    except Exception:
                        pass

    def _resolve_interfaces(self, interface=None):
        """
        Resolve interfaces to sniff.
        On Windows, include loopback so localhost scans are visible.
        """
        if interface:
            if isinstance(interface, (list, tuple)):
                return [str(i) for i in interface]
            return [str(interface)]

        resolved = []

        # Primary/default interface first.
        try:
            default_iface = str(scapy.conf.iface)
            if default_iface:
                resolved.append(default_iface)
        except Exception:
            pass

        # Add loopback interfaces on Windows for localhost traffic (nmap localhost).
        if platform.system().lower() == 'windows':
            try:
                for iface in scapy.get_if_list():
                    iface_str = str(iface)
                    lower_name = iface_str.lower()
                    if "loopback" in lower_name or "npcap" in lower_name and "loopback" in lower_name:
                        resolved.append(iface_str)
            except Exception:
                pass

            try:
                loop_name = getattr(scapy.conf, "loopback_name", None)
                if loop_name:
                    resolved.append(str(loop_name))
            except Exception:
                pass

        # Deduplicate while preserving order.
        unique = []
        seen = set()
        for iface in resolved:
            if iface not in seen:
                unique.append(iface)
                seen.add(iface)

        return unique if unique else ["Ethernet"]
    
    def _analysis_loop(self):
        """Background thread for flow analysis."""
        while True:
            try:
                self.analyze_flows()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
    
    def _print_summary(self):
        """Print monitoring summary."""
        with self._state_lock:
            stats_snapshot = dict(self.stats)
            recent_alerts = list(self.alerts)[-10:]
        uptime = datetime.now() - stats_snapshot['start_time']
        print(f"\n{'='*60}")
        print("MONITORING SUMMARY")
        print(f"{'='*60}")
        print(f"Uptime: {uptime}")
        print(f"Packets Processed: {stats_snapshot['packets_processed']:,}")
        print(f"Flows Analyzed: {stats_snapshot['flows_analyzed']:,}")
        print(f"Packet Processing Errors: {stats_snapshot['packet_processing_errors']:,}")
        print(f"Flow Analysis Errors: {stats_snapshot['flow_analysis_errors']:,}")
        print(f"Attacks Detected: {stats_snapshot['attacks_detected']}")
        print(f"Detection Rate: {stats_snapshot['attacks_detected']/max(1, stats_snapshot['flows_analyzed']):.2%}")
        
        if recent_alerts:
            print(f"\nLast 10 Alerts:")
            for alert in recent_alerts:
                print(f"  • {alert['timestamp']}: {alert['src_ip']}:{alert['src_port']} "
                      f"→ {alert['dst_ip']}:{alert['dst_port']} "
                      f"[{alert['confidence']:.2%}]")
    
    def get_stats(self):
        """Get current statistics."""
        with self._state_lock:
            stats_snapshot = dict(self.stats)
            recent_alerts = list(self.alerts)[-20:]
        return {
            'packets_processed': stats_snapshot['packets_processed'],
            'packet_processing_errors': stats_snapshot['packet_processing_errors'],
            'flows_analyzed': stats_snapshot['flows_analyzed'],
            'flow_analysis_errors': stats_snapshot['flow_analysis_errors'],
            'attacks_detected': stats_snapshot['attacks_detected'],
            'uptime': str(datetime.now() - stats_snapshot['start_time']),
            'recent_alerts': recent_alerts
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run real-time IDS monitoring")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to JSON config file")
    parser.add_argument("--model-path", default=None, help="Path to trained model (.pkl)")
    parser.add_argument("--scaler-path", default=None, help="Path to scaler (.pkl)")
    parser.add_argument("--encoders-path", default=None, help="Path to label encoders (.pkl)")
    parser.add_argument("--threshold", type=float, default=None, help="Alert threshold (0-1)")
    parser.add_argument("--interface", default=None, help="Network interface to monitor")
    parser.add_argument("--packet-count", type=int, default=None, help="Packet capture limit (0=infinite)")
    args = parser.parse_args()

    config = load_runtime_config(args.config)

    model_path = args.model_path or cfg_get(config, "runtime.model_path", "models/svm_model.pkl")
    scaler_path = args.scaler_path or cfg_get(config, "runtime.scaler_path", "data/processed/scaler.pkl")
    encoders_path = args.encoders_path or cfg_get(config, "runtime.encoders_path", "data/processed/label_encoders.pkl")
    threshold = args.threshold if args.threshold is not None else cfg_get(config, "runtime.alert_threshold", 0.8)
    interface = args.interface if args.interface is not None else cfg_get(config, "monitoring.interface", None)
    packet_count = args.packet_count if args.packet_count is not None else cfg_get(config, "monitoring.packet_count", 0)
    loopback_window_seconds = cfg_get(config, "suppression.loopback_window_seconds", 5)
    loopback_min_distinct_ports = cfg_get(config, "suppression.loopback_min_distinct_ports_for_scan", 15)

    ids = RealtimeIDS(
        model_path=model_path,
        scaler_path=scaler_path,
        encoders_path=encoders_path,
        alert_threshold=threshold,
        loopback_window_seconds=loopback_window_seconds,
        loopback_min_distinct_ports_for_scan=loopback_min_distinct_ports,
    )
    ids.start_monitoring(interface=interface, packet_count=packet_count)

