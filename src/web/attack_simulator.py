"""Deterministic attack simulation scenarios for SentinelAI runtime APIs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class SimulationScenario:
    id: str
    name: str
    description: str
    attack_family_hint: str
    protocol: int
    target_ports: tuple[int, ...]
    target_ip_count: int
    default_event_count: int
    default_packets: int
    default_bytes: int
    default_confidence: float


class AttackSimulator:
    """Build deterministic alert payloads compatible with runtime incident processing."""

    MAX_BATCH_SIZE = 20

    def __init__(self) -> None:
        self._catalog: dict[str, SimulationScenario] = {
            "port-scan-recon": SimulationScenario(
                id="port-scan-recon",
                name="Port Scan Recon",
                description="Multi-port reconnaissance against multiple destination hosts.",
                attack_family_hint="Port Scan",
                protocol=6,
                target_ports=(
                    20,
                    21,
                    22,
                    23,
                    25,
                    53,
                    80,
                    110,
                    123,
                    135,
                    139,
                    143,
                    389,
                    443,
                    445,
                    3306,
                ),
                target_ip_count=2,
                default_event_count=8,
                default_packets=220,
                default_bytes=26000,
                default_confidence=0.91,
            ),
            "ssh-bruteforce": SimulationScenario(
                id="ssh-bruteforce",
                name="SSH Brute Force",
                description="Repeated SSH login-attempt style traffic against port 22.",
                attack_family_hint="SSH Brute Force",
                protocol=6,
                target_ports=(22,),
                target_ip_count=1,
                default_event_count=9,
                default_packets=140,
                default_bytes=21000,
                default_confidence=0.89,
            ),
            "web-payload-injection": SimulationScenario(
                id="web-payload-injection",
                name="Web Payload Injection",
                description="Bursty traffic focused on web service ports (80/443/8080).",
                attack_family_hint="Web Payload Injection",
                protocol=6,
                target_ports=(80, 443, 8080),
                target_ip_count=1,
                default_event_count=5,
                default_packets=95,
                default_bytes=42000,
                default_confidence=0.87,
            ),
            "udp-flood-burst": SimulationScenario(
                id="udp-flood-burst",
                name="UDP Flood Burst",
                description="High-volume UDP burst pattern consistent with flood behavior.",
                attack_family_hint="UDP Flood Pattern",
                protocol=17,
                target_ports=(53, 123, 1900),
                target_ip_count=1,
                default_event_count=35,
                default_packets=1250,
                default_bytes=860000,
                default_confidence=0.94,
            ),
        }

    def list_scenarios(self) -> list[dict[str, Any]]:
        return [self._scenario_to_dict(self._catalog[scenario_id]) for scenario_id in sorted(self._catalog)]

    def get_scenario(self, scenario_id: str) -> dict[str, Any]:
        scenario = self._catalog.get(str(scenario_id).strip())
        if scenario is None:
            known = ", ".join(sorted(self._catalog))
            raise ValueError(f"Unknown scenario_id '{scenario_id}'. Available: {known}")
        return self._scenario_to_dict(scenario)

    def generate_alerts(
        self,
        scenario_id: str,
        *,
        count: int = 1,
        sequence_start: int = 1,
        base_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        scenario_key = str(scenario_id).strip()
        scenario = self._catalog.get(scenario_key)
        if scenario is None:
            known = ", ".join(sorted(self._catalog))
            raise ValueError(f"Unknown scenario_id '{scenario_id}'. Available: {known}")

        normalized_count = _safe_int(count, 0)
        if normalized_count < 1 or normalized_count > self.MAX_BATCH_SIZE:
            raise ValueError(f"count must be between 1 and {self.MAX_BATCH_SIZE}")
        normalized_sequence_start = _safe_int(sequence_start, 0)
        if normalized_sequence_start < 1:
            raise ValueError("sequence_start must be >= 1")

        anchor = (base_time or datetime.utcnow()).replace(microsecond=0)
        return [
            self._build_alert(
                scenario,
                sequence=normalized_sequence_start + offset,
                event_time=anchor + timedelta(seconds=offset),
            )
            for offset in range(normalized_count)
        ]

    def _build_alert(
        self,
        scenario: SimulationScenario,
        *,
        sequence: int,
        event_time: datetime,
    ) -> dict[str, Any]:
        src_ip = self._source_ip(scenario.id, sequence)
        target_ips = self._target_ips(scenario.id, sequence, scenario.target_ip_count)
        target_ports = [int(port) for port in scenario.target_ports]

        src_port = 20000 + (self._seed(scenario.id, sequence, "src-port") % 32000)
        dst_port = target_ports[0]
        confidence = _clamp_confidence(
            scenario.default_confidence + ((self._seed(scenario.id, sequence, "confidence") % 7) - 3) / 100.0
        )
        event_count = max(
            1,
            scenario.default_event_count
            + (self._seed(scenario.id, sequence, "event-count") % 3)
            - 1,
        )
        packets = max(
            event_count,
            scenario.default_packets + (self._seed(scenario.id, sequence, "packets") % 24) - 12,
        )
        bytes_total = max(
            packets * 60,
            scenario.default_bytes + (self._seed(scenario.id, sequence, "bytes") % 3000) - 1500,
        )

        packets_per_event = max(1, packets // event_count)
        bytes_per_event = max(packets_per_event * 60, bytes_total // event_count)
        event_history_count = min(event_count, 25)
        event_start_time = event_time - timedelta(seconds=max(0, event_history_count - 1) * 2)

        events: list[dict[str, Any]] = []
        for idx in range(event_history_count):
            current_time = event_start_time + timedelta(seconds=idx * 2)
            target_port = target_ports[idx % len(target_ports)]
            target_ip = target_ips[idx % len(target_ips)]
            events.append(
                {
                    "timestamp": current_time,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": target_ip,
                    "dst_port": target_port,
                    "protocol": scenario.protocol,
                    "confidence": confidence,
                    "packets": packets_per_event,
                    "bytes": bytes_per_event,
                }
            )

        return {
            "timestamp": event_time,
            "first_seen": event_start_time,
            "last_seen": event_time,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": target_ips[0],
            "dst_port": dst_port,
            "protocol": scenario.protocol,
            "confidence": confidence,
            "packets": packets,
            "bytes": bytes_total,
            "event_count": event_count,
            "attacker_ip": src_ip,
            "target_ips": target_ips,
            "target_ports": target_ports,
            "events": events,
            "simulation": {
                "scenario_id": scenario.id,
                "scenario_name": scenario.name,
                "sequence": sequence,
            },
        }

    @staticmethod
    def _seed(scenario_id: str, sequence: int, salt: str) -> int:
        digest = hashlib.sha256(f"{scenario_id}:{sequence}:{salt}".encode("utf-8")).hexdigest()
        return int(digest[:8], 16)

    @classmethod
    def _source_ip(cls, scenario_id: str, sequence: int) -> str:
        seed = cls._seed(scenario_id, sequence, "source-ip")
        return f"203.0.113.{(seed % 200) + 10}"

    @classmethod
    def _target_ips(cls, scenario_id: str, sequence: int, count: int) -> list[str]:
        normalized_count = max(1, _safe_int(count, 1))
        values: list[str] = []
        for idx in range(normalized_count):
            seed = cls._seed(scenario_id, sequence, f"target-ip-{idx}")
            values.append(f"10.{(seed % 20) + 1}.{(seed // 20) % 255}.{(seed // 5120) % 240 + 10}")
        return values

    @staticmethod
    def _scenario_to_dict(scenario: SimulationScenario) -> dict[str, Any]:
        return {
            "id": scenario.id,
            "name": scenario.name,
            "description": scenario.description,
            "attack_family_hint": scenario.attack_family_hint,
            "defaults": {
                "protocol": scenario.protocol,
                "target_ports": list(scenario.target_ports),
                "target_ip_count": scenario.target_ip_count,
                "event_count": scenario.default_event_count,
                "packets": scenario.default_packets,
                "bytes": scenario.default_bytes,
                "confidence": scenario.default_confidence,
                "trigger_count": 1,
            },
        }
