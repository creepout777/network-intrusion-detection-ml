"""Deterministic regression checks for SentinelAI attack-typing metadata."""

from __future__ import annotations

import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from monitoring.packet_sniffer import RealtimeIDS
from web.attack_type_rules import AttackTypeRuleEngine
from web.query_dsl import QueryDslError
from web.runtime_service import SentinelAIRuntimeService

UNKNOWN_LABEL = "Unknown / Needs More Data"
TOP_LEVEL_KEYS = {
    "label",
    "primary_class",
    "confidence",
    "alternatives",
    "evidence_used",
    "evidence_missing",
    "limitations",
    "description",
    "rationale",
    "explanation",
    "source",
    "note",
    "scoring",
}
SCORING_KEYS = {
    "top_class",
    "top_score",
    "runner_up",
    "runner_up_score",
    "score_margin",
    "minimum_score",
    "minimum_margin",
    "required_evidence_missing",
    "gates_passed",
}
CERTAINTY_LEVELS = {"not_sure", "probable", "certain"}
CERTAINTY_PREFIX_BY_LEVEL = {
    "not_sure": "Not sure:",
    "probable": "Probable:",
    "certain": "Certain:",
}
REQUIRED_ATTACK_DETAIL_STRING_FIELDS = (
    "summary",
    "primary_class",
    "description",
    "source",
    "note",
    "certainty_text",
)
REQUIRED_ATTACK_DETAIL_LIST_FIELDS = (
    "rationale",
    "evidence_used",
    "evidence_missing",
    "limitations",
)
OBSERVABILITY_TOP_LEVEL_KEYS = {
    "incident_count",
    "incidents_with_fallback_fields",
    "incidents_with_low_confidence_fields",
    "low_confidence_threshold",
    "provenance_source_usage",
    "classification_source_usage",
    "rule_hit_coverage",
    "gate_failure_distribution",
    "fallback_field_usage",
    "low_confidence_field_usage",
    "enrichment_latency_ms",
}
RULE_HIT_COVERAGE_KEYS = {
    "scored_incident_count",
    "incidents_with_rule_hits",
    "incidents_with_gates_passed",
    "rule_hit_rate_pct",
    "gate_pass_rate_pct",
    "top_class_usage",
}
GATE_FAILURE_DISTRIBUTION_KEYS = {
    "scored_incident_count",
    "incidents_with_any_gate_failure",
    "score_gate_failures",
    "margin_gate_failures",
    "required_evidence_missing_failures",
    "ambiguity_failures",
}
LATENCY_SUMMARY_KEYS = {"count", "missing_count", "avg", "p95", "min", "max"}


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _validate_stable_shape(result: dict[str, Any], max_alternatives: int) -> None:
    _assert(set(result.keys()) == TOP_LEVEL_KEYS, "Classification payload top-level keys changed.")

    alternatives = result["alternatives"]
    _assert(isinstance(alternatives, list), "'alternatives' must be a list.")
    _assert(len(alternatives) <= max_alternatives, "Alternatives exceed configured max_alternatives.")
    for idx, candidate in enumerate(alternatives):
        _assert(isinstance(candidate, dict), f"alternatives[{idx}] must be an object.")
        _assert(
            set(candidate.keys()) == {"class", "score", "confidence"},
            f"alternatives[{idx}] key shape changed.",
        )
        _assert(bool(str(candidate["class"]).strip()), f"alternatives[{idx}].class must be non-empty.")
        _assert(isinstance(candidate["score"], (int, float)), f"alternatives[{idx}].score must be numeric.")
        _assert(
            isinstance(candidate["confidence"], (int, float)),
            f"alternatives[{idx}].confidence must be numeric.",
        )

    rationale = result["rationale"]
    _assert(isinstance(rationale, list) and len(rationale) >= 3, "'rationale' must have >= 3 lines.")
    _assert(
        all(isinstance(item, str) and item.strip() for item in rationale),
        "All rationale entries must be non-empty strings.",
    )
    _assert(
        rationale[0].startswith("ML attack decision is separate from typing:"),
        "rationale[0] prefix changed.",
    )
    _assert(rationale[1].startswith("Top class candidate:"), "rationale[1] prefix changed.")
    _assert(rationale[2].startswith("Runner-up:"), "rationale[2] prefix changed.")

    scoring = result["scoring"]
    _assert(isinstance(scoring, dict), "'scoring' must be an object.")
    _assert(set(scoring.keys()) == SCORING_KEYS, "'scoring' key shape changed.")
    _assert(isinstance(scoring["required_evidence_missing"], list), "required_evidence_missing must be a list.")
    _assert(isinstance(scoring["gates_passed"], bool), "gates_passed must be a bool.")

    explanation = result["explanation"]
    _assert(isinstance(explanation, dict), "'explanation' must be an object.")
    _assert(explanation.get("alternatives") == alternatives, "explanation.alternatives diverged from alternatives.")


def _build_engine() -> AttackTypeRuleEngine:
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config" / "ids_config.json"
    engine = AttackTypeRuleEngine.from_runtime_config(str(config_path))
    _assert(engine.fallback_class_id == "unknown", "Expected fallback class id 'unknown'.")
    return engine


class _StubAttackTypeEngine:
    def chart_labels(self) -> list[str]:
        return ["Port Scan", "SSH Brute Force", "Web Attack"]

    def metadata(self) -> dict[str, Any]:
        return {
            "source": "deterministic-rule-engine:regression-stub",
            "schema_version": "1.0",
            "rules_path": "config/attack_type_rules.json",
            "schema_path": "config/attack_type_rule_schema.json",
            "minimum_score": 3.0,
            "minimum_margin": 0.75,
            "fallback_class_id": "unknown",
            "max_alternatives": 3,
            "load_error": None,
        }


def _build_service_stub() -> SentinelAIRuntimeService:
    service = SentinelAIRuntimeService.__new__(SentinelAIRuntimeService)
    service.enable_staged_data = False
    service.attack_type_engine = _StubAttackTypeEngine()
    service._latest_attack_detail_observability = service._empty_attack_detail_observability()
    service._last_attack_detail_observability_signature = None
    service._threat_intel_lock = threading.Lock()
    service._shodan_api_key = ""
    service._shodan_key_source = "missing"
    service._threat_intel_lookup_limit = 25
    service._threat_intel_cache_ttl_seconds = 900
    service._threat_intel_timeout_seconds = 5
    service._threat_intel_max_services = 20
    service._threat_intel_max_vulns = 30
    service._threat_intel_max_map_points = 250
    service._threat_intel_cache = {}
    service._stats = lambda: {  # type: ignore[method-assign]
        "packets_processed": 2048,
        "attacks_detected": 6,
        "flows_analyzed": 24,
    }
    return service


def _build_ids_stub(local_ips: set[str]) -> RealtimeIDS:
    ids = RealtimeIDS.__new__(RealtimeIDS)
    ids.local_ips = {RealtimeIDS._normalize_ip(ip) for ip in local_ips}
    return ids


def _run_attacker_attribution_case() -> None:
    ids = _build_ids_stub({"127.0.0.1", "::1", "192.168.1.10"})
    attacker = ids._resolve_attacker_ip("192.168.1.10", "8.8.8.8")
    target = ids._resolve_target_ip("192.168.1.10", "8.8.8.8", attacker)
    _assert(attacker == "8.8.8.8", "Local->remote flow should resolve remote endpoint as attacker.")
    _assert(target == "192.168.1.10", "Target should be local endpoint when remote is attacker.")

    # Heuristic fallback for missed local identity: private->public likely outbound from local host.
    ids_missing_local = _build_ids_stub({"127.0.0.1", "::1"})
    attacker_missing_local = ids_missing_local._resolve_attacker_ip("192.168.1.10", "1.1.1.1")
    _assert(
        attacker_missing_local == "1.1.1.1",
        "Private->public flow should prefer public endpoint as attacker when local identity is ambiguous.",
    )


def _make_attack_detail(
    service: SentinelAIRuntimeService,
    *,
    summary: str,
    primary_class: str,
    confidence: float,
    certainty_level: str,
    certainty_text: str,
) -> dict[str, Any]:
    return service._validate_attack_detail_response(
        {
            "summary": summary,
            "primary_class": primary_class,
            "description": f"{certainty_text} Current telemetry best aligns with {primary_class}.",
            "source": "deterministic-rule-engine:regression",
            "note": f"{certainty_text} Binary ML detection remains separate from family typing.",
            "confidence": confidence,
            "certainty_text": certainty_text,
            "certainty": {"level": certainty_level, "text": certainty_text},
            "rationale": [f"Primary class best guess: {primary_class}."],
            "evidence_used": [f"Deterministic class candidate resolved as {primary_class}."],
            "evidence_missing": ["Additional corroborating evidence would increase confidence."],
            "limitations": ["Attack-family typing is deterministic and evidence-driven."],
            "field_metadata": {},
        }
    )


def _assert_attack_detail_contract_semantics(detail: dict[str, Any]) -> None:
    for field in REQUIRED_ATTACK_DETAIL_STRING_FIELDS:
        value = detail.get(field)
        _assert(isinstance(value, str) and value.strip(), f"attack_detail.{field} must be non-empty.")
    for field in REQUIRED_ATTACK_DETAIL_LIST_FIELDS:
        value = detail.get(field)
        _assert(
            isinstance(value, list)
            and value
            and all(isinstance(item, str) and item.strip() for item in value),
            f"attack_detail.{field} must be a non-empty string list.",
        )

    certainty = detail.get("certainty")
    _assert(isinstance(certainty, dict), "attack_detail.certainty must be an object.")
    level = certainty.get("level")
    _assert(level in CERTAINTY_LEVELS, "attack_detail.certainty.level must be normalized.")
    expected_prefix = CERTAINTY_PREFIX_BY_LEVEL[str(level)]
    _assert(
        str(certainty.get("text", "")).startswith(expected_prefix),
        "attack_detail.certainty.text prefix must match certainty.level.",
    )
    _assert(
        str(detail.get("certainty_text", "")).startswith(expected_prefix),
        "attack_detail.certainty_text prefix must match certainty.level.",
    )
    _assert(
        str(detail.get("note", "")).startswith(expected_prefix),
        "attack_detail.note prefix must match certainty.level.",
    )
    _assert(
        any("uncertainty notes:" in item.lower() for item in detail["rationale"]),
        "rationale must include explicit uncertainty notes.",
    )
    _assert(
        any("deterministic" in item.lower() and "rule" in item.lower() for item in detail["limitations"]),
        "limitations should preserve deterministic-evidence framing.",
    )

    evidence = detail.get("evidence")
    _assert(isinstance(evidence, dict), "attack_detail.evidence must be an object.")
    _assert(evidence.get("used") == detail["evidence_used"], "attack_detail.evidence.used must mirror evidence_used.")
    _assert(
        evidence.get("missing") == detail["evidence_missing"],
        "attack_detail.evidence.missing must mirror evidence_missing.",
    )

    confidence = float(detail.get("confidence", 0.0))
    _assert(0.0 <= confidence <= 1.0, "attack_detail.confidence must be normalized to [0, 1].")
    if level == "not_sure":
        _assert(confidence <= 0.59, "not_sure certainty should keep conservative confidence bounds.")
        _assert(
            any("provisional" in item.lower() for item in detail["limitations"]),
            "not_sure certainty should include provisional caveat in limitations.",
        )
    elif level == "probable":
        _assert(confidence <= 0.89, "probable certainty should keep confidence below certain-level bounds.")


def _assert_latency_summary_shape(latency_summary: dict[str, Any], incident_count: int) -> None:
    _assert(set(latency_summary.keys()) == LATENCY_SUMMARY_KEYS, "latency summary key shape changed.")
    count = latency_summary.get("count")
    missing_count = latency_summary.get("missing_count")
    _assert(isinstance(count, int) and count >= 0, "latency count must be a non-negative int.")
    _assert(
        isinstance(missing_count, int) and missing_count >= 0,
        "latency missing_count must be a non-negative int.",
    )
    _assert(
        count + missing_count == incident_count,
        "latency count + missing_count must equal observability incident_count.",
    )
    for field in ("avg", "p95", "min", "max"):
        value = latency_summary.get(field)
        _assert(isinstance(value, (int, float)), f"latency {field} must be numeric.")
        _assert(value >= 0.0, f"latency {field} must be non-negative.")
    if count == 0:
        _assert(
            all(float(latency_summary[field]) == 0.0 for field in ("avg", "p95", "min", "max")),
            "empty latency summaries must remain zeroed.",
        )
        return
    _assert(
        float(latency_summary["min"]) <= float(latency_summary["avg"]) <= float(latency_summary["max"]),
        "latency avg should stay within [min, max].",
    )
    _assert(
        float(latency_summary["min"]) <= float(latency_summary["p95"]) <= float(latency_summary["max"]),
        "latency p95 should stay within [min, max].",
    )


def _assert_observability_shape(summary: dict[str, Any], *, incident_count: int) -> None:
    _assert(set(summary.keys()) == OBSERVABILITY_TOP_LEVEL_KEYS, "observability summary top-level key shape changed.")
    _assert(summary.get("incident_count") == incident_count, "observability incident_count must match incidents.")
    _assert(
        summary.get("low_confidence_threshold") == SentinelAIRuntimeService.ATTACK_DETAIL_LOW_CONFIDENCE_THRESHOLD,
        "observability low_confidence_threshold must track runtime constant.",
    )
    rule_hit_coverage = summary.get("rule_hit_coverage")
    _assert(isinstance(rule_hit_coverage, dict), "rule_hit_coverage must be an object.")
    _assert(set(rule_hit_coverage.keys()) == RULE_HIT_COVERAGE_KEYS, "rule_hit_coverage key shape changed.")
    _assert(
        isinstance(rule_hit_coverage.get("top_class_usage"), dict),
        "rule_hit_coverage.top_class_usage must be an object.",
    )
    gate_failure_distribution = summary.get("gate_failure_distribution")
    _assert(isinstance(gate_failure_distribution, dict), "gate_failure_distribution must be an object.")
    _assert(
        set(gate_failure_distribution.keys()) == GATE_FAILURE_DISTRIBUTION_KEYS,
        "gate_failure_distribution key shape changed.",
    )
    _assert(
        isinstance(summary.get("classification_source_usage"), dict),
        "classification_source_usage must be an object.",
    )
    _assert(isinstance(summary.get("provenance_source_usage"), dict), "provenance_source_usage must be an object.")
    _assert(isinstance(summary.get("fallback_field_usage"), dict), "fallback_field_usage must be an object.")
    _assert(
        isinstance(summary.get("low_confidence_field_usage"), dict),
        "low_confidence_field_usage must be an object.",
    )
    _assert_latency_summary_shape(summary.get("enrichment_latency_ms", {}), incident_count=incident_count)


def _run_detail_contract_completion_case(engine: AttackTypeRuleEngine) -> None:
    service = _build_service_stub()
    sparse = engine.classify(
        {
            "target_ports": [22],
            "target_ips": ["10.0.0.5"],
            "event_count": 1,
            "packets": 3,
            "bytes": 1500,
            "protocol": 6,
        },
        ml_confidence=0.92,
        ml_threshold=0.80,
    )
    normalized = service._normalize_classification_details(sparse)
    detail = service._validate_attack_detail_response(
        service._build_attack_detail_contract(
            classification_details=normalized,
            classification_label=normalized["label"],
            attack_typing_metadata=service._attack_typing_metadata(),
        )
    )
    _assert_attack_detail_contract_semantics(detail)

    for field in REQUIRED_ATTACK_DETAIL_STRING_FIELDS:
        value = detail.get(field)
        _assert(isinstance(value, str) and value.strip(), f"attack_detail.{field} must be non-empty.")
    for field in REQUIRED_ATTACK_DETAIL_LIST_FIELDS:
        value = detail.get(field)
        _assert(
            isinstance(value, list)
            and len(value) > 0
            and all(isinstance(item, str) and item.strip() for item in value),
            f"attack_detail.{field} must be a non-empty string list.",
        )
    _assert(detail["certainty"]["level"] in CERTAINTY_LEVELS, "certainty level must be normalized.")
    _assert(
        detail["certainty"]["text"].lower().startswith(("probable:", "not sure:", "certain:")),
        "certainty text should explicitly communicate uncertainty/certainty level.",
    )
    _assert(
        any("uncertainty notes:" in item.lower() for item in detail["rationale"]),
        "rationale should include explicit uncertainty notes.",
    )
    _assert(
        any("deterministic" in item.lower() and "rule" in item.lower() for item in detail["limitations"]),
        "limitations should preserve deterministic-evidence framing.",
    )


def _run_detail_contract_guard_case() -> None:
    service = _build_service_stub()
    guarded = service._validate_attack_detail_response(
        {
            "summary": " ",
            "primary_class": "Port Scan",
            "description": " ",
            "source": "",
            "note": "Certain: deterministic gates passed.",
            "confidence": 0.42,
            "certainty_text": "Certain: Port Scan is fully confirmed.",
            "certainty": {"level": "certain", "text": "Certain: Port Scan is fully confirmed."},
            "rationale": ["  "],
            "evidence_used": ["Top candidate was Port Scan."],
            "evidence_missing": ["Need score >= 3.00; observed 1.20."],
            "limitations": ["Rule output only."],
            "field_metadata": {},
        }
    )
    _assert_attack_detail_contract_semantics(guarded)
    for field in REQUIRED_ATTACK_DETAIL_STRING_FIELDS:
        _assert(bool(str(guarded.get(field, "")).strip()), f"guarded attack_detail.{field} must stay non-empty.")
    for field in REQUIRED_ATTACK_DETAIL_LIST_FIELDS:
        value = guarded.get(field)
        _assert(
            isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value),
            f"guarded attack_detail.{field} must stay a non-empty string list.",
        )
    _assert(guarded["certainty"]["level"] == "not_sure", "low-confidence contradictory certainty must downgrade.")
    _assert(
        guarded["certainty"]["text"].startswith("Not sure:"),
        "downgraded certainty text must use conservative prefix.",
    )
    _assert(
        any("uncertainty notes:" in item.lower() for item in guarded["rationale"]),
        "rationale must carry uncertainty note coherence.",
    )
    _assert(
        any("missing evidence" in item.lower() or "insufficient" in item.lower() for item in guarded["rationale"]),
        "rationale must acknowledge missing-evidence constraints.",
    )
    _assert(
        any("provisional" in item.lower() for item in guarded["limitations"]),
        "limitations should warn that uncertain assignments are provisional.",
    )

    unknown_class = service._validate_attack_detail_response(
        {
            "summary": "Unknown / Needs More Data",
            "primary_class": "Unknown / Needs More Data",
            "description": "Probable: best class candidate still unknown.",
            "source": "deterministic-rule-engine:regression",
            "note": "Probable: best class candidate remains unknown.",
            "confidence": 0.88,
            "certainty_text": "Probable: best class candidate remains unknown.",
            "certainty": {"level": "probable", "text": "Probable: best class candidate remains unknown."},
            "rationale": ["Classifier fallback triggered."],
            "evidence_used": ["Insufficient deterministic evidence for named family."],
            "evidence_missing": [],
            "limitations": ["Deterministic fallback path."],
            "field_metadata": {},
        }
    )
    _assert_attack_detail_contract_semantics(unknown_class)
    _assert(
        unknown_class["certainty"]["level"] == "not_sure",
        "unknown class should never keep probable/certain certainty.",
    )
    _assert(
        unknown_class["certainty"]["text"].startswith("Not sure:"),
        "unknown class certainty text should be conservative.",
    )


def _run_dashboard_contract_case() -> None:
    service = _build_service_stub()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sample_incidents = [
        {
            "id": "INC-1001",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "source_ip": "203.0.113.10",
            "attacker_ip": "203.0.113.10",
            "target_ip": "10.0.0.10",
            "severity": "HIGH",
            "confidence": 0.91,
            "attack_detail": _make_attack_detail(
                service,
                summary="Port Scan",
                primary_class="Port Scan",
                confidence=0.88,
                certainty_level="probable",
                certainty_text="Probable: Port Scan is the strongest deterministic match, but this remains a best guess.",
            ),
        },
        {
            "id": "INC-1002",
            "timestamp": (now - timedelta(minutes=3)).isoformat(),
            "source_ip": "198.51.100.20",
            "attacker_ip": "198.51.100.20",
            "target_ip": "10.0.0.15",
            "severity": "MED",
            "confidence": 0.74,
            "attack_detail": _make_attack_detail(
                service,
                summary="Unknown / Needs More Data",
                primary_class="Unknown / Needs More Data",
                confidence=0.38,
                certainty_level="not_sure",
                certainty_text="Not sure: available evidence is insufficient for certain family assignment.",
            ),
        },
    ]
    service.list_incidents = lambda limit=100: sample_incidents[:limit]  # type: ignore[method-assign]

    overview = service.get_overview_summary()
    charts = service.get_overview_charts()
    network = service.get_network_graph()
    threat_map = service.get_threat_map()
    hunting = service.get_hunting_view()

    _assert(
        overview.get("meta", {}).get("canonical_attack_model") == "attack_detail",
        "overview canonical_attack_model must be attack_detail.",
    )
    _assert(
        charts.get("meta", {}).get("attack_typing", {}).get("attack_detail_contract_version") == "1.0",
        "charts meta must expose attack_detail contract version.",
    )
    _assert(
        network.get("meta", {}).get("canonical_attack_model") == "attack_detail",
        "network graph canonical_attack_model must be attack_detail.",
    )
    _assert(
        threat_map.get("meta", {}).get("canonical_attack_model") == "attack_detail",
        "threat map canonical_attack_model must be attack_detail.",
    )
    _assert(
        hunting.get("meta", {}).get("canonical_attack_model") == "attack_detail",
        "hunting canonical_attack_model must be attack_detail.",
    )

    for node in network.get("nodes", []):
        _assert(bool(str(node.get("attack_primary_class", "")).strip()), "node.attack_primary_class is required.")
        _assert(isinstance(node.get("attack_confidence_avg"), (int, float)), "node.attack_confidence_avg must be numeric.")
        _assert(
            node.get("attack_certainty", {}).get("level") in CERTAINTY_LEVELS,
            "node.attack_certainty.level must be normalized.",
        )
    for edge in network.get("edges", []):
        _assert(bool(str(edge.get("attack_primary_class", "")).strip()), "edge.attack_primary_class is required.")
        _assert(isinstance(edge.get("attack_confidence_avg"), (int, float)), "edge.attack_confidence_avg must be numeric.")
        _assert(
            edge.get("attack_certainty", {}).get("level") in CERTAINTY_LEVELS,
            "edge.attack_certainty.level must be normalized.",
        )
    threat_items = threat_map.get("items", threat_map.get("points", []))
    _assert(isinstance(threat_map.get("analytics"), dict), "threat intel analytics payload must be an object.")
    _assert(isinstance(threat_map.get("map_points"), list), "threat intel map_points payload must be a list.")
    _assert(
        isinstance(threat_map.get("analytics", {}).get("totals"), dict),
        "threat intel analytics.totals must be present.",
    )
    _assert(
        isinstance(threat_map.get("analytics", {}).get("totals", {}).get("unique_ips"), int),
        "threat intel analytics.totals.unique_ips must be numeric.",
    )
    for point in threat_items:
        _assert(bool(str(point.get("attack_primary_class", "")).strip()), "threat intel attack_primary_class is required.")
        _assert(isinstance(point.get("attack_confidence"), (int, float)), "threat intel attack_confidence must be numeric.")
        _assert(
            point.get("attack_certainty", {}).get("level") in CERTAINTY_LEVELS,
            "threat intel attack_certainty.level must be normalized.",
        )
        _assert(isinstance(point.get("services_count"), int), "threat intel services_count must be numeric.")
        _assert(isinstance(point.get("services"), list), "threat intel services must be a list.")
        _assert(isinstance(point.get("vuln_details"), list), "threat intel vuln_details must be a list.")
    for source in hunting.get("hot_sources", []):
        _assert(bool(str(source.get("attack_primary_class", "")).strip()), "hot source attack_primary_class is required.")
        _assert(isinstance(source.get("attack_confidence_avg"), (int, float)), "hot source attack_confidence_avg must be numeric.")
        _assert(
            source.get("attack_certainty", {}).get("level") in CERTAINTY_LEVELS,
            "hot source attack_certainty.level must be normalized.",
        )


def _run_attack_detail_observability_case() -> None:
    service = _build_service_stub()
    rich_detail = _make_attack_detail(
        service,
        summary="Port Scan",
        primary_class="Port Scan",
        confidence=0.88,
        certainty_level="probable",
        certainty_text="Probable: Port Scan is the strongest deterministic match.",
    )
    sparse_detail = _make_attack_detail(
        service,
        summary="Unknown / Needs More Data",
        primary_class="Unknown / Needs More Data",
        confidence=0.84,
        certainty_level="not_sure",
        certainty_text="Not sure: evidence is still ambiguous and incomplete.",
    )
    sparse_detail["field_metadata"]["summary"] = {
        "provenance": "completion-engine:fallback:summary",
        "confidence": 0.2,
    }
    sparse_detail["field_metadata"]["note"] = {
        "provenance": "completion-engine:matrix:note",
        "confidence": 0.3,
    }
    ambiguous_detail = _make_attack_detail(
        service,
        summary="Web Attack",
        primary_class="Web Attack",
        confidence=0.44,
        certainty_level="not_sure",
        certainty_text="Not sure: web telemetry is mixed and still ambiguous.",
    )
    ambiguous_detail["field_metadata"]["description"] = {
        "provenance": "completion-engine:matrix:description",
        "confidence": 0.45,
    }
    adversarial_detail = service._validate_attack_detail_response(
        {
            "summary": "",
            "primary_class": "Web Attack",
            "description": None,
            "source": "",
            "note": 1234,
            "confidence": "0.97",
            "certainty_text": "Certain: web attack is fully confirmed.",
            "certainty": {"level": "certain", "text": "Certain: web attack is fully confirmed."},
            "rationale": ["", None],
            "evidence_used": [],
            "evidence_missing": ["Need score >= 3.00; observed 0.00."],
            "limitations": [],
            "field_metadata": {
                "summary": {"provenance": "completion-engine:fallback:summary", "confidence": 0.1},
                "note": {"provenance": "response-validator:note", "confidence": 0.2},
            },
        }
    )
    for detail in (rich_detail, sparse_detail, ambiguous_detail, adversarial_detail):
        _assert_attack_detail_contract_semantics(detail)

    incidents = [
        {
            "attack_detail": rich_detail,
            "classification_source": "deterministic-rule-engine:test",
            "classification_scoring": {
                "top_class": "Port Scan",
                "top_score": 4.2,
                "runner_up": "SSH Brute Force",
                "runner_up_score": 2.8,
                "score_margin": 1.4,
                "minimum_score": 3.0,
                "minimum_margin": 0.75,
                "required_evidence_missing": [],
                "gates_passed": True,
            },
            "classification_evidence_missing": [],
            "enrichment_latency_ms": 2.3,
        },
        {
            "attack_detail": sparse_detail,
            "classification_source": "completion-engine:fallback",
            "classification_scoring": {
                "top_class": "SSH Brute Force",
                "top_score": 1.8,
                "runner_up": "Port Scan",
                "runner_up_score": 1.7,
                "score_margin": 0.1,
                "minimum_score": 3.0,
                "minimum_margin": 0.75,
                "required_evidence_missing": ["ssh_temporal_focus"],
                "gates_passed": False,
            },
            "classification_evidence_missing": [
                "Top class is too close to an alternative; evidence is ambiguous.",
            ],
            "enrichment_latency_ms": 7.8,
        },
        {
            "attack_detail": ambiguous_detail,
            "classification_source": "   ",
            "classification_scoring": {
                "top_class": "Web Attack",
                "top_score": 3.4,
                "runner_up": "Port Scan",
                "runner_up_score": 3.2,
                "score_margin": 0.2,
                "minimum_score": 3.0,
                "minimum_margin": 0.75,
                "required_evidence_missing": [],
                "gates_passed": False,
            },
            "classification_evidence_missing": [
                "Top class is too close to an alternative; evidence is ambiguous.",
            ],
            "enrichment_latency_ms": "3.1",
        },
        {
            "attack_detail": adversarial_detail,
            "classification_scoring": {
                "top_class": "Unknown / Needs More Data",
                "top_score": 0.0,
                "runner_up": "Port Scan",
                "runner_up_score": 0.0,
                "score_margin": 0.0,
                "minimum_score": 3.0,
                "minimum_margin": 0.75,
                "required_evidence_missing": [],
                "gates_passed": False,
            },
            "classification_evidence_missing": ["Need score >= 3.00; observed 0.00."],
            "enrichment_latency_ms": -4.0,
        },
    ]
    summary = service._summarize_attack_detail_observability(incidents)
    repeated_summary = service._summarize_attack_detail_observability(incidents)
    _assert(summary == repeated_summary, "observability summaries must stay deterministic for identical inputs.")
    _assert_observability_shape(summary, incident_count=len(incidents))
    _assert(
        summary.get("classification_source_usage", {}).get("deterministic-rule-engine:test") == 1,
        "classification source usage must count deterministic source.",
    )
    _assert(
        summary.get("classification_source_usage", {}).get("completion-engine:fallback") == 1,
        "classification source usage must count fallback source.",
    )
    _assert(
        summary.get("classification_source_usage", {}).get("deterministic-rule-engine:unknown") == 1,
        "classification source usage should fall back to validated attack_detail source when absent.",
    )
    _assert(
        summary.get("classification_source_usage", {}).get("unknown") == 1,
        "classification source usage must normalize blank sources to unknown.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("scored_incident_count") == 4,
        "rule-hit coverage must count scored incidents.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("incidents_with_rule_hits") == 3,
        "rule-hit coverage must count positive-scoring candidates.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("incidents_with_gates_passed") == 1,
        "rule-hit coverage must count gate-passed incidents.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("rule_hit_rate_pct") == 75.0,
        "rule-hit coverage must keep deterministic rate calculations.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("gate_pass_rate_pct") == 25.0,
        "gate-pass coverage must keep deterministic rate calculations.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("top_class_usage", {}).get("Port Scan") == 1,
        "top_class_usage must include rich evidence class counts.",
    )
    _assert(
        summary.get("rule_hit_coverage", {}).get("top_class_usage", {}).get("Unknown / Needs More Data") == 1,
        "top_class_usage must include adversarial unknown-class counts.",
    )
    _assert(
        summary.get("gate_failure_distribution", {}).get("incidents_with_any_gate_failure") == 3,
        "gate-failure distribution must count incidents with at least one failure.",
    )
    _assert(
        summary.get("gate_failure_distribution", {}).get("score_gate_failures") == 2,
        "gate-failure distribution must include score-gate failures.",
    )
    _assert(
        summary.get("gate_failure_distribution", {}).get("margin_gate_failures") == 3,
        "gate-failure distribution must include margin-gate failures.",
    )
    _assert(
        summary.get("gate_failure_distribution", {}).get("required_evidence_missing_failures") == 1,
        "gate-failure distribution must include required-evidence failures.",
    )
    _assert(
        summary.get("gate_failure_distribution", {}).get("ambiguity_failures") == 3,
        "gate-failure distribution must include ambiguity failures.",
    )
    _assert(
        summary.get("enrichment_latency_ms", {}).get("count") == 3,
        "enrichment latency summary must count samples.",
    )
    _assert(
        summary.get("enrichment_latency_ms", {}).get("missing_count") == 1,
        "enrichment latency summary must report missing/invalid samples.",
    )
    _assert(
        summary.get("enrichment_latency_ms", {}).get("avg") == 4.4,
        "enrichment latency avg must remain deterministic.",
    )
    _assert(
        summary.get("enrichment_latency_ms", {}).get("p95") == 7.8,
        "enrichment latency p95 must remain deterministic.",
    )
    _assert(
        summary.get("incidents_with_fallback_fields", 0) >= 1,
        "observability should report fallback provenance coverage.",
    )
    _assert(
        summary.get("incidents_with_low_confidence_fields", 0) >= 2,
        "observability should report low-confidence-field coverage.",
    )
    _assert(
        summary.get("low_confidence_field_usage", {}).get("summary", 0) >= 2,
        "observability low-confidence usage should surface summary-field weakness.",
    )


def _run_hunting_query_contract_case() -> None:
    service = _build_service_stub()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sample_incidents = [
        {
            "id": "INC-HUNT-001",
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "source_ip": "10.0.0.42",
            "attacker_ip": "140.82.114.21",
            "target_ip": "10.0.0.20",
            "target_ports": [22, 80],
            "severity": "HIGH",
            "triage_state": "open",
            "event_count": 18,
            "packets": 240,
            "bytes": 18000,
            "confidence": 0.93,
            "detection_confidence": 0.93,
            "attack_confidence": 0.91,
            "attack_certainty_level": "certain",
            "attack_primary_class": "SSH Brute Force",
            "attack_detail": _make_attack_detail(
                service,
                summary="SSH Brute Force",
                primary_class="SSH Brute Force",
                confidence=0.91,
                certainty_level="certain",
                certainty_text="Certain: deterministic evidence is strongly aligned with SSH brute-force behavior.",
            ),
        },
        {
            "id": "INC-HUNT-002",
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "source_ip": "192.168.1.7",
            "attacker_ip": "192.168.1.7",
            "target_ip": "10.0.0.10",
            "target_ports": [443],
            "severity": "MED",
            "triage_state": "dismissed",
            "event_count": 3,
            "packets": 18,
            "bytes": 2400,
            "confidence": 0.61,
            "detection_confidence": 0.61,
            "attack_confidence": 0.33,
            "attack_certainty_level": "not_sure",
            "attack_primary_class": UNKNOWN_LABEL,
            "attack_detail": _make_attack_detail(
                service,
                summary=UNKNOWN_LABEL,
                primary_class=UNKNOWN_LABEL,
                confidence=0.33,
                certainty_level="not_sure",
                certainty_text="Not sure: available evidence is incomplete and ambiguous.",
            ),
        },
        {
            "id": "INC-HUNT-003",
            "timestamp": (now - timedelta(minutes=8)).isoformat(),
            "source_ip": "8.8.8.8",
            "attacker_ip": "8.8.8.8",
            "target_ip": "10.0.0.30",
            "target_ports": [8080],
            "severity": "CRITICAL",
            "triage_state": "in_review",
            "event_count": 26,
            "packets": 320,
            "bytes": 26000,
            "confidence": 0.97,
            "detection_confidence": 0.97,
            "attack_confidence": 0.86,
            "attack_certainty_level": "probable",
            "attack_primary_class": "Port Scan",
            "attack_detail": _make_attack_detail(
                service,
                summary="Port Scan",
                primary_class="Port Scan",
                confidence=0.86,
                certainty_level="probable",
                certainty_text="Probable: deterministic evidence favors a port-scan pattern.",
            ),
        },
    ]
    service.list_incidents = lambda limit=100: sample_incidents[:limit]  # type: ignore[method-assign]

    capabilities = service.get_hunting_query_capabilities()
    _assert(
        isinstance(capabilities.get("dsl", {}).get("field_allowlist"), list),
        "hunting capabilities must expose DSL field allowlist.",
    )
    _assert(
        capabilities.get("meta", {}).get("query_api", {}).get("get_endpoint") == "/api/hunting/query",
        "hunting capabilities query API metadata is required.",
    )
    _assert(
        "z_score_outliers" in capabilities.get("scientific_methods", {}).get("available", []),
        "hunting capabilities must advertise scientific methods.",
    )
    field_allowlist = capabilities.get("dsl", {}).get("field_allowlist", [])
    _assert(
        "packet_source_ip" in field_allowlist,
        "hunting capabilities must expose packet_source_ip for packet-direction queries.",
    )
    field_semantics = capabilities.get("meta", {}).get("field_semantics", {})
    _assert(
        "attacker" in str(field_semantics.get("source_ip", "")).lower(),
        "hunting capabilities must describe attacker-oriented source_ip semantics.",
    )
    _assert(
        "packet_source_ip" in field_semantics,
        "hunting capabilities must document packet_source_ip semantics.",
    )

    payload = {
        "limit": 10,
        "offset": 0,
        "scan_limit": 20,
        "filters": {
            "source_ips": ["140.82.114.21", "8.8.8.8"],
            "severities": ["HIGH", "CRITICAL"],
            "triage_states": ["open", "in_review"],
            "event_count_gte": 10,
            "attack_confidence_gte": 0.80,
        },
        "dsl": "attack_confidence >= 0.9 and attack_certainty_level == certain",
        "scientific_methods": {
            "enabled": ["z_score_outliers", "temporal_bursts"],
            "max_incidents": 120,
        },
    }
    result = service.query_hunting(payload)
    items = result.get("items", [])
    _assert(
        isinstance(items, list) and len(items) == 1,
        "hunting query should return a deterministic filtered result set.",
    )
    _assert(
        str(items[0].get("id", "")).strip() == "INC-HUNT-001",
        "hunting query filter + DSL intersection should retain only INC-HUNT-001.",
    )
    _assert(
        result.get("query", {}).get("structured_filters_applied") is True,
        "hunting query should report structured_filters_applied.",
    )
    _assert(
        result.get("query", {}).get("dsl_applied") is True,
        "hunting query should report dsl_applied.",
    )
    _assert(
        isinstance(result.get("scientific_methods", {}).get("meta"), dict),
        "hunting query should include scientific methods metadata.",
    )
    source_alias_result = service.query_hunting({"dsl": "source_ip == '140.82.114.21'"})
    source_alias_items = source_alias_result.get("items", [])
    _assert(
        isinstance(source_alias_items, list)
        and len(source_alias_items) == 1
        and str(source_alias_items[0].get("id", "")).strip() == "INC-HUNT-001",
        "source_ip DSL queries must resolve to attacker attribution when attacker_ip exists.",
    )
    _assert(
        str(source_alias_items[0].get("source_ip", "")).strip() == "10.0.0.42",
        "hunting query responses must preserve original incident source_ip payload shape.",
    )

    packet_source_result = service.query_hunting({"dsl": "packet_source_ip == '10.0.0.42'"})
    packet_source_items = packet_source_result.get("items", [])
    _assert(
        isinstance(packet_source_items, list)
        and len(packet_source_items) == 1
        and str(packet_source_items[0].get("id", "")).strip() == "INC-HUNT-001",
        "packet_source_ip DSL queries must preserve access to directional packet source.",
    )

    attacker_ip_result = service.query_hunting({"dsl": "attacker_ip == '140.82.114.21'"})
    attacker_ip_items = attacker_ip_result.get("items", [])
    _assert(
        isinstance(attacker_ip_items, list)
        and len(attacker_ip_items) == 1
        and str(attacker_ip_items[0].get("id", "")).strip() == "INC-HUNT-001",
        "attacker_ip DSL queries must remain supported.",
    )

    source_filter_result = service.query_hunting({"filters": {"source_ips": ["140.82.114.21"]}})
    source_filter_items = source_filter_result.get("items", [])
    _assert(
        isinstance(source_filter_items, list)
        and len(source_filter_items) == 1
        and str(source_filter_items[0].get("id", "")).strip() == "INC-HUNT-001",
        "structured source_ips filtering must use attacker-oriented source semantics.",
    )

    try:
        service.query_hunting({"filters": {"attack_confidence_gte": 0.95, "attack_confidence_lte": 0.10}})
    except ValueError:
        pass
    else:
        raise AssertionError("invalid confidence filter range should raise ValueError")

    try:
        service.query_hunting({"dsl": "attack_confidence === 0.9"})
    except QueryDslError:
        pass
    else:
        raise AssertionError("invalid DSL should raise QueryDslError")


def _run_threat_intel_focus_coverage_case() -> None:
    service = _build_service_stub()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sample_incidents = [
        {
            "id": "INC-MAP-001",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "source_ip": "140.82.114.21",
            "attacker_ip": "140.82.114.21",
            "target_ip": "8.8.8.8",
            "severity": "HIGH",
            "confidence": 0.9,
            "attack_detail": _make_attack_detail(
                service,
                summary="Port Scan",
                primary_class="Port Scan",
                confidence=0.86,
                certainty_level="probable",
                certainty_text="Probable: deterministic evidence points to a port-scan sequence.",
            ),
        },
        {
            "id": "INC-MAP-002",
            "timestamp": (now - timedelta(minutes=3)).isoformat(),
            "source_ip": "1.1.1.1",
            "attacker_ip": "1.1.1.1",
            "target_ip": "10.0.0.50",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "attack_detail": _make_attack_detail(
                service,
                summary="SSH Brute Force",
                primary_class="SSH Brute Force",
                confidence=0.89,
                certainty_level="certain",
                certainty_text="Certain: deterministic evidence confirms SSH brute-force behavior.",
            ),
        },
    ]
    service.list_incidents = lambda limit=100: sample_incidents[:limit]  # type: ignore[method-assign]
    service._threat_intel_lookup_limit = 1
    service._threat_intel_max_map_points = 50

    def _stub_intel(ip: str, provider_status: str) -> dict[str, Any]:
        return {
            "source": "fallback",
            "provider_status": provider_status,
            "scope": service._ip_scope(ip),
            "org": "",
            "isp": "",
            "asn": "",
            "hostnames": [],
            "os": "",
            "last_update": "",
            "open_ports": [],
            "services": [],
            "services_count": 0,
            "vuln_count": 0,
            "vuln_ids": [],
            "vuln_details": [],
            "vuln_severity": {},
            "risk": "unknown",
            "country": "--",
            "city": "--",
            "latitude": None,
            "longitude": None,
            "cache_hit": False,
        }

    service._lookup_threat_intel = lambda ip: _stub_intel(ip, "stub-lookup")  # type: ignore[method-assign]
    service._fallback_threat_intel = lambda ip, reason: _stub_intel(ip, reason)  # type: ignore[method-assign]

    threat_intel = service.get_threat_intel(limit=50)
    map_points = threat_intel.get("map_points", [])
    mapped_ips = {str(point.get("ip")) for point in map_points if isinstance(point, dict)}
    required_public_ips = {"140.82.114.21", "8.8.8.8", "1.1.1.1"}
    missing_ips = required_public_ips.difference(mapped_ips)
    _assert(
        not missing_ips,
        f"threat-intel map points must include public incident-linked focus IPs; missing={sorted(missing_ips)}",
    )
    _assert(
        threat_intel.get("meta", {}).get("lookups_skipped", 0) >= 1,
        "threat-intel metadata should report skipped lookups when lookup limit is reached.",
    )
    _assert(
        threat_intel.get("analytics", {}).get("totals", {}).get("mapped_with_synthetic", 0) >= 1,
        "threat-intel analytics should report synthetic map points when provider coordinates are absent.",
    )


def _run_sparse_evidence_case(engine: AttackTypeRuleEngine) -> None:
    result = engine.classify(
        {
            "target_ports": [22],
            "target_ips": ["10.0.0.5"],
            "event_count": 1,
            "packets": 5,
            "bytes": 4000,
            "protocol": 6,
        },
        ml_confidence=0.91,
        ml_threshold=0.80,
    )
    _validate_stable_shape(result, engine.max_alternatives)
    scoring = result["scoring"]
    _assert(result["label"] == UNKNOWN_LABEL, "Sparse evidence must not assign a named primary class.")
    _assert(float(result["confidence"]) < 0.5, "Sparse evidence should not produce high fallback confidence.")
    _assert(float(scoring["top_score"]) < float(scoring["minimum_score"]), "Sparse case must fail minimum_score gate.")
    _assert(not scoring["gates_passed"], "Sparse case must fail gates.")
    _assert(
        any("Need score >=" in message for message in result["evidence_missing"]),
        "Sparse case should explain minimum_score shortfall.",
    )
    _assert(
        any(candidate["class"] == "SSH Brute Force" for candidate in result["alternatives"]),
        "Sparse case should preserve top candidate as an alternative.",
    )


def _run_margin_gate_case(engine: AttackTypeRuleEngine) -> None:
    result = engine.classify(
        {
            "target_ports": [22, 23, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012],
            "target_ips": ["10.0.0.5"],
            "event_count": 4,
            "packets": 30,
            "bytes": 9000,
            "protocol": 6,
        },
        ml_confidence=0.91,
        ml_threshold=0.80,
    )
    _validate_stable_shape(result, engine.max_alternatives)
    scoring = result["scoring"]
    _assert(result["label"] == UNKNOWN_LABEL, "Margin gate case must fallback to unknown.")
    _assert(float(scoring["top_score"]) >= float(scoring["minimum_score"]), "Margin case should pass score gate.")
    _assert(
        float(scoring["score_margin"]) < float(scoring["minimum_margin"]),
        "Margin case must fail minimum_margin gate.",
    )
    _assert(not scoring["gates_passed"], "Margin case must fail gates.")
    _assert(float(result["confidence"]) < 0.5, "Margin-fallback confidence should remain conservative.")
    _assert(
        any("ambiguous" in message.lower() for message in result["evidence_missing"]),
        "Margin case should report ambiguous evidence.",
    )


def _run_rich_evidence_case(engine: AttackTypeRuleEngine) -> None:
    result = engine.classify(
        {
            "target_ports": [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014],
            "target_ips": ["10.0.0.5", "10.0.0.6"],
            "event_count": 4,
            "packets": 20,
            "bytes": 4000,
            "protocol": 6,
        },
        ml_confidence=0.91,
        ml_threshold=0.80,
    )
    _validate_stable_shape(result, engine.max_alternatives)
    scoring = result["scoring"]
    _assert(result["label"] == "Port Scan", "Rich scan evidence should produce Port Scan classification.")
    _assert(scoring["gates_passed"], "Rich scan case should pass gates.")
    _assert(float(scoring["top_score"]) >= float(scoring["minimum_score"]), "Rich case must pass minimum_score.")
    _assert(
        float(scoring["score_margin"]) >= float(scoring["minimum_margin"]),
        "Rich case must pass minimum_margin.",
    )
    _assert(float(result["confidence"]) >= 0.7, "Rich case should produce confident named class.")
    _assert(
        all(candidate["class"] != result["label"] for candidate in result["alternatives"]),
        "Primary class must not appear in alternatives when gates pass.",
    )


def _run_ssh_temporal_focus_case(engine: AttackTypeRuleEngine) -> None:
    now = datetime.now(timezone.utc)
    result = engine.classify(
        {
            "target_ports": [22],
            "target_ips": ["10.0.0.22"],
            "event_count": 2,
            "packets": 10,
            "bytes": 4000,
            "protocol": 6,
            "events": [
                {
                    "timestamp": now - timedelta(seconds=20),
                    "src_port": 43110,
                    "dst_port": 22,
                    "protocol": 6,
                    "packets": 5,
                    "bytes": 2000,
                },
                {
                    "timestamp": now,
                    "src_port": 43111,
                    "dst_port": 22,
                    "protocol": 6,
                    "packets": 5,
                    "bytes": 2000,
                },
            ],
        },
        ml_confidence=0.94,
        ml_threshold=0.80,
    )
    _validate_stable_shape(result, engine.max_alternatives)
    scoring = result["scoring"]
    _assert(result["label"] == "SSH Brute Force", "Temporal SSH focus case should produce SSH Brute Force.")
    _assert(scoring["gates_passed"], "Temporal SSH focus case should pass gates.")
    _assert(
        any(
            "temporal concentration on ssh-focused events supports brute-force automation"
            in item.lower()
            for item in result["evidence_used"]
        ),
        "Temporal SSH focus case should report timing-focused SSH evidence.",
    )


def _run_adversarial_input_case(engine: AttackTypeRuleEngine) -> None:
    adversarial_alert = {
        "target_ports": "22,80,443",
        "dst_port": "not-a-port",
        "target_ips": "10.0.0.5",
        "dst_ip": "",
        "event_count": -99,
        "packets": -200,
        "bytes": -12000,
        "protocol": "not-a-protocol",
        "events": [
            {"timestamp": "not-a-time", "dst_port": "x", "protocol": "udp"},
            "junk-event-record",
            {"timestamp": None, "dst_port": -1, "protocol": 17},
        ],
    }
    result = engine.classify(adversarial_alert, ml_confidence=0.99, ml_threshold=0.80)
    _validate_stable_shape(result, engine.max_alternatives)
    scoring = result["scoring"]
    _assert(result["label"] == UNKNOWN_LABEL, "Adversarial noisy input must safely fallback to unknown.")
    _assert(
        float(scoring["top_score"]) < float(scoring["minimum_score"]),
        "Adversarial noisy input must remain below minimum_score gate.",
    )
    _assert(
        float(scoring["score_margin"]) >= 0.0,
        "Adversarial noisy input score margin must stay non-negative.",
    )
    _assert(not scoring["gates_passed"], "Adversarial noisy input must fail deterministic gates.")
    _assert(
        float(result["confidence"]) < 0.5,
        "Adversarial noisy fallback confidence should stay conservative.",
    )
    _assert(
        bool(scoring["required_evidence_missing"]),
        "Adversarial noisy input should surface required-evidence gaps.",
    )
    _assert(
        any("Need score >=" in message for message in result["evidence_missing"]),
        "Adversarial noisy input should report score-gate shortfall.",
    )

    for _ in range(8):
        repeated = engine.classify(adversarial_alert, ml_confidence=0.99, ml_threshold=0.80)
        _assert(repeated == result, "Adversarial classification output must remain deterministic across repeats.")


def _run_efficiency_proxy_case(engine: AttackTypeRuleEngine) -> None:
    benchmark_alerts = [
        {
            "target_ports": [22],
            "target_ips": ["10.0.0.5"],
            "event_count": 1,
            "packets": 5,
            "bytes": 4000,
            "protocol": 6,
        },
        {
            "target_ports": [22, 23, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012],
            "target_ips": ["10.0.0.5"],
            "event_count": 4,
            "packets": 30,
            "bytes": 9000,
            "protocol": 6,
        },
        {
            "target_ports": [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014],
            "target_ips": ["10.0.0.5", "10.0.0.6"],
            "event_count": 4,
            "packets": 20,
            "bytes": 4000,
            "protocol": 6,
        },
        {
            "target_ports": "22,80,443",
            "dst_port": "not-a-port",
            "target_ips": "10.0.0.5",
            "dst_ip": "",
            "event_count": -99,
            "packets": -200,
            "bytes": -12000,
            "protocol": "not-a-protocol",
        },
    ]
    baseline = [
        engine.classify(alert, ml_confidence=0.93, ml_threshold=0.80) for alert in benchmark_alerts
    ]
    for _ in range(16):
        for idx, alert in enumerate(benchmark_alerts):
            repeated = engine.classify(alert, ml_confidence=0.93, ml_threshold=0.80)
            _assert(
                repeated == baseline[idx],
                f"deterministic efficiency proxy failed for benchmark alert index {idx}",
            )

    cache_budget = max(0, int(getattr(engine, "_evaluation_cache_size", 0)))
    if cache_budget > 0:
        metrics_cache_size = len(getattr(engine, "_metrics_cache", {}))
        rule_cache_size = len(getattr(engine, "_rule_match_cache", {}))
        _assert(metrics_cache_size <= cache_budget, "metrics cache size exceeded configured cache budget.")
        _assert(rule_cache_size <= cache_budget, "rule-match cache size exceeded configured cache budget.")
        _assert(
            metrics_cache_size >= len(benchmark_alerts),
            "efficiency proxy expected benchmark alerts to be represented in metrics cache.",
        )


def main() -> int:
    engine = _build_engine()
    checks = [
        ("sparse-evidence-gate", _run_sparse_evidence_case),
        ("margin-gate", _run_margin_gate_case),
        ("rich-evidence-pass", _run_rich_evidence_case),
        ("ssh-temporal-focus-pass", _run_ssh_temporal_focus_case),
        ("adversarial-input-gate", _run_adversarial_input_case),
        ("detail-contract-completion", _run_detail_contract_completion_case),
        ("detail-contract-guards", lambda _: _run_detail_contract_guard_case()),
        ("dashboard-contract-regression", lambda _: _run_dashboard_contract_case()),
        ("attack-detail-observability", lambda _: _run_attack_detail_observability_case()),
        ("hunting-query-contract", lambda _: _run_hunting_query_contract_case()),
        ("threat-intel-focus-coverage", lambda _: _run_threat_intel_focus_coverage_case()),
        ("attacker-attribution-resolution", lambda _: _run_attacker_attribution_case()),
        ("efficiency-proxy-determinism", _run_efficiency_proxy_case),
    ]
    for name, check in checks:
        check(engine)
        print(f"[ok] {name}")
    print("[ok] attack-typing metadata regression checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        raise SystemExit(1)
