"""Runtime service layer powering SentinelAI web views and APIs."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
import ipaddress
import socket
import csv
from collections import Counter, defaultdict, deque
import copy
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from common.config_utils import cfg_get, load_runtime_config
from monitoring.packet_sniffer import RealtimeIDS
from web.attack_simulator import AttackSimulator
from web.attack_type_rules import AttackTypeRuleEngine
from web.query_dsl import compile_query
from web.scientific_methods import run_scientific_methods

logger = logging.getLogger(__name__)


def _to_iso(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = _safe_str(value).strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _read_shodan_api_key_from_windows_user_env() -> str:
    if os.name != "nt":
        return ""
    try:
        import winreg
    except ImportError:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as env_key:
            value, _ = winreg.QueryValueEx(env_key, "SHODAN_API_KEY")
    except OSError:
        return ""
    return _safe_str(value).strip()


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _safe_str(item).strip()
        if text:
            normalized.append(text)
    return normalized


def _clamp_confidence(value: Any, default: float = 0.0) -> float:
    numeric = _safe_float(value, default)
    return max(0.0, min(1.0, numeric))


class SentinelAIRuntimeService:
    """Encapsulates IDS lifecycle plus API-ready aggregations."""

    ATTACK_DETAIL_CONTRACT_VERSION = "1.0"
    TRIAGE_STATES = ("open", "in_review", "contained", "dismissed")
    TRIAGE_DEFAULT_STATE = "open"
    ATTACK_DETAIL_REQUIRED_STRING_FIELDS = (
        "summary",
        "primary_class",
        "description",
        "source",
        "note",
        "certainty_text",
    )
    ATTACK_DETAIL_REQUIRED_LIST_FIELDS = (
        "rationale",
        "evidence_used",
        "evidence_missing",
        "limitations",
    )
    ATTACK_DETAIL_LOW_CONFIDENCE_THRESHOLD = 0.5
    ATTACK_DETAIL_FALLBACK_STRINGS = {
        "summary": "Unknown / Needs More Data",
        "primary_class": "Unknown / Needs More Data",
        "description": (
            "Not sure: current telemetry is attack-like but not sufficient for a certain "
            "attack-family narrative."
        ),
        "source": "deterministic-rule-engine:unknown",
        "note": (
            "Not sure: this attack-family assessment is a best guess and should be "
            "validated with additional evidence."
        ),
        "certainty_text": (
            "Not sure: available evidence does not justify certainty for this attack-family "
            "assignment."
        ),
    }
    ATTACK_DETAIL_FALLBACK_LISTS = {
        "rationale": [
            "The engine produced a best-guess classification because deterministic evidence was limited."
        ],
        "evidence_used": ["Best-guess completion used available deterministic scoring context."],
        "evidence_missing": [
            "Additional corroborating evidence is needed before treating this attack-family assignment as certain."
        ],
        "limitations": [
            "Attack-family typing is deterministic and based on configured evidence rules."
        ],
    }
    INCIDENT_EXPORT_COLUMNS = (
        "id",
        "timestamp",
        "attacker_ip",
        "target_ip",
        "target_ips",
        "target_ports",
        "severity",
        "attack_primary_class",
        "attack_summary",
        "attack_confidence",
        "attack_certainty_level",
        "detection_confidence",
        "event_count",
        "packets",
        "bytes",
        "attack_method",
        "attack_description",
        "detection_rationale",
    )
    HUNTING_QUERY_ALLOWED_FIELDS = (
        "id",
        "timestamp",
        "source_ip",
        "packet_source_ip",
        "attacker_ip",
        "target_ip",
        "severity",
        "attack_summary",
        "attack_primary_class",
        "attack_confidence",
        "attack_certainty_level",
        "attack_method",
        "detection_confidence",
        "event_count",
        "packets",
        "bytes",
        "triage_state",
        "attack_detail.summary",
        "attack_detail.primary_class",
        "attack_detail.confidence",
        "attack_detail.method",
        "attack_detail.source",
        "attack_detail.certainty.level",
        "attack_detail.certainty.text",
    )
    HUNTING_QUERY_ALLOWED_OPERATORS = (
        "==",
        "!=",
        ">",
        ">=",
        "<",
        "<=",
        "in",
        "not in",
        "contains",
        "startswith",
        "endswith",
        "is null",
        "is not null",
        "is empty",
        "is non-empty",
        "and",
        "or",
        "not",
    )
    HUNTING_QUERY_MAX_LIMIT = 500
    HUNTING_QUERY_MAX_SCAN = 1200
    HUNTING_QUERY_DEFAULT_LIMIT = 100
    HUNTING_QUERY_DEFAULT_SCAN = 600
    HUNTING_QUERY_MAX_QUERY_LENGTH = 512
    HUNTING_QUERY_MAX_TOKENS = 256
    HUNTING_QUERY_MAX_DEPTH = 16

    def __init__(
        self,
        *,
        model_path: str,
        scaler_path: str,
        encoders_path: str,
        alert_threshold: float,
        interface: str | None,
        web_port: int,
        config_path: str,
        loopback_window_seconds: int,
        loopback_min_distinct_ports_for_scan: int,
        enable_staged_data: bool,
        refresh_interval_seconds: int,
    ) -> None:
        self.interface = interface
        self.web_port = int(web_port)
        self.config_path = config_path
        self.enable_staged_data = bool(enable_staged_data)
        self.refresh_interval_seconds = int(refresh_interval_seconds)
        self._config_lock = threading.Lock()
        self._monitoring_thread: threading.Thread | None = None
        self._threat_intel_lock = threading.Lock()
        runtime_config = self._load_full_config()
        threat_intel_cfg = cfg_get(runtime_config, "runtime.threat_intel", {})
        if not isinstance(threat_intel_cfg, dict):
            threat_intel_cfg = {}
        env_shodan_key = _safe_str(os.getenv("SHODAN_API_KEY")).strip()
        windows_user_env_shodan_key = _read_shodan_api_key_from_windows_user_env()
        cfg_shodan_key = _safe_str(threat_intel_cfg.get("shodan_api_key")).strip()
        if env_shodan_key:
            self._shodan_api_key = env_shodan_key
            self._shodan_key_source = "env"
        elif windows_user_env_shodan_key:
            self._shodan_api_key = windows_user_env_shodan_key
            self._shodan_key_source = "windows-user-env"
        elif cfg_shodan_key:
            self._shodan_api_key = cfg_shodan_key
            self._shodan_key_source = "config"
        else:
            self._shodan_api_key = ""
            self._shodan_key_source = "missing"
        self._threat_intel_lookup_limit = max(1, _safe_int(threat_intel_cfg.get("lookup_limit"), 25))
        self._threat_intel_cache_ttl_seconds = max(30, _safe_int(threat_intel_cfg.get("cache_ttl_seconds"), 900))
        self._threat_intel_timeout_seconds = max(1, _safe_int(threat_intel_cfg.get("timeout_seconds"), 5))
        self._threat_intel_max_services = max(1, _safe_int(threat_intel_cfg.get("max_services_per_host"), 20))
        self._threat_intel_max_vulns = max(1, _safe_int(threat_intel_cfg.get("max_vulns_per_host"), 30))
        self._threat_intel_max_map_points = max(10, _safe_int(threat_intel_cfg.get("max_map_points"), 250))
        self._threat_intel_cache: dict[str, dict[str, Any]] = {}

        self.ids = RealtimeIDS(
            model_path=model_path,
            scaler_path=scaler_path,
            encoders_path=encoders_path,
            alert_threshold=alert_threshold,
            loopback_window_seconds=loopback_window_seconds,
            loopback_min_distinct_ports_for_scan=loopback_min_distinct_ports_for_scan,
        )
        self.ids.set_dashboard_port(self.web_port)
        self.attack_type_engine = AttackTypeRuleEngine.from_runtime_config(self.config_path)
        self.attack_simulator = AttackSimulator()
        self._simulation_sequence = 0
        self._latest_attack_detail_observability = self._empty_attack_detail_observability()
        self._last_attack_detail_observability_signature: str | None = None
        self._triage_lock = threading.Lock()
        self._incident_triage: dict[str, dict[str, str]] = {}

    def start(self) -> None:
        """Start background IDS monitoring once."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        self._monitoring_thread = threading.Thread(
            target=lambda: self.ids.start_monitoring(interface=self.interface),
            daemon=True,
            name="sentinelai-monitor",
        )
        self._monitoring_thread.start()

    def _stats(self) -> dict[str, Any]:
        return self.ids.get_stats()

    def _recent_alerts(self, stats_snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        stats = stats_snapshot if isinstance(stats_snapshot, dict) else self._stats()
        alerts = stats.get("recent_alerts", [])
        if not isinstance(alerts, list):
            return []
        return [dict(alert) for alert in alerts if isinstance(alert, dict)]

    @staticmethod
    def _severity_from_confidence(confidence: float) -> str:
        if confidence >= 0.9:
            return "CRITICAL"
        if confidence >= 0.8:
            return "HIGH"
        if confidence >= 0.65:
            return "MED"
        return "LOW"

    def _classification_details(self, alert: dict[str, Any], confidence: float) -> dict[str, Any]:
        return self.attack_type_engine.classify(
            alert,
            ml_confidence=confidence,
            ml_threshold=float(alert.get("alert_threshold", self.ids.alert_threshold)),
        )

    def _attack_typing_metadata(self) -> dict[str, Any]:
        raw = self.attack_type_engine.metadata()
        if not isinstance(raw, dict):
            raw = {}
        load_error = raw.get("load_error")
        return {
            "source": _safe_str(raw.get("source"), "deterministic-rule-engine:unknown"),
            "schema_version": _safe_str(raw.get("schema_version"), "1.0"),
            "attack_detail_contract_version": self.ATTACK_DETAIL_CONTRACT_VERSION,
            "attack_detail_required_fields": list(self.ATTACK_DETAIL_REQUIRED_STRING_FIELDS)
            + list(self.ATTACK_DETAIL_REQUIRED_LIST_FIELDS),
            "rules_path": _safe_str(raw.get("rules_path"), ""),
            "schema_path": _safe_str(raw.get("schema_path"), ""),
            "minimum_score": _safe_float(raw.get("minimum_score"), 0.0),
            "minimum_margin": _safe_float(raw.get("minimum_margin"), 0.0),
            "fallback_class_id": _safe_str(raw.get("fallback_class_id"), "unknown"),
            "max_alternatives": max(1, _safe_int(raw.get("max_alternatives"), 3)),
            "load_error": _safe_str(load_error) if load_error else None,
        }

    def _normalize_classification_details(self, details: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(details, dict):
            details = {}

        alternatives_raw = details.get("alternatives")
        if not isinstance(alternatives_raw, list):
            alternatives_raw = []
        alternatives: list[dict[str, Any]] = []
        for candidate in alternatives_raw:
            if not isinstance(candidate, dict):
                continue
            alternatives.append(
                {
                    "class": _safe_str(candidate.get("class"), "Unknown / Needs More Data"),
                    "score": _safe_float(candidate.get("score"), 0.0),
                    "confidence": _safe_float(candidate.get("confidence"), 0.0),
                }
            )

        evidence_used_raw = details.get("evidence_used")
        if not isinstance(evidence_used_raw, list):
            evidence_used_raw = []
        evidence_missing_raw = details.get("evidence_missing")
        if not isinstance(evidence_missing_raw, list):
            evidence_missing_raw = []
        limitations_raw = details.get("limitations")
        if not isinstance(limitations_raw, list):
            limitations_raw = []
        rationale_raw = details.get("rationale")
        if not isinstance(rationale_raw, list):
            rationale_raw = []

        scoring = details.get("scoring")
        if not isinstance(scoring, dict):
            scoring = {}
        explanation = details.get("explanation")
        if not isinstance(explanation, dict):
            explanation = {}

        return {
            "label": _safe_str(details.get("label"), "Unknown / Needs More Data"),
            "primary_class": _safe_str(details.get("primary_class"), "Unknown / Needs More Data"),
            "confidence": _safe_float(details.get("confidence"), 0.0),
            "alternatives": alternatives,
            "evidence_used": [_safe_str(item) for item in evidence_used_raw if _safe_str(item)],
            "evidence_missing": [_safe_str(item) for item in evidence_missing_raw if _safe_str(item)],
            "limitations": [_safe_str(item) for item in limitations_raw if _safe_str(item)],
            "description": _safe_str(details.get("description")),
            "rationale": [_safe_str(item) for item in rationale_raw if _safe_str(item)],
            "explanation": {
                "primary_class": _safe_str(
                    explanation.get("primary_class"), _safe_str(details.get("primary_class"))
                ),
                "confidence": _safe_float(
                    explanation.get("confidence"), _safe_float(details.get("confidence"), 0.0)
                ),
                "alternatives": alternatives,
                "evidence_used": [_safe_str(item) for item in evidence_used_raw if _safe_str(item)],
                "evidence_missing": [_safe_str(item) for item in evidence_missing_raw if _safe_str(item)],
                "limitations": [_safe_str(item) for item in limitations_raw if _safe_str(item)],
                "description": _safe_str(explanation.get("description"), _safe_str(details.get("description"))),
            },
            "source": _safe_str(details.get("source"), self._attack_typing_metadata()["source"]),
            "note": _safe_str(details.get("note")),
            "scoring": {
                "top_class": _safe_str(scoring.get("top_class"), "Unknown / Needs More Data"),
                "top_score": _safe_float(scoring.get("top_score"), 0.0),
                "runner_up": _safe_str(scoring.get("runner_up"), "Unknown / Needs More Data"),
                "runner_up_score": _safe_float(scoring.get("runner_up_score"), 0.0),
                "score_margin": _safe_float(scoring.get("score_margin"), 0.0),
                "minimum_score": _safe_float(scoring.get("minimum_score"), 0.0),
                "minimum_margin": _safe_float(scoring.get("minimum_margin"), 0.0),
                "required_evidence_missing": [
                    _safe_str(item)
                    for item in (scoring.get("required_evidence_missing") or [])
                    if _safe_str(item)
                ],
                "gates_passed": bool(scoring.get("gates_passed", False)),
            },
        }

    @staticmethod
    def _normalize_certainty_level(level: str) -> str:
        normalized = level.strip().lower().replace(" ", "_")
        if normalized in {"not_sure", "probable", "certain"}:
            return normalized
        return "not_sure"

    @staticmethod
    def _normalize_attack_alternatives(
        alternatives: Any,
        *,
        primary_class: str = "",
        max_items: int = 3,
    ) -> list[dict[str, Any]]:
        if not isinstance(alternatives, list):
            return []

        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        normalized_primary = _safe_str(primary_class).strip().casefold()
        limit = max(1, _safe_int(max_items, 3))
        for candidate in alternatives:
            if isinstance(candidate, dict):
                class_name = _safe_str(
                    candidate.get("class"),
                    _safe_str(candidate.get("label"), candidate.get("id")),
                ).strip()
                if not class_name:
                    continue
                class_key = class_name.casefold()
                if class_key == normalized_primary or class_key in seen:
                    continue
                score = _safe_float(
                    candidate.get("score"),
                    _safe_float(candidate.get("confidence"), 0.0),
                )
                confidence = _clamp_confidence(
                    candidate.get("confidence"),
                    _clamp_confidence(score, 0.0),
                )
                normalized.append({"class": class_name, "score": score, "confidence": confidence})
                seen.add(class_key)
            elif isinstance(candidate, str):
                class_name = candidate.strip()
                class_key = class_name.casefold()
                if not class_name or class_key == normalized_primary or class_key in seen:
                    continue
                normalized.append({"class": class_name, "score": 0.0, "confidence": 0.0})
                seen.add(class_key)
            if len(normalized) >= limit:
                break
        return normalized

    def _build_attack_detail_contract(
        self,
        *,
        classification_details: dict[str, Any],
        classification_label: str,
        attack_typing_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        details = classification_details if isinstance(classification_details, dict) else {}
        explanation = details.get("explanation")
        if not isinstance(explanation, dict):
            explanation = {}
        scoring = details.get("scoring")
        if not isinstance(scoring, dict):
            scoring = {}

        base_confidence = _clamp_confidence(details.get("confidence"), 0.0)
        fallback_confidence = min(0.49, base_confidence if base_confidence > 0.0 else 0.25)

        def pick_text(
            candidates: list[tuple[Any, str, float]],
            *,
            field: str,
        ) -> tuple[str, str, float]:
            for value, provenance, confidence in candidates:
                text = _safe_str(value).strip()
                if text:
                    return text, provenance, _clamp_confidence(confidence, base_confidence)
            return (
                self.ATTACK_DETAIL_FALLBACK_STRINGS[field],
                f"completion-engine:fallback:{field}",
                fallback_confidence,
            )

        def pick_list(
            candidates: list[tuple[Any, str, float]],
            *,
            field: str,
        ) -> tuple[list[str], str, float]:
            for value, provenance, confidence in candidates:
                items = _string_list(value)
                if items:
                    return items, provenance, _clamp_confidence(confidence, base_confidence)
            return (
                list(self.ATTACK_DETAIL_FALLBACK_LISTS[field]),
                f"completion-engine:fallback:{field}",
                fallback_confidence,
            )

        def dedupe_items(values: list[str]) -> list[str]:
            deduped: list[str] = []
            seen: set[str] = set()
            for value in values:
                text = _safe_str(value).strip()
                if not text or text in seen:
                    continue
                deduped.append(text)
                seen.add(text)
            return deduped

        def append_sentence(base_text: str, addition: str) -> str:
            base = _safe_str(base_text).strip()
            suffix = _safe_str(addition).strip()
            if not suffix:
                return base
            if not base:
                return suffix
            if suffix.lower() in base.lower():
                return base
            spacer = "" if base.endswith((".", "!", "?")) else "."
            return f"{base}{spacer} {suffix}".strip()

        def merge_text_with_matrix(
            value: str,
            provenance: str,
            confidence: float,
            *,
            additions: list[str],
            field: str,
        ) -> tuple[str, str, float]:
            merged = _safe_str(value).strip()
            appended = False
            for addition in additions:
                updated = append_sentence(merged, addition)
                if updated != merged:
                    appended = True
                merged = updated
            if not merged:
                return (
                    self.ATTACK_DETAIL_FALLBACK_STRINGS[field],
                    f"completion-engine:fallback:{field}",
                    fallback_confidence,
                )
            if appended:
                matrix_tag = f"completion-engine:matrix:{field}"
                normalized_provenance = _safe_str(provenance).strip()
                if not normalized_provenance:
                    normalized_provenance = matrix_tag
                elif matrix_tag not in normalized_provenance:
                    normalized_provenance = f"{normalized_provenance}+{matrix_tag}"
                return (
                    merged,
                    normalized_provenance,
                    _clamp_confidence(max(confidence, max(0.45, base_confidence)), fallback_confidence),
                )
            return merged, provenance, confidence

        def merge_list_with_matrix(
            values: list[str],
            provenance: str,
            confidence: float,
            *,
            additions: list[str],
            field: str,
        ) -> tuple[list[str], str, float]:
            base_items = dedupe_items(values)
            matrix_items = dedupe_items(additions)
            merged = dedupe_items(base_items + matrix_items)
            if not merged:
                return (
                    list(self.ATTACK_DETAIL_FALLBACK_LISTS[field]),
                    f"completion-engine:fallback:{field}",
                    fallback_confidence,
                )
            if merged != base_items:
                matrix_tag = f"completion-engine:matrix:{field}"
                normalized_provenance = _safe_str(provenance).strip()
                if not normalized_provenance or self._is_fallback_provenance(normalized_provenance):
                    normalized_provenance = matrix_tag
                elif matrix_tag not in normalized_provenance:
                    normalized_provenance = f"{normalized_provenance}+{matrix_tag}"
                return (
                    merged,
                    normalized_provenance,
                    _clamp_confidence(max(confidence, max(0.45, base_confidence)), fallback_confidence),
                )
            return merged, provenance, confidence

        summary, summary_provenance, summary_confidence = pick_text(
            [
                (details.get("label"), "classification.label", base_confidence),
                (classification_label, "incident.classification", base_confidence),
                (details.get("primary_class"), "classification.primary_class", base_confidence),
            ],
            field="summary",
        )
        primary_class, primary_provenance, primary_confidence = pick_text(
            [
                (details.get("primary_class"), "classification.primary_class", base_confidence),
                (details.get("label"), "classification.label", base_confidence),
                (classification_label, "incident.classification", base_confidence),
            ],
            field="primary_class",
        )

        note_text = _safe_str(details.get("note")).strip()
        note_lower = note_text.lower()
        if note_lower.startswith("certain:"):
            certainty_level = "certain"
            certainty_provenance = "classification.note"
        elif note_lower.startswith("probable:"):
            certainty_level = "probable"
            certainty_provenance = "classification.note"
        elif note_lower.startswith("not sure:") or note_lower.startswith("not_sure:"):
            certainty_level = "not_sure"
            certainty_provenance = "classification.note"
        elif bool(scoring.get("gates_passed", False)) and base_confidence >= 0.6:
            certainty_level = "probable"
            certainty_provenance = "completion-engine:scoring-inference"
        else:
            certainty_level = "not_sure"
            certainty_provenance = "completion-engine:scoring-inference"

        top_class = _safe_str(scoring.get("top_class"), primary_class)
        runner_up_class = _safe_str(scoring.get("runner_up"), "Unknown / Needs More Data")
        top_score = _safe_float(scoring.get("top_score"), 0.0)
        runner_up_score = _safe_float(scoring.get("runner_up_score"), 0.0)
        score_margin = _safe_float(scoring.get("score_margin"), top_score - runner_up_score)
        minimum_score = _safe_float(scoring.get("minimum_score"), 0.0)
        minimum_margin = _safe_float(scoring.get("minimum_margin"), 0.0)
        required_evidence_missing = _string_list(scoring.get("required_evidence_missing"))
        gates_passed = bool(scoring.get("gates_passed", False))

        if not gates_passed and certainty_level != "not_sure":
            certainty_level = "not_sure"
            certainty_provenance = "completion-engine:gate-normalization"

        certainty_text, certainty_text_provenance, certainty_text_confidence = pick_text(
            [
                (
                    (
                        "Certain: explicit evidence-rule criteria were matched for this "
                        f"{primary_class} assignment."
                    )
                    if certainty_level == "certain"
                    else "",
                    "completion-engine:certainty-text",
                    base_confidence,
                ),
                (
                    (
                        f"Probable: {primary_class} is the strongest deterministic match, but "
                        "this remains a best guess."
                    )
                    if certainty_level == "probable"
                    else "",
                    "completion-engine:certainty-text",
                    max(0.45, base_confidence),
                ),
                (
                    (
                        f"Not sure: available evidence is still insufficient to classify "
                        f"{primary_class} with certainty."
                    )
                    if certainty_level == "not_sure"
                    else "",
                    "completion-engine:certainty-text",
                    min(0.49, max(0.2, base_confidence)),
                ),
            ],
            field="certainty_text",
        )

        source, source_provenance, source_confidence = pick_text(
            [
                (details.get("source"), "classification.source", base_confidence),
                (attack_typing_metadata.get("source"), "attack_typing.metadata.source", base_confidence),
            ],
            field="source",
        )

        gate_summary_sentence = (
            "Deterministic evidence gates "
            + ("passed" if gates_passed else "failed")
            + (
                f" (top score {top_score:.2f} vs minimum {minimum_score:.2f}; "
                f"margin {score_margin:.2f} vs minimum {minimum_margin:.2f})."
            )
        )
        method_source_details = (
            f"Detection method/source details: {source}; top class candidate '{top_class}' "
            f"with runner-up '{runner_up_class}'."
        )

        description, description_provenance, description_confidence = pick_text(
            [
                (details.get("description"), "classification.description", base_confidence),
                (explanation.get("description"), "classification.explanation.description", base_confidence),
                (
                    (
                        f"{certainty_text} Current telemetry best aligns with the "
                        f"{primary_class} family."
                    ),
                    "completion-engine:description-fallback",
                    fallback_confidence,
                ),
            ],
            field="description",
        )
        description, description_provenance, description_confidence = merge_text_with_matrix(
            description,
            description_provenance,
            description_confidence,
            additions=[gate_summary_sentence],
            field="description",
        )

        note, note_provenance, note_confidence = pick_text(
            [
                (details.get("note"), "classification.note", base_confidence),
                (
                    f"{certainty_text} Binary ML detection remains separate from family typing.",
                    "completion-engine:note-fallback",
                    fallback_confidence,
                ),
            ],
            field="note",
        )
        if not note.lower().startswith(("certain:", "probable:", "not sure:", "not_sure:")):
            note = f"{certainty_text} {note}".strip()
            note_provenance = (
                f"{note_provenance}+completion-engine:matrix:note-prefix"
                if note_provenance
                else "completion-engine:matrix:note-prefix"
            )
            note_confidence = _clamp_confidence(
                max(note_confidence, max(0.45, base_confidence)),
                fallback_confidence,
            )
        note, note_provenance, note_confidence = merge_text_with_matrix(
            note,
            note_provenance,
            note_confidence,
            additions=[method_source_details, gate_summary_sentence],
            field="note",
        )

        rationale, rationale_provenance, rationale_confidence = pick_list(
            [
                (details.get("rationale"), "classification.rationale", base_confidence),
                (
                    [
                        f"Primary class best guess: {primary_class}.",
                        certainty_text,
                        "Deterministic scoring and evidence completeness were used for this completion.",
                    ],
                    "completion-engine:rationale-fallback",
                    fallback_confidence,
                ),
            ],
            field="rationale",
        )
        rationale, rationale_provenance, rationale_confidence = merge_list_with_matrix(
            rationale,
            rationale_provenance,
            rationale_confidence,
            additions=[
                method_source_details,
                gate_summary_sentence,
                f"Uncertainty notes: {certainty_text}",
            ],
            field="rationale",
        )

        evidence_used, evidence_used_provenance, evidence_used_confidence = pick_list(
            [
                (details.get("evidence_used"), "classification.evidence_used", base_confidence),
                (explanation.get("evidence_used"), "classification.explanation.evidence_used", base_confidence),
                (
                    [f"Deterministic top-class candidate was resolved as {primary_class}."],
                    "completion-engine:evidence-used-fallback",
                    fallback_confidence,
                ),
            ],
            field="evidence_used",
        )
        evidence_used_matrix_additions = [
            f"Top candidate '{top_class}' scored {top_score:.2f}.",
            (
                f"Runner-up '{runner_up_class}' scored {runner_up_score:.2f}; "
                f"margin observed {score_margin:.2f}."
            ),
        ]
        if gates_passed:
            evidence_used_matrix_additions.append(
                "Deterministic score and margin gates passed for the assigned class."
            )
        evidence_used, evidence_used_provenance, evidence_used_confidence = merge_list_with_matrix(
            evidence_used,
            evidence_used_provenance,
            evidence_used_confidence,
            additions=evidence_used_matrix_additions,
            field="evidence_used",
        )

        evidence_missing, evidence_missing_provenance, evidence_missing_confidence = pick_list(
            [
                (details.get("evidence_missing"), "classification.evidence_missing", base_confidence),
                (
                    explanation.get("evidence_missing"),
                    "classification.explanation.evidence_missing",
                    base_confidence,
                ),
                (
                    list(self.ATTACK_DETAIL_FALLBACK_LISTS["evidence_missing"]),
                    "completion-engine:evidence-missing-fallback",
                    fallback_confidence,
                ),
            ],
            field="evidence_missing",
        )
        missing_matrix_additions: list[str] = []
        if required_evidence_missing:
            missing_matrix_additions.append(
                "Missing required evidence ids for deterministic gating: "
                + ", ".join(required_evidence_missing)
                + "."
            )
        if top_score < minimum_score:
            missing_matrix_additions.append(
                f"Need top score >= {minimum_score:.2f}; observed {top_score:.2f}."
            )
        if score_margin < minimum_margin:
            missing_matrix_additions.append(
                f"Need top-vs-runner-up margin >= {minimum_margin:.2f}; observed {score_margin:.2f}."
            )
        if not gates_passed and not missing_matrix_additions:
            missing_matrix_additions.append(
                "Deterministic evidence gates failed, so more corroborating evidence is required."
            )
        if gates_passed and self._is_fallback_provenance(evidence_missing_provenance):
            evidence_missing = []
            evidence_missing_provenance = "completion-engine:matrix:evidence_missing"
            evidence_missing_confidence = _clamp_confidence(
                max(evidence_missing_confidence, max(0.45, base_confidence)),
                fallback_confidence,
            )
            missing_matrix_additions.append(
                "No mandatory deterministic evidence gaps were detected; additional corroboration may still improve confidence."
            )
        evidence_missing, evidence_missing_provenance, evidence_missing_confidence = merge_list_with_matrix(
            evidence_missing,
            evidence_missing_provenance,
            evidence_missing_confidence,
            additions=missing_matrix_additions,
            field="evidence_missing",
        )

        limitations, limitations_provenance, limitations_confidence = pick_list(
            [
                (details.get("limitations"), "classification.limitations", base_confidence),
                (explanation.get("limitations"), "classification.explanation.limitations", base_confidence),
                (
                    list(self.ATTACK_DETAIL_FALLBACK_LISTS["limitations"]),
                    "completion-engine:limitations-fallback",
                    fallback_confidence,
                ),
            ],
            field="limitations",
        )
        limitations_matrix_additions = [
            "Attack-family typing is deterministic and based on configured evidence rules.",
            "Binary ML detection (attack vs normal) remains independent from family assignment.",
        ]
        if not gates_passed:
            limitations_matrix_additions.append(
                "Gate failures indicate that family assignment should be treated as provisional."
            )
        limitations, limitations_provenance, limitations_confidence = merge_list_with_matrix(
            limitations,
            limitations_provenance,
            limitations_confidence,
            additions=limitations_matrix_additions,
            field="limitations",
        )

        max_alternatives = max(1, _safe_int(attack_typing_metadata.get("max_alternatives"), 3))
        return {
            "contract_version": self.ATTACK_DETAIL_CONTRACT_VERSION,
            "summary": summary,
            "primary_class": primary_class,
            "description": description,
            "source": source,
            "method": source,
            "note": note,
            "confidence": base_confidence,
            "certainty_text": certainty_text,
            "certainty": {
                "level": self._normalize_certainty_level(certainty_level),
                "text": certainty_text,
            },
            "alternatives": self._normalize_attack_alternatives(
                details.get("alternatives"),
                primary_class=primary_class,
                max_items=max_alternatives,
            ),
            "rationale": rationale,
            "evidence_used": evidence_used,
            "evidence_missing": evidence_missing,
            "evidence": {
                "used": evidence_used,
                "missing": evidence_missing,
            },
            "limitations": limitations,
            "field_metadata": {
                "summary": {
                    "provenance": summary_provenance,
                    "confidence": summary_confidence,
                },
                "primary_class": {
                    "provenance": primary_provenance,
                    "confidence": primary_confidence,
                },
                "description": {
                    "provenance": description_provenance,
                    "confidence": description_confidence,
                },
                "source": {
                    "provenance": source_provenance,
                    "confidence": source_confidence,
                },
                "note": {
                    "provenance": note_provenance,
                    "confidence": note_confidence,
                },
                "certainty_text": {
                    "provenance": (
                        "classification.note"
                        if certainty_text_provenance == "completion-engine:certainty-text"
                        and certainty_provenance == "classification.note"
                        else certainty_text_provenance
                    ),
                    "confidence": certainty_text_confidence,
                },
                "rationale": {
                    "provenance": rationale_provenance,
                    "confidence": rationale_confidence,
                },
                "evidence_used": {
                    "provenance": evidence_used_provenance,
                    "confidence": evidence_used_confidence,
                },
                "evidence_missing": {
                    "provenance": evidence_missing_provenance,
                    "confidence": evidence_missing_confidence,
                },
                "limitations": {
                    "provenance": limitations_provenance,
                    "confidence": limitations_confidence,
                },
            },
        }

    def _validate_attack_detail_response(self, attack_detail: dict[str, Any]) -> dict[str, Any]:
        detail = dict(attack_detail) if isinstance(attack_detail, dict) else {}
        detail["contract_version"] = self.ATTACK_DETAIL_CONTRACT_VERSION
        detail["confidence"] = _clamp_confidence(detail.get("confidence"), 0.0)

        field_metadata = detail.get("field_metadata")
        if not isinstance(field_metadata, dict):
            field_metadata = {}

        def dedupe_items(values: list[str]) -> list[str]:
            deduped: list[str] = []
            seen: set[str] = set()
            for value in values:
                text = _safe_str(value).strip()
                key = text.casefold()
                if not text or key in seen:
                    continue
                deduped.append(text)
                seen.add(key)
            return deduped

        def append_sentence(base_text: str, addition: str) -> str:
            base = _safe_str(base_text).strip()
            suffix = _safe_str(addition).strip()
            if not suffix:
                return base
            if not base:
                return suffix
            if suffix.lower() in base.lower():
                return base
            spacer = "" if base.endswith((".", "!", "?")) else "."
            return f"{base}{spacer} {suffix}".strip()

        def strip_certainty_prefix(text: str) -> str:
            normalized = _safe_str(text).strip()
            lowered = normalized.lower()
            for prefix in ("certain:", "probable:", "not sure:", "not_sure:"):
                if lowered.startswith(prefix):
                    return normalized[len(prefix) :].strip()
            return normalized

        def certainty_prefix(level: str) -> str:
            if level == "certain":
                return "Certain:"
            if level == "probable":
                return "Probable:"
            return "Not sure:"

        def certainty_level_from_text(text: str) -> str | None:
            normalized = _safe_str(text).strip().lower()
            if not normalized:
                return None
            if normalized.startswith("certain:"):
                return "certain"
            if normalized.startswith("probable:"):
                return "probable"
            if normalized.startswith("not sure:") or normalized.startswith("not_sure:"):
                return "not_sure"
            if any(
                marker in normalized
                for marker in (
                    "not sure",
                    "insufficient",
                    "uncertain",
                    "inconclusive",
                    "ambiguous",
                    "needs more data",
                )
            ):
                return "not_sure"
            if any(marker in normalized for marker in ("probable", "likely", "best guess")):
                return "probable"
            if any(marker in normalized for marker in ("confirmed", "definitive", "certain")):
                return "certain"
            return None

        def is_unknown_class(value: str) -> bool:
            normalized = _safe_str(value).strip().lower()
            return not normalized or "unknown" in normalized or "needs more data" in normalized

        def has_material_evidence_gap(values: list[str]) -> bool:
            for value in values:
                lowered = value.lower()
                if "no mandatory deterministic evidence gaps were detected" in lowered:
                    continue
                if any(
                    marker in lowered
                    for marker in (
                        "need ",
                        "needs ",
                        "missing",
                        "insufficient",
                        "failed",
                        "ambiguous",
                        "required evidence",
                        "not enough",
                    )
                ):
                    return True
            return False

        def mark_guarded(field: str, *, confidence_cap: float | None = None) -> None:
            metadata = field_metadata.get(field)
            if not isinstance(metadata, dict):
                metadata = {}
            provenance = _safe_str(metadata.get("provenance")).strip()
            guard_tag = "response-validator:coherence-guard"
            if guard_tag not in provenance:
                provenance = f"{provenance}+{guard_tag}" if provenance else guard_tag
            confidence = _clamp_confidence(metadata.get("confidence"), detail["confidence"])
            if confidence_cap is not None:
                confidence = min(confidence, confidence_cap)
            field_metadata[field] = {"provenance": provenance, "confidence": confidence}

        def ensure_text(field: str) -> None:
            text = _safe_str(detail.get(field)).strip()
            metadata = field_metadata.get(field)
            if not isinstance(metadata, dict):
                metadata = {}
            provenance = _safe_str(metadata.get("provenance")).strip()
            confidence = _clamp_confidence(metadata.get("confidence"), detail["confidence"])

            if not text:
                text = self.ATTACK_DETAIL_FALLBACK_STRINGS[field]
                provenance = f"response-validator:{field}"
                confidence = min(0.35, detail["confidence"] if detail["confidence"] > 0 else 0.2)
            elif not provenance:
                provenance = "response-validator:provenance-backfill"

            detail[field] = text
            field_metadata[field] = {"provenance": provenance, "confidence": confidence}

        def ensure_list(field: str) -> None:
            items = _string_list(detail.get(field))
            metadata = field_metadata.get(field)
            if not isinstance(metadata, dict):
                metadata = {}
            provenance = _safe_str(metadata.get("provenance")).strip()
            confidence = _clamp_confidence(metadata.get("confidence"), detail["confidence"])

            if not items:
                items = list(self.ATTACK_DETAIL_FALLBACK_LISTS[field])
                provenance = f"response-validator:{field}"
                confidence = min(0.35, detail["confidence"] if detail["confidence"] > 0 else 0.2)
            elif not provenance:
                provenance = "response-validator:provenance-backfill"

            detail[field] = items
            field_metadata[field] = {"provenance": provenance, "confidence": confidence}

        for field in self.ATTACK_DETAIL_REQUIRED_STRING_FIELDS:
            ensure_text(field)
        for field in self.ATTACK_DETAIL_REQUIRED_LIST_FIELDS:
            ensure_list(field)

        detail["rationale"] = dedupe_items(_string_list(detail["rationale"]))
        detail["evidence_used"] = dedupe_items(_string_list(detail["evidence_used"]))
        detail["evidence_missing"] = dedupe_items(_string_list(detail["evidence_missing"]))
        detail["limitations"] = dedupe_items(_string_list(detail["limitations"]))
        detail["alternatives"] = self._normalize_attack_alternatives(
            detail.get("alternatives"),
            primary_class=detail["primary_class"],
            max_items=max(1, _safe_int(self._attack_typing_metadata().get("max_alternatives"), 3)),
        )

        certainty = detail.get("certainty")
        if not isinstance(certainty, dict):
            certainty = {}
        certainty_level = self._normalize_certainty_level(_safe_str(certainty.get("level")))
        certainty_text = _safe_str(certainty.get("text"), detail["certainty_text"]).strip()
        if not certainty_text:
            certainty_text = detail["certainty_text"]
        parsed_text_level = certainty_level_from_text(certainty_text)
        if parsed_text_level and self._certainty_level_rank(parsed_text_level) < self._certainty_level_rank(
            certainty_level
        ):
            certainty_level = parsed_text_level

        if certainty_level == "certain":
            note_text = detail["note"].lower()
            rationale_text = " ".join(detail["rationale"]).lower()
            explicit_rule_justification = (
                "explicit certainty evidence rules matched" in note_text
                or "explicit evidence-rule criteria were matched" in note_text
                or "explicit certainty evidence rules matched" in rationale_text
                or "explicit evidence-rule criteria were matched" in rationale_text
            )
            if not explicit_rule_justification:
                certainty_level = "probable"
                certainty_text = (
                    f"Probable: {detail['primary_class']} is the best deterministic match, "
                    "but explicit certainty-rule justification is missing."
                )
                mark_guarded("certainty_text", confidence_cap=0.89)
                mark_guarded("note", confidence_cap=0.89)

        confidence = detail["confidence"]
        if confidence < 0.5 and certainty_level != "not_sure":
            certainty_level = "not_sure"
            mark_guarded("certainty_text", confidence_cap=0.59)
        elif confidence < 0.85 and certainty_level == "certain":
            certainty_level = "probable"
            mark_guarded("certainty_text", confidence_cap=0.89)

        if is_unknown_class(detail["primary_class"]) and certainty_level != "not_sure":
            certainty_level = "not_sure"
            mark_guarded("certainty_text", confidence_cap=0.59)
            mark_guarded("note", confidence_cap=0.59)

        evidence_missing = detail["evidence_missing"]
        material_gap = has_material_evidence_gap(evidence_missing)
        if material_gap and certainty_level == "certain":
            certainty_level = "probable" if confidence >= 0.65 else "not_sure"
            mark_guarded("certainty_text", confidence_cap=0.89 if certainty_level == "probable" else 0.59)
            mark_guarded("note", confidence_cap=0.89 if certainty_level == "probable" else 0.59)

        if certainty_level == "not_sure" and not material_gap:
            evidence_missing = dedupe_items(
                evidence_missing
                + ["Available evidence is still insufficient for certain family assignment."]
            )
            detail["evidence_missing"] = evidence_missing
            material_gap = True
            mark_guarded("evidence_missing", confidence_cap=0.59)

        certainty_body = strip_certainty_prefix(certainty_text)
        if not certainty_body:
            if certainty_level == "certain":
                certainty_body = (
                    f"explicit evidence-rule criteria were matched for this {detail['primary_class']} assignment."
                )
            elif certainty_level == "probable":
                certainty_body = (
                    f"{detail['primary_class']} is the strongest deterministic match, but this remains a best guess."
                )
            else:
                certainty_body = (
                    "available evidence is still insufficient for certain family assignment."
                )
        if not is_unknown_class(detail["primary_class"]) and detail["primary_class"].lower() not in certainty_body.lower():
            certainty_body = append_sentence(
                certainty_body,
                f"Current best class assignment is {detail['primary_class']}.",
            )
        if certainty_level == "not_sure":
            certainty_body = append_sentence(
                certainty_body,
                "Treat this family assignment as provisional until missing evidence is resolved.",
            )
            if detail["confidence"] > 0.59:
                detail["confidence"] = 0.59
                mark_guarded("certainty_text", confidence_cap=0.59)
        elif certainty_level == "probable" and detail["confidence"] > 0.89:
            detail["confidence"] = 0.89
            mark_guarded("certainty_text", confidence_cap=0.89)

        certainty_text = f"{certainty_prefix(certainty_level)} {certainty_body}".strip()

        note_body = strip_certainty_prefix(detail["note"])
        if not note_body:
            note_body = "Binary ML detection remains separate from family typing."
        if certainty_level != "certain":
            note_body = append_sentence(
                note_body,
                "This family assignment should be treated as a best guess until corroborated.",
            )
        detail["note"] = f"{certainty_prefix(certainty_level)} {note_body}".strip()

        rationale = detail["rationale"]
        if not any("uncertainty notes:" in item.lower() for item in rationale):
            rationale.append(f"Uncertainty notes: {certainty_text}")
            mark_guarded("rationale")
        if material_gap and not any(
            marker in " ".join(rationale).lower() for marker in ("missing evidence", "insufficient")
        ):
            rationale.append("Missing evidence currently limits deterministic certainty for this class assignment.")
            mark_guarded("rationale")
        rationale = dedupe_items(rationale)
        detail["rationale"] = rationale

        limitations = detail["limitations"]
        if not any("deterministic" in item.lower() and "rule" in item.lower() for item in limitations):
            limitations.append("Attack-family typing is deterministic and based on configured evidence rules.")
            mark_guarded("limitations")
        if material_gap and not any(
            marker in item.lower()
            for item in limitations
            for marker in ("provisional", "missing evidence", "additional evidence")
        ):
            limitations.append("Family assignment remains provisional until missing evidence is resolved.")
            mark_guarded("limitations")
        detail["limitations"] = dedupe_items(limitations)

        detail["certainty_text"] = certainty_text
        detail["certainty"] = {"level": certainty_level, "text": certainty_text}
        detail["method"] = _safe_str(detail.get("method"), detail["source"]).strip() or detail["source"]
        field_metadata["certainty_text"] = {
            "provenance": _safe_str(field_metadata.get("certainty_text", {}).get("provenance")).strip()
            or "response-validator:certainty",
            "confidence": _clamp_confidence(
                field_metadata.get("certainty_text", {}).get("confidence"),
                detail["confidence"],
            ),
        }
        source_metadata = field_metadata.get("source")
        if not isinstance(source_metadata, dict):
            source_metadata = {}
        method_metadata = field_metadata.get("method")
        if not isinstance(method_metadata, dict):
            method_metadata = {}
        method_provenance = _safe_str(method_metadata.get("provenance")).strip()
        if not method_provenance:
            method_provenance = _safe_str(source_metadata.get("provenance")).strip() or "response-validator:method-alias"
        method_confidence = _clamp_confidence(
            method_metadata.get("confidence"),
            _clamp_confidence(source_metadata.get("confidence"), detail["confidence"]),
        )
        field_metadata["method"] = {
            "provenance": method_provenance,
            "confidence": method_confidence,
        }

        detail["evidence"] = {
            "used": list(detail["evidence_used"]),
            "missing": list(detail["evidence_missing"]),
        }
        detail["field_metadata"] = field_metadata
        return detail

    def _classification(self, alert: dict[str, Any], confidence: float) -> str:
        return self._classification_details(alert, confidence)["label"]

    @staticmethod
    def _certainty_level_rank(level: str) -> int:
        normalized = level.strip().lower().replace(" ", "_")
        if normalized == "certain":
            return 2
        if normalized == "probable":
            return 1
        return 0

    def _certainty_counts_from_counter(self, counts: Counter[str]) -> dict[str, int]:
        return {
            "certain": _safe_int(counts.get("certain"), 0),
            "probable": _safe_int(counts.get("probable"), 0),
            "not_sure": _safe_int(counts.get("not_sure"), 0),
        }

    def _dominant_certainty_level(self, counts: Counter[str]) -> str:
        best_level = "not_sure"
        best_score = (-1, -1)
        for raw_level in ("not_sure", "probable", "certain"):
            level = self._normalize_certainty_level(raw_level)
            score = (
                _safe_int(counts.get(level), 0),
                self._certainty_level_rank(level),
            )
            if score > best_score:
                best_level = level
                best_score = score
        return best_level

    def _incident_attack_detail(self, incident: dict[str, Any]) -> dict[str, Any]:
        safe_incident = incident if isinstance(incident, dict) else {}
        attack_detail = safe_incident.get("attack_detail")
        if isinstance(attack_detail, dict):
            return self._validate_attack_detail_response(attack_detail)

        legacy_certainty = safe_incident.get("classification_certainty")
        if isinstance(legacy_certainty, dict):
            certainty_level = self._normalize_certainty_level(_safe_str(legacy_certainty.get("level")))
            certainty_text = _safe_str(legacy_certainty.get("text"))
        else:
            certainty_level = "not_sure"
            certainty_text = ""

        legacy_confidence = _clamp_confidence(
            safe_incident.get("classification_confidence"),
            _clamp_confidence(
                safe_incident.get("attack_confidence"),
                _clamp_confidence(safe_incident.get("confidence"), 0.0),
            ),
        )
        legacy_summary = _safe_str(
            safe_incident.get("classification"),
            self.ATTACK_DETAIL_FALLBACK_STRINGS["summary"],
        )
        legacy_primary = _safe_str(
            safe_incident.get("classification_primary"),
            _safe_str(safe_incident.get("attack_primary_class"), legacy_summary),
        )
        fallback_detail = {
            "summary": legacy_summary or self.ATTACK_DETAIL_FALLBACK_STRINGS["summary"],
            "primary_class": legacy_primary or self.ATTACK_DETAIL_FALLBACK_STRINGS["primary_class"],
            "description": _safe_str(
                safe_incident.get("attack_description"),
                self.ATTACK_DETAIL_FALLBACK_STRINGS["description"],
            ),
            "source": _safe_str(
                safe_incident.get("classification_source"),
                self.ATTACK_DETAIL_FALLBACK_STRINGS["source"],
            ),
            "method": _safe_str(
                safe_incident.get("classification_source"),
                self.ATTACK_DETAIL_FALLBACK_STRINGS["source"],
            ),
            "note": _safe_str(
                safe_incident.get("classification_note"),
                self.ATTACK_DETAIL_FALLBACK_STRINGS["note"],
            ),
            "confidence": legacy_confidence,
            "certainty_text": certainty_text or self.ATTACK_DETAIL_FALLBACK_STRINGS["certainty_text"],
            "certainty": {
                "level": certainty_level,
                "text": certainty_text or self.ATTACK_DETAIL_FALLBACK_STRINGS["certainty_text"],
            },
            "alternatives": self._normalize_attack_alternatives(
                safe_incident.get("classification_alternatives"),
                primary_class=legacy_primary,
                max_items=max(1, _safe_int(self._attack_typing_metadata().get("max_alternatives"), 3)),
            ),
            "rationale": list(_string_list(safe_incident.get("detection_rationale"))),
            "evidence_used": list(_string_list(safe_incident.get("classification_evidence_used"))),
            "evidence_missing": list(_string_list(safe_incident.get("classification_evidence_missing"))),
            "limitations": list(_string_list(safe_incident.get("classification_limitations"))),
            "field_metadata": {},
        }
        return self._validate_attack_detail_response(fallback_detail)

    def _incident_attack_primary_class(self, incident: dict[str, Any]) -> str:
        detail = self._incident_attack_detail(incident)
        return _safe_str(
            detail.get("primary_class"),
            _safe_str(detail.get("summary"), "Unknown / Needs More Data"),
        )

    def _incident_attack_confidence(self, incident: dict[str, Any]) -> float:
        detail = self._incident_attack_detail(incident)
        return _clamp_confidence(
            detail.get("confidence"),
            _clamp_confidence(
                incident.get("classification_confidence"),
                _clamp_confidence(incident.get("confidence"), 0.0),
            ),
        )

    @staticmethod
    def _incident_detection_confidence(incident: dict[str, Any]) -> float:
        return _clamp_confidence(
            incident.get("detection_confidence"),
            _clamp_confidence(incident.get("confidence"), 0.0),
        )

    def _incident_attack_certainty(self, incident: dict[str, Any]) -> dict[str, str]:
        detail = self._incident_attack_detail(incident)
        certainty = detail.get("certainty")
        if not isinstance(certainty, dict):
            certainty = {}
        level = self._normalize_certainty_level(_safe_str(certainty.get("level"), "not_sure"))
        text = _safe_str(certainty.get("text"), _safe_str(detail.get("certainty_text")))
        if not text:
            text = self.ATTACK_DETAIL_FALLBACK_STRINGS["certainty_text"]
        return {"level": level, "text": text}

    @staticmethod
    def _counter_to_sorted_dict(counter: Counter[str]) -> dict[str, int]:
        return {key: int(counter[key]) for key in sorted(counter)}

    @staticmethod
    def _is_fallback_provenance(provenance: str) -> bool:
        normalized = provenance.strip().lower()
        return "fallback" in normalized or normalized.startswith("response-validator:")

    def _empty_attack_detail_observability(self) -> dict[str, Any]:
        return {
            "incident_count": 0,
            "incidents_with_fallback_fields": 0,
            "incidents_with_low_confidence_fields": 0,
            "low_confidence_threshold": self.ATTACK_DETAIL_LOW_CONFIDENCE_THRESHOLD,
            "provenance_source_usage": {},
            "classification_source_usage": {},
            "rule_hit_coverage": {
                "scored_incident_count": 0,
                "incidents_with_rule_hits": 0,
                "incidents_with_gates_passed": 0,
                "rule_hit_rate_pct": 0.0,
                "gate_pass_rate_pct": 0.0,
                "top_class_usage": {},
            },
            "gate_failure_distribution": {
                "scored_incident_count": 0,
                "incidents_with_any_gate_failure": 0,
                "score_gate_failures": 0,
                "margin_gate_failures": 0,
                "required_evidence_missing_failures": 0,
                "ambiguity_failures": 0,
            },
            "fallback_field_usage": {},
            "low_confidence_field_usage": {},
            "enrichment_latency_ms": {
                "count": 0,
                "missing_count": 0,
                "avg": 0.0,
                "p95": 0.0,
                "min": 0.0,
                "max": 0.0,
            },
        }

    def _summarize_attack_detail_observability(
        self,
        incidents: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tracked_fields = list(self.ATTACK_DETAIL_REQUIRED_STRING_FIELDS) + list(
            self.ATTACK_DETAIL_REQUIRED_LIST_FIELDS
        )
        provenance_source_usage: Counter[str] = Counter()
        classification_source_usage: Counter[str] = Counter()
        top_class_usage: Counter[str] = Counter()
        fallback_field_usage: Counter[str] = Counter()
        low_confidence_field_usage: Counter[str] = Counter()
        incidents_with_fallback_fields = 0
        incidents_with_low_confidence_fields = 0
        scored_incident_count = 0
        incidents_with_rule_hits = 0
        incidents_with_gates_passed = 0
        incidents_with_any_gate_failure = 0
        score_gate_failures = 0
        margin_gate_failures = 0
        required_evidence_missing_failures = 0
        ambiguity_failures = 0
        enrichment_latency_ms_samples: list[float] = []

        for incident in incidents:
            attack_detail = incident.get("attack_detail")
            if not isinstance(attack_detail, dict):
                continue
            classification_source = _safe_str(
                incident.get("classification_source"),
                _safe_str(attack_detail.get("source"), "unknown"),
            ).strip()
            classification_source_usage[classification_source or "unknown"] += 1

            scoring = incident.get("classification_scoring")
            if not isinstance(scoring, dict):
                scoring = {}
            if any(
                key in scoring
                for key in (
                    "top_score",
                    "minimum_score",
                    "score_margin",
                    "minimum_margin",
                    "required_evidence_missing",
                    "gates_passed",
                )
            ):
                scored_incident_count += 1
                top_class = _safe_str(
                    scoring.get("top_class"),
                    _safe_str(
                        incident.get("classification_primary"),
                        _safe_str(attack_detail.get("primary_class")),
                    ),
                )
                if top_class:
                    top_class_usage[top_class] += 1
                top_score = _safe_float(scoring.get("top_score"), 0.0)
                minimum_score = _safe_float(scoring.get("minimum_score"), 0.0)
                score_margin = _safe_float(scoring.get("score_margin"), 0.0)
                minimum_margin = _safe_float(scoring.get("minimum_margin"), 0.0)
                required_evidence_missing = _string_list(scoring.get("required_evidence_missing"))
                gates_passed = bool(scoring.get("gates_passed", False))
                if top_score > 0.0:
                    incidents_with_rule_hits += 1
                if gates_passed:
                    incidents_with_gates_passed += 1
                else:
                    score_gate_failed = top_score < minimum_score
                    margin_gate_failed = score_margin < minimum_margin
                    required_evidence_missing_failed = bool(required_evidence_missing)
                    evidence_missing_messages = _string_list(
                        incident.get(
                            "classification_evidence_missing",
                            attack_detail.get("evidence_missing"),
                        )
                    )
                    ambiguity_failed = margin_gate_failed or any(
                        "ambiguous" in message.lower() for message in evidence_missing_messages
                    )

                    if score_gate_failed:
                        score_gate_failures += 1
                    if margin_gate_failed:
                        margin_gate_failures += 1
                    if required_evidence_missing_failed:
                        required_evidence_missing_failures += 1
                    if ambiguity_failed:
                        ambiguity_failures += 1
                    if (
                        score_gate_failed
                        or margin_gate_failed
                        or required_evidence_missing_failed
                        or ambiguity_failed
                    ):
                        incidents_with_any_gate_failure += 1

            enrichment_latency_ms = _safe_float(incident.get("enrichment_latency_ms"), -1.0)
            if enrichment_latency_ms >= 0.0:
                enrichment_latency_ms_samples.append(round(enrichment_latency_ms, 3))

            field_metadata = attack_detail.get("field_metadata")
            if not isinstance(field_metadata, dict):
                continue

            saw_fallback = False
            saw_low_confidence = False
            for field in tracked_fields:
                metadata = field_metadata.get(field)
                if not isinstance(metadata, dict):
                    metadata = {}

                provenance = _safe_str(metadata.get("provenance"), "unknown")
                provenance_source_usage[provenance] += 1
                confidence = _clamp_confidence(metadata.get("confidence"), 0.0)

                if confidence < self.ATTACK_DETAIL_LOW_CONFIDENCE_THRESHOLD:
                    low_confidence_field_usage[field] += 1
                    saw_low_confidence = True

                if self._is_fallback_provenance(provenance):
                    fallback_field_usage[field] += 1
                    saw_fallback = True

            if saw_fallback:
                incidents_with_fallback_fields += 1
            if saw_low_confidence:
                incidents_with_low_confidence_fields += 1

        if enrichment_latency_ms_samples:
            sorted_latency = sorted(enrichment_latency_ms_samples)
            latency_count = len(sorted_latency)
            latency_p95_index = min(latency_count - 1, round((latency_count - 1) * 0.95))
            latency_summary = {
                "count": latency_count,
                "missing_count": max(0, len(incidents) - latency_count),
                "avg": round(sum(sorted_latency) / latency_count, 3),
                "p95": round(sorted_latency[latency_p95_index], 3),
                "min": round(sorted_latency[0], 3),
                "max": round(sorted_latency[-1], 3),
            }
        else:
            latency_summary = {
                "count": 0,
                "missing_count": len(incidents),
                "avg": 0.0,
                "p95": 0.0,
                "min": 0.0,
                "max": 0.0,
            }
        rule_hit_rate_pct = (
            round((incidents_with_rule_hits / scored_incident_count) * 100.0, 3)
            if scored_incident_count
            else 0.0
        )
        gate_pass_rate_pct = (
            round((incidents_with_gates_passed / scored_incident_count) * 100.0, 3)
            if scored_incident_count
            else 0.0
        )
        return {
            "incident_count": len(incidents),
            "incidents_with_fallback_fields": incidents_with_fallback_fields,
            "incidents_with_low_confidence_fields": incidents_with_low_confidence_fields,
            "low_confidence_threshold": self.ATTACK_DETAIL_LOW_CONFIDENCE_THRESHOLD,
            "provenance_source_usage": self._counter_to_sorted_dict(provenance_source_usage),
            "classification_source_usage": self._counter_to_sorted_dict(classification_source_usage),
            "rule_hit_coverage": {
                "scored_incident_count": scored_incident_count,
                "incidents_with_rule_hits": incidents_with_rule_hits,
                "incidents_with_gates_passed": incidents_with_gates_passed,
                "rule_hit_rate_pct": rule_hit_rate_pct,
                "gate_pass_rate_pct": gate_pass_rate_pct,
                "top_class_usage": self._counter_to_sorted_dict(top_class_usage),
            },
            "gate_failure_distribution": {
                "scored_incident_count": scored_incident_count,
                "incidents_with_any_gate_failure": incidents_with_any_gate_failure,
                "score_gate_failures": score_gate_failures,
                "margin_gate_failures": margin_gate_failures,
                "required_evidence_missing_failures": required_evidence_missing_failures,
                "ambiguity_failures": ambiguity_failures,
            },
            "fallback_field_usage": self._counter_to_sorted_dict(fallback_field_usage),
            "low_confidence_field_usage": self._counter_to_sorted_dict(low_confidence_field_usage),
            "enrichment_latency_ms": latency_summary,
        }

    def _update_attack_detail_observability(self, incidents: list[dict[str, Any]]) -> None:
        summary = self._summarize_attack_detail_observability(incidents)
        self._latest_attack_detail_observability = summary
        signature = json.dumps(summary, sort_keys=True)
        if signature != self._last_attack_detail_observability_signature:
            logger.info("attack-detail-observability %s", signature)
            self._last_attack_detail_observability_signature = signature

    def _dashboard_meta(
        self,
        *,
        source: str,
        staged: bool,
        include_attack_typing: bool = True,
        extras: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "source": _safe_str(source, "unknown"),
            "staged": bool(staged),
            "canonical_attack_model": "attack_detail",
            "canonical_attack_detail_path": "attack_detail",
            "attack_detail_contract_version": self.ATTACK_DETAIL_CONTRACT_VERSION,
        }
        if include_attack_typing:
            meta["attack_typing"] = self._attack_typing_metadata()
        if isinstance(extras, dict):
            meta.update(extras)
        return meta

    @classmethod
    def _normalize_triage_state(cls, state: Any) -> str:
        normalized = (
            _safe_str(state)
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )
        if normalized in cls.TRIAGE_STATES:
            return normalized
        return cls.TRIAGE_DEFAULT_STATE

    @classmethod
    def _parse_triage_state(cls, state: Any) -> str:
        normalized = cls._normalize_triage_state(state)
        raw_state = _safe_str(state).strip()
        if normalized == cls.TRIAGE_DEFAULT_STATE and raw_state.lower() not in {"", "open"}:
            allowed = ", ".join(cls.TRIAGE_STATES)
            raise ValueError(f"Invalid triage state. Allowed values: {allowed}.")
        return normalized

    def _incident_triage_payload(self, incident_id: str) -> dict[str, Any]:
        normalized_incident_id = _safe_str(incident_id).strip()
        triage_state = self.TRIAGE_DEFAULT_STATE
        triage_updated_at: str | None = None
        if normalized_incident_id:
            with self._triage_lock:
                stored = self._incident_triage.get(normalized_incident_id, {})
            if isinstance(stored, dict):
                triage_state = self._normalize_triage_state(stored.get("state"))
                updated_at_raw = _safe_str(stored.get("updated_at")).strip()
                triage_updated_at = updated_at_raw or None
        return {
            "state": triage_state,
            "updated_at": triage_updated_at,
        }

    def update_incident_triage(self, incident_id: str, triage_state: Any) -> dict[str, Any]:
        normalized_incident_id = _safe_str(incident_id).strip()
        if not normalized_incident_id:
            raise ValueError("Incident id is required.")
        normalized_state = self._parse_triage_state(triage_state)
        updated_at = datetime.utcnow().isoformat()
        triage_payload = {
            "state": normalized_state,
            "updated_at": updated_at,
        }
        with self._triage_lock:
            self._incident_triage[normalized_incident_id] = dict(triage_payload)
        return {
            "incident_id": normalized_incident_id,
            "triage": triage_payload,
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                include_attack_typing=False,
                extras={
                    "triage": {
                        "states": list(self.TRIAGE_STATES),
                        "default_state": self.TRIAGE_DEFAULT_STATE,
                    }
                },
            ),
        }

    def _aggregate_attack_detail(
        self,
        *,
        summary: str,
        primary_class: str,
        confidence: float,
        certainty_level: str,
        source: str,
        certainty_counts: Counter[str] | None = None,
    ) -> dict[str, Any]:
        normalized_summary = _safe_str(summary, self.ATTACK_DETAIL_FALLBACK_STRINGS["summary"]).strip()
        if not normalized_summary:
            normalized_summary = self.ATTACK_DETAIL_FALLBACK_STRINGS["summary"]
        normalized_primary = _safe_str(primary_class, normalized_summary).strip() or normalized_summary
        normalized_confidence = _clamp_confidence(confidence, 0.0)
        normalized_certainty_level = self._normalize_certainty_level(certainty_level)

        if normalized_certainty_level == "certain":
            certainty_text = (
                f"Certain: aggregated telemetry consistently maps to {normalized_primary}."
            )
        elif normalized_certainty_level == "probable":
            certainty_text = (
                f"Probable: {normalized_primary} is the strongest aggregate pattern, but remains a best guess."
            )
        else:
            certainty_text = (
                f"Not sure: aggregate evidence is insufficient for certain {normalized_primary} assignment."
            )

        certainty: dict[str, Any] = {
            "level": normalized_certainty_level,
            "text": certainty_text,
        }
        if isinstance(certainty_counts, Counter):
            certainty["counts"] = self._certainty_counts_from_counter(certainty_counts)

        method = _safe_str(source, "derived-aggregation").strip() or "derived-aggregation"
        return {
            "contract_version": self.ATTACK_DETAIL_CONTRACT_VERSION,
            "summary": normalized_summary,
            "primary_class": normalized_primary,
            "confidence": normalized_confidence,
            "certainty_text": certainty_text,
            "certainty": certainty,
            "source": method,
            "method": method,
            "alternatives": [],
            "meta": {
                "derived": True,
                "scope": "aggregate",
                "source": method,
            },
        }

    @staticmethod
    def _payload_preview(alert: dict[str, Any], classification: str, rationale: list[str] | None = None) -> str:
        rationale = rationale or []
        src_ip = alert.get("src_ip", "unknown")
        dst_ip = alert.get("dst_ip", "unknown")
        dst_port = _safe_int(alert.get("dst_port"), 0)
        rationale_lines = ""
        if rationale:
            rationale_lines = "\n" + "\n".join(f"reason={item}" for item in rationale[:2])
        return (
            f"src={src_ip} dst={dst_ip}:{dst_port}\n"
            f"class={classification}\n"
            f"confidence={_safe_float(alert.get('confidence'), 0.0):.2%}"
            f"{rationale_lines}"
        )

    @staticmethod
    def _stable_incident_id(alert: dict[str, Any]) -> str:
        first_seen = alert.get("first_seen")
        if not first_seen:
            events = alert.get("events")
            if isinstance(events, list) and events:
                first_event = events[0] if isinstance(events[0], dict) else {}
                first_seen = first_event.get("timestamp")
        if not first_seen:
            first_seen = alert.get("timestamp")

        target_ips_raw = alert.get("target_ips")
        if not isinstance(target_ips_raw, list):
            target_ips_raw = [alert.get("dst_ip")]
        target_ips = sorted({_safe_str(ip) for ip in target_ips_raw if _safe_str(ip)})
        if not target_ips and _safe_str(alert.get("dst_ip")):
            target_ips = [_safe_str(alert.get("dst_ip"))]

        incident_key = {
            "first_seen": _to_iso(first_seen),
            "attacker_ip": _safe_str(alert.get("attacker_ip")),
            "source_ip": _safe_str(alert.get("src_ip")),
            "target_ips": target_ips,
            "protocol": _safe_int(alert.get("protocol"), 0),
        }
        digest = hashlib.sha256(
            json.dumps(incident_key, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16].upper()
        return f"INC-{digest}"

    def _list_incidents_from_stats(
        self,
        stats: dict[str, Any],
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        attack_typing_metadata = self._attack_typing_metadata()
        alerts = sorted(
            self._recent_alerts(stats_snapshot=stats),
            key=lambda a: _to_iso(a.get("timestamp")),
            reverse=True,
        )[:limit]
        incidents: list[dict[str, Any]] = []
        for alert in alerts:
            enrichment_started = time.perf_counter()
            confidence = _safe_float(alert.get("confidence"), 0.0)
            alert_for_classification = dict(alert)
            alert_for_classification["alert_threshold"] = self.ids.alert_threshold
            classification_details = self._normalize_classification_details(
                self._classification_details(alert_for_classification, confidence)
            )
            attack_detail = self._validate_attack_detail_response(
                self._build_attack_detail_contract(
                    classification_details=classification_details,
                    classification_label=classification_details["label"],
                    attack_typing_metadata=attack_typing_metadata,
                )
            )
            enrichment_latency_ms = round((time.perf_counter() - enrichment_started) * 1000.0, 3)
            classification = attack_detail["summary"]
            severity = self._severity_from_confidence(confidence)
            fallback_target_ip = _safe_str(alert.get("dst_ip"))
            target_ips_raw = alert.get("target_ips")
            if not isinstance(target_ips_raw, list):
                target_ips_raw = [fallback_target_ip]
            target_ips = [_safe_str(v) for v in target_ips_raw if _safe_str(v)]
            if not target_ips and fallback_target_ip:
                target_ips = [fallback_target_ip]
            primary_target_ip = target_ips[0] if target_ips else fallback_target_ip

            fallback_target_port = _safe_int(alert.get("dst_port"), 0)
            target_ports_raw = alert.get("target_ports")
            if not isinstance(target_ports_raw, list):
                target_ports_raw = [fallback_target_port]
            target_ports = [_safe_int(v, 0) for v in target_ports_raw if _safe_int(v, 0) > 0]
            if not target_ports and fallback_target_port > 0:
                target_ports = [fallback_target_port]
            incident_id = self._stable_incident_id(alert)
            triage = self._incident_triage_payload(incident_id)

            attack_typing = {
                "summary": attack_detail["summary"],
                "label": classification,
                "primary_class": attack_detail["primary_class"],
                "confidence": attack_detail["confidence"],
                "alternatives": attack_detail["alternatives"],
                "evidence": {
                    "used": attack_detail["evidence_used"],
                    "missing": attack_detail["evidence_missing"],
                },
                "limitations": attack_detail["limitations"],
                "description": attack_detail["description"],
                "rationale": attack_detail["rationale"],
                "source": attack_detail["source"],
                "method": attack_detail["method"],
                "note": attack_detail["note"],
                "certainty": attack_detail["certainty"],
                "field_metadata": attack_detail["field_metadata"],
                "contract_version": attack_detail["contract_version"],
                "scoring": classification_details["scoring"],
                "explanation": classification_details["explanation"],
                "enrichment_latency_ms": enrichment_latency_ms,
                "metadata": attack_typing_metadata,
            }
            incidents.append(
                {
                    "id": incident_id,
                    "triage_state": triage["state"],
                    "triage_updated_at": triage["updated_at"],
                    "triage": triage,
                    "timestamp": _to_iso(alert.get("timestamp")),
                    "source_ip": _safe_str(alert.get("src_ip")),
                    "attacker_ip": _safe_str(alert.get("attacker_ip", alert.get("src_ip", ""))),
                    "target_ip": primary_target_ip,
                    "target_ips": target_ips,
                    "target_ports": target_ports,
                    "classification": classification,
                    "attack_summary": attack_detail["summary"],
                    "attack_primary_class": attack_detail["primary_class"],
                    "attack_confidence": attack_detail["confidence"],
                    "attack_certainty_level": _safe_str(attack_detail["certainty"].get("level"), "not_sure"),
                    "attack_certainty_text": _safe_str(
                        attack_detail["certainty"].get("text"),
                        attack_detail["certainty_text"],
                    ),
                    "attack_method": attack_detail["method"],
                    "attack_detail": attack_detail,
                    "attack_typing": attack_typing,
                    "classification_primary": attack_detail["primary_class"],
                    "classification_confidence": attack_detail["confidence"],
                    "classification_alternatives": attack_detail["alternatives"],
                    "classification_evidence_used": attack_detail["evidence_used"],
                    "classification_evidence_missing": attack_detail["evidence_missing"],
                    "classification_limitations": attack_detail["limitations"],
                    "classification_scoring": classification_details["scoring"],
                    "classification_explanation": classification_details["explanation"],
                    "attack_description": attack_detail["description"],
                    "classification_source": attack_detail["source"],
                    "classification_note": attack_detail["note"],
                    "classification_certainty": attack_detail["certainty"],
                    "classification_field_metadata": attack_detail["field_metadata"],
                    "detection_rationale": attack_detail["rationale"],
                    "model_name": "SVM",
                    "model_decision": "attack",
                    "model_threshold": float(self.ids.alert_threshold),
                    "severity": severity,
                    "detection_confidence": confidence,
                    "confidence": confidence,
                    "event_count": _safe_int(alert.get("event_count"), 1),
                    "packets": _safe_int(alert.get("packets"), 0),
                    "bytes": _safe_int(alert.get("bytes"), 0),
                    "protocol": _safe_int(alert.get("protocol"), 0),
                    "enrichment_latency_ms": enrichment_latency_ms,
                    "payload_preview": self._payload_preview(
                        alert, classification, attack_detail["rationale"]
                    ),
                }
            )
        self._update_attack_detail_observability(incidents)
        return incidents

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        """Flatten current alert groups into incident rows for UI/API use."""
        stats = self._stats()
        return self._list_incidents_from_stats(stats, limit=limit)

    @staticmethod
    def _incident_export_scalar(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            flattened: list[str] = []
            for item in value:
                text = _safe_str(item).strip()
                if text:
                    flattened.append(text)
            return "; ".join(flattened)
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return _safe_str(value)

    def _incident_export_row(self, incident: dict[str, Any]) -> dict[str, str]:
        attack_detail = self._incident_attack_detail(incident)
        target_ips = _string_list(incident.get("target_ips"))
        target_ip = _safe_str(incident.get("target_ip")).strip()
        if target_ip and target_ip not in target_ips:
            target_ips.insert(0, target_ip)
        row = {
            "id": _safe_str(incident.get("id")).strip(),
            "timestamp": _safe_str(incident.get("timestamp")).strip(),
            "attacker_ip": _safe_str(incident.get("attacker_ip")).strip(),
            "target_ip": target_ip,
            "target_ips": target_ips,
            "target_ports": incident.get("target_ports"),
            "severity": _safe_str(incident.get("severity")).strip(),
            "attack_primary_class": _safe_str(attack_detail.get("primary_class")).strip(),
            "attack_summary": _safe_str(attack_detail.get("summary")).strip(),
            "attack_confidence": round(self._incident_attack_confidence(incident), 4),
            "attack_certainty_level": self._incident_attack_certainty(incident).get("level", "not_sure"),
            "detection_confidence": round(self._incident_detection_confidence(incident), 4),
            "event_count": _safe_int(incident.get("event_count"), 0),
            "packets": _safe_int(incident.get("packets"), 0),
            "bytes": _safe_int(incident.get("bytes"), 0),
            "attack_method": _safe_str(attack_detail.get("method")).strip(),
            "attack_description": _safe_str(attack_detail.get("description")).strip(),
            "detection_rationale": _string_list(attack_detail.get("rationale")),
        }
        return {
            field: self._incident_export_scalar(row.get(field))
            for field in self.INCIDENT_EXPORT_COLUMNS
        }

    def _incidents_csv(self, incidents: list[dict[str, Any]]) -> str:
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=list(self.INCIDENT_EXPORT_COLUMNS))
        writer.writeheader()
        for incident in incidents:
            writer.writerow(self._incident_export_row(incident))
        return output.getvalue()

    def get_incidents_export(self, *, limit: int = 1000, export_format: str = "csv") -> dict[str, str]:
        normalized_limit = max(1, min(_safe_int(limit, 1000), 1000))
        incidents = self.list_incidents(limit=normalized_limit)
        normalized_format = _safe_str(export_format, "csv").strip().lower() or "csv"
        filename_suffix = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        if normalized_format == "csv":
            return {
                "content": self._incidents_csv(incidents),
                "mimetype": "text/csv; charset=utf-8",
                "filename": f"sentinelai-incidents-{filename_suffix}.csv",
            }
        if normalized_format == "json":
            payload = {
                "items": incidents,
                "meta": self._dashboard_meta(
                    source="live",
                    staged=False,
                    extras={
                        "count": len(incidents),
                        "export_format": "json",
                    },
                ),
            }
            return {
                "content": json.dumps(payload, ensure_ascii=False, indent=2),
                "mimetype": "application/json; charset=utf-8",
                "filename": f"sentinelai-incidents-{filename_suffix}.json",
            }
        raise ValueError("Unsupported incident export format. Use 'csv' or 'json'.")

    def get_incidents_payload(self, limit: int = 100) -> dict[str, Any]:
        items = self.list_incidents(limit=limit)
        return {
            "items": items,
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                extras={
                    "count": len(items),
                    "attack_detail_observability": dict(self._latest_attack_detail_observability),
                    "certainty_levels": ["not_sure", "probable", "certain"],
                    "triage": {
                        "states": list(self.TRIAGE_STATES),
                        "default_state": self.TRIAGE_DEFAULT_STATE,
                        "field": "triage_state",
                    },
                    "confidence_semantics": {
                        "attack_confidence": "attack-family confidence from attack_detail.confidence (0..1)",
                        "detection_confidence": "binary detector confidence from incident confidence (0..1)",
                    },
                    "method_semantics": {
                        "attack_detail.method": "canonical deterministic typing source/method alias",
                        "triage_state": "operator-managed triage workflow state",
                    },
                },
            ),
        }

    def get_overview_summary(self) -> dict[str, Any]:
        stats = self._stats()
        incidents = self._list_incidents_from_stats(stats, limit=300)
        critical = sum(1 for i in incidents if i["severity"] == "CRITICAL")
        attacks = _safe_int(stats.get("attacks_detected"), 0)
        flows = max(1, _safe_int(stats.get("flows_analyzed"), 0))
        attack_confidences = [self._incident_attack_confidence(incident) for incident in incidents]
        detection_confidences = [self._incident_detection_confidence(incident) for incident in incidents]
        avg_attack_confidence = (
            sum(attack_confidences) / len(attack_confidences) if attack_confidences else 0.0
        )
        avg_detection_confidence = (
            sum(detection_confidences) / len(detection_confidences) if detection_confidences else 0.0
        )
        certainty_counts: Counter[str] = Counter()
        for incident in incidents:
            certainty_level = self._incident_attack_certainty(incident)["level"]
            certainty_counts[certainty_level] += 1
        return {
            "events_processed": _safe_int(stats.get("packets_processed"), 0),
            "threats_blocked": attacks,
            "active_critical_incidents": critical,
            "detection_rate_pct": (attacks / flows) * 100.0,
            "ai_confidence_score_pct": avg_attack_confidence * 100.0,
            "attack_confidence_score_pct": avg_attack_confidence * 100.0,
            "model_confidence_score_pct": avg_detection_confidence * 100.0,
            "attack_uncertainty": self._certainty_counts_from_counter(certainty_counts),
            "last_updated_utc": datetime.utcnow().isoformat(),
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                extras={
                    "attack_uncertainty": self._certainty_counts_from_counter(certainty_counts),
                    "confidence_semantics": {
                        "ai_confidence_score_pct": "attack_detail.confidence mean in percent",
                        "model_confidence_score_pct": "incident confidence mean in percent",
                    },
                },
            ),
        }

    def _incident_timeseries(self, incidents: list[dict[str, Any]]) -> tuple[list[str], list[int]]:
        now = datetime.utcnow()
        buckets = [now - timedelta(minutes=9 - i) for i in range(10)]
        labels = [b.strftime("%H:%M") for b in buckets]
        counts = [0 for _ in buckets]
        for incident in incidents:
            try:
                ts = datetime.fromisoformat(str(incident["timestamp"]).replace("Z", ""))
            except (TypeError, ValueError, KeyError):
                continue
            diff_minutes = int((now - ts).total_seconds() // 60)
            if 0 <= diff_minutes <= 9:
                bucket_index = 9 - diff_minutes
                counts[bucket_index] += 1
        return labels, counts

    def get_overview_charts(self) -> dict[str, Any]:
        incidents = self.list_incidents(limit=500)
        labels, anomaly_counts = self._incident_timeseries(incidents)
        attack_typing_meta = self._attack_typing_metadata()

        if self.enable_staged_data:
            ingress_volume = [max(10, v * 6 + 28 + (i % 3) * 2) for i, v in enumerate(anomaly_counts)]
            ingress_source = "simulated"
        else:
            ingress_volume = [v * 10 for v in anomaly_counts]
            ingress_source = "derived-live"

        threat_vector_counts = Counter(self._incident_attack_primary_class(incident) for incident in incidents)
        certainty_counts: Counter[str] = Counter(
            self._incident_attack_certainty(incident)["level"] for incident in incidents
        )
        top_targets = Counter(i["target_ip"] for i in incidents if i["target_ip"])
        taxonomy_labels = self.attack_type_engine.chart_labels()
        threat_vector_labels = taxonomy_labels + ["Other"]
        matched_total = sum(threat_vector_counts.get(label, 0) for label in taxonomy_labels)
        attack_uncertainty = self._certainty_counts_from_counter(certainty_counts)

        return {
            "traffic": {
                "labels": labels,
                "ingress_volume_mb_s": ingress_volume,
                "anomalous_packets": anomaly_counts,
                "meta": {"source": ingress_source, "staged": self.enable_staged_data},
            },
            "threat_vectors": {
                "labels": threat_vector_labels,
                "values": [threat_vector_counts.get(label, 0) for label in taxonomy_labels]
                + [max(0, len(incidents) - matched_total)],
                "meta": self._dashboard_meta(
                    source="live",
                    staged=False,
                    include_attack_typing=False,
                    extras={
                        "attack_typing": {
                            "source": attack_typing_meta["source"],
                            "schema_version": attack_typing_meta["schema_version"],
                            "attack_detail_contract_version": attack_typing_meta[
                                "attack_detail_contract_version"
                            ],
                        },
                        "attack_uncertainty": attack_uncertainty,
                    },
                ),
            },
            "top_endpoints": {
                "labels": [k for k, _ in top_targets.most_common(8)],
                "values": [v for _, v in top_targets.most_common(8)],
                "meta": {"source": "live", "staged": False},
            },
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                extras={
                    "attack_typing": attack_typing_meta,
                    "attack_uncertainty": attack_uncertainty,
                },
            ),
        }

    def get_network_graph(self) -> dict[str, Any]:
        incidents = self.list_incidents(limit=500)
        node_types: dict[str, str] = {}
        edge_counts: Counter[tuple[str, str]] = Counter()
        node_incident_counts: Counter[str] = Counter()
        node_class_counts: dict[str, Counter[str]] = defaultdict(Counter)
        node_certainty_counts: dict[str, Counter[str]] = defaultdict(Counter)
        node_attack_confidence_totals: Counter[str] = Counter()
        edge_class_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        edge_certainty_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        edge_attack_confidence_totals: Counter[tuple[str, str]] = Counter()
        for item in incidents:
            attacker = item["attacker_ip"] or item["source_ip"]
            target = item["target_ip"]
            primary_class = self._incident_attack_primary_class(item)
            attack_confidence = self._incident_attack_confidence(item)
            certainty_level = self._incident_attack_certainty(item)["level"]
            if attacker:
                node_types.setdefault(attacker, "attacker")
                node_incident_counts[attacker] += 1
                node_class_counts[attacker][primary_class] += 1
                node_certainty_counts[attacker][certainty_level] += 1
                node_attack_confidence_totals[attacker] += attack_confidence
            if target:
                node_types.setdefault(target, "target")
                node_incident_counts[target] += 1
                node_class_counts[target][primary_class] += 1
                node_certainty_counts[target][certainty_level] += 1
                node_attack_confidence_totals[target] += attack_confidence
            if attacker and target:
                edge_counts[(attacker, target)] += 1
                edge_class_counts[(attacker, target)][primary_class] += 1
                edge_certainty_counts[(attacker, target)][certainty_level] += 1
                edge_attack_confidence_totals[(attacker, target)] += attack_confidence

        nodes = []
        for ip, role in sorted(node_types.items()):
            incident_count = _safe_int(node_incident_counts.get(ip), 0)
            dominant_class = (
                node_class_counts[ip].most_common(1)[0][0]
                if node_class_counts[ip]
                else "Unknown / Needs More Data"
            )
            certainty_counter = node_certainty_counts[ip]
            attack_confidence_avg = (
                float(node_attack_confidence_totals[ip]) / incident_count
                if incident_count > 0
                else 0.0
            )
            node_attack_detail = self._aggregate_attack_detail(
                summary=dominant_class,
                primary_class=dominant_class,
                confidence=attack_confidence_avg,
                certainty_level=self._dominant_certainty_level(certainty_counter),
                source="network-node-aggregation",
                certainty_counts=certainty_counter,
            )
            nodes.append(
                {
                    "id": ip,
                    "role": role,
                    "label": ip,
                    "incident_count": incident_count,
                    "attack_primary_class": dominant_class,
                    "attack_confidence_avg": attack_confidence_avg,
                    "attack_certainty": {
                        "level": _safe_str(node_attack_detail["certainty"].get("level"), "not_sure"),
                        "text": _safe_str(node_attack_detail["certainty"].get("text")),
                        "counts": self._certainty_counts_from_counter(certainty_counter),
                    },
                    "attack_detail": node_attack_detail,
                }
            )

        edges = []
        for (src, dst), weight in edge_counts.most_common(200):
            certainty_counter = edge_certainty_counts[(src, dst)]
            dominant_class = (
                edge_class_counts[(src, dst)].most_common(1)[0][0]
                if edge_class_counts[(src, dst)]
                else "Unknown / Needs More Data"
            )
            edge_attack_confidence_avg = float(edge_attack_confidence_totals[(src, dst)]) / max(1, weight)
            edge_attack_detail = self._aggregate_attack_detail(
                summary=dominant_class,
                primary_class=dominant_class,
                confidence=edge_attack_confidence_avg,
                certainty_level=self._dominant_certainty_level(certainty_counter),
                source="network-edge-aggregation",
                certainty_counts=certainty_counter,
            )
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "weight": weight,
                    "attack_primary_class": dominant_class,
                    "attack_confidence_avg": edge_attack_confidence_avg,
                    "attack_certainty": {
                        "level": _safe_str(edge_attack_detail["certainty"].get("level"), "not_sure"),
                        "text": _safe_str(edge_attack_detail["certainty"].get("text")),
                        "counts": self._certainty_counts_from_counter(certainty_counter),
                    },
                    "attack_detail": edge_attack_detail,
                }
            )

        uncertainty_totals: Counter[str] = Counter()
        for certainty_counter in edge_certainty_counts.values():
            for level, count in certainty_counter.items():
                uncertainty_totals[self._normalize_certainty_level(level)] += _safe_int(count, 0)
        return {
            "nodes": nodes,
            "edges": edges,
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                extras={
                    "attack_uncertainty": self._certainty_counts_from_counter(uncertainty_totals),
                },
            ),
        }

    @staticmethod
    def _normalize_ip(value: Any) -> str:
        text = _safe_str(value).strip()
        if not text:
            return ""
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text

    @staticmethod
    def _ip_scope(ip: str) -> str:
        normalized = _safe_str(ip).strip()
        if not normalized:
            return "unknown"
        try:
            ip_obj = ipaddress.ip_address(normalized)
        except ValueError:
            return "unknown"
        if ip_obj.is_loopback:
            return "loopback"
        if ip_obj.is_private:
            return "private"
        if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return "non-routable"
        return "public"

    @staticmethod
    def _safe_coordinate(value: Any, minimum: float, maximum: float) -> float | None:
        numeric = _safe_float(value, float("nan"))
        if not math.isfinite(numeric):
            return None
        if numeric < minimum or numeric > maximum:
            return None
        return numeric

    @staticmethod
    def _synthetic_public_map_coordinates(ip: str) -> tuple[float, float] | None:
        normalized_ip = _safe_str(ip).strip()
        if not normalized_ip:
            return None
        if SentinelAIRuntimeService._ip_scope(normalized_ip) != "public":
            return None
        digest = hashlib.sha256(normalized_ip.encode("utf-8")).digest()
        max_uint64 = float((1 << 64) - 1)
        lat_seed = int.from_bytes(digest[:8], "big") / max_uint64
        lon_seed = int.from_bytes(digest[8:16], "big") / max_uint64
        latitude = round((lat_seed * 120.0) - 60.0, 6)
        longitude = round((lon_seed * 360.0) - 180.0, 6)
        return latitude, longitude

    @staticmethod
    def _cvss_severity(cvss: Any) -> str:
        numeric = _safe_float(cvss, -1.0)
        if numeric < 0:
            return "unknown"
        if numeric >= 9.0:
            return "critical"
        if numeric >= 7.0:
            return "high"
        if numeric >= 4.0:
            return "medium"
        return "low"

    def _fallback_threat_intel(self, ip: str, reason: str) -> dict[str, Any]:
        scope = self._ip_scope(ip)
        host = ""
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        return {
            "source": "fallback",
            "provider_status": reason,
            "scope": scope,
            "org": "",
            "isp": "",
            "asn": "",
            "country": "",
            "city": "",
            "region": "",
            "latitude": None,
            "longitude": None,
            "os": "",
            "hostnames": [host] if host else [],
            "domains": [],
            "open_ports": [],
            "services": [],
            "services_count": 0,
            "service_fingerprints": [],
            "tags": [],
            "vulns": [],
            "vuln_details": [],
            "vuln_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
            "vuln_count": 0,
            "risk": "unknown",
            "last_update": "",
        }

    def _fetch_shodan_host_intel(self, ip: str) -> dict[str, Any]:
        if not self._shodan_api_key:
            return self._fallback_threat_intel(ip, "shodan-key-missing")
        if self._ip_scope(ip) != "public":
            return self._fallback_threat_intel(ip, "non-public-ip")

        query = urlparse.urlencode({"key": self._shodan_api_key})
        endpoint = f"https://api.shodan.io/shodan/host/{urlparse.quote(ip)}?{query}"
        request_obj = urlrequest.Request(
            endpoint,
            headers={"User-Agent": "SentinelAI-Runtime/1.0"},
        )
        try:
            with urlrequest.urlopen(request_obj, timeout=self._threat_intel_timeout_seconds) as response:
                body = response.read().decode("utf-8")
            payload = json.loads(body) if body else {}
        except urlerror.HTTPError as exc:
            reason = f"shodan-http-{exc.code}"
            return self._fallback_threat_intel(ip, reason)
        except Exception:
            return self._fallback_threat_intel(ip, "shodan-request-failed")

        if not isinstance(payload, dict):
            return self._fallback_threat_intel(ip, "shodan-invalid-response")

        ports = sorted({int(v) for v in payload.get("ports", []) if _safe_int(v, 0) > 0})
        services: list[dict[str, Any]] = []
        service_fingerprint_counter: Counter[str] = Counter()
        raw_services = payload.get("data")
        if isinstance(raw_services, list):
            for entry in raw_services:
                if not isinstance(entry, dict):
                    continue
                port = _safe_int(entry.get("port"), 0)
                if port <= 0:
                    continue
                transport = _safe_str(entry.get("transport")).strip().lower()
                product = _safe_str(entry.get("product")).strip()
                version = _safe_str(entry.get("version")).strip()
                shodan_meta = entry.get("_shodan")
                module = _safe_str(shodan_meta.get("module") if isinstance(shodan_meta, dict) else "").strip()
                cpe_values = [str(v) for v in entry.get("cpe", []) if str(v).strip()] if isinstance(entry.get("cpe"), list) else []
                if not cpe_values and str(entry.get("cpe", "")).strip():
                    cpe_values = [str(entry.get("cpe")).strip()]
                label = product or module or (f"{transport}/{port}" if transport else str(port))
                if product and version:
                    label = f"{product} {version}"
                service_fingerprint_counter[label] += 1
                services.append(
                    {
                        "port": port,
                        "transport": transport or "--",
                        "product": product or "--",
                        "version": version or "--",
                        "module": module or "--",
                        "cpe": cpe_values,
                        "timestamp": _safe_str(entry.get("timestamp")).strip(),
                        "label": label,
                    }
                )
        services.sort(key=lambda item: (_safe_int(item.get("port"), 0), _safe_str(item.get("transport"))))

        vuln_details: list[dict[str, Any]] = []
        raw_vulns = payload.get("vulns")
        if isinstance(raw_vulns, dict):
            for vuln_id, vuln_payload in raw_vulns.items():
                vuln = _safe_str(vuln_id).strip()
                if not vuln:
                    continue
                detail = vuln_payload if isinstance(vuln_payload, dict) else {}
                cvss = _safe_float(detail.get("cvss"), -1.0)
                cvss_value = cvss if cvss >= 0 else None
                vuln_details.append(
                    {
                        "id": vuln,
                        "cvss": cvss_value,
                        "severity": self._cvss_severity(cvss_value),
                        "summary": _safe_str(detail.get("summary")).strip(),
                        "verified": bool(detail.get("verified")),
                    }
                )
        elif isinstance(raw_vulns, list):
            for vuln_id in raw_vulns:
                vuln = _safe_str(vuln_id).strip()
                if not vuln:
                    continue
                vuln_details.append(
                    {
                        "id": vuln,
                        "cvss": None,
                        "severity": "unknown",
                        "summary": "",
                        "verified": False,
                    }
                )
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        vuln_details.sort(
            key=lambda item: (
                -severity_rank.get(_safe_str(item.get("severity"), "unknown"), 0),
                -_safe_float(item.get("cvss"), -1.0),
                _safe_str(item.get("id")),
            )
        )
        vuln_details = vuln_details[: self._threat_intel_max_vulns]
        vulns = [str(item.get("id", "")).strip() for item in vuln_details if str(item.get("id", "")).strip()]
        vuln_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for detail in vuln_details:
            severity = _safe_str(detail.get("severity"), "unknown").strip().lower()
            if severity not in vuln_severity:
                severity = "unknown"
            vuln_severity[severity] += 1

        if vuln_severity["critical"] or vuln_severity["high"]:
            risk = "high"
        elif vuln_severity["medium"] or len(ports) >= 8:
            risk = "medium"
        elif ports or services:
            risk = "low"
        else:
            risk = "unknown"

        service_fingerprints = [label for label, _count in service_fingerprint_counter.most_common(8)]
        latitude = self._safe_coordinate(payload.get("latitude"), -90.0, 90.0)
        longitude = self._safe_coordinate(payload.get("longitude"), -180.0, 180.0)

        return {
            "source": "shodan",
            "provider_status": "ok",
            "scope": self._ip_scope(ip),
            "org": _safe_str(payload.get("org")),
            "isp": _safe_str(payload.get("isp")),
            "asn": _safe_str(payload.get("asn")),
            "country": _safe_str(payload.get("country_name")),
            "city": _safe_str(payload.get("city")),
            "region": _safe_str(payload.get("region_code") or payload.get("region_name")),
            "latitude": latitude,
            "longitude": longitude,
            "os": _safe_str(payload.get("os")),
            "hostnames": [str(v) for v in payload.get("hostnames", []) if str(v).strip()],
            "domains": [str(v) for v in payload.get("domains", []) if str(v).strip()],
            "open_ports": ports,
            "services": services[: self._threat_intel_max_services],
            "services_count": len(services),
            "service_fingerprints": service_fingerprints,
            "tags": [str(v) for v in payload.get("tags", []) if str(v).strip()],
            "vulns": vulns,
            "vuln_details": vuln_details,
            "vuln_severity": vuln_severity,
            "vuln_count": len(vulns),
            "risk": risk,
            "last_update": _safe_str(payload.get("last_update")),
        }

    def _lookup_threat_intel(self, ip: str) -> dict[str, Any]:
        normalized_ip = self._normalize_ip(ip)
        if not normalized_ip:
            intel = self._fallback_threat_intel("", "invalid-ip")
            intel["cache_hit"] = False
            return intel

        now = time.time()
        with self._threat_intel_lock:
            cached = self._threat_intel_cache.get(normalized_ip)
            if isinstance(cached, dict):
                fetched_at = _safe_float(cached.get("fetched_at"), 0.0)
                if now - fetched_at <= self._threat_intel_cache_ttl_seconds:
                    cached_data = dict(cached.get("data", {}))
                    cached_data["cache_hit"] = True
                    return cached_data

        intel = self._fetch_shodan_host_intel(normalized_ip)
        with self._threat_intel_lock:
            self._threat_intel_cache[normalized_ip] = {
                "fetched_at": now,
                "data": dict(intel),
            }
        intel["cache_hit"] = False
        return intel

    def get_threat_intel(self, limit: int = 300) -> dict[str, Any]:
        incidents = self.list_incidents(limit=max(1, int(limit)))
        rows: list[dict[str, Any]] = []
        for inc in incidents:
            attack_detail = self._incident_attack_detail(inc)
            attack_certainty = self._incident_attack_certainty(inc)
            roles_and_ips = [
                ("attacker", inc.get("attacker_ip") or inc.get("source_ip")),
                ("target", inc.get("target_ip")),
            ]
            for role, raw_ip in roles_and_ips:
                normalized_ip = self._normalize_ip(raw_ip)
                if not normalized_ip:
                    continue
                rows.append(
                    {
                        "incident_id": _safe_str(inc.get("id")),
                        "ip": normalized_ip,
                        "role": role,
                        "severity": _safe_str(inc.get("severity"), "LOW"),
                        "attack_primary_class": _safe_str(
                            attack_detail.get("primary_class"),
                            _safe_str(attack_detail.get("summary"), "Unknown / Needs More Data"),
                        ),
                        "attack_confidence": self._incident_attack_confidence(inc),
                        "attack_certainty": attack_certainty,
                        "attack_method": _safe_str(attack_detail.get("method"), attack_detail.get("source")),
                    }
                )

        ordered_ips: list[str] = []
        seen_ips: set[str] = set()
        for row in rows:
            ip = row["ip"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            ordered_ips.append(ip)

        lookup_limit = min(len(ordered_ips), self._threat_intel_lookup_limit)
        lookup_ips = ordered_ips[:lookup_limit]
        skipped_ips = ordered_ips[lookup_limit:]

        intel_by_ip: dict[str, dict[str, Any]] = {}
        role_counts_by_ip: dict[str, Counter[str]] = defaultdict(Counter)
        incident_ids_by_ip: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            ip = _safe_str(row.get("ip")).strip()
            role = _safe_str(row.get("role"), "unknown").strip() or "unknown"
            incident_id = _safe_str(row.get("incident_id")).strip()
            if not ip:
                continue
            role_counts_by_ip[ip][role] += 1
            if incident_id:
                incident_ids_by_ip[ip].add(incident_id)
        cache_hits = 0
        shodan_count = 0
        fallback_count = 0
        for ip in lookup_ips:
            intel = self._lookup_threat_intel(ip)
            intel_by_ip[ip] = intel
            if bool(intel.get("cache_hit")):
                cache_hits += 1
            if intel.get("source") == "shodan":
                shodan_count += 1
            else:
                fallback_count += 1
        for ip in skipped_ips:
            intel_by_ip[ip] = self._fallback_threat_intel(ip, "lookup-limit-reached")
            fallback_count += 1

        items: list[dict[str, Any]] = []
        for row in rows:
            ip = row["ip"]
            intel = dict(intel_by_ip.get(ip, self._fallback_threat_intel(ip, "lookup-missing")))
            ports = [int(v) for v in intel.get("open_ports", []) if _safe_int(v, 0) > 0]
            port_summary = ", ".join(str(v) for v in ports[:8]) if ports else "--"
            if ports and len(ports) > 8:
                port_summary = f"{port_summary}, +{len(ports) - 8} more"
            items.append(
                {
                    "incident_id": row["incident_id"],
                    "ip": ip,
                    "role": row["role"],
                    "severity": row["severity"],
                    "attack_primary_class": row["attack_primary_class"],
                    "attack_confidence": row["attack_confidence"],
                    "attack_certainty": row["attack_certainty"],
                    "attack_method": row["attack_method"],
                    "intel_source": _safe_str(intel.get("source"), "fallback"),
                    "intel_scope": _safe_str(intel.get("scope"), "unknown"),
                    "provider_status": _safe_str(intel.get("provider_status"), "unknown"),
                    "org": _safe_str(intel.get("org"), "--"),
                    "asn": _safe_str(intel.get("asn"), "--"),
                    "isp": _safe_str(intel.get("isp"), "--"),
                    "os": _safe_str(intel.get("os"), "--"),
                    "country": _safe_str(intel.get("country"), "--"),
                    "city": _safe_str(intel.get("city"), "--"),
                    "region": _safe_str(intel.get("region"), "--"),
                    "latitude": intel.get("latitude"),
                    "longitude": intel.get("longitude"),
                    "risk": _safe_str(intel.get("risk"), "unknown"),
                    "open_ports": ports,
                    "open_ports_summary": port_summary,
                    "vuln_count": _safe_int(intel.get("vuln_count"), 0),
                    "hostnames": [str(v) for v in intel.get("hostnames", []) if str(v).strip()],
                    "domains": [str(v) for v in intel.get("domains", []) if str(v).strip()],
                    "tags": [str(v) for v in intel.get("tags", []) if str(v).strip()],
                    "services_count": _safe_int(intel.get("services_count"), len(intel.get("services", []))),
                    "service_fingerprints": [
                        str(v) for v in intel.get("service_fingerprints", []) if str(v).strip()
                    ],
                    "services": [dict(v) for v in intel.get("services", []) if isinstance(v, dict)],
                    "vuln_details": [dict(v) for v in intel.get("vuln_details", []) if isinstance(v, dict)],
                    "vuln_severity": dict(intel.get("vuln_severity", {}))
                    if isinstance(intel.get("vuln_severity"), dict)
                    else {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                    "last_update": _safe_str(intel.get("last_update")),
                    "cache_hit": bool(intel.get("cache_hit")),
                }
            )

        risk_counter: Counter[str] = Counter()
        country_counter: Counter[str] = Counter()
        organization_counter: Counter[str] = Counter()
        asn_counter: Counter[str] = Counter()
        port_counter: Counter[int] = Counter()
        service_counter: Counter[str] = Counter()
        vuln_severity_counter: Counter[str] = Counter()
        cve_counter: Counter[str] = Counter()
        cve_metadata: dict[str, dict[str, Any]] = {}
        map_points: list[dict[str, Any]] = []
        synthetic_map_points = 0
        public_ip_count = 0
        with_services_count = 0
        with_vulns_count = 0

        for ip in ordered_ips:
            intel = dict(intel_by_ip.get(ip, self._fallback_threat_intel(ip, "lookup-missing")))
            risk = _safe_str(intel.get("risk"), "unknown").strip().lower() or "unknown"
            risk_counter[risk] += 1
            country = _safe_str(intel.get("country")).strip()
            org = _safe_str(intel.get("org")).strip()
            asn = _safe_str(intel.get("asn")).strip()
            scope = _safe_str(intel.get("scope"), "unknown").strip()
            if country:
                country_counter[country] += 1
            if org:
                organization_counter[org] += 1
            if asn:
                asn_counter[asn] += 1
            ports = [int(v) for v in intel.get("open_ports", []) if _safe_int(v, 0) > 0]
            for port in ports:
                port_counter[port] += 1
            service_fingerprints = [str(v) for v in intel.get("service_fingerprints", []) if str(v).strip()]
            for fingerprint in service_fingerprints:
                service_counter[fingerprint] += 1
            services_count = _safe_int(intel.get("services_count"), len(intel.get("services", [])))
            if services_count > 0:
                with_services_count += 1
            if _safe_int(intel.get("vuln_count"), 0) > 0:
                with_vulns_count += 1
            raw_vuln_severity = intel.get("vuln_severity")
            if isinstance(raw_vuln_severity, dict):
                for severity, count in raw_vuln_severity.items():
                    normalized_severity = _safe_str(severity, "unknown").strip().lower() or "unknown"
                    vuln_severity_counter[normalized_severity] += max(0, _safe_int(count, 0))
            vuln_details = [dict(v) for v in intel.get("vuln_details", []) if isinstance(v, dict)]
            for detail in vuln_details:
                vuln_id = _safe_str(detail.get("id")).strip()
                if not vuln_id:
                    continue
                cve_counter[vuln_id] += 1
                if vuln_id not in cve_metadata:
                    cve_metadata[vuln_id] = {
                        "severity": _safe_str(detail.get("severity"), "unknown").strip().lower() or "unknown",
                        "cvss": detail.get("cvss"),
                    }
            if scope == "public":
                public_ip_count += 1
            latitude = self._safe_coordinate(intel.get("latitude"), -90.0, 90.0)
            longitude = self._safe_coordinate(intel.get("longitude"), -180.0, 180.0)
            geo_source = "provider"
            if latitude is None or longitude is None:
                synthetic_coordinates = self._synthetic_public_map_coordinates(ip)
                if synthetic_coordinates is None:
                    continue
                latitude, longitude = synthetic_coordinates
                geo_source = "synthetic"
                synthetic_map_points += 1
            role_counter = role_counts_by_ip.get(ip, Counter())
            if role_counter.get("attacker", 0) and role_counter.get("target", 0):
                dominant_role = "mixed"
            elif role_counter.get("attacker", 0):
                dominant_role = "attacker"
            elif role_counter.get("target", 0):
                dominant_role = "target"
            else:
                dominant_role = "unknown"
            open_ports_summary = ", ".join(str(v) for v in ports[:6]) if ports else "--"
            if len(ports) > 6:
                open_ports_summary = f"{open_ports_summary}, +{len(ports) - 6} more"
            map_points.append(
                {
                    "ip": ip,
                    "latitude": latitude,
                    "longitude": longitude,
                    "country": country or "--",
                    "city": _safe_str(intel.get("city"), "--"),
                    "org": org or "--",
                    "risk": risk,
                    "role": dominant_role,
                    "incident_count": len(incident_ids_by_ip.get(ip, set())),
                    "vuln_count": _safe_int(intel.get("vuln_count"), 0),
                    "open_ports_summary": open_ports_summary,
                    "intel_source": _safe_str(intel.get("source"), "fallback"),
                    "provider_status": _safe_str(intel.get("provider_status"), "unknown"),
                    "geo_source": geo_source,
                }
            )

        map_points = sorted(
            map_points,
            key=lambda point: (
                -_safe_int(point.get("incident_count"), 0),
                -_safe_int(point.get("vuln_count"), 0),
                _safe_str(point.get("ip")),
            ),
        )[: self._threat_intel_max_map_points]
        synthetic_map_points = sum(
            1 for point in map_points if _safe_str(point.get("geo_source")).strip().lower() == "synthetic"
        )
        risk_order = ("high", "medium", "low", "unknown")
        severity_order = ("critical", "high", "medium", "low", "unknown")
        top_cves = []
        for vuln_id, count in cve_counter.most_common(10):
            metadata = cve_metadata.get(vuln_id, {})
            top_cves.append(
                {
                    "id": vuln_id,
                    "count": count,
                    "severity": _safe_str(metadata.get("severity"), "unknown"),
                    "cvss": metadata.get("cvss"),
                }
            )
        analytics = {
            "risk_distribution": [
                {"label": label, "count": risk_counter.get(label, 0)}
                for label in risk_order
                if risk_counter.get(label, 0) > 0
            ],
            "top_countries": [{"label": label, "count": count} for label, count in country_counter.most_common(8)],
            "top_organizations": [{"label": label, "count": count} for label, count in organization_counter.most_common(8)],
            "top_asns": [{"label": label, "count": count} for label, count in asn_counter.most_common(8)],
            "top_ports": [{"port": port, "count": count} for port, count in port_counter.most_common(12)],
            "top_services": [{"label": label, "count": count} for label, count in service_counter.most_common(12)],
            "vulnerability_severity": [
                {"severity": severity, "count": vuln_severity_counter.get(severity, 0)}
                for severity in severity_order
                if vuln_severity_counter.get(severity, 0) > 0
            ],
            "top_cves": top_cves,
            "totals": {
                "unique_ips": len(ordered_ips),
                "public_ips": public_ip_count,
                "mapped_ips": len(map_points),
                "with_services": with_services_count,
                "with_vulnerabilities": with_vulns_count,
                "mapped_with_synthetic": synthetic_map_points,
            },
        }

        return {
            "items": items,
            "map_points": map_points,
            "analytics": analytics,
            "meta": self._dashboard_meta(
                source="threat-intel",
                staged=False,
                extras={
                    "provider": "shodan",
                    "shodan_configured": bool(self._shodan_api_key),
                    "shodan_key_source": self._shodan_key_source,
                    "lookup_limit": self._threat_intel_lookup_limit,
                    "unique_ips": len(ordered_ips),
                    "lookups_executed": len(lookup_ips),
                    "lookups_skipped": len(skipped_ips),
                    "cache_hits": cache_hits,
                    "provider_hits": {"shodan": shodan_count, "fallback": fallback_count},
                    "map_points": len(map_points),
                    "synthetic_map_points": synthetic_map_points,
                    "max_services_per_host": self._threat_intel_max_services,
                    "max_vulns_per_host": self._threat_intel_max_vulns,
                },
            ),
        }

    def get_threat_map(self) -> dict[str, Any]:
        """Backward-compatible alias that now returns threat-intel payload."""
        return self.get_threat_intel(limit=300)

    @staticmethod
    def _normalize_hunting_filter_values(
        raw_value: Any,
        *,
        field_name: str,
        max_items: int = 50,
    ) -> list[str]:
        if raw_value is None:
            return []
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        normalized: list[str] = []
        for value in values:
            text = _safe_str(value).strip()
            if text:
                normalized.append(text)
        if len(normalized) > max_items:
            raise ValueError(f"filters.{field_name} exceeds max item count ({max_items})")
        return normalized

    def _normalize_hunting_filters(self, raw_filters: Any) -> dict[str, Any]:
        if raw_filters is None:
            return {}
        if not isinstance(raw_filters, dict):
            raise ValueError("filters must be a JSON object")

        source_ips = self._normalize_hunting_filter_values(raw_filters.get("source_ips"), field_name="source_ips")
        target_ips = self._normalize_hunting_filter_values(raw_filters.get("target_ips"), field_name="target_ips")
        severities = self._normalize_hunting_filter_values(raw_filters.get("severities"), field_name="severities")
        attack_primary_classes = self._normalize_hunting_filter_values(
            raw_filters.get("attack_primary_classes"),
            field_name="attack_primary_classes",
        )
        certainty_levels_raw = self._normalize_hunting_filter_values(
            raw_filters.get("certainty_levels"),
            field_name="certainty_levels",
        )
        triage_states_raw = self._normalize_hunting_filter_values(
            raw_filters.get("triage_states"),
            field_name="triage_states",
        )

        certainty_levels = sorted({self._normalize_certainty_level(item) for item in certainty_levels_raw})
        triage_states = sorted({self._parse_triage_state(item) for item in triage_states_raw})

        attack_confidence_gte = _safe_float(raw_filters.get("attack_confidence_gte"), -1.0)
        attack_confidence_lte = _safe_float(raw_filters.get("attack_confidence_lte"), 2.0)
        detection_confidence_gte = _safe_float(raw_filters.get("detection_confidence_gte"), -1.0)
        detection_confidence_lte = _safe_float(raw_filters.get("detection_confidence_lte"), 2.0)
        event_count_gte = _safe_int(raw_filters.get("event_count_gte"), -1)
        event_count_lte = _safe_int(raw_filters.get("event_count_lte"), -1)
        bytes_gte = _safe_int(raw_filters.get("bytes_gte"), -1)
        bytes_lte = _safe_int(raw_filters.get("bytes_lte"), -1)
        packets_gte = _safe_int(raw_filters.get("packets_gte"), -1)
        packets_lte = _safe_int(raw_filters.get("packets_lte"), -1)

        def _validate_confidence_range(name: str, minimum: float, maximum: float) -> None:
            if minimum >= 0.0 and not 0.0 <= minimum <= 1.0:
                raise ValueError(f"filters.{name}_gte must be in range [0,1]")
            has_maximum = raw_filters.get(f"{name}_lte") is not None
            if has_maximum and not 0.0 <= maximum <= 1.0:
                raise ValueError(f"filters.{name}_lte must be in range [0,1]")
            if minimum >= 0.0 and has_maximum and minimum > maximum:
                raise ValueError(f"filters.{name}_gte must be <= filters.{name}_lte")

        _validate_confidence_range("attack_confidence", attack_confidence_gte, attack_confidence_lte)
        _validate_confidence_range("detection_confidence", detection_confidence_gte, detection_confidence_lte)

        for range_name, minimum, maximum in (
            ("event_count", event_count_gte, event_count_lte),
            ("bytes", bytes_gte, bytes_lte),
            ("packets", packets_gte, packets_lte),
        ):
            if minimum >= 0 and maximum >= 0 and minimum > maximum:
                raise ValueError(f"filters.{range_name}_gte must be <= filters.{range_name}_lte")

        from_timestamp = raw_filters.get("from_timestamp")
        to_timestamp = raw_filters.get("to_timestamp")
        parsed_from = _parse_iso_datetime(from_timestamp) if from_timestamp else None
        parsed_to = _parse_iso_datetime(to_timestamp) if to_timestamp else None
        if from_timestamp and parsed_from is None:
            raise ValueError("filters.from_timestamp must be ISO-8601")
        if to_timestamp and parsed_to is None:
            raise ValueError("filters.to_timestamp must be ISO-8601")
        if parsed_from and parsed_to and parsed_from > parsed_to:
            raise ValueError("filters.from_timestamp must be <= filters.to_timestamp")

        text_contains = _safe_str(raw_filters.get("text_contains")).strip()
        if len(text_contains) > 128:
            raise ValueError("filters.text_contains must be <= 128 characters")

        return {
            "source_ips": {item.lower() for item in source_ips},
            "target_ips": {item.lower() for item in target_ips},
            "severities": {item.lower() for item in severities},
            "attack_primary_classes": {item.lower() for item in attack_primary_classes},
            "certainty_levels": set(certainty_levels),
            "triage_states": set(triage_states),
            "attack_confidence_gte": attack_confidence_gte if attack_confidence_gte >= 0.0 else None,
            "attack_confidence_lte": attack_confidence_lte if 0.0 <= attack_confidence_lte <= 1.0 else None,
            "detection_confidence_gte": detection_confidence_gte if detection_confidence_gte >= 0.0 else None,
            "detection_confidence_lte": (
                detection_confidence_lte if 0.0 <= detection_confidence_lte <= 1.0 else None
            ),
            "event_count_gte": event_count_gte if event_count_gte >= 0 else None,
            "event_count_lte": event_count_lte if event_count_lte >= 0 else None,
            "bytes_gte": bytes_gte if bytes_gte >= 0 else None,
            "bytes_lte": bytes_lte if bytes_lte >= 0 else None,
            "packets_gte": packets_gte if packets_gte >= 0 else None,
            "packets_lte": packets_lte if packets_lte >= 0 else None,
            "from_timestamp": parsed_from,
            "to_timestamp": parsed_to,
            "text_contains": text_contains.lower(),
        }

    @staticmethod
    def _hunting_filters_active(filters: dict[str, Any]) -> bool:
        for value in filters.values():
            if isinstance(value, (set, list, tuple, dict)):
                if value:
                    return True
                continue
            if isinstance(value, str):
                if value.strip():
                    return True
                continue
            if value is not None:
                return True
        return False

    @staticmethod
    def _incident_packet_source_ip(incident: dict[str, Any]) -> str:
        return _safe_str(incident.get("source_ip")).strip()

    @classmethod
    def _incident_hunting_source_ip(cls, incident: dict[str, Any]) -> str:
        attacker_ip = _safe_str(incident.get("attacker_ip")).strip()
        if attacker_ip:
            return attacker_ip
        return cls._incident_packet_source_ip(incident)

    @classmethod
    def _hunting_query_record(cls, incident: dict[str, Any]) -> dict[str, Any]:
        packet_source_ip = cls._incident_packet_source_ip(incident)
        attacker_ip = _safe_str(incident.get("attacker_ip")).strip()
        attacker_or_source = attacker_ip or packet_source_ip
        record = dict(incident) if isinstance(incident, dict) else {}
        record["packet_source_ip"] = packet_source_ip
        record["source_ip"] = attacker_or_source
        record["attacker_ip"] = attacker_or_source
        return record

    def _incident_matches_hunting_filters(self, incident: dict[str, Any], filters: dict[str, Any]) -> bool:
        source_ip = self._incident_hunting_source_ip(incident).strip().lower()
        target_ip = _safe_str(incident.get("target_ip")).strip().lower()
        severity = _safe_str(incident.get("severity")).strip().lower()
        attack_primary_class = self._incident_attack_primary_class(incident).strip().lower()
        certainty_level = self._incident_attack_certainty(incident)["level"]
        triage_state = self._parse_triage_state(incident.get("triage_state"))

        if filters.get("source_ips") and source_ip not in filters["source_ips"]:
            return False
        if filters.get("target_ips") and target_ip not in filters["target_ips"]:
            return False
        if filters.get("severities") and severity not in filters["severities"]:
            return False
        if filters.get("attack_primary_classes") and attack_primary_class not in filters["attack_primary_classes"]:
            return False
        if filters.get("certainty_levels") and certainty_level not in filters["certainty_levels"]:
            return False
        if filters.get("triage_states") and triage_state not in filters["triage_states"]:
            return False

        attack_confidence = self._incident_attack_confidence(incident)
        detection_confidence = self._incident_detection_confidence(incident)
        event_count = _safe_int(incident.get("event_count"), 0)
        bytes_value = _safe_int(incident.get("bytes"), 0)
        packets = _safe_int(incident.get("packets"), 0)

        for field_name, candidate in (
            ("attack_confidence_gte", attack_confidence),
            ("detection_confidence_gte", detection_confidence),
            ("event_count_gte", event_count),
            ("bytes_gte", bytes_value),
            ("packets_gte", packets),
        ):
            floor = filters.get(field_name)
            if floor is not None and candidate < floor:
                return False
        for field_name, candidate in (
            ("attack_confidence_lte", attack_confidence),
            ("detection_confidence_lte", detection_confidence),
            ("event_count_lte", event_count),
            ("bytes_lte", bytes_value),
            ("packets_lte", packets),
        ):
            ceiling = filters.get(field_name)
            if ceiling is not None and candidate > ceiling:
                return False

        from_timestamp = filters.get("from_timestamp")
        to_timestamp = filters.get("to_timestamp")
        if from_timestamp is not None or to_timestamp is not None:
            incident_timestamp = _parse_iso_datetime(incident.get("timestamp"))
            if incident_timestamp is None:
                return False
            if from_timestamp is not None and incident_timestamp < from_timestamp:
                return False
            if to_timestamp is not None and incident_timestamp > to_timestamp:
                return False

        text_contains = _safe_str(filters.get("text_contains")).strip().lower()
        if text_contains:
            detail = self._incident_attack_detail(incident)
            searchable_text = " ".join(
                (
                    _safe_str(incident.get("id")),
                    self._incident_hunting_source_ip(incident),
                    self._incident_packet_source_ip(incident),
                    _safe_str(incident.get("target_ip")),
                    _safe_str(incident.get("severity")),
                    _safe_str(detail.get("summary")),
                    _safe_str(detail.get("primary_class")),
                    _safe_str(detail.get("description")),
                    _safe_str(detail.get("certainty_text")),
                )
            ).lower()
            if text_contains not in searchable_text:
                return False

        return True

    def get_hunting_query_capabilities(self) -> dict[str, Any]:
        return {
            "dsl": {
                "field_allowlist": list(self.HUNTING_QUERY_ALLOWED_FIELDS),
                "operators": list(self.HUNTING_QUERY_ALLOWED_OPERATORS),
                "max_query_length": self.HUNTING_QUERY_MAX_QUERY_LENGTH,
                "max_tokens": self.HUNTING_QUERY_MAX_TOKENS,
                "max_depth": self.HUNTING_QUERY_MAX_DEPTH,
                "examples": [
                    "attack_confidence >= 0.85 and attack_certainty_level in (probable,certain)",
                    "severity in (CRITICAL,HIGH) and source_ip startswith '203.0.113.'",
                    "packet_source_ip startswith '10.' and attacker_ip == '203.0.113.7'",
                    "attack_detail.certainty.level == probable and bytes > 10000",
                ],
            },
            "filters": {
                "list_fields": [
                    "source_ips",
                    "target_ips",
                    "severities",
                    "attack_primary_classes",
                    "certainty_levels",
                    "triage_states",
                ],
                "range_fields": [
                    "attack_confidence_gte/lte",
                    "detection_confidence_gte/lte",
                    "event_count_gte/lte",
                    "bytes_gte/lte",
                    "packets_gte/lte",
                ],
                "time_range_fields": ["from_timestamp", "to_timestamp"],
                "text_field": "text_contains",
            },
            "scientific_methods": {
                "available": [
                    "z_score_outliers",
                    "temporal_bursts",
                    "entropy_indicators",
                    "clustering_lite",
                ],
                "default_max_incidents": 800,
            },
            "meta": self._dashboard_meta(
                source="hunting-query-capabilities",
                staged=False,
                extras={
                    "query_api": {
                        "get_endpoint": "/api/hunting/query",
                        "post_endpoint": "/api/hunting/query",
                        "capabilities_endpoint": "/api/hunting/capabilities",
                        "compatibility_endpoints": [
                            "/api/hunting",
                            "/api/hunting/search",
                            "/api/hunting/execute",
                            "/api/threat-hunting/query",
                            "/api/threat-hunting/search",
                            "/api/threat-hunting/execute",
                        ],
                    },
                    "guardrails": {
                        "max_scan_incidents": self.HUNTING_QUERY_MAX_SCAN,
                        "max_result_limit": self.HUNTING_QUERY_MAX_LIMIT,
                    },
                    "field_semantics": {
                        "source_ip": (
                            "Attacker-oriented alias for hunting. Uses attacker_ip when present; "
                            "otherwise falls back to the incident packet source."
                        ),
                        "attacker_ip": "Canonical attacker attribution for hunting queries.",
                        "packet_source_ip": "Original directional packet source from incident.source_ip.",
                        "source_ips_filter": (
                            "Structured filters.source_ips uses the same attacker-oriented semantics "
                            "as source_ip in DSL."
                        ),
                    },
                },
            ),
        }

    def query_hunting(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        request_payload = payload if isinstance(payload, dict) else {}
        requested_limit = _safe_int(request_payload.get("limit"), self.HUNTING_QUERY_DEFAULT_LIMIT)
        limit = max(1, min(requested_limit, self.HUNTING_QUERY_MAX_LIMIT))
        requested_offset = _safe_int(request_payload.get("offset"), 0)
        offset = max(0, min(requested_offset, self.HUNTING_QUERY_MAX_SCAN))
        requested_scan = _safe_int(request_payload.get("scan_limit"), self.HUNTING_QUERY_DEFAULT_SCAN)
        scan_limit = max(limit + offset, requested_scan)
        scan_limit = max(1, min(scan_limit, self.HUNTING_QUERY_MAX_SCAN))

        incidents = self.list_incidents(limit=scan_limit)
        normalized_filters = self._normalize_hunting_filters(request_payload.get("filters"))
        filtered_incidents = [
            incident
            for incident in incidents
            if self._incident_matches_hunting_filters(incident, normalized_filters)
        ]

        dsl_query = _safe_str(request_payload.get("dsl", request_payload.get("query"))).strip()
        compiled = None
        if dsl_query:
            compiled = compile_query(
                dsl_query,
                allowed_fields=self.HUNTING_QUERY_ALLOWED_FIELDS,
                max_query_length=self.HUNTING_QUERY_MAX_QUERY_LENGTH,
                max_tokens=self.HUNTING_QUERY_MAX_TOKENS,
                max_depth=self.HUNTING_QUERY_MAX_DEPTH,
            )
            filtered_incidents = [
                incident
                for incident in filtered_incidents
                if compiled.evaluate(self._hunting_query_record(incident))
            ]

        total_matches = len(filtered_incidents)
        items = filtered_incidents[offset : offset + limit]

        scientific_methods_cfg = request_payload.get("scientific_methods")
        if not isinstance(scientific_methods_cfg, dict):
            scientific_methods_cfg = {}
        scientific_methods = run_scientific_methods(
            filtered_incidents,
            config=scientific_methods_cfg,
        )

        return {
            "items": items,
            "total_matches": total_matches,
            "query": {
                "dsl": dsl_query,
                "limit": limit,
                "offset": offset,
                "scan_limit": scan_limit,
                "structured_filters_applied": self._hunting_filters_active(normalized_filters),
                "dsl_applied": bool(compiled),
            },
            "scientific_methods": scientific_methods,
            "meta": self._dashboard_meta(
                source="hunting-query",
                staged=False,
                extras={
                    "base_incident_count": len(incidents),
                    "post_filter_incident_count": total_matches,
                    "page_size": len(items),
                    "field_allowlist_size": len(self.HUNTING_QUERY_ALLOWED_FIELDS),
                    "query_guardrails": {
                        "max_result_limit": self.HUNTING_QUERY_MAX_LIMIT,
                        "max_scan_incidents": self.HUNTING_QUERY_MAX_SCAN,
                    },
                    "certainty_levels": ["not_sure", "probable", "certain"],
                },
            ),
        }

    def get_hunting_view(self) -> dict[str, Any]:
        incidents = self.list_incidents(limit=500)
        source_counts: Counter[str] = Counter()
        source_attack_confidence_totals: Counter[str] = Counter()
        source_primary_class_counts: dict[str, Counter[str]] = defaultdict(Counter)
        source_certainty_counts: dict[str, Counter[str]] = defaultdict(Counter)
        overall_certainty_counts: Counter[str] = Counter()

        for incident in incidents:
            source_ip = _safe_str(incident.get("source_ip"))
            if not source_ip:
                continue
            source_counts[source_ip] += 1
            attack_confidence = self._incident_attack_confidence(incident)
            source_attack_confidence_totals[source_ip] += attack_confidence
            primary_class = self._incident_attack_primary_class(incident)
            source_primary_class_counts[source_ip][primary_class] += 1
            certainty_level = self._incident_attack_certainty(incident)["level"]
            source_certainty_counts[source_ip][certainty_level] += 1
            overall_certainty_counts[certainty_level] += 1

        hot_sources = []
        for ip, count in source_counts.most_common(15):
            certainty_counter = source_certainty_counts[ip]
            dominant_class = (
                source_primary_class_counts[ip].most_common(1)[0][0]
                if source_primary_class_counts[ip]
                else "Unknown / Needs More Data"
            )
            attack_confidence_avg = float(source_attack_confidence_totals[ip]) / max(1, count)
            hot_source_attack_detail = self._aggregate_attack_detail(
                summary=dominant_class,
                primary_class=dominant_class,
                confidence=attack_confidence_avg,
                certainty_level=self._dominant_certainty_level(certainty_counter),
                source="hunting-source-aggregation",
                certainty_counts=certainty_counter,
            )
            hot_sources.append(
                {
                    "ip": ip,
                    "count": count,
                    "attack_primary_class": dominant_class,
                    "attack_confidence_avg": attack_confidence_avg,
                    "attack_certainty": {
                        "level": _safe_str(hot_source_attack_detail["certainty"].get("level"), "not_sure"),
                        "text": _safe_str(hot_source_attack_detail["certainty"].get("text")),
                        "counts": self._certainty_counts_from_counter(certainty_counter),
                    },
                    "attack_detail": hot_source_attack_detail,
                }
            )

        high_confidence_attack_threshold = 0.85
        high_confidence_certainty_levels = {"probable", "certain"}
        high_confidence_max_results = 20
        high_confidence_candidates: list[tuple[dict[str, Any], float, str]] = []
        for incident in incidents:
            attack_confidence = self._incident_attack_confidence(incident)
            certainty_level = self._incident_attack_certainty(incident)["level"]
            if (
                attack_confidence >= high_confidence_attack_threshold
                and certainty_level in high_confidence_certainty_levels
            ):
                high_confidence_candidates.append((incident, attack_confidence, certainty_level))
        high_confidence_candidates.sort(
            key=lambda item: (
                item[1],
                self._certainty_level_rank(item[2]),
                _safe_str(item[0].get("timestamp")),
            ),
            reverse=True,
        )
        high_confidence_findings = [
            item[0] for item in high_confidence_candidates[:high_confidence_max_results]
        ]
        high_confidence_certainty_ordered = sorted(
            high_confidence_certainty_levels,
            key=self._certainty_level_rank,
            reverse=True,
        )
        return {
            "hot_sources": hot_sources,
            "high_confidence_findings": high_confidence_findings,
            "high_confidence_incidents": high_confidence_findings,
            "high_confidence_attack_incidents": high_confidence_findings,
            "recommended_queries": [
                "attack_detail.certainty.level in (probable,certain) and attack_detail.confidence >= 0.85",
                "source_ip with >= 3 incidents in 15m and stable attack_detail.primary_class",
                "attack_detail.evidence.missing is non-empty with severity in (CRITICAL,HIGH)",
            ],
            "meta": self._dashboard_meta(
                source="live-derived",
                staged=False,
                extras={
                    "attack_uncertainty": self._certainty_counts_from_counter(overall_certainty_counts),
                    "high_confidence_criteria": {
                        "attack_confidence_gte": high_confidence_attack_threshold,
                        "certainty_levels": high_confidence_certainty_ordered,
                        "max_results": high_confidence_max_results,
                    },
                    "high_confidence_total_candidates": len(high_confidence_candidates),
                    "high_confidence_result_count": len(high_confidence_findings),
                    "query_api": {
                        "capabilities_endpoint": "/api/hunting/capabilities",
                        "query_endpoint": "/api/hunting/query",
                        "compatibility_endpoints": [
                            "/api/hunting",
                            "/api/hunting/search",
                            "/api/hunting/execute",
                            "/api/threat-hunting/query",
                            "/api/threat-hunting/search",
                            "/api/threat-hunting/execute",
                        ],
                    },
                },
            ),
        }

    def get_compliance_logs(self, tail_lines: int = 200) -> dict[str, Any]:
        log_path = os.path.join("logs", "ids_alerts.log")
        if not os.path.exists(log_path):
            return {"lines": [], "meta": {"source": "logfile", "staged": False}}

        normalized_tail = max(1, _safe_int(tail_lines, 200))
        recent_lines: deque[str] = deque(maxlen=normalized_tail)
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                recent_lines.append(line.rstrip("\n"))

        return {"lines": list(recent_lines), "meta": {"source": "logfile", "staged": False}}

    def _load_full_config(self) -> dict[str, Any]:
        config = load_runtime_config(self.config_path)
        return config if isinstance(config, dict) else {}

    def _save_full_config(self, config: dict[str, Any]) -> None:
        directory = os.path.dirname(self.config_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)

    @staticmethod
    def _validate_attack_typing_updates(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("attack_typing must be a JSON object")

        updates: dict[str, Any] = {}
        if "minimum_score" in payload:
            value = _safe_float(payload["minimum_score"], -1.0)
            if value < 0.0:
                raise ValueError("attack_typing.minimum_score must be >= 0.0")
            updates["minimum_score"] = float(value)

        if "minimum_margin" in payload:
            value = _safe_float(payload["minimum_margin"], -1.0)
            if value < 0.0:
                raise ValueError("attack_typing.minimum_margin must be >= 0.0")
            updates["minimum_margin"] = float(value)

        if "fallback_class_id" in payload:
            value = _safe_str(payload["fallback_class_id"]).strip()
            if not value:
                raise ValueError("attack_typing.fallback_class_id must be non-empty")
            updates["fallback_class_id"] = value

        if "max_alternatives" in payload:
            value = _safe_int(payload["max_alternatives"], 0)
            if value < 1:
                raise ValueError("attack_typing.max_alternatives must be >= 1")
            updates["max_alternatives"] = int(value)

        if "rules_path" in payload:
            value = _safe_str(payload["rules_path"]).strip()
            if not value:
                raise ValueError("attack_typing.rules_path must be non-empty")
            updates["rules_path"] = value

        if "schema_path" in payload:
            value = _safe_str(payload["schema_path"]).strip()
            if not value:
                raise ValueError("attack_typing.schema_path must be non-empty")
            updates["schema_path"] = value

        return updates

    def get_rules(self) -> dict[str, Any]:
        return {
            "alert_threshold": float(self.ids.alert_threshold),
            "loopback_window_seconds": int(self.ids.loopback_window_seconds),
            "loopback_min_distinct_ports_for_scan": int(
                self.ids.loopback_min_distinct_ports_for_scan
            ),
            "attack_typing": self._attack_typing_metadata(),
            "meta": self._dashboard_meta(
                source="live-config",
                staged=False,
                extras={"scope": "rules"},
            ),
        }

    def update_rules(self, payload: dict[str, Any]) -> dict[str, Any]:
        attack_typing_updates: dict[str, Any] = {}
        if "attack_typing" in payload:
            attack_typing_updates = self._validate_attack_typing_updates(payload["attack_typing"])

        next_alert_threshold = float(self.ids.alert_threshold)
        if "alert_threshold" in payload:
            threshold = _safe_float(payload["alert_threshold"], -1.0)
            if threshold < 0.0 or threshold > 1.0:
                raise ValueError("alert_threshold must be between 0.0 and 1.0")
            next_alert_threshold = float(threshold)

        next_loopback_window_seconds = int(self.ids.loopback_window_seconds)
        if "loopback_window_seconds" in payload:
            value = _safe_int(payload["loopback_window_seconds"], -1)
            if value <= 0:
                raise ValueError("loopback_window_seconds must be > 0")
            next_loopback_window_seconds = int(value)

        next_loopback_min_distinct_ports = int(self.ids.loopback_min_distinct_ports_for_scan)
        if "loopback_min_distinct_ports_for_scan" in payload:
            value = _safe_int(payload["loopback_min_distinct_ports_for_scan"], -1)
            if value <= 0:
                raise ValueError("loopback_min_distinct_ports_for_scan must be > 0")
            next_loopback_min_distinct_ports = int(value)

        previous_alert_threshold = float(self.ids.alert_threshold)
        previous_loopback_window_seconds = int(self.ids.loopback_window_seconds)
        previous_loopback_min_distinct_ports = int(self.ids.loopback_min_distinct_ports_for_scan)
        previous_engine = self.attack_type_engine

        with self._config_lock:
            previous_config = self._load_full_config()
            config = copy.deepcopy(previous_config)
            runtime_config = config.get("runtime")
            if not isinstance(runtime_config, dict):
                runtime_config = {}
                config["runtime"] = runtime_config
            suppression_config = config.get("suppression")
            if not isinstance(suppression_config, dict):
                suppression_config = {}
                config["suppression"] = suppression_config
            runtime_config["alert_threshold"] = float(next_alert_threshold)
            suppression_config["loopback_window_seconds"] = int(next_loopback_window_seconds)
            suppression_config["loopback_min_distinct_ports_for_scan"] = int(
                next_loopback_min_distinct_ports
            )
            if attack_typing_updates:
                attack_typing_config = runtime_config.setdefault("attack_typing", {})
                if not isinstance(attack_typing_config, dict):
                    attack_typing_config = {}
                    runtime_config["attack_typing"] = attack_typing_config
                attack_typing_config.update(attack_typing_updates)
            config_saved = False
            try:
                self._save_full_config(config)
                config_saved = True
                self.ids.alert_threshold = next_alert_threshold
                self.ids.loopback_window_seconds = next_loopback_window_seconds
                self.ids.loopback_min_distinct_ports_for_scan = next_loopback_min_distinct_ports
                if attack_typing_updates:
                    self.attack_type_engine = AttackTypeRuleEngine.from_runtime_config(self.config_path)
            except Exception:
                self.ids.alert_threshold = previous_alert_threshold
                self.ids.loopback_window_seconds = previous_loopback_window_seconds
                self.ids.loopback_min_distinct_ports_for_scan = previous_loopback_min_distinct_ports
                self.attack_type_engine = previous_engine
                if config_saved:
                    try:
                        self._save_full_config(previous_config)
                    except Exception:
                        logger.exception("Failed to restore previous runtime config after update_rules error")
                raise
        return self.get_rules()

    def get_sensors(self) -> dict[str, Any]:
        configured = self.interface
        active = configured if configured else "auto-detected"
        return {
            "sensors": [
                {
                    "id": "sensor-primary",
                    "interface": str(active),
                    "status": "active",
                    "packets_processed": _safe_int(self._stats().get("packets_processed"), 0),
                }
            ],
            "meta": self._dashboard_meta(
                source="live",
                staged=False,
                extras={"scope": "sensors"},
            ),
        }

    def get_settings(self) -> dict[str, Any]:
        config = self._load_full_config()
        return {
            "host": cfg_get(config, "web.host", "127.0.0.1"),
            "port": cfg_get(config, "web.port", self.web_port),
            "refresh_interval_seconds": int(self.refresh_interval_seconds),
            "enable_staged_data": bool(self.enable_staged_data),
            "meta": self._dashboard_meta(
                source="runtime",
                staged=False,
                extras={"scope": "settings"},
            ),
        }

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        next_refresh_interval_seconds = int(self.refresh_interval_seconds)
        if "refresh_interval_seconds" in payload:
            value = _safe_int(payload["refresh_interval_seconds"], -1)
            if value <= 0:
                raise ValueError("refresh_interval_seconds must be > 0")
            next_refresh_interval_seconds = int(value)

        next_enable_staged_data = bool(self.enable_staged_data)
        if "enable_staged_data" in payload:
            next_enable_staged_data = bool(payload["enable_staged_data"])

        previous_refresh_interval_seconds = int(self.refresh_interval_seconds)
        previous_enable_staged_data = bool(self.enable_staged_data)

        with self._config_lock:
            previous_config = self._load_full_config()
            config = copy.deepcopy(previous_config)
            web_config = config.get("web")
            if not isinstance(web_config, dict):
                web_config = {}
                config["web"] = web_config
            web_config["refresh_interval_seconds"] = int(next_refresh_interval_seconds)
            web_config["enable_staged_data"] = bool(next_enable_staged_data)
            config_saved = False
            try:
                self._save_full_config(config)
                config_saved = True
                self.refresh_interval_seconds = next_refresh_interval_seconds
                self.enable_staged_data = next_enable_staged_data
            except Exception:
                self.refresh_interval_seconds = previous_refresh_interval_seconds
                self.enable_staged_data = previous_enable_staged_data
                if config_saved:
                    try:
                        self._save_full_config(previous_config)
                    except Exception:
                        logger.exception("Failed to restore previous runtime config after update_settings error")
                raise
        return self.get_settings()

    def get_simulation_scenarios(self) -> dict[str, Any]:
        items = self.attack_simulator.list_scenarios()
        return {
            "items": items,
            "meta": self._dashboard_meta(
                source="simulation-catalog",
                staged=True,
                extras={"count": len(items)},
            ),
        }

    def _validate_simulation_trigger_payload(self, payload: dict[str, Any]) -> tuple[str, int]:
        scenario_id = _safe_str(payload.get("scenario_id", payload.get("scenario"))).strip()
        if not scenario_id:
            raise ValueError("scenario_id is required")

        count = 1
        if "count" in payload:
            count = _safe_int(payload.get("count"), -1)
        if count < 1 or count > self.attack_simulator.MAX_BATCH_SIZE:
            raise ValueError(f"count must be between 1 and {self.attack_simulator.MAX_BATCH_SIZE}")
        return scenario_id, count

    def trigger_simulation_scenario(self, payload: dict[str, Any]) -> dict[str, Any]:
        scenario_id, count = self._validate_simulation_trigger_payload(payload)
        sequence_start = self._simulation_sequence + 1
        alerts = self.attack_simulator.generate_alerts(
            scenario_id,
            count=count,
            sequence_start=sequence_start,
            base_time=datetime.utcnow(),
        )

        with self.ids._state_lock:
            for alert in alerts:
                self.ids.alerts.append(alert)
                self.ids.stats["attacks_detected"] = _safe_int(self.ids.stats.get("attacks_detected"), 0) + 1
                self.ids.stats["flows_analyzed"] = _safe_int(self.ids.stats.get("flows_analyzed"), 0) + max(
                    1, _safe_int(alert.get("event_count"), 1)
                )
                self.ids.stats["packets_processed"] = _safe_int(
                    self.ids.stats.get("packets_processed"), 0
                ) + max(0, _safe_int(alert.get("packets"), 0))
            self._simulation_sequence += len(alerts)

        scenario = self.attack_simulator.get_scenario(scenario_id)
        preview = self._list_incidents_from_stats({"recent_alerts": alerts}, limit=len(alerts))
        return {
            "scenario": scenario,
            "count": len(alerts),
            "incident_preview": preview,
            "meta": self._dashboard_meta(
                source="simulation-trigger",
                staged=True,
                extras={
                    "sequence_start": sequence_start,
                    "sequence_end": self._simulation_sequence,
                },
            ),
        }
