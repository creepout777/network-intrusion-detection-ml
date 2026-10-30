"""Deterministic attack-family typing based on configurable JSON rules."""

from __future__ import annotations

import json
import logging
import os
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar

from common.config_utils import cfg_get, load_runtime_config

logger = logging.getLogger(__name__)
_T = TypeVar("_T")


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


def _safe_timestamp(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        try:
            return value.timestamp()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _as_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    result: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name}[{idx}] must be a non-empty string")
        result.append(item.strip())
    return result


def _load_json_file(path: str, label: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{label} at '{path}' must be a JSON object")
    return data


def _resolve_path(config_path: str, candidate_path: str) -> str:
    if os.path.isabs(candidate_path):
        return candidate_path

    direct = os.path.abspath(candidate_path)
    if os.path.exists(direct):
        return direct

    config_abs_path = os.path.abspath(config_path)
    config_dir = os.path.dirname(config_abs_path)

    joined_with_config_dir = os.path.abspath(os.path.join(config_dir, candidate_path))
    if os.path.exists(joined_with_config_dir):
        return joined_with_config_dir

    project_root = os.path.abspath(os.path.join(config_dir, os.pardir))
    joined_with_project_root = os.path.abspath(os.path.join(project_root, candidate_path))
    if os.path.exists(joined_with_project_root):
        return joined_with_project_root

    return joined_with_project_root


class AttackTypeRuleEngine:
    """Deterministic scoring engine for attack-family assignment."""

    _METRIC_FAMILY_BY_METRIC = {
        "target_ports": "targeting",
        "distinct_target_ports": "targeting",
        "target_ips": "targeting",
        "distinct_target_ips": "targeting",
        "dominant_target_port_event_ratio": "targeting",
        "ssh_target_port_ratio": "targeting",
        "web_target_port_ratio": "targeting",
        "event_count": "volume",
        "packets": "volume",
        "bytes": "volume",
        "bytes_per_packet": "volume",
        "packets_per_event": "volume",
        "bytes_per_event": "volume",
        "event_records_count": "temporal",
        "event_span_seconds": "temporal",
        "events_per_minute": "temporal",
        "protocol": "transport",
        "udp_event_ratio": "transport",
    }

    def __init__(
        self,
        *,
        ruleset: dict[str, Any],
        source: str,
        rules_path: str,
        schema_path: str,
        load_error: str | None = None,
        evaluation_cache_size: int = 256,
    ) -> None:
        self.source = source
        self.rules_path = rules_path
        self.schema_path = schema_path
        self.load_error = load_error

        self.schema_version = str(ruleset.get("schema_version", "1.0"))
        self.taxonomy = list(ruleset["taxonomy"])
        self.taxonomy_by_id = {entry["id"]: entry for entry in self.taxonomy}
        self.taxonomy_order = [entry["id"] for entry in self.taxonomy]
        self.rules = list(ruleset["rules"])

        scoring = dict(ruleset["scoring"])
        self.minimum_score = _safe_float(scoring.get("minimum_score"), 3.0)
        self.minimum_margin = _safe_float(scoring.get("minimum_margin"), 0.75)
        self.fallback_class_id = str(scoring.get("fallback_class_id", "unknown"))
        self.max_alternatives = max(1, _safe_int(scoring.get("max_alternatives"), 3))
        self._candidate_class_ids = [
            class_id for class_id in self.taxonomy_order if class_id != self.fallback_class_id
        ]
        self._evaluation_cache_size = max(0, _safe_int(evaluation_cache_size, 0))
        self._metrics_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._rule_match_cache: OrderedDict[
            str,
            tuple[dict[str, float], dict[str, tuple[str, ...]], dict[str, frozenset[str]]],
        ] = OrderedDict()

        self.required_evidence_by_class: dict[str, set[str]] = {}
        self.certainty_evidence_by_class: dict[str, set[str]] = {}
        for entry in self.taxonomy:
            self.required_evidence_by_class[entry["id"]] = set(entry["required_evidence"])
            self.certainty_evidence_by_class[entry["id"]] = set(entry.get("certainty_evidence", []))

        self.missing_message_by_evidence: dict[str, str] = {}
        self.class_max_scores: dict[str, float] = {
            class_id: 0.0 for class_id in self.taxonomy_by_id.keys()
        }
        for rule in self.rules:
            self.class_max_scores[rule["class_id"]] += float(rule["weight"])
            self.missing_message_by_evidence.setdefault(
                rule["evidence_id"], rule["missing_if_absent"]
            )

        self._compiled_rules: list[dict[str, Any]] = []
        self._compiled_rule_indexes_by_family: dict[str, tuple[int, ...]] = {}
        self._rule_eval_plan_by_family_signature: dict[tuple[str, ...], tuple[int, ...]] = {}
        family_rule_indexes: dict[str, list[int]] = {}

        for idx, rule in enumerate(self.rules):
            compiled_conditions = tuple(
                self._compile_condition_evaluator(condition) for condition in rule["conditions"]
            )
            compiled_rule = {
                "id": rule["id"],
                "class_id": rule["class_id"],
                "weight": float(rule["weight"]),
                "logic": rule["logic"],
                "evaluate": self._compile_rule_evaluator(rule["logic"], compiled_conditions),
                "evidence": rule["evidence"],
                "evidence_id": rule["evidence_id"],
            }
            self._compiled_rules.append(compiled_rule)
            families = {
                self._METRIC_FAMILY_BY_METRIC.get(str(condition["metric"]).strip(), "other")
                for condition in rule["conditions"]
            }
            for family in families:
                family_rule_indexes.setdefault(family, []).append(idx)

        self._compiled_rule_indexes_by_family = {
            family: tuple(indexes) for family, indexes in family_rule_indexes.items()
        }

    @classmethod
    def from_runtime_config(cls, config_path: str) -> "AttackTypeRuleEngine":
        config = load_runtime_config(config_path)
        attack_typing_cfg = cfg_get(config, "runtime.attack_typing", {})
        if not isinstance(attack_typing_cfg, dict):
            attack_typing_cfg = {}

        default_rules_path = os.path.join("config", "attack_type_rules.json")
        default_schema_path = os.path.join("config", "attack_type_rule_schema.json")
        configured_rules_path = str(attack_typing_cfg.get("rules_path", default_rules_path)).strip()
        configured_schema_path = str(attack_typing_cfg.get("schema_path", default_schema_path)).strip()
        if not configured_rules_path:
            configured_rules_path = default_rules_path
        if not configured_schema_path:
            configured_schema_path = default_schema_path
        rules_path = _resolve_path(config_path, configured_rules_path)
        schema_path = _resolve_path(config_path, configured_schema_path)

        try:
            schema = _load_json_file(schema_path, "attack rule schema")
            ruleset = _load_json_file(rules_path, "attack type rules")
            validated = cls._validate_ruleset(schema=schema, ruleset=ruleset)

            scoring = dict(validated["scoring"])
            default_minimum_score = _safe_float(scoring.get("minimum_score"), 3.0)
            default_minimum_margin = _safe_float(scoring.get("minimum_margin"), 0.75)
            default_fallback_class_id = str(scoring.get("fallback_class_id", "unknown")).strip() or "unknown"
            default_max_alternatives = max(1, _safe_int(scoring.get("max_alternatives"), 3))
            default_evaluation_cache_size = 256
            known_taxonomy_ids = {entry["id"] for entry in validated["taxonomy"]}

            if "minimum_score" in attack_typing_cfg:
                minimum_score = _safe_float(
                    attack_typing_cfg["minimum_score"], default_minimum_score
                )
                if minimum_score < 0.0:
                    logger.warning(
                        "runtime.attack_typing.minimum_score (%s) is invalid; using %.2f.",
                        attack_typing_cfg["minimum_score"],
                        default_minimum_score,
                    )
                    minimum_score = default_minimum_score
                scoring["minimum_score"] = minimum_score
            if "minimum_margin" in attack_typing_cfg:
                minimum_margin = _safe_float(
                    attack_typing_cfg["minimum_margin"], default_minimum_margin
                )
                if minimum_margin < 0.0:
                    logger.warning(
                        "runtime.attack_typing.minimum_margin (%s) is invalid; using %.2f.",
                        attack_typing_cfg["minimum_margin"],
                        default_minimum_margin,
                    )
                    minimum_margin = default_minimum_margin
                scoring["minimum_margin"] = minimum_margin
            if "fallback_class_id" in attack_typing_cfg:
                fallback_class_id = str(attack_typing_cfg["fallback_class_id"]).strip()
                if fallback_class_id in known_taxonomy_ids:
                    scoring["fallback_class_id"] = fallback_class_id
                else:
                    logger.warning(
                        "runtime.attack_typing.fallback_class_id (%s) is invalid; using '%s'.",
                        attack_typing_cfg["fallback_class_id"],
                        default_fallback_class_id,
                    )
                    scoring["fallback_class_id"] = default_fallback_class_id
            if "max_alternatives" in attack_typing_cfg:
                max_alternatives = _safe_int(
                    attack_typing_cfg["max_alternatives"], default_max_alternatives
                )
                if max_alternatives < 1:
                    logger.warning(
                        "runtime.attack_typing.max_alternatives (%s) is invalid; using %d.",
                        attack_typing_cfg["max_alternatives"],
                        default_max_alternatives,
                    )
                    max_alternatives = default_max_alternatives
                scoring["max_alternatives"] = max_alternatives

            evaluation_cache_size = _safe_int(
                attack_typing_cfg.get("evaluation_cache_size", default_evaluation_cache_size),
                default_evaluation_cache_size,
            )
            if evaluation_cache_size < 0:
                logger.warning(
                    "runtime.attack_typing.evaluation_cache_size (%s) is invalid; using %d.",
                    attack_typing_cfg.get("evaluation_cache_size"),
                    default_evaluation_cache_size,
                )
                evaluation_cache_size = default_evaluation_cache_size
            validated["scoring"] = scoring

            return cls(
                ruleset=validated,
                source=f"deterministic-rule-engine:{rules_path}",
                rules_path=configured_rules_path,
                schema_path=configured_schema_path,
                evaluation_cache_size=evaluation_cache_size,
            )
        except Exception as exc:
            logger.warning(
                "Attack-type rule loading failed (%s). Falling back to 'Unknown / Needs More Data'.",
                exc,
            )
            return cls(
                ruleset=cls._fallback_ruleset(),
                source="deterministic-rule-engine:fallback",
                rules_path=configured_rules_path,
                schema_path=configured_schema_path,
                load_error=str(exc),
                evaluation_cache_size=0,
            )

    @staticmethod
    def _fallback_ruleset() -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "taxonomy": [
                {
                    "id": "unknown",
                    "display_name": "Unknown / Needs More Data",
                    "description": (
                        "Insufficient or ambiguous evidence for attack-family assignment."
                    ),
                    "rich_description": (
                        "Attack-family assignment could not be made because valid typing rules "
                        "were unavailable."
                    ),
                    "limitations": [
                        "Rule set could not be loaded.",
                        "Attack-family typing is unavailable until configuration is fixed.",
                    ],
                    "required_evidence": [],
                    "certainty_evidence": [],
                }
            ],
            "scoring": {
                "minimum_score": 3.0,
                "minimum_margin": 0.75,
                "fallback_class_id": "unknown",
                "max_alternatives": 3,
            },
            "rules": [],
        }

    @staticmethod
    def _validate_ruleset(schema: dict[str, Any], ruleset: dict[str, Any]) -> dict[str, Any]:
        required_top_level = _as_string_list(
            schema.get("required_top_level", []), "schema.required_top_level"
        )
        required_taxonomy_fields = _as_string_list(
            schema.get("required_taxonomy_fields", []), "schema.required_taxonomy_fields"
        )
        required_rule_fields = _as_string_list(
            schema.get("required_rule_fields", []), "schema.required_rule_fields"
        )
        required_condition_fields = _as_string_list(
            schema.get("required_condition_fields", []), "schema.required_condition_fields"
        )
        allowed_logic = set(_as_string_list(schema.get("allowed_logic", []), "schema.allowed_logic"))
        allowed_operators = set(
            _as_string_list(schema.get("allowed_operators", []), "schema.allowed_operators")
        )

        for key in required_top_level:
            if key not in ruleset:
                raise ValueError(f"Ruleset missing top-level key '{key}'")

        taxonomy_raw = ruleset.get("taxonomy")
        if not isinstance(taxonomy_raw, list) or not taxonomy_raw:
            raise ValueError("ruleset.taxonomy must be a non-empty list")

        taxonomy: list[dict[str, Any]] = []
        taxonomy_ids: set[str] = set()
        for idx, entry in enumerate(taxonomy_raw):
            if not isinstance(entry, dict):
                raise ValueError(f"taxonomy[{idx}] must be an object")
            for field in required_taxonomy_fields:
                if field not in entry:
                    raise ValueError(f"taxonomy[{idx}] missing required field '{field}'")

            class_id = str(entry["id"]).strip()
            if not class_id:
                raise ValueError(f"taxonomy[{idx}].id must be non-empty")
            if class_id in taxonomy_ids:
                raise ValueError(f"Duplicate taxonomy id '{class_id}'")
            taxonomy_ids.add(class_id)

            display_name = str(entry["display_name"]).strip()
            description = str(entry["description"]).strip()
            rich_description = str(entry["rich_description"]).strip()
            limitations = _as_string_list(entry["limitations"], f"taxonomy[{idx}].limitations")
            required_evidence = _as_string_list(
                entry["required_evidence"], f"taxonomy[{idx}].required_evidence"
            )
            certainty_evidence = _as_string_list(
                entry.get("certainty_evidence", []), f"taxonomy[{idx}].certainty_evidence"
            )
            taxonomy.append(
                {
                    "id": class_id,
                    "display_name": display_name,
                    "description": description,
                    "rich_description": rich_description,
                    "limitations": limitations,
                    "required_evidence": required_evidence,
                    "certainty_evidence": certainty_evidence,
                }
            )

        scoring = ruleset.get("scoring")
        if not isinstance(scoring, dict):
            raise ValueError("ruleset.scoring must be an object")

        minimum_score = _safe_float(scoring.get("minimum_score"), -1.0)
        minimum_margin = _safe_float(scoring.get("minimum_margin"), -1.0)
        if minimum_score < 0.0:
            raise ValueError("scoring.minimum_score must be >= 0.0")
        if minimum_margin < 0.0:
            raise ValueError("scoring.minimum_margin must be >= 0.0")

        fallback_class_id = str(scoring.get("fallback_class_id", "")).strip()
        if fallback_class_id not in taxonomy_ids:
            raise ValueError("scoring.fallback_class_id must reference an existing taxonomy id")
        max_alternatives = max(1, _safe_int(scoring.get("max_alternatives"), 3))

        rules_raw = ruleset.get("rules")
        if not isinstance(rules_raw, list):
            raise ValueError("ruleset.rules must be a list")

        rules: list[dict[str, Any]] = []
        rule_ids: set[str] = set()
        evidence_ids_by_class: dict[str, set[str]] = {class_id: set() for class_id in taxonomy_ids}
        for idx, rule in enumerate(rules_raw):
            if not isinstance(rule, dict):
                raise ValueError(f"rules[{idx}] must be an object")
            for field in required_rule_fields:
                if field not in rule:
                    raise ValueError(f"rules[{idx}] missing required field '{field}'")

            rule_id = str(rule["id"]).strip()
            if not rule_id:
                raise ValueError(f"rules[{idx}].id must be non-empty")
            if rule_id in rule_ids:
                raise ValueError(f"Duplicate rule id '{rule_id}'")
            rule_ids.add(rule_id)

            class_id = str(rule["class_id"]).strip()
            if class_id not in taxonomy_ids:
                raise ValueError(
                    f"rules[{idx}].class_id '{class_id}' must reference an existing taxonomy id"
                )

            weight = _safe_float(rule["weight"], -1.0)
            if weight <= 0.0:
                raise ValueError(f"rules[{idx}].weight must be > 0")

            logic = str(rule["logic"]).strip()
            if logic not in allowed_logic:
                raise ValueError(
                    f"rules[{idx}].logic '{logic}' is invalid; allowed: {sorted(allowed_logic)}"
                )

            conditions_raw = rule["conditions"]
            if not isinstance(conditions_raw, list) or not conditions_raw:
                raise ValueError(f"rules[{idx}].conditions must be a non-empty list")
            conditions: list[dict[str, Any]] = []
            for cond_idx, condition in enumerate(conditions_raw):
                if not isinstance(condition, dict):
                    raise ValueError(f"rules[{idx}].conditions[{cond_idx}] must be an object")
                for field in required_condition_fields:
                    if field not in condition:
                        raise ValueError(
                            f"rules[{idx}].conditions[{cond_idx}] missing required field '{field}'"
                        )

                metric = str(condition["metric"]).strip()
                operator = str(condition["operator"]).strip()
                if operator not in allowed_operators:
                    raise ValueError(
                        f"rules[{idx}].conditions[{cond_idx}].operator "
                        f"'{operator}' is invalid; allowed: {sorted(allowed_operators)}"
                    )
                value = condition["value"]
                if operator == "between":
                    if (
                        not isinstance(value, list)
                        or len(value) != 2
                        or not all(isinstance(v, (int, float)) for v in value)
                    ):
                        raise ValueError(
                            f"rules[{idx}].conditions[{cond_idx}].value for 'between' "
                            "must be a numeric [min, max] list"
                        )
                elif operator in {"in", "not_in", "contains_any", "contains_all"}:
                    if not isinstance(value, list):
                        raise ValueError(
                            f"rules[{idx}].conditions[{cond_idx}].value for '{operator}' "
                            "must be a list"
                        )

                conditions.append({"metric": metric, "operator": operator, "value": value})

            evidence_id = str(rule["evidence_id"]).strip()
            evidence = str(rule["evidence"]).strip()
            missing_if_absent = str(rule["missing_if_absent"]).strip()
            if not evidence_id or not evidence or not missing_if_absent:
                raise ValueError(
                    f"rules[{idx}] evidence_id/evidence/missing_if_absent must be non-empty"
                )
            evidence_ids_by_class.setdefault(class_id, set()).add(evidence_id)

            rules.append(
                {
                    "id": rule_id,
                    "class_id": class_id,
                    "weight": weight,
                    "logic": logic,
                    "conditions": conditions,
                    "evidence_id": evidence_id,
                    "evidence": evidence,
                    "missing_if_absent": missing_if_absent,
                }
            )

        for entry in taxonomy:
            class_id = entry["id"]
            known_evidence_ids = evidence_ids_by_class.get(class_id, set())
            unknown_certainty_ids = sorted(set(entry.get("certainty_evidence", [])) - known_evidence_ids)
            if unknown_certainty_ids:
                raise ValueError(
                    f"taxonomy certainty_evidence for class '{class_id}' references unknown evidence ids: "
                    f"{unknown_certainty_ids}"
                )

        return {
            "schema_version": str(ruleset.get("schema_version", "1.0")),
            "taxonomy": taxonomy,
            "scoring": {
                "minimum_score": minimum_score,
                "minimum_margin": minimum_margin,
                "fallback_class_id": fallback_class_id,
                "max_alternatives": max_alternatives,
            },
            "rules": rules,
        }

    def _display_name(self, class_id: str) -> str:
        return self.taxonomy_by_id.get(class_id, {}).get("display_name", class_id)

    def chart_labels(self) -> list[str]:
        return [entry["display_name"] for entry in self.taxonomy]

    def metadata(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "schema_version": self.schema_version,
            "rules_path": self.rules_path,
            "schema_path": self.schema_path,
            "minimum_score": self.minimum_score,
            "minimum_margin": self.minimum_margin,
            "fallback_class_id": self.fallback_class_id,
            "max_alternatives": self.max_alternatives,
            "load_error": self.load_error,
        }

    @staticmethod
    def _cache_get(cache: OrderedDict[str, _T], key: str) -> _T | None:
        value = cache.get(key)
        if value is None:
            return None
        cache.move_to_end(key)
        return value

    def _cache_set(self, cache: OrderedDict[str, _T], key: str, value: _T) -> None:
        if self._evaluation_cache_size <= 0:
            return
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self._evaluation_cache_size:
            cache.popitem(last=False)

    @classmethod
    def _normalize_signature_component(cls, value: Any) -> Any:
        if isinstance(value, dict):
            normalized_items = sorted(
                ((str(key), cls._normalize_signature_component(item)) for key, item in value.items()),
                key=lambda item: item[0],
            )
            return {key: item for key, item in normalized_items}
        if isinstance(value, (list, tuple)):
            return [cls._normalize_signature_component(item) for item in value]
        if isinstance(value, set):
            normalized_items = [cls._normalize_signature_component(item) for item in value]
            return sorted(
                normalized_items,
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ),
            )
        if isinstance(value, datetime):
            return {"__datetime__": value.isoformat()}
        if isinstance(value, float):
            if value != value:
                return "nan"
            if value == float("inf"):
                return "inf"
            if value == float("-inf"):
                return "-inf"
            return value
        if isinstance(value, (str, int, bool)) or value is None:
            return value
        return str(value)

    @classmethod
    def _signature_for_payload(cls, payload: Any) -> str:
        normalized = cls._normalize_signature_component(payload)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _extract_metrics_cached(self, alert: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        if self._evaluation_cache_size <= 0:
            return self._extract_metrics(alert), None
        signature = self._signature_for_payload(alert)
        cached_metrics = self._cache_get(self._metrics_cache, signature)
        if cached_metrics is not None:
            return cached_metrics, signature
        metrics = self._extract_metrics(alert)
        self._cache_set(self._metrics_cache, signature, metrics)
        return metrics, signature

    @staticmethod
    def _active_metric_families(metrics: dict[str, Any]) -> tuple[str, ...]:
        families: set[str] = {"volume"}
        if metrics.get("distinct_target_ports", 0) > 0 or metrics.get("distinct_target_ips", 0) > 0:
            families.add("targeting")
        if metrics.get("event_records_count", 0) > 0 or metrics.get("events_per_minute", 0.0) > 0.0:
            families.add("temporal")
        if metrics.get("protocol", 0) > 0 or metrics.get("udp_event_ratio", 0.0) > 0.0:
            families.add("transport")
        return tuple(sorted(families))

    def _rule_eval_plan_for_metrics(self, metrics: dict[str, Any]) -> tuple[int, ...]:
        family_signature = self._active_metric_families(metrics)
        cached_plan = self._rule_eval_plan_by_family_signature.get(family_signature)
        if cached_plan is not None:
            return cached_plan

        ordered_indexes: list[int] = []
        seen_indexes: set[int] = set()
        for family in family_signature:
            for idx in self._compiled_rule_indexes_by_family.get(family, ()):
                if idx not in seen_indexes:
                    seen_indexes.add(idx)
                    ordered_indexes.append(idx)
        for idx in range(len(self._compiled_rules)):
            if idx not in seen_indexes:
                ordered_indexes.append(idx)

        plan = tuple(ordered_indexes)
        self._rule_eval_plan_by_family_signature[family_signature] = plan
        return plan

    def _evaluate_rules(
        self, metrics: dict[str, Any], alert_signature: str | None
    ) -> tuple[dict[str, float], dict[str, tuple[str, ...]], dict[str, frozenset[str]]]:
        if alert_signature and self._evaluation_cache_size > 0:
            cached = self._cache_get(self._rule_match_cache, alert_signature)
            if cached is not None:
                return cached

        scores: dict[str, float] = {class_id: 0.0 for class_id in self._candidate_class_ids}
        evidence_used_by_class: dict[str, list[str]] = {
            class_id: [] for class_id in self._candidate_class_ids
        }
        matched_evidence_by_class: dict[str, set[str]] = {
            class_id: set() for class_id in self._candidate_class_ids
        }

        for rule_index in self._rule_eval_plan_for_metrics(metrics):
            rule = self._compiled_rules[rule_index]
            class_id = str(rule["class_id"])
            if class_id not in scores:
                continue
            evaluate_rule = rule["evaluate"]
            if not callable(evaluate_rule):
                continue
            if evaluate_rule(metrics):
                scores[class_id] += float(rule["weight"])
                evidence_used_by_class[class_id].append(str(rule["evidence"]))
                matched_evidence_by_class[class_id].add(str(rule["evidence_id"]))

        frozen_evidence = {
            class_id: tuple(items) for class_id, items in evidence_used_by_class.items()
        }
        frozen_matches = {
            class_id: frozenset(items) for class_id, items in matched_evidence_by_class.items()
        }
        result = (scores, frozen_evidence, frozen_matches)
        if alert_signature and self._evaluation_cache_size > 0:
            self._cache_set(self._rule_match_cache, alert_signature, result)
        return result

    @staticmethod
    def _compile_rule_evaluator(
        logic: str, condition_evaluators: tuple[Callable[[dict[str, Any]], bool], ...]
    ) -> Callable[[dict[str, Any]], bool]:
        if logic == "all":
            def _evaluate_all(metrics: dict[str, Any]) -> bool:
                for evaluator in condition_evaluators:
                    if not evaluator(metrics):
                        return False
                return True

            return _evaluate_all

        def _evaluate_any(metrics: dict[str, Any]) -> bool:
            for evaluator in condition_evaluators:
                if evaluator(metrics):
                    return True
            return False

        return _evaluate_any

    @staticmethod
    def _compile_condition_evaluator(
        condition: dict[str, Any],
    ) -> Callable[[dict[str, Any]], bool]:
        metric = str(condition["metric"]).strip()
        operator = str(condition["operator"]).strip()
        expected = condition["value"]

        if operator in {"gte", "gt", "lte", "lt"}:
            expected_num = _safe_float(expected, float("nan"))
            if expected_num != expected_num:
                return lambda _metrics: False
            if operator == "gte":
                return lambda metrics: (
                    (actual := _safe_float(metrics.get(metric), float("nan"))) == actual
                    and actual >= expected_num
                )
            if operator == "gt":
                return lambda metrics: (
                    (actual := _safe_float(metrics.get(metric), float("nan"))) == actual
                    and actual > expected_num
                )
            if operator == "lte":
                return lambda metrics: (
                    (actual := _safe_float(metrics.get(metric), float("nan"))) == actual
                    and actual <= expected_num
                )
            return lambda metrics: (
                (actual := _safe_float(metrics.get(metric), float("nan"))) == actual
                and actual < expected_num
            )

        if operator == "eq":
            return lambda metrics: metrics.get(metric) == expected
        if operator == "neq":
            return lambda metrics: metrics.get(metric) != expected

        if operator in {"in", "not_in"}:
            expected_values = tuple(expected) if isinstance(expected, list) else tuple()
            if operator == "in":
                return lambda metrics: metrics.get(metric) in expected_values
            return lambda metrics: metrics.get(metric) not in expected_values

        if operator == "between":
            if not isinstance(expected, list) or len(expected) != 2:
                return lambda _metrics: False
            lower = _safe_float(expected[0], float("nan"))
            upper = _safe_float(expected[1], float("nan"))
            if lower != lower or upper != upper:
                return lambda _metrics: False
            return lambda metrics: (
                (actual := _safe_float(metrics.get(metric), float("nan"))) == actual
                and lower <= actual <= upper
            )

        if operator in {"contains_any", "contains_all"}:
            expected_values = tuple(expected) if isinstance(expected, list) else tuple()
            expected_set = set(expected_values)
            if operator == "contains_any":
                return lambda metrics: isinstance(metrics.get(metric), list) and bool(
                    set(metrics.get(metric, [])).intersection(expected_set)
                )
            return lambda metrics: isinstance(metrics.get(metric), list) and expected_set.issubset(
                set(metrics.get(metric, []))
            )

        return lambda _metrics: False

    def classify(
        self,
        alert: dict[str, Any],
        *,
        ml_confidence: float,
        ml_threshold: float,
    ) -> dict[str, Any]:
        metrics, alert_signature = self._extract_metrics_cached(alert)
        scores, evidence_used_by_class, matched_evidence_by_class = self._evaluate_rules(
            metrics, alert_signature
        )

        ranked = sorted(scores.items(), key=lambda item: (item[1], item[0]), reverse=True)
        if ranked:
            top_class_id, top_score = ranked[0]
            runner_up_class_id, runner_up_score = (
                ranked[1] if len(ranked) > 1 else (self.fallback_class_id, 0.0)
            )
        else:
            top_class_id, top_score = self.fallback_class_id, 0.0
            runner_up_class_id, runner_up_score = self.fallback_class_id, 0.0
        margin = top_score - runner_up_score

        missing_required_ids = sorted(
            self.required_evidence_by_class.get(top_class_id, set())
            - matched_evidence_by_class.get(top_class_id, frozenset())
        )
        gate_failures: list[str] = []
        if top_score <= 0.0:
            gate_failures.append("No class-specific evidence rules matched.")
        if missing_required_ids:
            gate_failures.append(
                "Required evidence is missing for the highest-scoring class candidate."
            )
        if top_score < self.minimum_score:
            gate_failures.append(
                f"Top class score {top_score:.2f} is below minimum_score {self.minimum_score:.2f}."
            )
        if margin < self.minimum_margin:
            gate_failures.append(
                f"Top score margin {margin:.2f} is below minimum_margin {self.minimum_margin:.2f}."
            )

        assigned_class_id = top_class_id
        if gate_failures:
            assigned_class_id = self.fallback_class_id

        if assigned_class_id == self.fallback_class_id:
            confidence = self._unknown_confidence(top_score)
            primary_evidence = list(evidence_used_by_class.get(top_class_id, ()))
        else:
            confidence = self._class_confidence(assigned_class_id, top_score, margin)
            primary_evidence = list(evidence_used_by_class.get(assigned_class_id, ()))
        certainty_level, certainty_reason = self._certainty_assessment(
            assigned_class_id=assigned_class_id,
            gate_failures=gate_failures,
            matched_evidence_ids=matched_evidence_by_class,
        )

        evidence_missing: list[str] = []
        for evidence_id in missing_required_ids:
            evidence_missing.append(
                self.missing_message_by_evidence.get(
                    evidence_id, f"Missing required evidence '{evidence_id}'."
                )
            )
        if top_score <= 0.0:
            evidence_missing.append("No configured rule evidence matched this alert.")
        if top_score < self.minimum_score:
            evidence_missing.append(
                f"Need score >= {self.minimum_score:.2f}; observed {top_score:.2f}."
            )
        if margin < self.minimum_margin:
            evidence_missing.append(
                "Top class is too close to an alternative; evidence is ambiguous."
            )
        evidence_missing = _dedupe(evidence_missing)

        alternatives: list[dict[str, Any]] = []
        for class_id, score in ranked:
            if score <= 0.0:
                continue
            if assigned_class_id != self.fallback_class_id and class_id == assigned_class_id:
                continue
            alternatives.append(
                {
                    "class": self._display_name(class_id),
                    "score": round(score, 3),
                    "confidence": self._class_confidence(class_id, score, 0.0),
                }
            )
            if len(alternatives) >= self.max_alternatives:
                break

        primary_taxonomy = self.taxonomy_by_id.get(
            assigned_class_id, self.taxonomy_by_id[self.fallback_class_id]
        )
        description = primary_taxonomy["rich_description"]
        if assigned_class_id == self.fallback_class_id and ranked:
            description = (
                f"{description} Top candidate '{self._display_name(top_class_id)}' "
                f"scored {top_score:.2f}."
            )

        limitations = list(primary_taxonomy["limitations"])
        limitations.append(
            "Attack-family typing is deterministic and uses configured scoring rules."
        )
        limitations.append(
            "ML decision (attack vs normal) remains independent from family assignment."
        )
        if self.load_error:
            limitations.append(f"Rule-loading issue: {self.load_error}")
        limitations = _dedupe(limitations)

        rationale = [
            (
                "ML attack decision is separate from typing: "
                f"confidence={ml_confidence:.2%}, threshold={ml_threshold:.2%}."
            ),
            (
                f"Top class candidate: {self._display_name(top_class_id)} "
                f"(score {top_score:.2f})."
            ),
            (
                f"Runner-up: {self._display_name(runner_up_class_id)} "
                f"(score {runner_up_score:.2f}, margin {margin:.2f})."
            ),
        ]
        rationale.extend(primary_evidence[:3])
        rationale.extend(gate_failures)
        rationale.append(f"Certainty assessment: {certainty_reason}")

        explanation = {
            "primary_class": self._display_name(assigned_class_id),
            "confidence": confidence,
            "alternatives": alternatives,
            "evidence_used": primary_evidence[:8],
            "evidence_missing": evidence_missing,
            "limitations": limitations,
            "description": description,
        }

        return {
            "label": explanation["primary_class"],
            "primary_class": explanation["primary_class"],
            "confidence": confidence,
            "alternatives": alternatives,
            "evidence_used": explanation["evidence_used"],
            "evidence_missing": evidence_missing,
            "limitations": limitations,
            "description": description,
            "rationale": rationale,
            "explanation": explanation,
            "source": self.source,
            "note": (
                f"{certainty_level.replace('_', ' ').title()}: {certainty_reason} "
                "Binary ML detection (attack vs normal) is separate from attack-family typing, "
                "which is produced by deterministic evidence rules."
            ),
            "scoring": {
                "top_class": self._display_name(top_class_id),
                "top_score": round(top_score, 3),
                "runner_up": self._display_name(runner_up_class_id),
                "runner_up_score": round(runner_up_score, 3),
                "score_margin": round(margin, 3),
                "minimum_score": round(self.minimum_score, 3),
                "minimum_margin": round(self.minimum_margin, 3),
                "required_evidence_missing": missing_required_ids,
                "gates_passed": not gate_failures,
            },
        }

    def _class_confidence(self, class_id: str, score: float, margin: float) -> float:
        max_score = max(self.class_max_scores.get(class_id, self.minimum_score), self.minimum_score, 1.0)
        score_ratio = min(1.0, max(0.0, score) / max_score)
        margin_ratio = min(1.0, max(0.0, margin) / max(self.minimum_margin, 1e-6))
        return round(min(1.0, 0.7 * score_ratio + 0.3 * margin_ratio), 3)

    def _unknown_confidence(self, top_score: float) -> float:
        if top_score <= 0.0:
            return 0.05
        normalized = min(1.0, top_score / max(self.minimum_score, 1e-6))
        return round(min(0.49, 0.1 + normalized * 0.35), 3)

    def _certainty_assessment(
        self,
        *,
        assigned_class_id: str,
        gate_failures: list[str],
        matched_evidence_ids: dict[str, set[str] | frozenset[str]],
    ) -> tuple[str, str]:
        if assigned_class_id == self.fallback_class_id or gate_failures:
            return (
                "not_sure",
                "Evidence is incomplete or ambiguous, so this is best treated as a not-sure assessment.",
            )

        certainty_ids = self.certainty_evidence_by_class.get(assigned_class_id, set())
        matched_ids = matched_evidence_ids.get(assigned_class_id, set())
        if certainty_ids and certainty_ids.issubset(matched_ids):
            return (
                "certain",
                "Certainty is justified because explicit certainty evidence rules matched: "
                + ", ".join(sorted(certainty_ids))
                + ".",
            )

        return (
            "probable",
            "The class is a probable best guess from deterministic evidence, but certainty is not justified "
            "without explicit certainty-rule coverage.",
        )

    @staticmethod
    def _extract_metrics(alert: dict[str, Any]) -> dict[str, Any]:
        ports_raw = alert.get("target_ports")
        if not isinstance(ports_raw, list):
            ports_raw = [alert.get("dst_port")]
        target_ports = sorted({p for p in (_safe_int(v, 0) for v in ports_raw) if p > 0})

        target_ips_raw = alert.get("target_ips")
        if not isinstance(target_ips_raw, list):
            target_ips_raw = [alert.get("dst_ip")]
        target_ips = sorted({str(v) for v in target_ips_raw if str(v).strip()})

        event_count = max(1, _safe_int(alert.get("event_count"), 1))
        packets = max(0, _safe_int(alert.get("packets"), 0))
        total_bytes = max(0, _safe_int(alert.get("bytes"), 0))
        protocol = _safe_int(alert.get("protocol"), 0)
        bytes_per_packet = total_bytes / max(1, packets)
        packets_per_event = packets / max(1, event_count)
        bytes_per_event = total_bytes / max(1, event_count)

        events_raw = alert.get("events")
        events = [item for item in events_raw if isinstance(item, dict)] if isinstance(events_raw, list) else []

        event_timestamps: list[float] = []
        event_port_counts: dict[int, int] = {}
        udp_event_count = 0
        for event in events:
            timestamp = _safe_timestamp(event.get("timestamp"))
            if timestamp is not None:
                event_timestamps.append(timestamp)

            dst_port = _safe_int(event.get("dst_port"), 0)
            if dst_port > 0:
                event_port_counts[dst_port] = event_port_counts.get(dst_port, 0) + 1

            if _safe_int(event.get("protocol"), 0) == 17:
                udp_event_count += 1

        event_span_seconds = 0.0
        events_per_minute = 0.0
        if len(event_timestamps) >= 2:
            span_seconds = max(0.0, max(event_timestamps) - min(event_timestamps))
            event_span_seconds = span_seconds
            events_per_minute = (len(events) * 60.0) / max(1.0, span_seconds)

        dominant_target_port_event_ratio = 0.0
        if events and event_port_counts:
            dominant_target_port_event_ratio = max(event_port_counts.values()) / max(1, len(events))
        elif target_ports:
            dominant_target_port_event_ratio = 1.0 / max(1, len(target_ports))

        ssh_target_port_ratio = (
            sum(1 for port in target_ports if port == 22) / max(1, len(target_ports))
            if target_ports
            else 0.0
        )
        web_target_ports = {80, 443, 8080, 8000, 8443}
        web_target_port_ratio = (
            sum(1 for port in target_ports if port in web_target_ports) / max(1, len(target_ports))
            if target_ports
            else 0.0
        )
        udp_event_ratio = (
            udp_event_count / max(1, len(events)) if events else (1.0 if protocol == 17 else 0.0)
        )

        return {
            "target_ports": target_ports,
            "distinct_target_ports": len(target_ports),
            "target_ips": target_ips,
            "distinct_target_ips": len(target_ips),
            "event_count": event_count,
            "packets": packets,
            "bytes": total_bytes,
            "protocol": protocol,
            "bytes_per_packet": bytes_per_packet,
            "packets_per_event": packets_per_event,
            "bytes_per_event": bytes_per_event,
            "event_records_count": len(events),
            "event_span_seconds": event_span_seconds,
            "events_per_minute": events_per_minute,
            "dominant_target_port_event_ratio": dominant_target_port_event_ratio,
            "ssh_target_port_ratio": ssh_target_port_ratio,
            "web_target_port_ratio": web_target_port_ratio,
            "udp_event_ratio": udp_event_ratio,
        }

    def _matches_rule(self, rule: dict[str, Any], metrics: dict[str, Any]) -> bool:
        checks = [self._matches_condition(condition, metrics) for condition in rule["conditions"]]
        if rule["logic"] == "all":
            return all(checks)
        return any(checks)

    @staticmethod
    def _matches_condition(condition: dict[str, Any], metrics: dict[str, Any]) -> bool:
        actual = metrics.get(condition["metric"])
        expected = condition["value"]
        operator = condition["operator"]

        if operator in {"gte", "gt", "lte", "lt"}:
            if actual is None:
                return False
            actual_num = _safe_float(actual, float("nan"))
            expected_num = _safe_float(expected, float("nan"))
            if actual_num != actual_num or expected_num != expected_num:
                return False
            if operator == "gte":
                return actual_num >= expected_num
            if operator == "gt":
                return actual_num > expected_num
            if operator == "lte":
                return actual_num <= expected_num
            return actual_num < expected_num

        if operator == "eq":
            return actual == expected
        if operator == "neq":
            return actual != expected

        if operator in {"in", "not_in"}:
            if not isinstance(expected, list):
                return False
            contains = actual in expected
            return contains if operator == "in" else not contains

        if operator == "between":
            if not isinstance(expected, list) or len(expected) != 2:
                return False
            actual_num = _safe_float(actual, float("nan"))
            if actual_num != actual_num:
                return False
            lower = _safe_float(expected[0], float("nan"))
            upper = _safe_float(expected[1], float("nan"))
            if lower != lower or upper != upper:
                return False
            return lower <= actual_num <= upper

        if operator in {"contains_any", "contains_all"}:
            if not isinstance(expected, list):
                return False
            if not isinstance(actual, list):
                return False
            actual_values = set(actual)
            expected_values = set(expected)
            if operator == "contains_any":
                return bool(actual_values.intersection(expected_values))
            return expected_values.issubset(actual_values)

        return False
