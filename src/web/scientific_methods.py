"""Bounded scientific-method heuristics for threat hunting."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence


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


def _parse_timestamp(value: Any) -> datetime | None:
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


def _clamp(value: int | float, minimum: int | float, maximum: int | float) -> int | float:
    return max(minimum, min(maximum, value))


def _shannon_entropy(counter: Counter[str]) -> tuple[float, float]:
    total = sum(counter.values())
    if total <= 0:
        return (0.0, 0.0)
    entropy = 0.0
    for count in counter.values():
        if count <= 0:
            continue
        probability = float(count) / float(total)
        entropy -= probability * math.log2(probability)
    normalized = entropy / math.log2(len(counter)) if len(counter) > 1 else 0.0
    return (entropy, normalized)


def _quantize_confidence(value: float, bins: int = 5) -> int:
    normalized = max(0.0, min(1.0, value))
    if bins <= 1:
        return 0
    return int(round(normalized * float(bins - 1)))


def _quantize_log_volume(value: int, max_bucket: int) -> int:
    bounded = max(0, value)
    if bounded <= 1:
        return 0
    return min(max_bucket, int(math.log2(float(bounded))))


def _method_enabled(enabled: set[str], name: str) -> bool:
    return name in enabled or "all" in enabled


def _z_score_outliers(incidents: Sequence[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    threshold = float(_clamp(_safe_float(config.get("threshold"), 2.5), 1.0, 10.0))
    max_results = int(_clamp(_safe_int(config.get("max_results"), 25), 1, 200))
    allowed_metrics = {"event_count", "packets", "bytes", "detection_confidence", "attack_confidence"}
    metric_input = config.get("metrics")
    if isinstance(metric_input, list):
        metrics = [str(item).strip() for item in metric_input if str(item).strip() in allowed_metrics]
        if not metrics:
            metrics = sorted(allowed_metrics)
    else:
        metrics = sorted(allowed_metrics)

    outliers: list[dict[str, Any]] = []
    metric_stats: dict[str, dict[str, Any]] = {}

    for metric in metrics:
        values = [_safe_float(incident.get(metric), 0.0) for incident in incidents]
        if len(values) < 3:
            metric_stats[metric] = {"mean": 0.0, "std_dev": 0.0, "outlier_count": 0}
            continue
        mean = float(sum(values)) / float(len(values))
        variance = sum((value - mean) ** 2 for value in values) / float(len(values))
        std_dev = math.sqrt(variance)
        metric_outlier_count = 0
        if std_dev > 0.0:
            for incident, value in zip(incidents, values):
                z_score = (value - mean) / std_dev
                absolute = abs(z_score)
                if absolute < threshold:
                    continue
                metric_outlier_count += 1
                outliers.append(
                    {
                        "incident_id": _safe_str(incident.get("id")),
                        "source_ip": _safe_str(incident.get("source_ip")),
                        "timestamp": _safe_str(incident.get("timestamp")),
                        "metric": metric,
                        "value": value,
                        "z_score": round(z_score, 4),
                        "absolute_z_score": round(absolute, 4),
                    }
                )
        metric_stats[metric] = {
            "mean": round(mean, 6),
            "std_dev": round(std_dev, 6),
            "outlier_count": metric_outlier_count,
        }

    outliers.sort(key=lambda item: float(item.get("absolute_z_score", 0.0)), reverse=True)
    return {
        "threshold": threshold,
        "metrics": metric_stats,
        "outliers": outliers[:max_results],
    }


def _temporal_burst_detection(incidents: Sequence[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    window_minutes = int(_clamp(_safe_int(config.get("window_minutes"), 60), 5, 720))
    min_count = int(_clamp(_safe_int(config.get("min_count"), 3), 1, 200))
    z_threshold = float(_clamp(_safe_float(config.get("z_threshold"), 2.0), 0.5, 8.0))
    max_bursts = int(_clamp(_safe_int(config.get("max_bursts"), 25), 1, 200))
    max_sources = int(_clamp(_safe_int(config.get("max_sources"), 20), 1, 100))

    parsed_points: list[tuple[datetime, dict[str, Any]]] = []
    latest_timestamp: datetime | None = None
    for incident in incidents:
        parsed = _parse_timestamp(incident.get("timestamp"))
        if parsed is None:
            continue
        parsed_points.append((parsed, incident))
        if latest_timestamp is None or parsed > latest_timestamp:
            latest_timestamp = parsed

    if latest_timestamp is None:
        latest_timestamp = datetime.utcnow()

    window_start = latest_timestamp - timedelta(minutes=window_minutes)
    bucket_count = window_minutes
    bucket_counts = [0 for _ in range(bucket_count)]
    bucket_sources = [Counter() for _ in range(bucket_count)]

    for parsed, incident in parsed_points:
        if parsed < window_start or parsed > latest_timestamp:
            continue
        minute_delta = int((parsed - window_start).total_seconds() // 60)
        if minute_delta < 0 or minute_delta >= bucket_count:
            continue
        bucket_counts[minute_delta] += 1
        source_ip = _safe_str(incident.get("source_ip"), "unknown")
        bucket_sources[minute_delta][source_ip or "unknown"] += 1

    mean = float(sum(bucket_counts)) / float(len(bucket_counts)) if bucket_counts else 0.0
    variance = (
        sum((count - mean) ** 2 for count in bucket_counts) / float(len(bucket_counts))
        if bucket_counts
        else 0.0
    )
    std_dev = math.sqrt(variance)

    bursts: list[dict[str, Any]] = []
    burst_sources: Counter[str] = Counter()
    for index, count in enumerate(bucket_counts):
        z_score = (float(count) - mean) / std_dev if std_dev > 0 else 0.0
        qualifies = bool(count >= min_count and (z_score >= z_threshold or (std_dev == 0.0 and count >= min_count * 2)))
        if not qualifies:
            continue
        bucket_start = window_start + timedelta(minutes=index)
        bucket_end = bucket_start + timedelta(minutes=1)
        top_sources = [
            {"source_ip": source, "count": source_count}
            for source, source_count in bucket_sources[index].most_common(5)
        ]
        for source, source_count in bucket_sources[index].items():
            burst_sources[source] += source_count
        bursts.append(
            {
                "bucket_start": bucket_start.isoformat() + "Z",
                "bucket_end": bucket_end.isoformat() + "Z",
                "count": int(count),
                "z_score": round(z_score, 4),
                "top_sources": top_sources,
            }
        )

    bursts.sort(key=lambda item: (item["count"], item["z_score"]), reverse=True)
    return {
        "window_minutes": window_minutes,
        "baseline": {"mean": round(mean, 6), "std_dev": round(std_dev, 6)},
        "bursts": bursts[:max_bursts],
        "burst_sources": [
            {"source_ip": source, "count": count}
            for source, count in burst_sources.most_common(max_sources)
        ],
    }


def _entropy_indicators(incidents: Sequence[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    min_source_events = int(_clamp(_safe_int(config.get("min_source_events"), 5), 2, 100))
    max_source_profiles = int(_clamp(_safe_int(config.get("max_source_profiles"), 30), 1, 200))

    source_counter: Counter[str] = Counter()
    target_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    class_counter: Counter[str] = Counter()
    source_port_distributions: dict[str, Counter[str]] = defaultdict(Counter)

    for incident in incidents:
        source = _safe_str(incident.get("source_ip"), "unknown") or "unknown"
        target = _safe_str(incident.get("target_ip"), "unknown") or "unknown"
        classification = _safe_str(incident.get("attack_primary_class"), "unknown") or "unknown"
        source_counter[source] += 1
        target_counter[target] += 1
        class_counter[classification] += 1

        target_ports = incident.get("target_ports")
        if isinstance(target_ports, list):
            for port in target_ports:
                port_text = _safe_str(port)
                if port_text:
                    port_counter[port_text] += 1
                    source_port_distributions[source][port_text] += 1
        else:
            port_value = _safe_str(incident.get("target_port"))
            if port_value:
                port_counter[port_value] += 1
                source_port_distributions[source][port_value] += 1

    def summarize(counter: Counter[str]) -> dict[str, Any]:
        entropy, normalized = _shannon_entropy(counter)
        total = sum(counter.values())
        dominant = counter.most_common(1)
        dominant_value = dominant[0][0] if dominant else ""
        dominant_count = dominant[0][1] if dominant else 0
        dominant_share = (float(dominant_count) / float(total)) if total > 0 else 0.0
        return {
            "total": int(total),
            "unique": len(counter),
            "entropy": round(entropy, 6),
            "normalized_entropy": round(normalized, 6),
            "dominant_value": dominant_value,
            "dominant_share": round(dominant_share, 6),
        }

    distributions = {
        "source_ip": summarize(source_counter),
        "target_ip": summarize(target_counter),
        "target_ports": summarize(port_counter),
        "attack_primary_class": summarize(class_counter),
    }

    indicators: list[str] = []
    if distributions["source_ip"]["normalized_entropy"] < 0.45 and distributions["source_ip"]["total"] >= 10:
        indicators.append("high_source_concentration")
    if distributions["target_ports"]["normalized_entropy"] > 0.8 and distributions["target_ports"]["unique"] >= 8:
        indicators.append("broad_target_port_dispersion")
    if distributions["attack_primary_class"]["normalized_entropy"] < 0.35 and distributions["attack_primary_class"]["total"] >= 10:
        indicators.append("dominant_attack_family_pattern")

    source_profiles: list[dict[str, Any]] = []
    for source, source_events in source_counter.items():
        if source_events < min_source_events:
            continue
        profile_counter = source_port_distributions.get(source, Counter())
        entropy, normalized = _shannon_entropy(profile_counter)
        source_profiles.append(
            {
                "source_ip": source,
                "events": int(source_events),
                "distinct_ports": len(profile_counter),
                "port_entropy": round(entropy, 6),
                "port_entropy_normalized": round(normalized, 6),
            }
        )
    source_profiles.sort(key=lambda item: (item["events"], item["port_entropy_normalized"]), reverse=True)

    return {
        "distributions": distributions,
        "indicators": indicators,
        "source_port_profiles": source_profiles[:max_source_profiles],
    }


def _clustering_lite(incidents: Sequence[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    min_cluster_size = int(_clamp(_safe_int(config.get("min_cluster_size"), 2), 1, 20))
    max_clusters = int(_clamp(_safe_int(config.get("max_clusters"), 20), 1, 150))
    max_member_samples = int(_clamp(_safe_int(config.get("max_member_samples"), 5), 1, 20))

    clusters: dict[tuple[Any, ...], dict[str, Any]] = {}
    for incident in incidents:
        attack_class = _safe_str(incident.get("attack_primary_class"), "unknown").strip().lower() or "unknown"
        severity = _safe_str(incident.get("severity"), "unknown").strip().upper() or "UNKNOWN"
        certainty = _safe_str(incident.get("attack_certainty_level"), "not_sure").strip().lower() or "not_sure"
        key = (
            attack_class,
            severity,
            certainty,
            _quantize_confidence(_safe_float(incident.get("attack_confidence"), 0.0)),
            _quantize_confidence(_safe_float(incident.get("detection_confidence"), 0.0)),
            _quantize_log_volume(_safe_int(incident.get("event_count"), 0), 8),
            _quantize_log_volume(_safe_int(incident.get("bytes"), 0), 10),
        )
        payload = clusters.setdefault(
            key,
            {
                "size": 0,
                "attack_confidence_total": 0.0,
                "detection_confidence_total": 0.0,
                "source_counter": Counter(),
                "target_counter": Counter(),
                "samples": [],
            },
        )
        payload["size"] += 1
        payload["attack_confidence_total"] += _safe_float(incident.get("attack_confidence"), 0.0)
        payload["detection_confidence_total"] += _safe_float(incident.get("detection_confidence"), 0.0)
        payload["source_counter"][_safe_str(incident.get("source_ip"), "unknown")] += 1
        payload["target_counter"][_safe_str(incident.get("target_ip"), "unknown")] += 1
        if len(payload["samples"]) < max_member_samples:
            payload["samples"].append(_safe_str(incident.get("id")))

    cluster_rows: list[dict[str, Any]] = []
    small_cluster_incidents = 0
    for key, payload in clusters.items():
        size = int(payload["size"])
        if size < min_cluster_size:
            small_cluster_incidents += size
            continue
        cluster_rows.append(
            {
                "cluster_key": {
                    "attack_primary_class": key[0],
                    "severity": key[1],
                    "certainty_level": key[2],
                    "attack_confidence_bin": key[3],
                    "detection_confidence_bin": key[4],
                    "event_count_bin": key[5],
                    "bytes_bin": key[6],
                },
                "size": size,
                "avg_attack_confidence": round(
                    payload["attack_confidence_total"] / float(max(1, size)),
                    6,
                ),
                "avg_detection_confidence": round(
                    payload["detection_confidence_total"] / float(max(1, size)),
                    6,
                ),
                "top_sources": [
                    {"source_ip": source, "count": count}
                    for source, count in payload["source_counter"].most_common(5)
                ],
                "top_targets": [
                    {"target_ip": target, "count": count}
                    for target, count in payload["target_counter"].most_common(5)
                ],
                "sample_incident_ids": payload["samples"],
            }
        )

    cluster_rows.sort(key=lambda item: (item["size"], item["avg_attack_confidence"]), reverse=True)
    return {
        "min_cluster_size": min_cluster_size,
        "clusters": cluster_rows[:max_clusters],
        "small_cluster_incident_count": small_cluster_incidents,
    }


def run_scientific_methods(
    incidents: Sequence[dict[str, Any]],
    *,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = config if isinstance(config, dict) else {}
    max_incidents = int(_clamp(_safe_int(cfg.get("max_incidents"), 800), 50, 2000))
    sampled_incidents = list(incidents[:max_incidents])
    enabled_raw = cfg.get("enabled")
    if isinstance(enabled_raw, list):
        enabled = {str(item).strip().lower() for item in enabled_raw if str(item).strip()}
    else:
        enabled = {"z_score_outliers", "temporal_bursts", "entropy_indicators", "clustering_lite"}

    methods = {
        "z_score_outliers": _z_score_outliers,
        "temporal_bursts": _temporal_burst_detection,
        "entropy_indicators": _entropy_indicators,
        "clustering_lite": _clustering_lite,
    }
    results: dict[str, Any] = {}
    for method_name, method_impl in methods.items():
        if not _method_enabled(enabled, method_name):
            continue
        method_config = cfg.get(method_name)
        if not isinstance(method_config, dict):
            method_config = {}
        results[method_name] = method_impl(sampled_incidents, method_config)

    results["meta"] = {
        "analyzed_incidents": len(sampled_incidents),
        "input_incidents": len(incidents),
        "input_truncated": len(incidents) > len(sampled_incidents),
        "enabled_methods": sorted(name for name in methods if name in results),
        "max_incidents": max_incidents,
    }
    return results
