"""Flask server entrypoint for SentinelAI web platform."""

from __future__ import annotations

import argparse
import os
import time
import prometheus_client
from functools import wraps
from flask import Flask, Response, g, jsonify, request, send_from_directory

from common.config_utils import cfg_get, load_runtime_config
from web.query_dsl import QueryDslError
from web.runtime_service import SentinelAIRuntimeService

# Prometheus metrics
metrics = {
    'http_requests': prometheus_client.Counter(
        'http_requests_total',
        'Total HTTP requests',
        ['method', 'endpoint', 'status']
    ),
    'request_duration': prometheus_client.Histogram(
        'http_request_duration_seconds',
        'HTTP request duration in seconds'
    ),
    'incidents_detected': prometheus_client.Gauge(
        'incidents_detected_total',
        'Total incidents detected'
    ),
    'packets_processed': prometheus_client.Gauge(
        'packets_processed_total',
        'Total packets processed'
    ),
    'detection_latency': prometheus_client.Histogram(
        'detection_latency_seconds',
        'ML detection latency in seconds'
    ),
}


def authenticated(f):
    """API key authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        required_key = os.environ.get('API_KEY')
        if required_key and api_key != required_key:
            return jsonify({"error": "Unauthorized", "code": "invalid_api_key"}), 401
        return f(*args, **kwargs)
    return decorated


def create_app(service: SentinelAIRuntimeService) -> Flask:
    static_root = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(__name__, static_folder=static_root, static_url_path="")

    @app.before_request
    def _start_timer():
        g.request_started = time.time()

    @app.after_request
    def _record_metrics(response):
        # Label by route pattern, not raw path, to keep metric cardinality bounded.
        endpoint = request.url_rule.rule if request.url_rule else "unmatched"
        metrics['http_requests'].labels(method=request.method, endpoint=endpoint, status=response.status_code).inc()
        started = getattr(g, "request_started", None)
        if started is not None:
            metrics['request_duration'].observe(time.time() - started)
        return response

    hunting_query_keys = {"dsl", "query", "filters", "limit", "offset", "scan_limit", "scientific_methods"}
    hunting_action_aliases = {"query", "search", "run-query", "run_query", "execute-query", "execute_query"}
    hunting_query_argument_keys = {
        "action",
        "dsl",
        "query",
        "filters",
        "limit",
        "offset",
        "scan_limit",
        "scientific_methods",
        "methods",
        "scientific_max_incidents",
        "source_ips",
        "source_ip",
        "target_ips",
        "target_ip",
        "severities",
        "severity",
        "attack_primary_classes",
        "attack_primary_class",
        "certainty_levels",
        "certainty_level",
        "triage_states",
        "triage_state",
        "attack_confidence_gte",
        "attack_confidence_lte",
        "detection_confidence_gte",
        "detection_confidence_lte",
        "event_count_gte",
        "event_count_lte",
        "bytes_gte",
        "bytes_lte",
        "packets_gte",
        "packets_lte",
        "from_timestamp",
        "to_timestamp",
        "text_contains",
    }

    def _require_json_object():
        payload = request.get_json(silent=True)
        if payload is None:
            return None, (jsonify({"error": "Valid JSON object body required"}), 400)
        if not isinstance(payload, dict):
            return None, (jsonify({"error": "JSON object body required"}), 400)
        return payload, None

    def _config_update_failure_response(message: str):
        return jsonify({"error": message, "code": "config_update_failed"}), 500

    def _build_hunting_query_payload_from_args() -> dict[str, object]:
        filters: dict[str, object] = {}
        list_filter_mappings = {
            "source_ips": ("source_ips", "source_ip"),
            "target_ips": ("target_ips", "target_ip"),
            "severities": ("severities", "severity"),
            "attack_primary_classes": ("attack_primary_classes", "attack_primary_class"),
            "certainty_levels": ("certainty_levels", "certainty_level"),
            "triage_states": ("triage_states", "triage_state"),
        }
        for filter_key, aliases in list_filter_mappings.items():
            values: list[str] = []
            for alias in aliases:
                values.extend(request.args.getlist(alias))
            normalized_values = [value.strip() for value in values if value and value.strip()]
            if normalized_values:
                filters[filter_key] = normalized_values

        scalar_filter_keys = (
            "attack_confidence_gte",
            "attack_confidence_lte",
            "detection_confidence_gte",
            "detection_confidence_lte",
            "event_count_gte",
            "event_count_lte",
            "bytes_gte",
            "bytes_lte",
            "packets_gte",
            "packets_lte",
            "from_timestamp",
            "to_timestamp",
            "text_contains",
        )
        for key in scalar_filter_keys:
            value = request.args.get(key, type=str)
            if value is not None and value.strip():
                filters[key] = value.strip()

        methods = request.args.get("methods", type=str)
        scientific_methods_payload: dict[str, object] = {}
        if methods:
            enabled_methods = [name.strip() for name in methods.split(",") if name.strip()]
            if enabled_methods:
                scientific_methods_payload["enabled"] = enabled_methods
        max_scientific_incidents = request.args.get("scientific_max_incidents", type=int)
        if max_scientific_incidents is not None:
            scientific_methods_payload["max_incidents"] = max_scientific_incidents

        payload: dict[str, object] = {
            "dsl": request.args.get("dsl", default=request.args.get("query", default="", type=str), type=str),
            "limit": request.args.get("limit", default=100, type=int),
            "offset": request.args.get("offset", default=0, type=int),
            "scan_limit": request.args.get("scan_limit", default=600, type=int),
        }
        action = request.args.get("action", type=str)
        if action is not None and action.strip():
            payload["action"] = action.strip()
        if filters:
            payload["filters"] = filters
        if scientific_methods_payload:
            payload["scientific_methods"] = scientific_methods_payload
        return payload

    def _normalize_hunting_query_payload(raw_payload: object) -> tuple[dict[str, object] | None, tuple[Response, int] | None]:
        if not isinstance(raw_payload, dict):
            return None, (jsonify({"error": "JSON object body required"}), 400)

        payload: dict[str, object] = dict(raw_payload)

        for wrapper_key in ("payload", "request", "data", "query_payload"):
            wrapped = payload.get(wrapper_key)
            if not isinstance(wrapped, dict):
                continue
            merged: dict[str, object] = dict(wrapped)
            for key, value in payload.items():
                if key == wrapper_key:
                    continue
                merged.setdefault(key, value)
            payload = merged
            break

        wrapped_query = payload.get("query")
        if isinstance(wrapped_query, dict):
            has_explicit_query_keys = any(
                key in payload for key in hunting_query_keys if key != "query"
            )
            if not has_explicit_query_keys:
                merged_query_payload: dict[str, object] = dict(wrapped_query)
                for key, value in payload.items():
                    if key == "query":
                        continue
                    merged_query_payload.setdefault(key, value)
                payload = merged_query_payload

        return payload, None

    def _get_hunting_query_payload() -> tuple[dict[str, object] | None, tuple[Response, int] | None]:
        if request.method == "GET":
            return _build_hunting_query_payload_from_args(), None

        raw_payload = request.get_json(silent=True)
        if raw_payload is None:
            if request.args:
                return _build_hunting_query_payload_from_args(), None
            return None, (jsonify({"error": "Valid JSON object body required"}), 400)
        return _normalize_hunting_query_payload(raw_payload)

    def _execute_hunting_query(payload: dict[str, object]):
        try:
            return jsonify(service.query_hunting(payload))
        except QueryDslError as exc:
            return jsonify({"error": exc.message, **exc.to_dict()}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Failed to run /api/hunting/query")
            return jsonify({"error": "Failed to execute hunting query"}), 500

    def _validate_hunting_action(payload: dict[str, object]) -> tuple[bool, tuple[Response, int] | None]:
        action = str(payload.get("action", "")).strip().lower()
        if action and action not in hunting_action_aliases:
            return False, (jsonify({"error": f"Unsupported hunting action '{action}'"}), 400)
        return bool(action), None

    def _request_has_hunting_query_args() -> bool:
        return any(key in request.args for key in hunting_query_argument_keys)

    def _handle_hunting_route(*, view_on_empty_get: bool):
        payload, error = _get_hunting_query_payload()
        if error:
            return error
        assert payload is not None

        has_action, action_error = _validate_hunting_action(payload)
        if action_error:
            return action_error
        if has_action:
            return _execute_hunting_query(payload)

        if request.method == "GET":
            if view_on_empty_get and not _request_has_hunting_query_args():
                return jsonify(service.get_hunting_view())
            return _execute_hunting_query(payload)

        if any(key in payload for key in hunting_query_keys):
            return _execute_hunting_query(payload)
        return jsonify({"error": "Hunting POST/PUT requests must provide a query payload"}), 400

    @app.get("/api/health")
    def api_health():
        return jsonify({"status": "ok"})

    @app.get("/api/metrics")
    def api_metrics():
        stats = service.ids.get_stats()
        metrics['packets_processed'].set(stats.get('packets_processed', 0))
        metrics['incidents_detected'].set(stats.get('attacks_detected', 0))
        return Response(prometheus_client.generate_latest(), mimetype=prometheus_client.CONTENT_TYPE_LATEST)

    @app.get("/api/overview/summary")
    def api_overview_summary():
        return jsonify(service.get_overview_summary())

    @app.get("/api/overview/charts")
    def api_overview_charts():
        return jsonify(service.get_overview_charts())

    @app.get("/api/incidents")
    def api_incidents():
        limit = request.args.get("limit", default=100, type=int)
        normalized_limit = max(1, min(limit, 1000))
        if hasattr(service, "get_incidents_payload"):
            return jsonify(service.get_incidents_payload(limit=normalized_limit))
        return jsonify({"items": service.list_incidents(limit=normalized_limit)})

    @app.put("/api/incidents/<incident_id>/triage")
    @authenticated
    def api_incident_triage_put(incident_id: str):
        payload, error = _require_json_object()
        if error:
            return error
        requested_state = payload.get("state", payload.get("triage_state"))
        if requested_state is None:
            return jsonify({"error": "Triage state is required"}), 400
        try:
            return jsonify(service.update_incident_triage(incident_id, requested_state))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Failed to update /api/incidents/%s/triage", incident_id)
            return jsonify({"error": "Failed to update incident triage state"}), 500

    @app.get("/api/incidents/export")
    def api_incidents_export():
        limit = request.args.get("limit", default=1000, type=int)
        normalized_limit = max(1, min(limit, 1000))
        export_format = request.args.get("format", default="csv", type=str)
        try:
            payload = service.get_incidents_export(limit=normalized_limit, export_format=export_format)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        response = Response(payload["content"], mimetype=payload["mimetype"])
        response.headers["Content-Disposition"] = f'attachment; filename="{payload["filename"]}"'
        return response

    @app.get("/api/simulation/scenarios")
    def api_simulation_scenarios():
        return jsonify(service.get_simulation_scenarios())

    @app.post("/api/simulation/trigger")
    @authenticated
    def api_simulation_trigger():
        payload, error = _require_json_object()
        if error:
            return error
        try:
            return jsonify(service.trigger_simulation_scenario(payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Failed to trigger /api/simulation/trigger")
            return jsonify({"error": "Failed to trigger simulation scenario"}), 500

    @app.get("/api/network/graph")
    def api_network_graph():
        return jsonify(service.get_network_graph())

    @app.get("/api/threat-map")
    def api_threat_map():
        return jsonify(service.get_threat_map())

    @app.get("/api/threat-intel")
    def api_threat_intel():
        limit = request.args.get("limit", default=300, type=int)
        normalized_limit = max(1, min(limit, 1000))
        return jsonify(service.get_threat_intel(limit=normalized_limit))

    @app.route("/api/hunting", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/", methods=["GET", "POST", "PUT"])
    def api_hunting():
        return _handle_hunting_route(view_on_empty_get=True)

    @app.get("/api/hunting/capabilities")
    def api_hunting_capabilities():
        return jsonify(service.get_hunting_query_capabilities())

    @app.route("/api/hunting/query", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/query/", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/search", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/search/", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/execute", methods=["GET", "POST", "PUT"])
    @app.route("/api/hunting/execute/", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/query", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/query/", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/search", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/search/", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/execute", methods=["GET", "POST", "PUT"])
    @app.route("/api/threat-hunting/execute/", methods=["GET", "POST", "PUT"])
    def api_hunting_query():
        return _handle_hunting_route(view_on_empty_get=False)

    @app.get("/api/compliance/logs")
    def api_compliance_logs():
        tail_lines = request.args.get("tail", default=200, type=int)
        return jsonify(service.get_compliance_logs(tail_lines=max(1, min(tail_lines, 2000))))

    @app.get("/api/config/rules")
    def api_config_rules_get():
        return jsonify(service.get_rules())

    @app.put("/api/config/rules")
    @authenticated
    def api_config_rules_put():
        payload, error = _require_json_object()
        if error:
            return error
        try:
            return jsonify(service.update_rules(payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Failed to update /api/config/rules")
            return _config_update_failure_response("Failed to update configuration rules")

    @app.get("/api/config/sensors")
    def api_config_sensors_get():
        return jsonify(service.get_sensors())

    @app.get("/api/config/settings")
    def api_config_settings_get():
        return jsonify(service.get_settings())

    @app.put("/api/config/settings")
    @authenticated
    def api_config_settings_put():
        payload, error = _require_json_object()
        if error:
            return error
        try:
            return jsonify(service.update_settings(payload))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Failed to update /api/config/settings")
            return _config_update_failure_response("Failed to update configuration settings")

    @app.get("/")
    def static_index():
        return send_from_directory(static_root, "index.html")

    @app.get("/<path:asset_path>")
    def static_assets(asset_path: str):
        target = os.path.join(static_root, asset_path)
        if os.path.isfile(target):
            return send_from_directory(static_root, asset_path)
        return send_from_directory(static_root, "index.html")

    return app


def start_web_platform(
    *,
    model_path: str = "models/svm_model.pkl",
    scaler_path: str = "data/processed/scaler.pkl",
    encoders_path: str = "data/processed/label_encoders.pkl",
    host: str = "127.0.0.1",
    port: int = 8050,
    alert_threshold: float = 0.8,
    interface: str | None = None,
    config_path: str = os.path.join("config", "ids_config.json"),
    loopback_window_seconds: int = 5,
    loopback_min_distinct_ports_for_scan: int = 15,
    enable_staged_data: bool = True,
    refresh_interval_seconds: int = 2,
) -> None:
    service = SentinelAIRuntimeService(
        model_path=model_path,
        scaler_path=scaler_path,
        encoders_path=encoders_path,
        alert_threshold=alert_threshold,
        interface=interface,
        web_port=port,
        config_path=config_path,
        loopback_window_seconds=loopback_window_seconds,
        loopback_min_distinct_ports_for_scan=loopback_min_distinct_ports_for_scan,
        enable_staged_data=enable_staged_data,
        refresh_interval_seconds=refresh_interval_seconds,
    )
    service.start()
    app = create_app(service)

    print("\n" + "=" * 60)
    print("Starting SentinelAI Web Platform")
    print("=" * 60)
    print(f"[WEB] Frontend + API available at: http://{host}:{port}")
    print("[WEB] Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=False, use_reloader=False)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Run SentinelAI web platform")
    parser.add_argument("--config", default=os.path.join("config", "ids_config.json"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--scaler-path", default=None)
    parser.add_argument("--encoders-path", default=None)
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args()

    config = load_runtime_config(args.config)
    model_path = args.model_path or cfg_get(config, "runtime.model_path", "models/svm_model.pkl")
    scaler_path = args.scaler_path or cfg_get(config, "runtime.scaler_path", "data/processed/scaler.pkl")
    encoders_path = args.encoders_path or cfg_get(config, "runtime.encoders_path", "data/processed/label_encoders.pkl")
    threshold = args.threshold if args.threshold is not None else cfg_get(config, "runtime.alert_threshold", 0.8)
    interface = args.interface if args.interface is not None else cfg_get(config, "monitoring.interface", None)
    host = args.host or cfg_get(config, "web.host", "127.0.0.1")
    port = args.port if args.port is not None else cfg_get(config, "web.port", 8050)
    loopback_window_seconds = cfg_get(config, "suppression.loopback_window_seconds", 5)
    loopback_min_distinct_ports = cfg_get(config, "suppression.loopback_min_distinct_ports_for_scan", 15)
    enable_staged_data = cfg_get(config, "web.enable_staged_data", True)
    refresh_interval_seconds = cfg_get(config, "web.refresh_interval_seconds", 2)

    start_web_platform(
        model_path=model_path,
        scaler_path=scaler_path,
        encoders_path=encoders_path,
        host=host,
        port=port,
        alert_threshold=threshold,
        interface=interface,
        config_path=args.config,
        loopback_window_seconds=loopback_window_seconds,
        loopback_min_distinct_ports_for_scan=loopback_min_distinct_ports,
        enable_staged_data=enable_staged_data,
        refresh_interval_seconds=refresh_interval_seconds,
    )


if __name__ == "__main__":
    _main()
