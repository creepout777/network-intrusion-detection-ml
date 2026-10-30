"""Runtime CLI for IDS monitoring and SentinelAI web operations."""

import argparse

from common.config_utils import cfg_get, load_runtime_config
from monitoring.packet_sniffer import RealtimeIDS
from web.server import start_web_platform


def _add_runtime_args(parser):
    parser.add_argument("--config", default="config/ids_config.json")
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--scaler-path", default=None)
    parser.add_argument("--encoders-path", default=None)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--interface", default=None)


def _resolve_runtime_settings(args):
    config = load_runtime_config(args.config)
    host_arg = getattr(args, "host", None)
    port_arg = getattr(args, "port", None)
    return {
        "model_path": args.model_path or cfg_get(config, "runtime.model_path", "models/svm_model.pkl"),
        "scaler_path": args.scaler_path or cfg_get(config, "runtime.scaler_path", "data/processed/scaler.pkl"),
        "encoders_path": args.encoders_path or cfg_get(config, "runtime.encoders_path", "data/processed/label_encoders.pkl"),
        "alert_threshold": args.threshold if args.threshold is not None else cfg_get(config, "runtime.alert_threshold", 0.8),
        "interface": args.interface if args.interface is not None else cfg_get(config, "monitoring.interface", None),
        "loopback_window_seconds": cfg_get(config, "suppression.loopback_window_seconds", 5),
        "loopback_min_distinct_ports_for_scan": cfg_get(config, "suppression.loopback_min_distinct_ports_for_scan", 15),
        "dashboard_port": cfg_get(config, "dashboard.port", 8050),  # legacy key fallback
        "web_host": host_arg or cfg_get(config, "web.host", "127.0.0.1"),
        "web_port": port_arg if port_arg is not None else cfg_get(config, "web.port", cfg_get(config, "dashboard.port", 8050)),
        "web_enable_staged_data": cfg_get(config, "web.enable_staged_data", True),
        "web_refresh_interval_seconds": cfg_get(config, "web.refresh_interval_seconds", 2),
        "packet_count": cfg_get(config, "monitoring.packet_count", 0),
    }


def cmd_monitor(args):
    settings = _resolve_runtime_settings(args)
    packet_count = args.packet_count if args.packet_count is not None else settings["packet_count"]
    ids = RealtimeIDS(
        model_path=settings["model_path"],
        scaler_path=settings["scaler_path"],
        encoders_path=settings["encoders_path"],
        alert_threshold=settings["alert_threshold"],
        loopback_window_seconds=settings["loopback_window_seconds"],
        loopback_min_distinct_ports_for_scan=settings["loopback_min_distinct_ports_for_scan"],
    )
    ids.start_monitoring(interface=settings["interface"], packet_count=packet_count)


def cmd_web(args):
    settings = _resolve_runtime_settings(args)
    start_web_platform(
        model_path=settings["model_path"],
        scaler_path=settings["scaler_path"],
        encoders_path=settings["encoders_path"],
        host=settings["web_host"],
        port=settings["web_port"],
        alert_threshold=settings["alert_threshold"],
        interface=settings["interface"],
        config_path=args.config,
        loopback_window_seconds=settings["loopback_window_seconds"],
        loopback_min_distinct_ports_for_scan=settings["loopback_min_distinct_ports_for_scan"],
        enable_staged_data=settings["web_enable_staged_data"],
        refresh_interval_seconds=settings["web_refresh_interval_seconds"],
    )


def cmd_dashboard(args):
    """Backward-compatible alias to the new SentinelAI web platform."""
    cmd_web(args)


def build_parser():
    parser = argparse.ArgumentParser(description="Runtime IDS command-line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor_parser = subparsers.add_parser("monitor", help="Start real-time packet monitoring")
    _add_runtime_args(monitor_parser)
    monitor_parser.add_argument("--packet-count", type=int, default=None, help="Capture limit (0=infinite)")
    monitor_parser.set_defaults(func=cmd_monitor)

    web_parser = subparsers.add_parser("web", help="Start SentinelAI web platform")
    _add_runtime_args(web_parser)
    web_parser.add_argument("--host", default=None, help="Web host")
    web_parser.add_argument("--port", type=int, default=None, help="Web port")
    web_parser.set_defaults(func=cmd_web)

    dashboard_parser = subparsers.add_parser("dashboard", help="Alias for the 'web' command")
    _add_runtime_args(dashboard_parser)
    dashboard_parser.add_argument("--host", default=None, help="Web host")
    dashboard_parser.add_argument("--port", type=int, default=None, help="Web port")
    dashboard_parser.set_defaults(func=cmd_dashboard)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
