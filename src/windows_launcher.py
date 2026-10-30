"""Windows desktop launcher for SentinelAI runtime control."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
import os
import sys
import webbrowser

from cli import _resolve_runtime_settings
from web.server import start_web_platform
from windows_runtime_controller import RuntimeLaunchSettings, SentinelAIRuntimeController

APP_NAME = "SentinelAI Launcher"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8050
DEFAULT_THRESHOLD = 0.8
SETTINGS_FILE_NAME = "launcher_settings.json"


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _default_config_path(root: Path) -> str:
    return str(root / "config" / "ids_config.json")


def _settings_file_path(root: Path) -> Path:
    appdata = os.getenv("APPDATA")
    if appdata:
        directory = Path(appdata) / "SentinelAI"
    else:
        directory = root / "config"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / SETTINGS_FILE_NAME


def _load_launcher_settings(settings_path: Path) -> dict[str, object]:
    defaults: dict[str, object] = {
        "port": DEFAULT_PORT,
        "threshold": DEFAULT_THRESHOLD,
        "interface": "",
    }
    if not settings_path.exists():
        return defaults
    try:
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defaults
    if not isinstance(raw, dict):
        return defaults
    port = raw.get("port", DEFAULT_PORT)
    threshold = raw.get("threshold", DEFAULT_THRESHOLD)
    interface = str(raw.get("interface", "")).strip()
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        normalized_port = DEFAULT_PORT
    try:
        normalized_threshold = float(threshold)
    except (TypeError, ValueError):
        normalized_threshold = DEFAULT_THRESHOLD
    return {
        "port": normalized_port,
        "threshold": normalized_threshold,
        "interface": interface,
    }


def _save_launcher_settings(settings_path: Path, *, port: int, threshold: float, interface: str) -> None:
    payload = {
        "port": int(port),
        "threshold": float(threshold),
        "interface": interface.strip(),
    }
    settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class LauncherApp:
    """Tkinter desktop UI that toggles SentinelAI runtime."""

    def __init__(self, root: tk.Tk) -> None:
        self.window = root
        self.project_root = _project_root()
        self.config_path = _default_config_path(self.project_root)
        self.settings_path = _settings_file_path(self.project_root)
        persisted = _load_launcher_settings(self.settings_path)
        self.controller = SentinelAIRuntimeController(project_root=self.project_root)
        self._after_poll: str | None = None

        self.window.title(APP_NAME)
        self.window.geometry("560x300")
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        self.port_var = tk.StringVar(value=str(persisted["port"]))
        self.threshold_var = tk.StringVar(value=str(persisted["threshold"]))
        self.interface_var = tk.StringVar(value=str(persisted["interface"]))
        self.status_var = tk.StringVar(value="Status: stopped")

        self._build_ui()
        self._refresh_controls()
        self._schedule_poll()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Runtime Settings", font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
        )

        ttk.Label(frame, text="Port").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.port_var, width=24).grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(frame, text="Threshold (0-1)").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.threshold_var, width=24).grid(row=2, column=1, sticky="w", pady=4)

        ttk.Label(frame, text="Interface (optional)").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.interface_var, width=24).grid(row=3, column=1, sticky="w", pady=4)

        ttk.Label(frame, textvariable=self.status_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=(14, 10))

        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=2, sticky="w")

        self.start_button = ttk.Button(actions, text="Start", command=self._start_runtime)
        self.start_button.grid(row=0, column=0, padx=(0, 8))

        self.stop_button = ttk.Button(actions, text="Stop", command=self._stop_runtime)
        self.stop_button.grid(row=0, column=1, padx=(0, 8))

        self.open_dashboard_button = ttk.Button(actions, text="Open Dashboard", command=self._open_dashboard)
        self.open_dashboard_button.grid(row=0, column=2, padx=(0, 8))

        self.open_logs_button = ttk.Button(actions, text="Open Logs", command=self._open_logs)
        self.open_logs_button.grid(row=0, column=3)

    def _runtime_url(self) -> str:
        return f"http://{DEFAULT_HOST}:{self.port_var.get().strip()}"

    def _parse_settings(self) -> RuntimeLaunchSettings:
        config_path = Path(self.config_path)
        if not config_path.exists():
            raise ValueError(f"Runtime config file not found: {config_path}")

        port_text = self.port_var.get().strip()
        threshold_text = self.threshold_var.get().strip()
        interface_text = self.interface_var.get().strip()

        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("Port must be an integer.") from exc
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535.")

        try:
            threshold = float(threshold_text)
        except ValueError as exc:
            raise ValueError("Threshold must be a number between 0 and 1.") from exc
        if threshold < 0.0 or threshold > 1.0:
            raise ValueError("Threshold must be between 0 and 1.")

        return RuntimeLaunchSettings(
            config_path=str(config_path),
            host=DEFAULT_HOST,
            port=port,
            interface=interface_text or None,
            threshold=threshold,
        )

    def _refresh_controls(self) -> None:
        running = self.controller.is_running()
        self.start_button.state(["disabled"] if running else ["!disabled"])
        self.stop_button.state(["!disabled"] if running else ["disabled"])
        self.open_dashboard_button.state(["!disabled"] if running else ["disabled"])

    def _start_runtime(self) -> None:
        try:
            settings = self._parse_settings()
            self.controller.start(settings)
            _save_launcher_settings(
                self.settings_path,
                port=settings.port,
                threshold=settings.threshold,
                interface=settings.interface or "",
            )
            self.status_var.set(f"Status: starting (PID {self.controller.pid})")
        except (ValueError, OSError, RuntimeError) as exc:
            messagebox.showerror(APP_NAME, str(exc))
        self._refresh_controls()

    def _stop_runtime(self) -> None:
        try:
            self.controller.stop()
            self.status_var.set("Status: stopped")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Failed to stop runtime: {exc}")
        self._refresh_controls()

    def _open_dashboard(self) -> None:
        webbrowser.open(f"{self._runtime_url()}/")

    def _open_logs(self) -> None:
        logs_path = self.project_root / "logs" / "ids_alerts.log"
        logs_path.parent.mkdir(parents=True, exist_ok=True)
        logs_path.touch(exist_ok=True)
        if os.name == "nt":
            os.startfile(str(logs_path))
            return
        messagebox.showinfo(APP_NAME, f"Logs path: {logs_path}")

    def _schedule_poll(self) -> None:
        self._update_status()
        self._after_poll = self.window.after(1000, self._schedule_poll)

    def _update_status(self) -> None:
        if not self.controller.is_running():
            self.status_var.set("Status: stopped")
            self._refresh_controls()
            return
        if self.controller.health_ok():
            self.status_var.set(f"Status: running at {self._runtime_url()} (PID {self.controller.pid})")
        else:
            self.status_var.set(f"Status: starting... (PID {self.controller.pid})")
        self._refresh_controls()

    def _on_close(self) -> None:
        if self.controller.is_running():
            should_stop = messagebox.askyesno(APP_NAME, "SentinelAI is running. Stop it before exit?")
            if should_stop:
                self.controller.stop()
            else:
                return
        if self._after_poll is not None:
            self.window.after_cancel(self._after_poll)
            self._after_poll = None
        self.window.destroy()


def _run_runtime_child(args: argparse.Namespace) -> None:
    runtime_args = argparse.Namespace(
        config=args.config,
        model_path=None,
        scaler_path=None,
        encoders_path=None,
        threshold=args.threshold,
        interface=args.interface,
        host=args.host,
        port=args.port,
    )
    settings = _resolve_runtime_settings(runtime_args)
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelAI Windows launcher")
    parser.add_argument("--runtime-child", action="store_true", help="Internal runtime mode for launcher-controlled start")
    parser.add_argument("--config", default=str(_project_root() / "config" / "ids_config.json"))
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.runtime_child:
        _run_runtime_child(args)
        return

    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
