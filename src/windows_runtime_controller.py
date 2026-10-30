"""Runtime process controller for the Windows launcher."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import signal
import subprocess
import sys
import time
from urllib import error as urlerror
from urllib import request as urlrequest


@dataclass(frozen=True)
class RuntimeLaunchSettings:
    """Runtime settings used to launch SentinelAI web mode."""

    config_path: str
    host: str
    port: int
    interface: str | None
    threshold: float


class SentinelAIRuntimeController:
    """Starts/stops SentinelAI runtime as a managed child process."""

    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = Path(project_root or self._default_project_root()).resolve()
        self._process: subprocess.Popen[bytes] | None = None
        self._settings: RuntimeLaunchSettings | None = None

    @staticmethod
    def _default_project_root() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent.parent

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def pid(self) -> int | None:
        if self._process is None:
            return None
        return self._process.pid

    @property
    def settings(self) -> RuntimeLaunchSettings | None:
        return self._settings

    def start(self, settings: RuntimeLaunchSettings) -> None:
        if self.is_running():
            raise RuntimeError("SentinelAI runtime is already running.")

        command = self._build_command(settings)
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        self._process = subprocess.Popen(
            command,
            cwd=str(self.project_root),
            creationflags=creationflags,
        )
        self._settings = settings

    def stop(self, timeout_seconds: float = 8.0) -> None:
        if self._process is None:
            return

        process = self._process
        if process.poll() is not None:
            self._process = None
            return

        graceful_sent = False
        if os.name == "nt":
            ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
            if ctrl_break is not None:
                try:
                    process.send_signal(ctrl_break)
                    graceful_sent = True
                except OSError:
                    graceful_sent = False

        if graceful_sent:
            try:
                process.wait(timeout=max(1.0, timeout_seconds))
            except subprocess.TimeoutExpired:
                graceful_sent = False

        if not graceful_sent and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=max(1.0, timeout_seconds))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=max(1.0, timeout_seconds))

        self._process = None

    def health_ok(self, timeout_seconds: float = 1.0) -> bool:
        settings = self._settings
        if settings is None:
            return False
        if not self.is_running():
            return False
        url = f"http://{settings.host}:{settings.port}/api/health"
        try:
            with urlrequest.urlopen(url, timeout=timeout_seconds) as response:
                return 200 <= response.status < 300
        except (OSError, urlerror.URLError):
            return False

    def _build_command(self, settings: RuntimeLaunchSettings) -> list[str]:
        if getattr(sys, "frozen", False):
            return self._build_frozen_command(settings)
        return self._build_source_command(settings)

    def _build_source_command(self, settings: RuntimeLaunchSettings) -> list[str]:
        cli_path = self.project_root / "src" / "cli.py"
        if not cli_path.exists():
            raise FileNotFoundError(f"Expected CLI entrypoint not found: {cli_path}")
        command = [
            sys.executable,
            str(cli_path),
            "web",
            "--config",
            settings.config_path,
            "--host",
            settings.host,
            "--port",
            str(settings.port),
            "--threshold",
            str(settings.threshold),
        ]
        if settings.interface:
            command.extend(["--interface", settings.interface])
        return command

    def _build_frozen_command(self, settings: RuntimeLaunchSettings) -> list[str]:
        command = [
            sys.executable,
            "--runtime-child",
            "--config",
            settings.config_path,
            "--host",
            settings.host,
            "--port",
            str(settings.port),
            "--threshold",
            str(settings.threshold),
        ]
        if settings.interface:
            command.extend(["--interface", settings.interface])
        return command

    def wait_for_healthy(self, timeout_seconds: float = 20.0) -> bool:
        start = time.monotonic()
        while time.monotonic() - start <= timeout_seconds:
            if not self.is_running():
                return False
            if self.health_ok():
                return True
            time.sleep(0.5)
        return self.health_ok()
