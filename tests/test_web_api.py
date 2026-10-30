"""Smoke tests for the SentinelAI API (the packet sniffer is not started)."""

import shutil

import pytest

from web.runtime_service import SentinelAIRuntimeService
from web.server import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    config = tmp_path_factory.mktemp("cfg") / "ids_config.json"
    shutil.copy("config/ids_config.json", config)   # writes go to a copy, not the repo
    service = SentinelAIRuntimeService(
        model_path="models/svm_model.pkl",
        scaler_path="data/processed/scaler.pkl",
        encoders_path="data/processed/label_encoders.pkl",
        alert_threshold=0.8,
        interface="lo",
        web_port=8050,
        config_path=str(config),
        loopback_window_seconds=5,
        loopback_min_distinct_ports_for_scan=15,
        enable_staged_data=True,
        refresh_interval_seconds=2,
    )
    app = create_app(service)
    app.testing = True
    with app.test_client() as c:
        yield c


@pytest.mark.parametrize("path", [
    "/api/health", "/api/overview/summary", "/api/overview/charts", "/api/incidents",
    "/api/simulation/scenarios", "/api/network/graph", "/api/threat-map", "/api/hunting",
    "/api/hunting/capabilities", "/api/config/rules", "/api/config/sensors", "/api/config/settings",
])
def test_read_endpoints(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.data[:300]
    assert r.is_json


def test_metrics_endpoint(client):
    r = client.get("/api/metrics")
    assert r.status_code == 200 and b"http_requests_total" in r.data


def test_frontend_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and b"<html" in r.data.lower()


def test_simulation_creates_incidents(client):
    scenarios = client.get("/api/simulation/scenarios").get_json()
    items = scenarios.get("scenarios") or scenarios.get("items") or scenarios
    first = items[0]
    scenario_id = first.get("id") or first.get("scenario_id")
    r = client.post("/api/simulation/trigger", json={"scenario_id": scenario_id})
    assert r.status_code == 200, r.data[:300]
    incidents = client.get("/api/incidents").get_json()["items"]
    assert incidents and "attack_detail" in incidents[0]


def test_write_endpoints_require_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    assert client.put("/api/config/settings", json={}).status_code == 401
    r = client.put("/api/config/settings", json={}, headers={"X-API-Key": "test-key"})
    assert r.status_code != 401
