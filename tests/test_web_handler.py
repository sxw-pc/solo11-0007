"""本地 HTTP 服务、异步任务、筛选与下载测试。"""

from __future__ import annotations

import csv
import http.client
import io
import json
import socket
import threading
import time
from urllib.parse import urlencode

import pytest

from core.web_handler import AppContext, create_server

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]


@pytest.fixture
def live_server(tmp_path):
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "app.yaml").write_text(
        "password: WebSecret!2024\napi_key: webFAKEkey_12345678\ndebug: true\n",
        encoding="utf-8",
    )
    (sample_dir / "broken.json").write_text("{bad", encoding="utf-8")
    ctx = AppContext(base_dir=ROOT, rules_dir=ROOT / "rules", output_dir=tmp_path / "output")
    server = create_server("127.0.0.1", 0, ctx)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield ctx, server.server_address[1], sample_dir, tmp_path
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def request(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    response_headers = dict(response.getheaders())
    status = response.status
    connection.close()
    return status, response_headers, payload


def wait_for_job(port, job_id):
    for _ in range(100):
        status, _, body = request(port, "GET", f"/api/progress?job_id={job_id}")
        payload = json.loads(body)
        if payload["status"] in {"completed", "failed"}:
            return status, payload
        time.sleep(0.03)
    raise AssertionError("任务未在限定时间内完成")


def test_create_server_rejects_public_bind(tmp_path):
    context = AppContext(base_dir=ROOT, output_dir=tmp_path / "output")
    with pytest.raises(ValueError):
        create_server("0.0.0.0", 0, context)


def test_static_health_and_not_found(live_server):
    _, port, _, _ = live_server
    status, headers, body = request(port, "GET", "/")
    assert status == 200
    assert "配置漏检工具箱" in body.decode("utf-8")
    assert "http://" not in body.decode("utf-8")
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert request(port, "GET", "/style.css")[0] == 200
    assert request(port, "GET", "/app.js")[0] == 200
    assert request(port, "GET", "/favicon.ico")[0] == 204
    status, _, body = request(port, "GET", "/api/health")
    assert status == 200 and json.loads(body)["offline"] is True
    assert request(port, "GET", "/../README.md")[0] == 404
    assert request(port, "GET", "/api/nope")[0] == 404


def test_rules_api(live_server):
    _, port, _, _ = live_server
    status, _, body = request(port, "GET", "/api/rules")
    payload = json.loads(body)
    assert status == 200
    assert payload["count"] >= 30
    assert payload["errors"] == []
    assert any(rule["id"] == "HC-001" for rule in payload["rules"])


def test_scan_flow_filters_exports_and_downloads(live_server):
    ctx, port, sample_dir, tmp_path = live_server
    status, _, body = request(
        port, "POST", "/api/scan",
        json.dumps({"path": str(sample_dir)}).encode(),
        {"Content-Type": "application/json"},
    )
    assert status == 202
    created = json.loads(body)
    job_id = created["job_id"]
    assert created["status"] in {"queued", "loading", "scanning"}
    status, job = wait_for_job(port, job_id)
    assert status == 200
    assert job["status"] == "completed"
    assert job["progress"] == 100
    assert job["statistics"]["total_files"] == 2
    assert job["statistics"]["skipped_files"] == 1
    assert job["statistics"]["high"] >= 2
    assert job["reports"]["json_name"].endswith(".json")

    status, _, body = request(port, "GET", f"/api/results?job_id={job_id}")
    payload = json.loads(body)
    assert status == 200
    assert payload["findings"]
    assert "WebSecret!2024" not in body.decode("utf-8")
    assert payload["skipped"][0]["file_path"] == "broken.json"
    assert payload["job"]["job_id"] == job_id

    query = urlencode({"job_id": job_id, "severity": "high", "rule_id": "HC-001", "path": "app"})
    status, _, body = request(port, "GET", f"/api/results?{query}")
    filtered = json.loads(body)
    assert status == 200
    assert filtered["findings"]
    assert all(item["rule_id"] == "HC-001" for item in filtered["findings"])
    assert all(item["severity"] == "high" for item in filtered["findings"])

    export_query = urlencode({
        "job_id": job_id, "format": "csv", "severity": "high", "rule_id": "HC-001",
    })
    status, headers, body = request(port, "GET", f"/api/export?{export_query}")
    assert status == 200
    assert "attachment" in headers["Content-Disposition"]
    assert b"WebSecret!2024" not in body
    rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))
    assert rows and all(row["rule_id"] == "HC-001" for row in rows)
    assert rows[0]["matched_masked"].startswith("We")

    status, _, body = request(port, "GET", f"/api/download?job_id={job_id}&format=json")
    assert status == 200
    assert json.loads(body)["statistics"]["total_files"] == 2
    status, _, body = request(port, "GET", f"/api/download?job_id={job_id}&format=csv")
    assert status == 200 and b"record_type" in body
    report_files = list((tmp_path / "output").glob("*"))
    assert len(report_files) >= 4

    assert request(port, "GET", f"/api/export?job_id={job_id}&format=xml")[0] == 400
    assert request(port, "GET", f"/api/download?job_id={job_id}&format=txt")[0] == 404


def test_job_failure_and_missing_jobs(live_server):
    _, port, _, _ = live_server
    status, _, body = request(
        port, "POST", "/api/scan",
        json.dumps({"path": "definitely/not/here"}).encode(),
        {"Content-Type": "application/json"},
    )
    job_id = json.loads(body)["job_id"]
    _, job = wait_for_job(port, job_id)
    assert job["status"] == "failed"
    assert "路径不存在" in job["error"]
    assert request(port, "GET", f"/api/results?job_id={job_id}")[0] == 409
    assert request(port, "GET", f"/api/export?job_id={job_id}")[0] == 409
    assert request(port, "GET", f"/api/download?job_id={job_id}&format=json")[0] == 404

    assert request(port, "GET", "/api/progress?job_id=missing")[0] == 404
    assert request(port, "GET", "/api/results?job_id=missing")[0] == 404
    assert request(port, "GET", "/api/export?job_id=missing")[0] == 404
    assert request(port, "GET", "/api/download?job_id=missing")[0] == 404


def test_offline_flow_blocks_external_connections(live_server, monkeypatch):
    _, port, sample_dir, _ = live_server
    original_connect = socket.socket.connect

    def guarded_connect(sock, address):
        if isinstance(address, tuple) and address[0] not in {"127.0.0.1", "::1"}:
            raise OSError("offline test: external network blocked")
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    status, _, body = request(
        port, "POST", "/api/scan",
        json.dumps({"path": str(sample_dir)}).encode(),
        {"Content-Type": "application/json"},
    )
    assert status == 202
    _, job = wait_for_job(port, json.loads(body)["job_id"])
    assert job["status"] == "completed"
    assert job["statistics"]["total_findings"] > 0


def test_request_validation(live_server):
    _, port, _, _ = live_server
    headers = {"Content-Type": "application/json"}
    assert request(port, "POST", "/api/scan", b"", headers)[0] == 400
    assert request(port, "POST", "/api/scan", b"{bad", headers)[0] == 400
    assert request(port, "POST", "/api/scan", b"[]", headers)[0] == 400
    assert request(port, "POST", "/api/scan", b"{}", headers)[0] == 400
    assert request(port, "POST", "/api/other", b"{}", headers)[0] == 404
