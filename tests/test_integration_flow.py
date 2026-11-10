"""四类样本、报告、离线与合规要求的集成测试。"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from core.file_loader import FileLoader
from core.report_exporter import ReportExporter
from core.result_manager import ResultManager
from core.rule_engine import RuleEngine

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
RULES = ROOT / "rules"


def run_scan(path):
    loader = FileLoader()
    engine = RuleEngine(RULES)
    loaded = loader.scan(str(path))
    manager = ResultManager()
    manager.total_files = loaded.files_seen
    manager.scanned_files = len(loaded.targets)
    manager.rules_loaded = len(engine.rules)
    for skipped in loaded.skipped:
        manager.add_skipped(skipped.path, skipped.reason)
    for target in loaded.targets:
        manager.add_matches(target.display_path, engine.scan(target.content, target.format))
    manager.finish()
    return loaded, engine, manager


def test_normal_samples_have_zero_false_positives():
    loaded, engine, manager = run_scan(FIXTURES / "normal_samples")
    assert len(loaded.targets) == 7
    assert loaded.skipped[0].reason == "空文件"
    assert len(engine.rules) >= 30
    assert manager.findings == []
    assert manager.statistics()["high"] == 0


def test_clean_firmware_has_no_findings():
    _, _, manager = run_scan(FIXTURES / "firmware_samples" / "clean_fw.bin")
    assert manager.findings == []


def test_risky_samples_detect_every_builtin_rule():
    loaded, engine, manager = run_scan(FIXTURES / "risky_samples")
    assert len(loaded.targets) == 5
    found_ids = {finding.rule_id for finding in manager.findings}
    expected_ids = {rule.id for rule in engine.rules}
    assert expected_ids <= found_ids
    assert len(manager.findings) >= 40
    report_text = json.dumps(manager.build_report(), ensure_ascii=False)
    assert "SuperSecret123!" not in report_text
    assert "WebSecret!2024" not in report_text
    masks = {finding.matched_masked for finding in manager.findings}
    assert any("*" in value for value in masks)
    for finding in manager.findings:
        assert finding.file_path and finding.line > 0
        assert finding.remediation and finding.description


def test_archive_and_firmware_samples_are_parsed():
    loaded, _, archive_manager = run_scan(FIXTURES / "archive_samples")
    targets = {target.display_path for target in loaded.targets}
    assert "backup.zip!/backup/app.yaml" in targets
    assert "backup.tar.gz!/config/archive.ini" in targets
    assert "backup.tar.bz2!/config/cloud.conf" in targets
    assert any(item.path == "damaged.zip" and "损坏" in item.reason for item in loaded.skipped)
    assert {finding.rule_id for finding in archive_manager.findings} >= {"HC-001", "HC-002", "WS-004"}

    loaded, _, firmware_manager = run_scan(FIXTURES / "firmware_samples")
    firmware_targets = {target.display_path for target in loaded.targets}
    assert firmware_targets == {"router_fw.bin#config", "clean_fw.bin#config"}
    assert any(item.path == "no_config.bin" for item in loaded.skipped)
    assert {finding.rule_id for finding in firmware_manager.findings} >= {"HC-001", "HC-010", "WS-006"}


def test_full_and_filtered_reports(tmp_path):
    _, _, manager = run_scan(FIXTURES / "risky_samples")
    exporter = ReportExporter(tmp_path)
    written = exporter.write_reports(manager.build_report())
    payload = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    stats = payload["statistics"]
    assert stats["total_files"] == 5
    assert stats["skipped_files"] == 0
    assert stats["high"] + stats["medium"] + stats["low"] == stats["total_findings"]
    assert payload["scan_time"] and payload["findings"]
    with Path(written["csv"]).open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["total_files"] == "5"
    assert rows[0]["record_type"] == "finding"

    filtered = manager.build_report(severity="high", category="hardcoded_credential")
    assert filtered["statistics"]["total_findings"] > 0
    assert filtered["statistics"]["medium"] == 0
    assert all(item["severity"] == "high" for item in filtered["findings"])
    filtered_written = exporter.write_reports(filtered, prefix="filtered_high")
    assert Path(filtered_written["json"]).exists()
    assert Path(filtered_written["csv"]).exists()


def test_custom_rule_auto_loads_from_rule_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for source in RULES.glob("*.yaml"):
        (rules_dir / source.name).write_bytes(source.read_bytes())
    (rules_dir / "custom.yaml").write_text(
        """category: sensitive_info
rules:
  - id: CUSTOM-001
    severity: low
    description: 自定义测试规则
    remediation: 测试修复
    match:
      type: regex
      pattern: 'CUSTOM-LEAK-[0-9]{4}'
""",
        encoding="utf-8",
    )
    engine = RuleEngine(rules_dir)
    assert not engine.errors
    assert any(rule.id == "CUSTOM-001" for rule in engine.rules)
    matches = engine.scan("value: CUSTOM-LEAK-1234\n")
    assert [match.rule.id for match in matches] == ["CUSTOM-001"]


def test_code_compliance_line_limits_and_offline_assets():
    core_files = sorted((ROOT / "core").glob("*.py"))
    scripts = [ROOT / "run_web.py", ROOT / "run_tests.py"]
    test_files = sorted((ROOT / "tests").glob("test_*.py"))
    business = core_files + scripts + [ROOT / "web" / "app.js"]
    assert all(len(path.read_text(encoding="utf-8").splitlines()) <= 300 for path in business)
    assert all(len(path.read_text(encoding="utf-8").splitlines()) <= 300 for path in test_files)

    banned = [
        "import requests", "from urllib.request", "import urllib.request",
        "urlopen(", "socket.create_connection", "http.client", "import httpx", "aiohttp",
    ]
    for path in core_files + scripts:
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in banned), path
    server_source = (ROOT / "core" / "web_handler.py").read_text(encoding="utf-8")
    assert 'DEFAULT_HOST = "127.0.0.1"' in server_source
    assert 'host != DEFAULT_HOST' in server_source

    for name in ("index.html", "style.css", "app.js"):
        asset = (ROOT / "web" / name).read_text(encoding="utf-8")
        assert "http://" not in asset and "https://" not in asset and "//cdn" not in asset
    assert "外部资源" not in (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def test_project_size_and_encoding():
    suffixes = {
        ".py", ".yaml", ".yml", ".md", ".txt", ".html", ".css", ".js",
        ".ini", ".conf", ".json", ".xml", ".env", ".toml",
    }
    names = {".env", ".gitignore", "requirements.txt"}
    ignored = {"__pycache__", ".pytest_cache", ".git", "output", ".venv"}
    total = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in ignored for part in path.parts):
            continue
        if path.suffix not in suffixes and path.name not in names:
            continue
        text = path.read_text(encoding="utf-8")
        total += len(text.splitlines())
    assert 2500 <= total <= 4500, total

    yaml_files = list((ROOT / "rules").glob("*.yaml"))
    for path in yaml_files + [ROOT / "README.md", ROOT / "requirements.txt"]:
        assert path.read_text(encoding="utf-8")
