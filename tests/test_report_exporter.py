"""JSON / CSV 报告字段、统计、掩码与下载边界测试。"""

from __future__ import annotations

import csv
import json

from core.report_exporter import CSV_FIELDS, ReportExporter
from core.result_manager import ResultManager
from core.rule_engine import Rule, RuleMatch


def build_report(findings=True):
    manager = ResultManager()
    manager.total_files = 6
    manager.scanned_files = 5
    manager.rules_loaded = 43
    manager.add_skipped("empty.yaml", "空文件")
    if findings:
        rule = Rule(
            id="HC-001", category="hardcoded_credential", severity="high",
            description="明文密码", remediation="移除密码", match_type="regex",
            name="明文密码赋值",
        )
        manager.add_matches("app.yaml", [
            RuleMatch(rule, 3, "SuperSecret123!", "password: SuperSecret123!"),
        ])
        manager.add_matches("app.yaml", [
            RuleMatch(rule, 8, "RepeatedSecret!", "password: RepeatedSecret!"),
        ])
    manager.finish()
    return manager.build_report()


def test_write_json_and_csv_reports(tmp_path):
    exporter = ReportExporter(tmp_path)
    written = exporter.write_reports(build_report(), prefix="scan test")
    assert set(written) == {"json", "csv", "json_name", "csv_name", "base"}
    assert written["json_name"].startswith("scan_test_")
    assert written["json_name"].endswith(".json")

    payload = json.loads((tmp_path / written["json_name"]).read_text(encoding="utf-8"))
    assert payload["statistics"]["total_files"] == 6
    assert payload["statistics"]["skipped_files"] == 1
    assert payload["statistics"]["high"] == 2
    assert payload["findings"][0]["matched_masked"].startswith("Su")
    assert "SuperSecret123!" not in (tmp_path / written["json_name"]).read_text(encoding="utf-8")

    with (tmp_path / written["csv_name"]).open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert set(rows[0]) == set(CSV_FIELDS)
    assert rows[0]["record_type"] == "finding"
    assert rows[0]["total_files"] == "6"
    assert rows[0]["skipped_files"] == "1"
    assert rows[0]["high"] == "2"
    assert rows[0]["file_path"] == "app.yaml"
    assert rows[0]["line"] == "3"
    assert rows[0]["matched_masked"].startswith("Su")


def test_empty_report_has_machine_readable_summary(tmp_path):
    exporter = ReportExporter(tmp_path)
    written = exporter.write_reports(build_report(findings=False), prefix="empty")
    with (tmp_path / written["csv_name"]).open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["record_type"] == "summary"
    assert rows[0]["total_findings"] == "0"
    assert rows[0]["file_path"] == ""
    payload = json.loads((tmp_path / written["json_name"]).read_text(encoding="utf-8"))
    assert payload["findings"] == []


def test_filtered_report_and_safe_prefix(tmp_path):
    exporter = ReportExporter(tmp_path)
    report = build_report()
    report["export_type"] = "filtered"
    written = exporter.write_reports(report, prefix="../../bad prefix")
    assert (tmp_path / written["json_name"]).parent == tmp_path.resolve()
    assert ".." not in written["json_name"]
    assert written["csv_name"].endswith(".csv")
    second = exporter.write_reports(report, prefix="!!!")
    assert second["json_name"].startswith("config_leak_report_")
    assert second["json_name"] != written["json_name"]


def test_download_path_boundaries(tmp_path):
    exporter = ReportExporter(tmp_path)
    written = exporter.write_reports(build_report(), prefix="download")
    assert exporter.path_for_download(written["json_name"]) == tmp_path / written["json_name"]
    assert exporter.path_for_download(written["csv_name"]) is not None
    assert exporter.path_for_download("") is None
    assert exporter.path_for_download("../outside.json") is None
    assert exporter.path_for_download(str(tmp_path / written["json_name"])) is None
    assert exporter.path_for_download("notes.txt") is None
    assert exporter.path_for_download("missing.json") is None
