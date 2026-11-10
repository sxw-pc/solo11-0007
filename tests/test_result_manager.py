"""结果聚合、去重、掩码、筛选与统计测试。"""

from __future__ import annotations

from core.result_manager import ResultManager, mask_value
from core.rule_engine import Rule, RuleMatch


def make_rule(rule_id="HC-001", severity="high", category="hardcoded_credential"):
    return Rule(
        id=rule_id,
        category=category,
        severity=severity,
        description="测试风险",
        remediation="移除风险",
        match_type="regex",
        name="测试规则",
    )


def make_match(value="SuperSecret123!", line=1, rule=None):
    rule = rule or make_rule()
    return RuleMatch(rule=rule, line=line, value=value, raw_line=f"password: {value}")


def test_mask_value():
    assert mask_value("") == ""
    assert mask_value("ab") == "**"
    assert mask_value("abc") == "***"
    assert mask_value("abcd") == "ab*d"
    assert mask_value("SuperSecret123!") == "Su************!"
    assert "Secret" not in mask_value("SuperSecret123!")


def test_aggregation_and_deduplication():
    manager = ResultManager()
    rule = make_rule()
    manager.add_match("app.yaml", make_match(line=2, rule=rule))
    duplicate = manager.add_match("app.yaml", make_match(line=9, rule=rule))
    manager.add_match("app.yaml", make_match("OtherSecret!456", line=4, rule=rule))
    manager.add_match("app.env", make_match(line=2, rule=rule))
    manager.add_match("app.yaml", make_match("SuperSecret123!", line=6, rule=make_rule("WS-014")))
    assert len(manager.findings) == 4
    assert manager.duplicates_removed == 1
    assert duplicate.occurrences == 2
    assert duplicate.line_numbers == [2, 9]
    assert duplicate.line == 2
    assert "SuperSecret123!" not in repr(duplicate)
    assert manager.findings[0].matched_masked.startswith("Su")


def test_statistics_and_filters():
    manager = ResultManager()
    manager.total_files = 10
    manager.scanned_files = 8
    manager.rules_loaded = 43
    manager.add_skipped("empty.yaml", "空文件")
    manager.add_skipped("bad.zip", "损坏")
    manager.add_matches("dir/app.yaml", [
        make_match("HighSecret!", 3, make_rule("HC-001", "high")),
    ])
    manager.add_matches("dir/app.env", [
        make_match("mediumsecret", 2, make_rule("SI-001", "medium", "sensitive_info")),
    ])
    manager.add_matches("archive.zip!/x.conf", [
        make_match("lowsecret", 5, make_rule("SI-006", "low", "sensitive_info")),
    ])
    stats = manager.statistics()
    assert stats["total_files"] == 10
    assert stats["scanned_files"] == 8
    assert stats["skipped_files"] == 2
    assert stats["rules_loaded"] == 43
    assert stats["total_findings"] == 3
    assert (stats["high"], stats["medium"], stats["low"]) == (1, 1, 1)

    assert len(manager.filtered(severity="high")) == 1
    assert len(manager.filtered(rule_id="si-")) == 2
    assert len(manager.filtered(category="sensitive_info")) == 2
    assert len(manager.filtered(path="ARCHIVE")) == 1
    assert len(manager.filtered(path="dir\\")) == 2
    assert manager.filtered(severity="missing") == []
    assert len(manager.filtered(severity="low", category="sensitive_info", path="archive")) == 1
    assert len(manager.filtered(severity="high", category="sensitive_info")) == 0


def test_report_structure_filters_and_sorting():
    manager = ResultManager()
    manager.total_files = 4
    manager.scanned_files = 3
    manager.rules_loaded = 43
    manager.add_skipped("empty.yaml", "空文件")
    manager.add_matches("b.yaml", [
        make_match("LowSecret!", 8, make_rule("SI-006", "low", "sensitive_info")),
        make_match("HighSecret!", 2, make_rule("HC-001", "high")),
    ])
    manager.add_matches("a.yaml", [
        make_match("MidSecret!", 1, make_rule("WS-010", "medium", "weak_security")),
    ])
    manager.finish()
    report = manager.build_report()
    assert report["scan_time"]
    assert report["finished_at"]
    assert report["statistics"]["total_findings"] == 3
    assert [f["severity"] for f in report["findings"]] == ["high", "medium", "low"]
    assert report["skipped"] == [{"file_path": "empty.yaml", "reason": "空文件"}]
    assert report["filters"] == {"severity": "", "rule_id": "", "category": "", "path": ""}
    assert "HighSecret!" not in str(report)
    assert report["findings"][0]["remediation"] == "移除风险"

    filtered = manager.build_report(severity="high", path="b.yaml")
    assert filtered["statistics"]["total_findings"] == 1
    assert filtered["statistics"]["high"] == 1
    assert filtered["filters"]["severity"] == "high"
    assert filtered["findings"][0]["rule_id"] == "HC-001"
    assert manager.to_dict()["statistics"]["total_findings"] == 3
