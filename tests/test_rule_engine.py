"""规则加载、匹配类型与误报过滤测试。"""

from __future__ import annotations

import textwrap
from pathlib import Path

from core.rule_engine import RuleEngine, is_placeholder_value

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"


def write_rule(path: Path, body: str) -> Path:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def test_builtin_rules_load_with_all_categories_and_match_types():
    engine = RuleEngine(RULES)
    assert not engine.errors
    assert len(engine.rules) >= 30
    assert len({rule.id for rule in engine.rules}) == len(engine.rules)
    categories = {rule.category for rule in engine.rules}
    assert categories == {"hardcoded_credential", "weak_security", "sensitive_info"}
    match_types = {rule.match_type for rule in engine.rules}
    assert {"regex", "key", "range", "weak_password"} <= match_types
    for rule in engine.rules:
        assert rule.severity in {"high", "medium", "low"}
        assert rule.description and rule.remediation
    assert len(engine.get_rules("sensitive_info")) == 9
    assert engine.get_rules("missing") == []


def test_prefixed_credential_keys_and_placeholder_noise():
    engine = RuleEngine(RULES)
    content = "\n".join([
        "DB_PASSWORD=EnvSecret!2024", "admin_password: MiddlewarePass!2025",
        "openai_api_key=skFAKEopenai_12345678", "token: FAKEtoken1234567890",
        "password_min_length: 8", "token_type: bearer",
        "password: ${DB_PASSWORD}", "api_key: <API_KEY>",
    ])
    values = {(match.rule.id, match.value) for match in engine.scan(content)}
    assert {("HC-001", "EnvSecret!2024"), ("HC-001", "MiddlewarePass!2025")} <= values
    assert {("HC-002", "skFAKEopenai_12345678"), ("HC-010", "FAKEtoken1234567890")} <= values
    assert values.isdisjoint({("HC-001", "8"), ("HC-010", "bearer")})


def test_custom_rules_load_and_scan(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_rule(rules_dir / "custom.yml", """
        category: hardcoded_credential
        rules:
          - id: CUS-001
            severity: high
            description: 测试正则
            remediation: 移除
            match:
              type: regex
              pattern: '(?i)secret\\s*=\\s*(\\S+)'
              capture_group: 1
              value_pattern: '^[A-Za-z]'
          - id: CUS-002
            severity: medium
            description: 测试键名
            remediation: 关闭
            match:
              type: key
              keys: [debug]
              value_pattern: '^(?i:true)$'
          - id: CUS-003
            severity: low
            description: 测试范围
            remediation: 调整
            match:
              type: range
              keys: [count]
              min_value: 1
              max_value: 2
          - id: CUS-004
            severity: high
            description: 测试弱口令
            remediation: 更换
            match:
              type: weak_password
              keys: [pwd]
              values: [hunter2, letmein]
          - id: CUS-005
            enabled: false
            severity: high
            description: 禁用规则
            remediation: 无
            match:
              type: regex
              pattern: x
    """)
    engine = RuleEngine(rules_dir)
    assert not engine.errors
    assert [rule.id for rule in engine.rules] == ["CUS-001", "CUS-002", "CUS-003", "CUS-004"]
    content = "\n".join([
        "secret = alphaSecret",
        "secret = ${PLACEHOLDER}",
        "DEBUG: true",
        "count: 2",
        "pwd: HUNTER2",
        "pwd: ${PWD}",
    ])
    matches = engine.scan(content, "yaml")
    ids = [match.rule.id for match in matches]
    assert ids.count("CUS-001") == 1
    assert "CUS-002" in ids and "CUS-003" in ids and "CUS-004" in ids
    assert all(match.value != "${PLACEHOLDER}" for match in matches)


def test_placeholder_detection():
    for value in ["", '""', "${DB_PWD}", "$DB_PWD", "{{TOKEN}}", "<YOUR_API_KEY>", "%PWD%", "changeme", "your-key"]:
        assert is_placeholder_value(value), value
    for value in ["realSecret1!", "admin123", "127.0.0.1"]:
        assert not is_placeholder_value(value), value


def test_regex_capture_fallback_and_dedupe(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_rule(rules_dir / "fallback.yaml", """
        category: sensitive_info
        rules:
          - id: FB-001
            severity: low
            description: 回退分组
            remediation: 无
            match:
              type: regex
              pattern: 'token-[0-9]+'
              capture_group: 9
          - id: FB-002
            severity: low
            description: 值正则过滤
            remediation: 无
            match:
              type: regex
              pattern: 'value-(\\w+)'
              capture_group: 1
              value_pattern: '^NOPE$'
    """)
    engine = RuleEngine(rules_dir)
    matches = engine.scan("token-123 token-123\ntoken-456\nvalue-real\n")
    assert len(matches) == 2
    assert [match.value for match in matches] == ["token-123", "token-456"]


def test_key_range_and_weak_password_boundaries(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_rule(rules_dir / "values.yaml", """
        category: weak_security
        rules:
          - id: B-001
            severity: medium
            description: 范围
            remediation: 调整
            match:
              type: range
              keys: [limit]
              min_value: 5
              max_value: 10
          - id: B-002
            severity: high
            description: 弱口令
            remediation: 更换
            match:
              type: weak_password
              keys: [password]
              values: [Welcome1]
    """)
    engine = RuleEngine(rules_dir)
    content = "limit: 4\nlimit: 5\nlimit: 10\nlimit: 11\nlimit: abc\npassword: welcome1\n"
    matches = engine.scan(content)
    lines = [match.line for match in matches]
    assert lines == [2, 3, 6]
    assert matches[-1].value == "welcome1"


def test_invalid_rules_are_reported_without_crashing(tmp_path):
    rules_dir = tmp_path / "bad_rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yaml").write_text("rules: [", encoding="utf-8")
    (rules_dir / "no_list.yaml").write_text("category: weak_security\n", encoding="utf-8")
    write_rule(rules_dir / "invalid.yaml", """
        category: weak_security
        rules:
          - not-a-mapping
          - id: BAD-01
            severity: high
            description: 无 match
            remediation: 无
          - id: BAD-02
            category: unknown
            severity: high
            description: 类别错误
            remediation: 无
            match: {type: regex, pattern: x}
          - id: BAD-03
            severity: critical
            description: 等级错误
            remediation: 无
            match: {type: regex, pattern: x}
          - id: BAD-04
            severity: high
            description: 缺修复
            match: {type: regex, pattern: x}
          - id: BAD-05
            severity: high
            description: 类型错误
            remediation: 无
            match: {type: unknown}
          - id: BAD-06
            severity: high
            description: 缺正则
            remediation: 无
            match: {type: regex}
          - id: BAD-07
            severity: high
            description: 缺键
            remediation: 无
            match: {type: key}
          - id: BAD-08
            severity: high
            description: 缺弱口令字典
            remediation: 无
            match: {type: weak_password, keys: [pwd]}
          - id: BAD-09
            severity: high
            description: 正则错误
            remediation: 无
            match: {type: regex, pattern: "("}
          - id: BAD-10
            severity: high
            description: 范围缺边界
            remediation: 无
            match: {type: range, keys: [x]}
          - id: BAD-11
            severity: high
            description: 键类型错误
            remediation: 无
            match: {type: key, keys: 1}
          - id: BAD-12
            severity: high
            description: 值类型错误
            remediation: 无
            match: {type: weak_password, keys: [x], values: 1}
          - id: BAD-13
            severity: high
            description: 边界非数字
            remediation: 无
            match: {type: range, keys: [x], min_value: nope}
          - id: DUP-01
            severity: low
            description: 重复一
            remediation: 无
            match: {type: regex, pattern: a}
          - id: DUP-01
            severity: low
            description: 重复二
            remediation: 无
            match: {type: regex, pattern: b}
    """)
    engine = RuleEngine(rules_dir)
    assert len(engine.errors) >= 14
    assert len(engine.rules) == 1
    assert engine.rules[0].id == "DUP-01"


def test_missing_rules_directory_and_no_directory():
    engine = RuleEngine(RULES / "does-not-exist")
    assert engine.rules == []
    assert "不存在" in engine.errors[0]
    assert RuleEngine().rules == []


def test_xml_key_matching(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_rule(rules_dir / "xml.yaml", """
        category: weak_security
        rules:
          - id: XML-001
            severity: high
            description: XML 认证关闭
            remediation: 开启
            match:
              type: key
              keys: [admin_auth]
              value_pattern: '^(?i:false)$'
    """)
    engine = RuleEngine(rules_dir)
    matches = engine.scan("<config><admin_auth>false</admin_auth></config>")
    assert len(matches) == 1
    assert matches[0].value == "false"
