"""声明式 YAML 规则加载与匹配引擎。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

CATEGORIES = ("hardcoded_credential", "weak_security", "sensitive_info")
SEVERITIES = ("high", "medium", "low")
MATCH_TYPES = ("regex", "key", "range", "weak_password")
PAIR_RE = re.compile(r"^\s*(?:-\s*)?[\"']?([A-Za-z0-9_.-]+)[\"']?\s*[:=]\s*(.*?)\s*$")
XML_PAIR_RE = re.compile(r"<([A-Za-z_][\w.-]*)>\s*([^<]*?)\s*</\1>")
PLACEHOLDER_PATTERNS = (
    re.compile(r"^\$\{[^{}]+\}$"),
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\{\{[^{}]+\}\}$"),
    re.compile(r"^<[^<>]{1,80}>$"),
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),
)


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    description: str
    remediation: str
    match_type: str
    name: str = ""
    pattern: str = ""
    capture_group: int = 0
    value_pattern: str = ""
    keys: tuple[str, ...] = ()
    values: tuple[str, ...] = ()
    min_value: int | None = None
    max_value: int | None = None
    ignore_placeholder: bool = True
    source_file: str = ""
    _regex: re.Pattern[str] | None = field(default=None, repr=False)
    _value_regex: re.Pattern[str] | None = field(default=None, repr=False)


@dataclass
class RuleMatch:
    rule: Rule
    line: int
    value: str
    raw_line: str


def _clean_value(value: str) -> str:
    value = value.strip()
    if "#" in value and not value.startswith(("'", '"')):
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    value = value.rstrip(",").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.strip()


def is_placeholder_value(value: str) -> bool:
    """识别环境变量、模板占位符与空值，供误报过滤复用。"""
    value = _clean_value(value)
    if not value:
        return True
    if any(pattern.match(value) for pattern in PLACEHOLDER_PATTERNS):
        return True
    lowered = value.casefold()
    if lowered in {"changeme", "change_me", "placeholder", "todo", "none", "null", "nil"}:
        return True
    return lowered.startswith(("your_", "your-", "your ")) and len(value) < 80


def _iter_pairs(content: str) -> Iterator[tuple[str, str, int, str]]:
    for line_no, line in enumerate(content.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        for match in XML_PAIR_RE.finditer(line):
            value = _clean_value(match.group(2))
            if value:
                yield match.group(1), value, line_no, line
        match = PAIR_RE.match(line)
        if match:
            value = _clean_value(match.group(2))
            if value:
                yield match.group(1), value, line_no, line


def _extract_number(value: str) -> int | None:
    match = re.search(r"-?\d+", value)
    if not match:
        return None
    try:
        return int(match.group())
    except ValueError:
        return None


class RuleEngine:
    """从规则目录加载规则，并对纯文本目标执行只读匹配。"""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules: list[Rule] = []
        self.errors: list[str] = []
        self.rules_dir = Path(rules_dir) if rules_dir else None
        if self.rules_dir:
            self.load_rules()

    def load_rules(self) -> list[Rule]:
        self.rules = []
        self.errors = []
        if not self.rules_dir or not self.rules_dir.exists():
            self.errors.append(f"规则目录不存在: {self.rules_dir}")
            return []
        files = sorted(self.rules_dir.glob("*.yaml")) + sorted(self.rules_dir.glob("*.yml"))
        for path in files:
            self._load_file(path)
        return self.rules

    def _load_file(self, path: Path) -> None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            self.errors.append(f"{path.name}: 规则文件无法解析: {exc}")
            return
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            self.errors.append(f"{path.name}: 缺少 rules 列表")
            return
        category = data.get("category", "")
        known_ids = {rule.id for rule in self.rules}
        for index, raw in enumerate(data["rules"], start=1):
            if isinstance(raw, dict) and raw.get("enabled", True) is False:
                continue
            try:
                rule = self._build_rule(raw, category, path.name)
            except (ValueError, TypeError, re.error) as exc:
                self.errors.append(f"{path.name} 第{index}条: {exc}")
                continue
            if rule.id in known_ids:
                self.errors.append(f"{path.name}: 规则ID重复: {rule.id}")
                continue
            known_ids.add(rule.id)
            self.rules.append(rule)

    def _build_rule(self, raw: Any, default_category: str, source: str) -> Rule:
        if not isinstance(raw, dict):
            raise ValueError("规则必须是映射结构")
        rule_id = str(raw.get("id", "")).strip()
        category = str(raw.get("category", default_category)).strip()
        severity = str(raw.get("severity", "")).strip().lower()
        description = str(raw.get("description", "")).strip()
        remediation = str(raw.get("remediation", "")).strip()
        if not rule_id:
            raise ValueError("缺少 id")
        if category not in CATEGORIES:
            raise ValueError(f"category 必须是 {CATEGORIES} 之一")
        if severity not in SEVERITIES:
            raise ValueError("severity 必须是 high/medium/low")
        if not description or not remediation:
            raise ValueError("description 与 remediation 不能为空")
        match = raw.get("match")
        if not isinstance(match, dict):
            raise ValueError("缺少 match 映射")
        match_type = str(match.get("type", "")).strip()
        if match_type not in MATCH_TYPES:
            raise ValueError(f"match.type 必须是 {MATCH_TYPES} 之一")
        keys = match.get("keys", [])
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise ValueError("match.keys 必须是字符串列表")
        values = match.get("values", [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError("match.values 必须是字符串列表")
        pattern = str(match.get("pattern", ""))
        value_pattern = str(match.get("value_pattern", ""))
        if match_type == "regex" and not pattern:
            raise ValueError("正则规则缺少 pattern")
        if match_type in {"key", "range", "weak_password"} and not keys:
            raise ValueError("该规则缺少 keys")
        if match_type == "weak_password" and not values:
            raise ValueError("弱口令规则缺少 values")
        min_value = match.get("min_value")
        max_value = match.get("max_value")
        if min_value is not None:
            min_value = int(min_value)
        if max_value is not None:
            max_value = int(max_value)
        if match_type == "range" and min_value is None and max_value is None:
            raise ValueError("范围规则必须设置 min_value 或 max_value")
        compiled = re.compile(pattern) if pattern else None
        compiled_value = re.compile(value_pattern) if value_pattern else None
        return Rule(
            id=rule_id, category=category, severity=severity,
            description=description, remediation=remediation,
            match_type=match_type, name=str(raw.get("name", "")),
            pattern=pattern, capture_group=int(match.get("capture_group", 0)),
            value_pattern=value_pattern,
            keys=tuple(k.casefold() for k in keys),
            values=tuple(v.casefold() for v in values),
            min_value=min_value, max_value=max_value,
            ignore_placeholder=bool(match.get("ignore_placeholder", True)),
            source_file=source, _regex=compiled, _value_regex=compiled_value,
        )

    def get_rules(self, category: str | None = None) -> list[Rule]:
        if category is None:
            return list(self.rules)
        return [rule for rule in self.rules if rule.category == category]

    def scan(self, content: str, fmt: str = "conf") -> list[RuleMatch]:
        """扫描一段文本；fmt 用于保留调用语境，规则本身以文本行匹配。"""
        del fmt
        results: list[RuleMatch] = []
        for rule in self.rules:
            if rule.match_type == "regex":
                results.extend(self._match_regex(rule, content))
            else:
                results.extend(self._match_pairs(rule, content))
        return results

    def _match_regex(self, rule: Rule, content: str) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        seen: set[tuple[int, str]] = set()
        assert rule._regex is not None
        for line_no, line in enumerate(content.splitlines(), start=1):
            for found in rule._regex.finditer(line):
                try:
                    raw_value = found.group(rule.capture_group)
                except IndexError:
                    raw_value = found.group(0)
                value = _clean_value(raw_value or "")
                if not value:
                    continue
                if rule.ignore_placeholder and is_placeholder_value(value):
                    continue
                if rule._value_regex and not rule._value_regex.search(value):
                    continue
                key = (line_no, value)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(RuleMatch(rule, line_no, value, line))
        return matches

    def _match_pairs(self, rule: Rule, content: str) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        seen: set[tuple[int, str]] = set()
        weak_values = set(rule.values)
        for raw_key, value, line_no, line in _iter_pairs(content):
            if raw_key.casefold() not in rule.keys:
                continue
            if rule.ignore_placeholder and is_placeholder_value(value):
                continue
            if rule.match_type == "key":
                if rule._value_regex and not rule._value_regex.search(value):
                    continue
            elif rule.match_type == "range":
                number = _extract_number(value)
                if number is None:
                    continue
                if rule.min_value is not None and number < rule.min_value:
                    continue
                if rule.max_value is not None and number > rule.max_value:
                    continue
            elif rule.match_type == "weak_password":
                if value.casefold() not in weak_values:
                    continue
            dedupe_key = (line_no, value)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            matches.append(RuleMatch(rule, line_no, value, line))
        return matches
