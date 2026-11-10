"""检测结果聚合、去重、掩码与内存数据模型。"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime

from core.rule_engine import RuleMatch, SEVERITIES

SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


def mask_value(value: str) -> str:
    """仅保留前 2 位与后 1 位，短值全部替换。"""
    if not value:
        return ""
    if len(value) <= 3:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 3) + value[-1]


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Finding:
    file_path: str
    line: int
    matched_masked: str
    severity: str
    rule_id: str
    description: str
    remediation: str
    category: str
    rule_name: str = ""
    occurrences: int = 1
    line_numbers: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "matched_masked": self.matched_masked,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "description": self.description,
            "remediation": self.remediation,
            "category": self.category,
            "rule_name": self.rule_name,
            "occurrences": self.occurrences,
            "line_numbers": list(self.line_numbers),
        }


class ResultManager:
    """按文件、规则和原始匹配值聚合；原始敏感值不进入结果对象。"""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.skipped: list[dict[str, str]] = []
        self.total_files = 0
        self.scanned_files = 0
        self.rules_loaded = 0
        self.started_at = _now()
        self.finished_at: str | None = None
        self.duplicates_removed = 0
        self._index: dict[tuple[str, str, str], Finding] = {}
        self._lock = threading.RLock()

    def add_matches(self, file_path: str, matches: list[RuleMatch]) -> None:
        for match in matches:
            self.add_match(file_path, match)

    def add_match(self, file_path: str, match: RuleMatch) -> Finding:
        rule = match.rule
        raw_fingerprint = hashlib.sha256(match.value.encode("utf-8")).hexdigest()
        key = (file_path, rule.id, raw_fingerprint)
        with self._lock:
            existing = self._index.get(key)
            if existing:
                existing.occurrences += 1
                if match.line not in existing.line_numbers:
                    existing.line_numbers.append(match.line)
                self.duplicates_removed += 1
                return existing
            finding = Finding(
                file_path=file_path,
                line=match.line,
                matched_masked=mask_value(match.value),
                severity=rule.severity,
                rule_id=rule.id,
                description=rule.description,
                remediation=rule.remediation,
                category=rule.category,
                rule_name=rule.name,
                line_numbers=[match.line],
            )
            self._index[key] = finding
            self.findings.append(finding)
            return finding

    def add_skipped(self, path: str, reason: str) -> None:
        self.skipped.append({"file_path": path, "reason": reason})

    def finish(self) -> None:
        self.finished_at = _now()

    def severity_counts(self, findings: list[Finding] | None = None) -> dict[str, int]:
        source = self.findings if findings is None else findings
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in source:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def statistics(self, findings: list[Finding] | None = None) -> dict:
        source = self.findings if findings is None else findings
        counts = self.severity_counts(source)
        return {
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "skipped_files": len(self.skipped),
            "rules_loaded": self.rules_loaded,
            "total_findings": len(source),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "duplicates_removed": self.duplicates_removed,
        }

    def filtered(self, severity: str | None = None, rule_id: str | None = None,
                 category: str | None = None, path: str | None = None) -> list[Finding]:
        results = list(self.findings)
        if severity:
            wanted = severity.strip().lower()
            results = [f for f in results if f.severity == wanted]
        if rule_id:
            needle = rule_id.strip().casefold()
            results = [f for f in results if needle in f.rule_id.casefold()]
        if category:
            results = [f for f in results if f.category == category]
        if path:
            needle = path.strip().replace("\\", "/").casefold()
            results = [f for f in results if needle in f.file_path.casefold()]
        return self._sorted(results)

    @staticmethod
    def _sorted(findings: list[Finding]) -> list[Finding]:
        return sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line, f.rule_id),
        )

    def build_report(self, severity: str | None = None, rule_id: str | None = None,
                     category: str | None = None, path: str | None = None) -> dict:
        filters = {
            "severity": severity or "", "rule_id": rule_id or "",
            "category": category or "", "path": path or "",
        }
        has_filter = any(filters.values())
        findings = self.filtered(severity, rule_id, category, path) if has_filter else self._sorted(self.findings)
        return {
            "tool": "config-leak-checker",
            "tool_name": "配置漏检工具箱",
            "version": "1.0.0",
            "scan_time": self.started_at,
            "finished_at": self.finished_at or _now(),
            "statistics": self.statistics(findings),
            "filters": filters,
            "skipped": list(self.skipped),
            "findings": [finding.to_dict() for finding in findings],
        }

    def to_dict(self) -> dict:
        return self.build_report()
