"""本地 JSON 与 CSV 报告生成，不包含任何外发逻辑。"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path

CSV_FIELDS = [
    "record_type", "scan_time", "finished_at", "total_files", "scanned_files",
    "skipped_files", "rules_loaded", "high", "medium", "low", "total_findings",
    "duplicates_removed", "file_path", "line", "line_numbers", "severity",
    "rule_id", "rule_name", "category", "matched_masked", "description",
    "remediation", "occurrences",
]


class ReportExporter:
    """将内存报告写入本地 output 目录，并限制下载文件名。"""

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_reports(self, report: dict, prefix: str = "config_leak_report") -> dict:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base = f"{self._safe_prefix(prefix)}_{timestamp}"
        json_path = self.output_dir / f"{base}.json"
        csv_path = self.output_dir / f"{base}.csv"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        self._write_csv(csv_path, report)
        return {
            "json": str(json_path),
            "csv": str(csv_path),
            "json_name": json_path.name,
            "csv_name": csv_path.name,
            "base": base,
        }

    @staticmethod
    def _safe_prefix(prefix: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", prefix).strip("._")
        return (cleaned or "config_leak_report")[:80]

    def _write_csv(self, path: Path, report: dict) -> None:
        stats = report.get("statistics", {})
        common = {
            "scan_time": report.get("scan_time", ""),
            "finished_at": report.get("finished_at", ""),
            "total_files": stats.get("total_files", 0),
            "scanned_files": stats.get("scanned_files", 0),
            "skipped_files": stats.get("skipped_files", 0),
            "rules_loaded": stats.get("rules_loaded", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "total_findings": stats.get("total_findings", 0),
            "duplicates_removed": stats.get("duplicates_removed", 0),
        }
        findings = report.get("findings", [])
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            if not findings:
                writer.writerow({**common, "record_type": "summary"})
                return
            for finding in findings:
                row = {**common, "record_type": "finding", **finding}
                row["line_numbers"] = ",".join(str(n) for n in finding.get("line_numbers", []))
                writer.writerow({key: row.get(key, "") for key in CSV_FIELDS})

    def path_for_download(self, name: str) -> Path | None:
        """仅允许下载 output 目录内、由本工具生成的报告文件。"""
        if not name or Path(name).name != name or not name.lower().endswith((".json", ".csv")):
            return None
        candidate = (self.output_dir / name).resolve()
        try:
            candidate.relative_to(self.output_dir)
        except ValueError:
            return None
        return candidate if candidate.is_file() else None
