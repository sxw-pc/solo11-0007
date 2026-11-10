"""仅绑定回环地址的本地 HTTP 服务；无任何外部网络请求。"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from core.file_loader import FileLoader
from core.report_exporter import ReportExporter
from core.result_manager import ResultManager
from core.rule_engine import RuleEngine

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
MAX_BODY = 64 * 1024


@dataclass
class ScanJob:
    job_id: str
    path: str
    status: str = "queued"
    progress: int = 0
    message: str = "等待开始"
    error: str = ""
    rule_count: int = 0
    manager: ResultManager | None = None
    reports: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class AppContext:
    """保存本地路径配置、规则目录与内存中的检测任务。"""

    def __init__(self, base_dir: str | Path | None = None,
                 rules_dir: str | Path | None = None,
                 output_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir or BASE_DIR).resolve()
        self.rules_dir = Path(rules_dir or self.base_dir / "rules").resolve()
        self.output_dir = Path(output_dir or self.base_dir / "output").resolve()
        self.web_dir = self.base_dir / "web"
        self.jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()

    def create_job(self, path_value: str) -> ScanJob:
        job = ScanJob(job_id=uuid.uuid4().hex, path=path_value)
        with self._lock:
            self.jobs[job.job_id] = job
        threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
        return job

    def get_job(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self.jobs.get(job_id)

    def _run_job(self, job: ScanJob) -> None:
        try:
            job.status, job.progress, job.message = "loading", 3, "正在加载规则与文件"
            engine = RuleEngine(self.rules_dir)
            job.rule_count = len(engine.rules)
            job.warnings = list(engine.errors)
            if not engine.rules:
                raise RuntimeError("未加载到任何有效检测规则，请检查 rules 目录")
            scan_path = Path(job.path).expanduser()
            if not scan_path.is_absolute():
                scan_path = self.base_dir / scan_path
            loaded = FileLoader().scan(str(scan_path))
            manager = ResultManager()
            manager.total_files = loaded.files_seen
            manager.scanned_files = len(loaded.targets)
            manager.rules_loaded = len(engine.rules)
            for skipped in loaded.skipped:
                manager.add_skipped(skipped.path, skipped.reason)
            job.manager = manager
            job.status, job.progress, job.message = "scanning", 8, "正在执行静态规则匹配"
            total = max(len(loaded.targets), 1)
            for index, target in enumerate(loaded.targets, start=1):
                manager.add_matches(target.display_path, engine.scan(target.content, target.format))
                job.progress = 8 + int(index / total * 87)
                job.message = f"正在检测 {index}/{len(loaded.targets)} 个文件"
            manager.finish()
            exporter = ReportExporter(self.output_dir)
            written = exporter.write_reports(manager.build_report())
            job.reports = {
                "json_name": written["json_name"], "csv_name": written["csv_name"],
            }
            job.status, job.progress = "completed", 100
            job.message = f"检测完成，共发现 {len(manager.findings)} 条风险"
        except Exception as exc:  # 本地任务异常需回传给界面，不中断服务
            job.status, job.progress = "failed", 100
            job.error = str(exc)
            job.message = f"检测失败: {exc}"

    def job_payload(self, job: ScanJob) -> dict:
        stats = job.manager.statistics() if job.manager else None
        return {
            "job_id": job.job_id, "path": job.path, "status": job.status,
            "progress": job.progress, "message": job.message, "error": job.error,
            "rule_count": job.rule_count, "warnings": list(job.warnings),
            "statistics": stats, "reports": dict(job.reports),
        }

    def rule_payload(self) -> dict:
        engine = RuleEngine(self.rules_dir)
        rules = [
            {
                "id": rule.id, "name": rule.name, "category": rule.category,
                "severity": rule.severity, "match_type": rule.match_type,
                "description": rule.description, "remediation": rule.remediation,
            }
            for rule in engine.rules
        ]
        return {"count": len(rules), "rules": rules, "errors": engine.errors}


def create_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                  context: AppContext | None = None) -> ThreadingHTTPServer:
    if host != DEFAULT_HOST:
        raise ValueError("服务仅允许监听 127.0.0.1")
    ctx = context or AppContext()

    class LocalHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Handler(BaseHTTPRequestHandler):
        server_version = "ConfigLeakChecker/1.0"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            del fmt, args

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            if parsed.path in {"/api/rules"}:
                self._json(200, ctx.rule_payload())
            elif parsed.path == "/api/progress":
                self._progress(query)
            elif parsed.path == "/api/results":
                self._results(query)
            elif parsed.path == "/api/export":
                self._export(query)
            elif parsed.path == "/api/download":
                self._download(query)
            elif parsed.path == "/api/health":
                self._json(200, {"status": "ok", "offline": True, "host": DEFAULT_HOST})
            elif parsed.path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif parsed.path in STATIC_FILES:
                name, content_type = STATIC_FILES[parsed.path]
                self._static(name, content_type)
            else:
                self._json(404, {"error": "接口或文件不存在"})

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/api/scan":
                length = self.headers.get("Content-Length", "0")
                self.rfile.read(min(int(length) if length.isdigit() else 0, MAX_BODY))
                self._json(404, {"error": "接口不存在"})
                return
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            path_value = str(payload.get("path", "")).strip()
            if not path_value:
                self._json(400, {"error": "请提供本地文件或目录路径"})
                return
            job = ctx.create_job(path_value)
            self._json(202, ctx.job_payload(job))

        def _read_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length 无效") from exc
            if length <= 0 or length > MAX_BODY:
                raise ValueError("请求体为空或超过大小限制")
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("请求体必须是 UTF-8 JSON") from exc
            if not isinstance(data, dict):
                raise ValueError("请求体必须是 JSON 对象")
            return data

        def _job_from_query(self, query: dict) -> ScanJob | None:
            job_id = query.get("job_id", [""])[0]
            job = ctx.get_job(job_id)
            if job is None:
                self._json(404, {"error": "检测任务不存在或已过期"})
            return job

        def _progress(self, query: dict) -> None:
            job = self._job_from_query(query)
            if job:
                self._json(200, ctx.job_payload(job))

        def _results(self, query: dict) -> None:
            job = self._job_from_query(query)
            if not job:
                return
            if job.status != "completed" or job.manager is None:
                self._json(409, {"error": "检测尚未完成", "job": ctx.job_payload(job)})
                return
            report = job.manager.build_report(
                severity=query.get("severity", [""])[0],
                rule_id=query.get("rule_id", [""])[0],
                category=query.get("category", [""])[0],
                path=query.get("path", [""])[0],
            )
            report["job"] = ctx.job_payload(job)
            self._json(200, report)

        def _export(self, query: dict) -> None:
            job = self._job_from_query(query)
            if not job:
                return
            if job.status != "completed" or job.manager is None:
                self._json(409, {"error": "检测尚未完成"})
                return
            fmt = query.get("format", ["json"])[0].lower()
            if fmt not in {"json", "csv"}:
                self._json(400, {"error": "format 仅支持 json 或 csv"})
                return
            severity = query.get("severity", [""])[0]
            rule_id = query.get("rule_id", [""])[0]
            category = query.get("category", [""])[0]
            path_value = query.get("path", [""])[0]
            report = job.manager.build_report(severity, rule_id, category, path_value)
            report["export_type"] = "filtered" if any([severity, rule_id, category, path_value]) else "full"
            parts = ["config_leak", "filtered", severity or "all", category or "all"]
            written = ReportExporter(ctx.output_dir).write_reports(report, "_".join(parts))
            self._serve_path(Path(written[fmt]), download=True)

        def _download(self, query: dict) -> None:
            job = self._job_from_query(query)
            if not job:
                return
            fmt = query.get("format", ["json"])[0].lower()
            name = job.reports.get(f"{fmt}_name", "")
            exporter = ReportExporter(ctx.output_dir)
            path = exporter.path_for_download(name)
            if not path:
                self._json(404, {"error": "报告不存在或尚未生成"})
                return
            self._serve_path(path, download=True)

        def _static(self, name: str, content_type: str) -> None:
            path = (ctx.web_dir / name).resolve()
            if not path.is_file():
                self._json(404, {"error": "静态资源不存在"})
                return
            self._send(200, path.read_bytes(), content_type)

        def _serve_path(self, path: Path, download: bool = False) -> None:
            if not path.is_file():
                self._json(404, {"error": "文件不存在"})
                return
            content_type = "application/json; charset=utf-8" if path.suffix == ".json" else "text/csv; charset=utf-8"
            self._send(200, path.read_bytes(), content_type, download_name=path.name if download else None)

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _send(self, status: int, body: bytes, content_type: str,
                  download_name: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            )
            self.send_header("Cache-Control", "no-store")
            if download_name:
                self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.end_headers()
            if body:
                self.wfile.write(body)

    return LocalHTTPServer((DEFAULT_HOST, port), Handler)
