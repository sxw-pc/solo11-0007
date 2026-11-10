"""本地文件识别、解析、归档解包与固件明文片段提取。"""

from __future__ import annotations

import configparser
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

import tomli
import yaml

CONFIG_FORMATS = {
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "ini",
    ".conf": "conf", ".env": "env", ".json": "json", ".xml": "xml",
}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")
FIRMWARE_SUFFIXES = (".bin", ".img", ".fw")
FW_BEGIN = b"# FW-CONFIG-BEGIN"
FW_END = b"# FW-CONFIG-END"
PAIR_RE = re.compile(r"^\s*(?:-\s*)?[\"']?([A-Za-z0-9_.-]+)[\"']?\s*[:=]\s*(.*?)\s*$")


@dataclass
class ScanTarget:
    """一个可交给规则引擎检测的文本目标。"""

    display_path: str
    content: str
    format: str
    source: str = "file"


@dataclass
class SkippedFile:
    """无法解析或不在支持范围内的文件。"""

    path: str
    reason: str


@dataclass
class LoadResult:
    """一次路径加载的完整结果。"""

    targets: list[ScanTarget] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    files_seen: int = 0


def detect_format(filename: str) -> str | None:
    """按文件名识别配置、归档和固件类型。"""
    name = filename.lower()
    if name.endswith(ARCHIVE_SUFFIXES):
        return "archive"
    if name == ".env" or name.endswith(".env"):
        return "env"
    suffix = Path(name).suffix
    if suffix in CONFIG_FORMATS:
        return CONFIG_FORMATS[suffix]
    if suffix in FIRMWARE_SUFFIXES:
        return "firmware"
    return None


def parse_config(content: str, fmt: str):
    """解析支持的配置格式；解析失败时抛出异常。"""
    if not content.strip():
        raise ValueError("空文件")
    if "\x00" in content:
        raise ValueError("二进制内容无法按文本解析")
    if fmt == "yaml":
        documents = list(yaml.safe_load_all(content))
        return documents[0] if len(documents) == 1 else documents
    if fmt == "toml":
        return tomli.loads(content)
    if fmt == "json":
        return json.loads(content)
    if fmt == "xml":
        return ElementTree.fromstring(content)
    if fmt == "ini":
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(content)
        except configparser.MissingSectionHeaderError:
            return _parse_pairs(content)
        return parser
    if fmt in {"env", "conf"}:
        return _parse_pairs(content)
    raise ValueError(f"不支持的配置格式: {fmt}")


def _parse_pairs(content: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for line in content.splitlines():
        match = PAIR_RE.match(line)
        if match and not line.lstrip().startswith("#"):
            pairs[match.group(1)] = match.group(2).strip().strip("\"'")
    return pairs


def _relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base)).replace("\\", "/")
    except ValueError:
        return path.name


def _safe_member(name: str) -> str:
    parts = []
    for part in name.replace("\\", "/").split("/"):
        if part not in {"", ".", ".."}:
            parts.append(part)
    return "/".join(parts) or "unnamed"


class FileLoader:
    """只读访问本地路径，不跟随归档内部路径写盘。"""

    def __init__(self, max_file_bytes: int = 2 * 1024 * 1024,
                 max_archive_entries: int = 200) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_archive_entries = max_archive_entries

    def scan(self, path_value: str) -> LoadResult:
        """扫描显式指定文件或目录，跳过异常文件而不中断。"""
        if not path_value or not str(path_value).strip():
            raise ValueError("检测路径不能为空")
        value = str(path_value).strip()
        if value.startswith(("\\\\", "//")) or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
            raise ValueError("仅支持本地文件路径，不支持 UNC 或 URL 路径")
        root = Path(value).expanduser()
        if not root.exists():
            raise FileNotFoundError(f"路径不存在: {root}")
        result = LoadResult()
        if root.is_file():
            result.files_seen += 1
            self._process_path(root, root.name, result)
            return result
        if not root.is_dir():
            raise ValueError("仅支持普通文件或目录")
        try:
            candidates = sorted(root.rglob("*"))
        except OSError as exc:
            result.skipped.append(SkippedFile(str(root), f"目录遍历失败: {exc}"))
            return result
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            result.files_seen += 1
            self._process_path(path, _relative(path, root), result)
        return result

    def _process_path(self, path: Path, display: str, result: LoadResult) -> None:
        kind = detect_format(path.name)
        if kind == "archive":
            self._scan_archive(path, display, result)
        elif kind == "firmware":
            self._scan_firmware(path, display, result)
        elif kind and kind in CONFIG_FORMATS.values():
            try:
                raw = self._read_limited(path)
            except (OSError, ValueError) as exc:
                result.skipped.append(SkippedFile(display, f"读取失败: {exc}"))
                return
            self._add_target(raw, display, kind, "file", result)
        else:
            result.skipped.append(SkippedFile(display, "不支持的文件格式"))

    def _read_limited(self, path: Path) -> bytes:
        if path.stat().st_size > self.max_file_bytes:
            raise ValueError("文件超过大小上限")
        return path.read_bytes()

    def _add_target(self, raw: bytes, display: str, fmt: str,
                    source: str, result: LoadResult) -> None:
        if len(raw) > self.max_file_bytes:
            result.skipped.append(SkippedFile(display, "文件超过大小上限"))
            return
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            result.skipped.append(SkippedFile(display, "无法按 UTF-8 解码"))
            return
        if not content.strip():
            result.skipped.append(SkippedFile(display, "空文件"))
            return
        try:
            parse_config(content, fmt)
        except Exception as exc:  # 第三方解析器异常类型较多，统一记录
            result.skipped.append(SkippedFile(display, f"损坏或无法解析: {exc}"))
            return
        result.targets.append(ScanTarget(display, content, fmt, source))

    def _scan_archive(self, path: Path, display: str, result: LoadResult) -> None:
        try:
            if path.name.lower().endswith(".zip"):
                self._scan_zip(path, display, result)
            else:
                self._scan_tar(path, display, result)
        except Exception as exc:  # 归档格式多样，任何本地读取异常都只跳过该包
            result.skipped.append(SkippedFile(display, f"损坏或无法读取的归档包: {exc}"))

    def _scan_zip(self, path: Path, display: str, result: LoadResult) -> None:
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.infolist()):
                if info.is_dir():
                    continue
                if index >= self.max_archive_entries:
                    result.skipped.append(SkippedFile(display, "归档条目超过上限"))
                    break
                result.files_seen += 1
                member = f"{display}!/{_safe_member(info.filename)}"
                if info.flag_bits & 0x1:
                    result.skipped.append(SkippedFile(member, "加密归档条目"))
                    continue
                kind = detect_format(info.filename)
                if kind not in CONFIG_FORMATS.values():
                    result.skipped.append(SkippedFile(member, "归档内非配置文件"))
                    continue
                if info.file_size > self.max_file_bytes:
                    result.skipped.append(SkippedFile(member, "归档条目超过大小上限"))
                    continue
                try:
                    raw = archive.read(info)[:self.max_file_bytes + 1]
                except Exception as exc:
                    result.skipped.append(SkippedFile(member, f"归档条目读取失败: {exc}"))
                    continue
                self._add_target(raw, member, kind, "archive", result)

    def _scan_tar(self, path: Path, display: str, result: LoadResult) -> None:
        with tarfile.open(path, "r:*") as archive:
            members = [m for m in archive.getmembers() if m.isfile()]
            for index, info in enumerate(members):
                if index >= self.max_archive_entries:
                    result.skipped.append(SkippedFile(display, "归档条目超过上限"))
                    break
                result.files_seen += 1
                member = f"{display}!/{_safe_member(info.name)}"
                kind = detect_format(info.name)
                if kind not in CONFIG_FORMATS.values():
                    result.skipped.append(SkippedFile(member, "归档内非配置文件"))
                    continue
                if info.size > self.max_file_bytes:
                    result.skipped.append(SkippedFile(member, "归档条目超过大小上限"))
                    continue
                handle = archive.extractfile(info)
                if handle is None:
                    result.skipped.append(SkippedFile(member, "归档条目无法读取"))
                    continue
                try:
                    raw = handle.read(self.max_file_bytes + 1)
                except OSError as exc:
                    result.skipped.append(SkippedFile(member, f"归档条目读取失败: {exc}"))
                    continue
                self._add_target(raw, member, kind, "archive", result)

    def _scan_firmware(self, path: Path, display: str, result: LoadResult) -> None:
        try:
            raw = self._read_limited(path)
        except (OSError, ValueError) as exc:
            result.skipped.append(SkippedFile(display, f"固件读取失败: {exc}"))
            return
        begin = raw.find(FW_BEGIN)
        end = raw.find(FW_END, begin + 1) if begin >= 0 else -1
        if begin < 0 or end < 0:
            result.skipped.append(SkippedFile(display, "未发现明文配置特征头"))
            return
        fragment = raw[begin + len(FW_BEGIN):end].strip()
        self._add_target(fragment, f"{display}#config", "conf", "firmware", result)
