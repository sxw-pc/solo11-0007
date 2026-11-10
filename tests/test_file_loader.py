"""文件识别、解析、归档与固件提取测试。"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from core.file_loader import (
    FileLoader, ScanTarget, detect_format, parse_config,
)

ROOT = Path(__file__).resolve().parents[1]
NORMAL = ROOT / "fixtures" / "normal_samples"
ARCHIVES = ROOT / "fixtures" / "archive_samples"
FIRMWARE = ROOT / "fixtures" / "firmware_samples"


@pytest.mark.parametrize("name,expected", [
    ("a.yaml", "yaml"), ("a.yml", "yaml"), ("a.toml", "toml"),
    ("a.ini", "ini"), ("a.conf", "conf"), ("a.env", "env"),
    (".env", "env"), ("a.json", "json"), ("a.xml", "xml"),
    ("a.zip", "archive"), ("a.tar.gz", "archive"), ("a.tar.bz2", "archive"),
    ("a.tgz", "archive"), ("a.bin", "firmware"), ("a.img", "firmware"),
    ("a.txt", None), ("README", None),
])
def test_detect_format(name, expected):
    assert detect_format(name) == expected


def test_parse_supported_formats():
    assert parse_config("a: 1\n", "yaml") == {"a": 1}
    assert parse_config("---\na: 1\n---\nb: 2\n", "yaml") == [{"a": 1}, {"b": 2}]
    assert parse_config("name = 'demo'\n", "toml")["name"] == "demo"
    assert parse_config('{"a": 1}', "json") == {"a": 1}
    assert parse_config("<root><a>1</a></root>", "xml").tag == "root"
    assert parse_config("[db]\npassword=x\n", "ini").get("db", "password") == "x"
    assert parse_config("password=x\n# comment\n", "ini") == {"password": "x"}
    assert parse_config("A=1\nB=two\n", "env") == {"A": "1", "B": "two"}
    assert parse_config("server { listen 80; }", "conf") == {}


@pytest.mark.parametrize("content,fmt", [
    ("", "yaml"), ("\x00\x01", "json"), ("{bad", "json"),
    ("not a toml", "toml"), ("<root>", "xml"), ("key=x", "unknown"),
])
def test_parse_invalid_raises(content, fmt):
    with pytest.raises(Exception):
        parse_config(content, fmt)


def test_scan_single_file(tmp_path):
    path = tmp_path / "one.yaml"
    path.write_text("debug: false\n", encoding="utf-8")
    result = FileLoader().scan(str(path))
    assert result.files_seen == 1
    assert len(result.targets) == 1
    assert isinstance(result.targets[0], ScanTarget)
    assert result.targets[0].display_path == "one.yaml"
    assert result.targets[0].format == "yaml"
    assert result.targets[0].source == "file"


def test_scan_normal_directory_and_invalid_inputs(tmp_path):
    result = FileLoader().scan(str(NORMAL))
    assert len(result.targets) == 7
    assert len(result.skipped) == 1
    assert result.skipped[0].path == "empty.yaml"
    assert FileLoader().scan(str(NORMAL / "app.yaml")).targets[0].display_path == "app.yaml"
    with pytest.raises(ValueError):
        FileLoader().scan("")
    with pytest.raises(FileNotFoundError):
        FileLoader().scan(str(tmp_path / "missing"))
    for remote in ("\\\\server\\share\\config.yaml", "//server/share/config.yaml",
                   "https://example.test/config.yaml"):
        with pytest.raises(ValueError, match="本地"):
            FileLoader().scan(remote)

    unsupported = tmp_path / "notes.txt"
    unsupported.write_text("hello", encoding="utf-8")
    binary = tmp_path / "bad.yaml"
    binary.write_bytes(b"\xff\xfe\x00\x00")
    result = FileLoader().scan(str(tmp_path))
    reasons = {item.path: item.reason for item in result.skipped}
    assert reasons["notes.txt"] == "不支持的文件格式"
    assert "UTF-8" in reasons["bad.yaml"]


def test_oversized_file_is_skipped(tmp_path):
    path = tmp_path / "big.yaml"
    path.write_text("a: 123456789\n", encoding="utf-8")
    result = FileLoader(max_file_bytes=4).scan(str(path))
    assert not result.targets
    assert "上限" in result.skipped[0].reason


def test_archive_fixtures():
    result = FileLoader().scan(str(ARCHIVES))
    paths = {target.display_path for target in result.targets}
    skipped = {item.path: item.reason for item in result.skipped}
    assert "backup.zip!/backup/app.yaml" in paths
    assert "backup.tar.gz!/config/archive.ini" in paths
    assert "backup.tar.bz2!/config/cloud.conf" in paths
    assert "backup.zip!/backup/readme.txt" in skipped
    assert "backup.tar.gz!/config/notes.txt" in skipped
    assert "damaged.zip" in skipped
    assert "损坏" in skipped["damaged.zip"]


def test_zip_limits_encryption_and_member_path(tmp_path):
    target = tmp_path / "members.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("../escape.yaml", "password: fake\n")
        archive.writestr("huge.yaml", "x" * 100)
        archive.writestr("second.yaml", "a: 1\n")
    result = FileLoader(max_archive_entries=1).scan(str(target))
    assert [item.display_path for item in result.targets] == ["members.zip!/escape.yaml"]
    assert any("超过上限" in item.reason for item in result.skipped)

    limited = FileLoader(max_archive_entries=10, max_file_bytes=10).scan(str(target))
    assert all("!" in item.path and ".." not in item.path for item in limited.skipped)
    assert any("大小上限" in item.reason for item in limited.skipped)
    assert any(item.path == "members.zip!/escape.yaml" for item in limited.skipped)

    encrypted = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(encrypted, "w") as archive:
        archive.writestr("secret.yaml", "password: fake\n")
    data = bytearray(encrypted.read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = data.find(signature)
        data[index + offset] |= 1
    encrypted.write_bytes(data)
    result = FileLoader().scan(str(encrypted))
    assert any("加密" in item.reason for item in result.skipped)


def test_tar_limits_and_unreadable_member(tmp_path, monkeypatch):
    path = tmp_path / "many.tar"
    with tarfile.open(path, "w") as archive:
        for index in range(2):
            payload = b"a=1\n"
            info = tarfile.TarInfo(f"c{index}.conf")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    result = FileLoader(max_archive_entries=1).scan(str(path))
    assert any("超过上限" in item.reason for item in result.skipped)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", lambda *args: None)
    result = FileLoader().scan(str(path))
    assert any("无法读取" in item.reason for item in result.skipped)


def test_firmware_fixtures():
    result = FileLoader().scan(str(FIRMWARE))
    targets = {target.display_path: target for target in result.targets}
    assert set(targets) == {"router_fw.bin#config", "clean_fw.bin#config"}
    assert targets["router_fw.bin#config"].source == "firmware"
    assert "FirmwareSecret" in targets["router_fw.bin#config"].content
    assert any(item.path == "no_config.bin" for item in result.skipped)


def test_malformed_firmware_and_empty_archive_entry(tmp_path):
    (tmp_path / "half.bin").write_bytes(b"prefix\n# FW-CONFIG-BEGIN\npassword=x\n")
    result = FileLoader().scan(str(tmp_path / "half.bin"))
    assert "未发现" in result.skipped[0].reason

    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("empty.yaml", "")
    result = FileLoader().scan(str(zip_path))
    assert "空文件" in result.skipped[0].reason
