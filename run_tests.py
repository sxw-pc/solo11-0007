#!/usr/bin/env python3
"""单命令执行全量离线测试。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def main() -> int:
    os.chdir(BASE_DIR)
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))
    import pytest

    return int(pytest.main(["tests", "-q", "--disable-warnings"]))


if __name__ == "__main__":
    raise SystemExit(main())
