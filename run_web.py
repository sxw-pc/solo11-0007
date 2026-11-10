#!/usr/bin/env python3
"""单命令启动本地配置漏检 Web 服务。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.web_handler import AppContext, DEFAULT_HOST, DEFAULT_PORT, create_server


def main() -> int:
    parser = argparse.ArgumentParser(description="配置漏检工具箱本地 Web 服务")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="本地端口，默认 8765")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("端口必须在 1-65535 之间")
    context = AppContext(base_dir=BASE_DIR)
    server = create_server(DEFAULT_HOST, args.port, context)
    print(f"配置漏检工具箱已启动: http://{DEFAULT_HOST}:{server.server_address[1]}/")
    print("仅监听本机回环地址，按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
