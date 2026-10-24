#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实验环境重置：让下一次实验从干净基线开始

清掉三样东西：
  1. 图书系统的业务数据（图书 / 备份 / 快照 / 密钥 / 操作审计）—— 重新 seed
  2. 监管端的合谋事件与画像 —— 删 events.jsonl / profiles.json
  3. 采集端的操作日志（可选 --keep-logs 保留）

注意：服务端把 events.jsonl 读进内存，重置后**必须重启服务端**才生效。
本脚本会提示你重启，或加 --restart 自动重启（Windows）。

用法：
  python lab/reset_lab.py
  python lab/reset_lab.py --restart
  python lab/reset_lab.py --keep-logs
"""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOK = ROOT / "lab" / "book_system"
DB = BOOK / "library.db"
RUNTIME = BOOK / "runtime"
SERVER_DATA = ROOT / "data" / "server"
CLIENT_DATA = ROOT / "data" / "client"


def reset_book_system():
    if DB.exists():
        DB.unlink()
    for sub in ("backups", "snapshots"):
        d = RUNTIME / sub
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
    sys.path.insert(0, str(BOOK / "backend"))
    from database import setup_database  # noqa: E402
    setup_database()
    conn = sqlite3.connect(DB)
    books = conn.execute("SELECT COUNT(*) FROM books").fetchone()[0]
    users = [r[0] for r in conn.execute("SELECT username FROM users ORDER BY id")]
    conn.close()
    print("  图书库已重建：books=%d, users=%s" % (books, ", ".join(users)))


def reset_collusion():
    removed = 0
    for name in ("events.jsonl", "profiles.json", "audit.jsonl"):
        p = SERVER_DATA / "collusion" / name
        if p.exists():
            p.unlink()
            removed += 1
    print("  合谋事件/画像已清空（%d 个文件）" % removed)


def reset_logs():
    for d in (SERVER_DATA / "operation_logs", SERVER_DATA / "audit_summaries",
              SERVER_DATA / "alerts", SERVER_DATA / "ingested_batches"):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
    if CLIENT_DATA.exists():
        shutil.rmtree(CLIENT_DATA, ignore_errors=True)
    print("  采集端/服务端日志已清空")


def restart():
    subprocess.run(["taskkill", "/F", "/IM", "auditforwarder-server.exe"],
                   capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "auditforwarder-client.exe"],
                   capture_output=True)
    batch = ROOT / "lab" / "_srv.bat"
    subprocess.Popen(["explorer.exe", str(batch)])
    print("  已发出重启指令（explorer 拉起 _srv.bat），请等 4 秒后再起客户端")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-logs", action="store_true", help="保留采集/操作日志")
    ap.add_argument("--restart", action="store_true", help="重置后自动重启服务端")
    args = ap.parse_args()

    print("重置实验环境 ...")
    reset_book_system()
    reset_collusion()
    if not args.keep_logs:
        reset_logs()
    if args.restart:
        restart()
    else:
        print("\n请手动重启服务端与客户端，否则内存里仍是旧事件：")
        print("  lab\\stop_lab.bat  然后  lab\\start_lab.bat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
