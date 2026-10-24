#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""清空告警，让实验从 0 开始

只清「合谋事件 + 操作员画像」，**不动**图书系统的业务数据
（账号、图书、卷挂载状态、已有备份全部保留）。

清完会自动重启服务端与采集端，原因是：
  - 服务端启动时把 events.jsonl 读进内存，只删文件不重启等于没删；
  - 客户端没有重连逻辑，服务端一断它就永远采不到了，必须一起重启。

用法：
  python lab/clear_alerts.py             # 清告警 + 重启服务端与采集端（推荐）
  python lab/clear_alerts.py --status    # 只看当前计数，不清
  python lab/clear_alerts.py --hard      # 连操作日志、图书业务库一起重置
  python lab/clear_alerts.py --no-restart  # 只删文件（之后自己重启）
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
SERVER_DATA = ROOT / "data" / "server"
COLLUSION_DIR = SERVER_DATA / "collusion"
BOOK = LAB / "book_system"
BOOK_DB = BOOK / "library.db"

OVERVIEW = "http://127.0.0.1:8443/collusion/overview"


# ---------------------------------------------------------------------------
# HTTP（显式禁用系统代理，否则环境里的 http_proxy 会把 localhost 也劫走）
# ---------------------------------------------------------------------------
def overview(timeout=3):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(OVERVIEW, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def print_status(tag):
    try:
        d = overview()
    except Exception as e:
        print("  [%s] 服务端不可达：%s" % (tag, e))
        return None
    c = d.get("event_counts", {})
    print("  [%s] 高风险 %d / 中风险 %d / 低风险 %d  | 待复核 %d  | 画像人数 %d"
          % (tag, c.get("HIGH", 0), c.get("MID", 0), c.get("LOW", 0),
             d.get("pending_review", 0), d.get("profile_operators", 0)))
    return d


# ---------------------------------------------------------------------------
# 进程控制
# ---------------------------------------------------------------------------
def taskkill(exe):
    p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "taskkill.exe")
    if not os.path.exists(p):
        p = "taskkill"
    subprocess.run([p, "/F", "/IM", exe], capture_output=True)


def launch(bat):
    """用 explorer 拉起 bat。直接 Popen 的进程会随调用方退出被回收，
    交给 explorer 才能长期存活。"""
    subprocess.run(["explorer.exe", str(bat)], capture_output=True)
    time.sleep(1.0)


def wait_up(limit=40):
    for _ in range(limit):
        try:
            overview(timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def kill_book():
    """只杀监听 18080 的 python，避免误杀本机其他 python 进程。"""
    netstat = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "netstat.exe")
    if not os.path.exists(netstat):
        netstat = "netstat"
    out = subprocess.run([netstat, "-ano"], capture_output=True,
                         text=True, errors="ignore").stdout
    pids = set()
    for line in out.splitlines():
        if ":18080" in line and "LISTENING" in line.upper():
            parts = line.split()
            if parts:
                pids.add(parts[-1])
    for pid in pids:
        taskkill_pid(pid)
    time.sleep(1.0)


def taskkill_pid(pid):
    p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "taskkill.exe")
    if not os.path.exists(p):
        p = "taskkill"
    subprocess.run([p, "/F", "/PID", str(pid)], capture_output=True)


def kill_all(with_book=False, with_client=False):
    taskkill("auditforwarder-server.exe")
    # 默认不杀客户端：客户端一重启就进入几分钟的预热期，
    # 这期间带 body 的 POST/PUT 采不到，用户会以为检测坏了。
    # 实测只重启服务端就能把事件和画像清空，而且已确认的批次不会重发。
    if with_client:
        taskkill("auditforwarder-client.exe")
    if with_book:
        kill_book()
    time.sleep(1.5)


def wait_ready(limit=90):
    """等服务端与采集器的上报通道真正恢复。

    判据必须用"带请求体的 POST"，不能用 GET：
    实测 GET 能立刻被采集，但 PUT/POST 带 body 的请求在客户端刚重启的那段
    时间里会被静默丢掉（读 body 失败就直接 return，不 emit 事件）。
    而合谋实验的每一步都是 POST/PUT/DELETE，用 GET 判断会得到"已就绪"的
    假信号，然后操作全落空。

    探针带一个唯一身份头，这样能在日志里精确找到这一条，
    不会和浏览器轮询 /api/_alerts 的噪音混在一起。
    """
    logs_dir = SERVER_DATA / "operation_logs"
    marker = "readycheck"
    for i in range(limit):
        try:
            body = json.dumps({"username": "member1", "password": "member123"}).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:18080/api/auth/login", data=body, method="POST",
                headers={"Content-Type": "application/json", "x-af-operator": marker})
            urllib.request.build_opener(urllib.request.ProxyHandler(
                {"http": "http://127.0.0.1:8888"})).open(req, timeout=6).read()
        except Exception:
            pass
        time.sleep(2)
        if logs_dir.exists():
            for host_dir in logs_dir.iterdir():
                f = host_dir / "http_proxy.jsonl"
                if not f.is_file():
                    continue
                try:
                    tail = f.read_text(encoding="utf-8", errors="ignore")[-40000:]
                    if '"operator_id":"%s"' % marker in tail:
                        print("  采集上报通道已就绪（带 body 的 POST 已落库，等待 %d 秒）" % i)
                        return True
                except Exception:
                    pass
        if i and i % 10 == 0:
            print("  等待带 body 的请求能落库 ... %d 秒" % i)
    print("  !! %d 秒内带 body 的请求仍采不到。" % limit)
    print("     这是采集客户端刚重启时的预热期，不是检测坏了。")
    print("     做法：打开操作台先随便点一步（例如「造一个备份」），")
    print("     等 1~2 分钟看监管控制台有没有出现这一条；出现了再正式演。")
    return False


def start_all(with_book=False, with_client=False):
    if with_book:
        launch(LAB / "_book.bat")
    launch(LAB / "_srv.bat")
    if not wait_up():
        print("  !! 服务端 40 秒内没起来，看 data\\lab_server.log")
        return False
    if not with_client:
        return True
    launch(LAB / "_client.bat")
    # 第二实例（模拟第二台机器）存在就一起拉起，否则清空后它就停了，
    # 而 wash 掉的数据看起来像是"跨机聚合失效"。
    if (LAB / "_peer.bat").exists():
        launch(LAB / "_peer.bat")
    # 这里必须等够：采集器起来了（端口在听）不等于能上报。
    # remote 通道要完成注册/心跳之后才开始送 operation-logs，
    # 只等 4 秒就发请求，请求会成功但日志一条都进不来，看起来像检测失灵。
    time.sleep(10)
    return True


# ---------------------------------------------------------------------------
# 清理
# ---------------------------------------------------------------------------
def clear_collusion():
    n = 0
    for name in ("events.jsonl", "profiles.json", "audit.jsonl"):
        p = COLLUSION_DIR / name
        if p.exists():
            p.unlink()
            n += 1
    print("  合谋事件与画像已清空（%d 个文件）" % n)


def clear_client_spool():
    """清掉客户端未确认的待发批次。

    这一步不能省：客户端把批次持久化在 batches/ 与 super_batches/ 里，
    重启后会重发一遍。如果只清服务端的事件，重启后旧日志又会被重新判定，
    告警立刻回到原来的数量。

    data/client2 是第二台机器（或本机第二实例）的数据目录，必须一起清，
    否则它重启后会把旧批次重发，基线又回不去 0。
    """
    n = 0
    for client_dir in ("client", "client2"):
        base = ROOT / "data" / client_dir
        for name in ("batches", "super_batches"):
            d = base / name
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
                n += 1
        p = base / "transport.index"
        if p.exists():
            p.unlink()
            n += 1
    print("  客户端待发批次已清空（%d 项）" % n)


def clear_raw_logs():
    for d in ("operation_logs", "audit_summaries", "alerts", "ingested_batches"):
        p = SERVER_DATA / d
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    print("  服务端原始日志已清空")


def reset_book():
    if BOOK_DB.exists():
        BOOK_DB.unlink()
    for sub in ("backups", "snapshots"):
        d = BOOK / "runtime" / sub
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
    sys.path.insert(0, str(BOOK / "backend"))
    from database import setup_database  # noqa: E402
    setup_database()
    print("  图书业务库已重建（账号与图书恢复出厂）")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--status", action="store_true", help="只看当前计数")
    ap.add_argument("--hard", action="store_true", help="连原始日志与图书库一起重置")
    ap.add_argument("--no-restart", action="store_true", help="只删文件，不重启")
    ap.add_argument("--full", action="store_true",
                    help="连采集客户端一起重启（清它的待发批次；代价是几分钟预热期）")
    args = ap.parse_args()

    print("当前状态：")
    before = print_status("清理前")

    if args.status:
        return 0

    print("\n开始清理 ...")
    kill_all(with_book=args.hard, with_client=args.full)
    clear_collusion()
    if args.full:
        clear_client_spool()
    if args.hard:
        clear_raw_logs()
        reset_book()

    if args.no_restart:
        print("\n已停掉服务端. 请手动执行 lab\\start_lab.bat 再继续。")
        return 0

    print("  重启服务端 ...")
    if not start_all(with_book=args.hard, with_client=args.full):
        return 1
    if args.full:
        wait_ready()
    else:
        # 客户端没重启，只需要等心跳重新连上重启后的服务端
        time.sleep(4)

    print("\n清理后状态：")
    after = print_status("清理后")

    if after:
        c = after.get("event_counts", {})
        if after.get("pending_review", 0) == 0 and c.get("HIGH", 0) == 0:
            print("\n基线已归零。现在去操作台点任意剧本，每一步都会是「新增」。")
        else:
            print("\n计数没有归零，说明还有别的进程在写。先跑 lab\\stop_lab.bat 全停，再重跑本脚本。")

    if before and after:
        print("\n对照：清理前 HIGH=%d，清理后 HIGH=%d"
              % (before.get("event_counts", {}).get("HIGH", 0),
                 after.get("event_counts", {}).get("HIGH", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
