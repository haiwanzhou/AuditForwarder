#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨操作员合谋实验 —— 剧本执行器

作用：用真实 HTTP 请求（经采集器代理）驱动图书管理系统，完整走一遍
      浏览器操作 → HTTP 请求 → 采集器 → 服务端聚合 → 合谋判定 的链路。
      不合成事件、不直接调用检测接口，所有证据都来自真实日志。

前置：
  1. 服务端     build/Release/auditforwarder-server.exe -d data/server --listen 127.0.0.1:8443
  2. 图书系统   python lab/book_system/backend/app.py      (0.0.0.0:18080)
  3. 采集客户端 build/Release/auditforwarder-client.exe -c config/client_lab.yaml
                （代理监听 127.0.0.1:8888）

用法：
  python lab/run_scenario.py --scenario control
  python lab/run_scenario.py --scenario all
  python lab/run_scenario.py --scenario r001 --no-proxy     # 不经采集器，做对照
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# HTTP 基础设施：所有请求都走采集器代理，才能被采集成日志
# ---------------------------------------------------------------------------


def build_opener(proxy):
    handler = urllib.request.ProxyHandler({"http": proxy} if proxy else {})
    return urllib.request.build_opener(handler)


def call(opener, base, method, path, body=None, token=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with opener.open(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, (json.loads(raw) if raw.strip() else {})
            except json.JSONDecodeError:
                # 图书系统首页返回 HTML，不是 JSON；不能因此把成功响应当成连接失败
                return resp.status, {"raw": raw[:200]}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw[:200]}
    except Exception as exc:  # 代理未启动、服务未启动
        return 0, {"error": str(exc)}


def login(opener, base, username, password):
    status, body = call(opener, base, "POST", "/api/auth/login",
                        {"username": username, "password": password})
    if status != 200:
        raise SystemExit("登录失败 %s: %s %s" % (username, status, body))
    return body["data"]["token"]


class Step:
    """一次剧本步骤：谁、做了什么、期望被归一化成什么动作。"""

    def __init__(self, operator, label, expect, run):
        self.operator = operator
        self.label = label
        self.expect = expect
        self.run = run


def make_runner(opener, base):
    tokens = {}

    def token_of(user):
        if user not in tokens:
            tokens[user] = login(opener, base, user, "admin123")
        return tokens[user]

    def do(user, method, path, body=None):
        status, resp = call(opener, base, method, path, body, token_of(user))
        ok = 200 <= status < 300
        print("    [%s] %-6s %-46s -> %s%s" % (
            user, method, path, status, "" if ok else "  !! " + str(resp)[:120]))
        if not ok:
            raise SystemExit("步骤失败，终止剧本")
        return resp

    return do, token_of


# ---------------------------------------------------------------------------
# 剧本定义
# ---------------------------------------------------------------------------


def scenario_control(do, _tok, tag):
    """对照组：只做正常业务（删一本书），不碰备份/卷/快照。预期不告警。"""
    print("  [对照组] 正常业务：删除一本书")
    books = do("admin", "GET", "/api/books")
    items = books.get("data", {}).get("books", [])
    if not items:
        raise SystemExit("图书表为空，无法执行对照组")
    do("admin", "DELETE", "/api/books/%d" % items[0]["id"])


def scenario_r001(do, _tok, tag):
    """R-001 备份销毁合谋：删备份 → 卸卷 → 删快照。"""
    name = "lab_%s.db" % tag
    snap = "lab_%s.snap" % tag
    print("  前置：把实验对象恢复到初始状态并造好可删的备份/快照（都是正常运维）")
    vols0 = do("admin", "GET", "/api/storage/volume")
    for v in vols0["data"]["volumes"]:
        if not v["mounted"]:
            do("admin", "PATCH", "/api/storage/volume/%d/mount" % v["id"])
    do("admin", "POST", "/api/backup", {"name": name})
    do("admin", "POST", "/api/snapshot", {"name": snap})

    print("  第 1 步  admin   删除备份        → 期望 delete.backup")
    do("admin", "DELETE", "/api/backup/%s" % name)

    print("  第 2 步  admin2  卸载存储卷      → 期望 unmount.volume")
    vols = do("admin2", "GET", "/api/storage/volume")
    mounted = [v for v in vols["data"]["volumes"] if v["mounted"]]
    if not mounted:
        raise SystemExit("没有已挂载的卷，无法执行第 2 步")
    do("admin2", "PATCH", "/api/storage/volume/%d/unmount" % mounted[0]["id"])

    print("  第 3 步  admin3  删除快照        → 期望 delete.snapshot")
    do("admin3", "DELETE", "/api/snapshot/%s" % snap)


def scenario_r002(do, _tok, tag):
    """R-002 密钥权限拆分绕过：生成 → 分发 → 清密钥审计。"""
    print("  第 1 步  admin   生成密钥        → 期望 create.key")
    resp = do("admin", "POST", "/api/key", {"name": "lab_%s" % tag})
    key_id = resp["data"]["id"]

    print("  第 2 步  admin2  分发密钥        → 期望 distribute.key")
    do("admin2", "POST", "/api/key/%d/distribute" % key_id, {"to": "librarian1"})

    print("  第 3 步  admin3  清密钥审计      → 期望 clear.key_audit")
    do("admin3", "DELETE", "/api/key/audit/clear")


def scenario_r003(do, _tok, tag):
    """R-003 配置篡改链路：改配置 → 重启服务 → 清日志。"""
    print("  第 1 步  admin   修改系统配置    → 期望 update.config")
    do("admin", "PUT", "/api/system/config",
       {"log_retention_days": 1, "lab": tag})

    print("  第 2 步  admin2  重启服务        → 期望 restart.service")
    do("admin2", "POST", "/api/system/service/restart")

    print("  第 3 步  admin3  清空系统日志    → 期望 clear.logs")
    do("admin3", "DELETE", "/api/system/logs/clear")


def scenario_r004(do, _tok, tag):
    """R-004 数据批量外泄：提权 → 批量导出 → 清业务审计。"""
    print("  第 1 步  admin   授予导出权限    → 期望 grant.user")
    do("admin", "PATCH", "/api/users/3/privilege", {"privilege": "export"})

    print("  第 2 步  admin2  批量导出图书    → 期望 export.book")
    do("admin2", "GET", "/api/books/export")

    print("  第 3 步  admin3  清业务审计      → 期望 clear.book_audit")
    do("admin3", "DELETE", "/api/books/audit/clear")


def scenario_r005(do, tok, tag):
    """R-005 权限晋升合谋：建号 → 授权成管理员 → 用该号执行敏感动作。"""
    backdoor = "lab_backdoor_%s" % tag
    print("  第 1 步  admin   创建账号        → 期望 create.user")
    resp = do("admin", "POST", "/api/admin/user",
              {"username": backdoor, "password": "admin123", "role": "member"})
    uid = resp["data"]["id"]

    print("  第 2 步  admin2  提升为管理员    → 期望 assign.user")
    do("admin2", "POST", "/api/admin/user/%d/assign-admin" % uid)

    print("  第 3 步  %s  用后门账号执行 → 期望 exec.purge_books" % backdoor)
    # 后门账号刚被提权，用它的身份执行敏感动作：
    # 这一步单看是"管理员执行运维动作"，与前两步叠加才构成"自己造的后门自己用"
    do(backdoor, "POST", "/api/admin/exec", {"action": "purge_books"})


SCENARIOS = {
    "control": ("对照组（正常业务，预期不告警）", scenario_control),
    "r001": ("R-001 备份销毁合谋", scenario_r001),
    "r002": ("R-002 密钥权限拆分绕过", scenario_r002),
    "r003": ("R-003 配置篡改链路", scenario_r003),
    "r004": ("R-004 数据批量外泄", scenario_r004),
    "r005": ("R-005 权限晋升合谋", scenario_r005),
}

# ---------------------------------------------------------------------------
# 结果查询
# ---------------------------------------------------------------------------


def print_collusion(opener, base):
    status, body = call(opener, base, "GET", "/collusion/events?limit=20")
    print("\n==== /collusion/events  (status=%s) ====" % status)
    print(json.dumps(body, ensure_ascii=False, indent=2)[:4000])


def main():
    ap = argparse.ArgumentParser(description="跨操作员合谋实验剧本执行器")
    ap.add_argument("--scenario", default="all",
                    help="control | r001..r005 | all")
    ap.add_argument("--base", default="http://127.0.0.1:18080",
                    help="图书管理系统地址")
    ap.add_argument("--proxy", default="http://127.0.0.1:8888",
                    help="采集器 HTTP 代理地址")
    ap.add_argument("--server", default="http://127.0.0.1:8443",
                    help="监管服务端地址（查告警用，不走代理）")
    ap.add_argument("--no-proxy", action="store_true",
                    help="不经代理直连（对照组用：证明没有采集就没有告警）")
    ap.add_argument("--wait", type=int, default=14,
                    help="结束后等待秒数，让服务端聚合窗口结算")
    args = ap.parse_args()

    opener = build_opener(None if args.no_proxy else args.proxy)

    # 探活
    st, _ = call(opener, args.base, "GET", "/")
    if st == 0:
        print("无法连接图书系统 %s（先启动 app.py，或检查代理是否在运行）" % args.base)
        return 2
    print("图书系统可达（status=%s），代理：%s\n" % (st, "关闭" if args.no_proxy else args.proxy))

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for name in names:
        if name not in SCENARIOS:
            print("未知剧本：%s（可选：%s）" % (name, ", ".join(SCENARIOS)))
            return 2
        title, fn = SCENARIOS[name]
        print("=" * 78)
        print("剧本 %s —— %s" % (name.upper(), title))
        print("=" * 78)
        tag = "%s%d" % (name, int(time.time()) % 100000)
        do, tok = make_runner(opener, args.base)
        try:
            fn(do, tok, tag)
        except SystemExit as exc:
            print("  中止：%s" % exc)
        time.sleep(args.wait)
        print("")

    print_collusion(build_opener(None), args.server)
    return 0


if __name__ == "__main__":
    sys.exit(main())
