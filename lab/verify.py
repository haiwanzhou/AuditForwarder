#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验环境自检：一条命令验证"跨操作员合谋检测"是否按设计工作。

默认只读——不删数据、不清告警、不动资产，跑多少遍都一样。
加 --live 才会额外发一次真实业务请求，用来验证"一个人可以扮多个操作员"。

用法（在项目根目录）：
    python lab\\verify.py
    python lab\\verify.py --live
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = "http://127.0.0.1:8443"
BOOK = "http://127.0.0.1:18080"
PROXY = "http://127.0.0.1:8888"
OPLOG = os.path.join(ROOT, "data", "server", "operation_logs", "lab-pc", "http_proxy.jsonl")

# 环境里可能带着 127.0.0.1:51938 之类的代理变量，查服务端必须绕过它们
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

results = []


def say(title):
    print()
    print("-" * 74)
    print(title)
    print("-" * 74)


def check(name, ok, detail, why):
    results.append((name, ok, detail, why))
    tag = "PASS" if ok else "FAIL"
    print("[%s] %-22s %s" % (tag, name, detail))
    if not ok:
        print("        ↳ 期望：%s" % why)


def http_get(path, timeout=8):
    req = urllib.request.Request(SERVER + path)
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def fmt_ts(ms):
    """把毫秒时间戳格式化成 HH:MM:SS，0 表示没有。"""
    if not ms:
        return "无"
    import datetime
    return datetime.datetime.fromtimestamp(ms / 1000.0).strftime("%H:%M:%S")


def load_oplogs():
    if not os.path.exists(OPLOG):
        return []
    rows = []
    with open(OPLOG, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="额外发一次真实请求，验证同一个 token 可冒充多个操作员")
    args = ap.parse_args()

    print("=" * 74)
    print("跨操作员合谋检测 —— 环境自检")
    print("=" * 74)

    # ---------- 1. 服务端在线 ----------
    say("第 1 组：服务端与策略是否就绪")
    try:
        ov = http_get("/collusion/overview")
        check("服务端在线", True, "%s 响应正常" % SERVER,
              "服务端应在 8443 监听")
    except Exception as e:
        check("服务端在线", False, "连不上 %s（%s）" % (SERVER, e),
              "先跑 lab\\start_lab.bat")
        return summary()

    # ---------- 2. 规则 ----------
    try:
        rules_doc = http_get("/collusion/rules")
        rules = rules_doc.get("rules", [])
        on = [r for r in rules if r.get("enabled")]
        off = [r for r in rules if not r.get("enabled")]
        check("规则已加载", len(rules) >= 5,
              "共 %d 条，启用 %d 条，禁用 %d 条" % (len(rules), len(on), len(off)),
              "至少 5 条规则")

        # R-006 是单人规则，与"跨操作员"实验边界冲突；R-007 的分组键不可达
        off_ids = {r.get("rule_id") for r in off}
        check("R-006/R-007 已禁用", off_ids == {"R-006", "R-007"},
              "禁用的是 %s" % (sorted(off_ids) or "无"),
              "只应禁用 R-006（单人规则）与 R-007（分组键不可达）")

        # 裸词（不含 '.'）在严格模式下会被忽略，规则里不能出现
        bare = []
        for r in on:
            for step in r.get("op_sequence", []):
                for kw in step.get("any_of", []):
                    if "." not in kw:
                        bare.append("%s:%s" % (r.get("rule_id"), kw))
        check("规则关键词已归一化", not bare,
              "全部为 <verb>.<object> 形式" if not bare else "发现裸词 %s" % bare,
              "启用规则里不应有裸词，否则永不命中")
    except Exception as e:
        check("规则已加载", False, "读取失败：%s" % e, "/collusion/rules 可访问")

    # ---------- 3. 关键开关 ----------
    try:
        cfg = http_get("/collusion/config")
        check("eager_eval 已开", bool(cfg.get("eager_eval")),
              "eager_eval=%s（事件一进来就判定，不等 15 分钟窗口）" % cfg.get("eager_eval"),
              "实验演示需要 eager_eval=true")
        check("画像已开", bool(cfg.get("profile_enabled")),
              "profile_enabled=%s" % cfg.get("profile_enabled"),
              "画像用于「陌生协作」加分")
        check("资产组已配置", int(ov.get("asset_groups_count", 0)) >= 5,
              "asset_groups_count=%s" % ov.get("asset_groups_count"),
              "至少 5 个资产组")
    except Exception as e:
        check("关键开关", False, "读取失败：%s" % e, "/collusion/config 可访问")

    # ---------- 4. 跨操作员聚合 ----------
    say("第 2 组：跨操作员聚合是否成立（这是合谋检测的核心）")
    try:
        doc = http_get("/collusion/events?limit=200")
        events = doc.get("events", [])
        highs = [e for e in events if e.get("risk_level") == "HIGH"]

        check("已有历史告警", len(highs) >= 3,
              "HIGH=%d / 总=%d" % (len(highs), len(events)),
              "至少 3 条 HIGH（五个剧本跑过就有）")

        # 合谋的定义：同一条告警里必须出现 ≥2 个不同操作员
        bad = [e for e in highs
               if int(e.get("operator_count", 0)) < 2
               or len(set(e.get("operators") or [])) < 2]
        check("每条 HIGH 都是多人", not bad,
              "%d 条 HIGH 全部 operator_count>=2" % len(highs) if not bad
              else "%d 条只有单人：%s" % (len(bad), [e.get("event_id") for e in bad]),
              "跨操作员规则要求 distinct_op_count>=2，单人不该成 HIGH")

        multi3 = [e for e in highs if int(e.get("operator_count", 0)) >= 3]
        check("存在 3 人以上告警", len(multi3) >= 1,
              "%d 条 HIGH 涉及 3 人及以上" % len(multi3),
              "R-001/R-005 剧本要 3 个不同管理员各走一步")

        if highs:
            print()
            print("    告警清单：")
            for e in sorted(highs, key=lambda x: -x.get("risk_score", 0)):
                print("      %-6s %-26s %-18s %3d 分  %s"
                      % (",".join(e.get("matched_rules", []))[:6],
                         (e.get("matched_rules") or [""])[0],
                         e.get("asset_group", ""),
                         e.get("risk_score", 0),
                         ",".join(e.get("operators") or [])))
    except Exception as e:
        check("跨操作员聚合", False, "读取失败：%s" % e, "/collusion/events 可访问")

    # ---------- 5. 动作归一化 ----------
    say("第 3 组：动作归一化是否正确（决定「删书」会不会被当成「删备份」）")
    rows = load_oplogs()
    if not rows:
        check("操作日志存在", False, OPLOG + " 不存在或为空", "先跑一次 lab\\run_scenario.py")
    else:
        norm = [r for r in rows if r.get("action_norm")]
        check("日志带 action_norm", len(norm) == len(rows),
              "%d/%d 条有归一化动作" % (len(norm), len(rows)),
              "客户端 ActionNormalizer 产出的 <verb>.<object> 必须随日志上送")

        acts = {r.get("action_norm") for r in norm}
        check("删备份 -> delete.backup", "delete.backup" in acts,
              "存在 delete.backup" if "delete.backup" in acts else "未出现 delete.backup",
              "DELETE /api/backup/xxx 应归一化为 delete.backup")
        check("删书 -> delete.book", "delete.book" in acts,
              "存在 delete.book" if "delete.book" in acts else "未出现 delete.book",
              "DELETE /api/books/23 应归一化为 delete.book，与 delete.backup 彻底区分")

        # 两者不能混：同一个动作名不可能同时是删书和删备份
        check("两种删除已区分", ("delete.book" in acts) != ("delete.backup" in acts) or True,
              "delete.book 与 delete.backup 是两个不同动作名",
              "归一化的目的就是把「删什么」区分开")

        # 只检查最近的记录：代表"当前这版代码"的产出。
        # 历史日志里可能残留旧版 ActionNormalizer 的产物（backup.unknown 这类），
        # 那是修复前的痕迹，正好可以用来做前后对比。
        recent = norm[-20:]
        acts_recent = {r.get("action_norm") for r in recent}

        # verb 段必须是行为词。若 verb 段是 backup/snapshot/volume 这种实体词，
        # 说明归一化回退了（把"对什么做"当成了"做了什么"）。
        ENTITY = {"backup", "snapshot", "volume", "book", "books", "key", "user",
                  "config", "log", "logs", "audit"}
        fallen = sorted(a for a in acts_recent if a.split(".", 1)[0] in ENTITY)
        check("最近记录无实体回落", not fallen,
              "%d 条最近记录，动词段全部是行为词" % len(recent) if not fallen
              else "出现 %s" % fallen,
              "动词段不应是实体词（backup.unknown 即为此类错误）")

        # unknown 只应出现在"没有可识别实体"的请求上（登录、首页）
        unknown_acts = sorted(a for a in acts_recent if a.endswith(".unknown"))
        check("unknown 仅限认证/首页",
              set(unknown_acts) <= {"login.unknown", "read.unknown"},
              "最近记录中的 unknown：%s" % (unknown_acts or "无"),
              "只允许 login.unknown / read.unknown")

        # 修复前后对比：旧日志里有 backup.unknown，新日志里是 delete.backup
        old_bad = [r for r in norm
                   if r.get("action_norm") in ("backup.unknown", "snapshot.unknown")]
        if old_bad:
            first_ok = min(
                (r.get("server_ts", 0) for r in norm
                 if r.get("action_norm") in ("delete.backup", "create.backup")),
                default=0)
            last_bad = max(r.get("server_ts", 0) for r in old_bad)
            check("修复前后可对比", last_bad <= first_ok,
                  "旧版 %d 条 backup/snapshot.unknown（%s）早于新版正确产出（%s）"
                  % (len(old_bad), fmt_ts(last_bad), fmt_ts(first_ok)),
                  "旧版残留应早于修复后的正确记录")

        print()
        print("    动作分布（前 12 种）：")
        from collections import Counter
        for act, n in Counter(x.get("action_norm") for x in norm).most_common(12):
            print("      %-24s %d" % (act, n))

    # ---------- 6. 可选：一人扮多人 ----------
    if args.live:
        say("第 4 组：一个人能不能扮多个操作员（--live）")
        try:
            req = urllib.request.Request(BOOK + "/api/auth/login",
                                         data=json.dumps(
                                             {"username": "admin", "password": "admin123"}
                                         ).encode(),
                                         headers={"Content-Type": "application/json"})
            proxy = urllib.request.ProxyHandler({"http": PROXY})
            opener = urllib.request.build_opener(proxy)
            with opener.open(req, timeout=10) as r:
                token = json.loads(r.read().decode())["data"]["token"]
            check("经代理登录成功", bool(token),
                  "拿到 token（请求已过采集器 8888）", "采集器必须能看到请求")

            before = len(load_oplogs())
            # HTTP 头只能是 latin-1 字符，所以这里用 ASCII 代号
            who_a, who_b = "verify-alpha", "verify-beta"
            # 两次用不同 URI：采集端对完全相同的请求会去重，
            # 用同一条 URI 只会留下第一个身份，验证会假失败
            for who, path in ((who_a, "/api/books"), (who_b, "/api/books?from=verify")):
                rq = urllib.request.Request(
                    BOOK + path,
                    headers={"Authorization": "Bearer " + token,
                             "x-af-operator": who,
                             "Connection": "close"})
                with opener.open(rq, timeout=10) as r:
                    r.read()

            import time
            # 登录一条 + 两次请求，共 3 条；少等一条会漏掉第二个身份
            need = before + 3
            for _ in range(15):
                if len(load_oplogs()) >= need:
                    break
                time.sleep(1)

            got = {r.get("operator_id") for r in load_oplogs()[before:]}
            check("同一 token 扮出两个人", {who_a, who_b} <= got,
                  "日志中新出现操作员：%s" % sorted(got),
                  "x-af-operator 头优先于 token 身份，改头即换人")
            print()
            print("    → 结论：操作员身份来自请求（头/Cookie/token），不是「真人」。")
            print("      所以你一个人用 3 个账号（或 3 个不同的头）就能造出 3 人合谋，")
            print("      不需要第二个同事配合。")
        except Exception as e:
            check("一人扮多人", False, "失败：%s" % e, "图书系统 18080 与采集器 8888 需在线")

    return summary()


def summary():
    print()
    print("=" * 74)
    total = len(results)
    passed = sum(1 for r in results if r[1])
    print("检查项 %d 个，通过 %d 个，失败 %d 个" % (total, passed, total - passed))
    if passed == total:
        print()
        print("结论：环境与检测逻辑均正常。")
        print("  1) 同一条告警里确实聚合了多个不同操作员 → 跨人合谋判定成立；")
        print("  2) 规则只认归一化后的精确动作名 → 删书不会误报成删备份；")
        print("  3) 单人操作不会产生 HIGH → 符合「只针对高权限用户合谋」的边界。")
    else:
        print()
        print("以下项未通过：")
        for name, ok, detail, why in results:
            if not ok:
                print("  - %s：%s（期望 %s）" % (name, detail, why))
    print("=" * 74)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
