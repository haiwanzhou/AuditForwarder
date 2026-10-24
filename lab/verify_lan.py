#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""局域网双机合谋检测自检

验证一件具体的事：**两台机器、两个操作员、各自一个采集器，
在服务端能不能被聚合成同一条合谋告警。**

它不是模拟出来的结论，而是真的发两路 HTTP：
  - A 路走 proxy-a（默认 8888），用 admin 身份
  - B 路走 proxy-b（默认 8889），用 admin2 身份
两路都访问 http://<书籍系统IP>:18080（不是 127.0.0.1），
这样服务端收到的日志里会有两个不同的 host_id。

默认跑 R-003（配置篡改链路，最少 2 人、3 步），因为它最短，
能用最少的请求证明"跨机跨人聚合成立"。

用法：
  python lab/verify_lan.py                      # 自动探测本机局域网 IP
  python lab/verify_lan.py --book 192.168.1.5   # 指定图书系统所在机器
  python lab/verify_lan.py --server 192.168.1.9 # 指定服务端所在机器
  python lab/verify_lan.py --proxy-b 8888       # 两台真机时两边都是 8888

注意：运行前服务端必须监听 0.0.0.0，否则局域网 IP 连不上；
两个采集器的 target_hosts 里必须有 <图书系统IP>，否则一条都采不到。
"""

import argparse
import http.cookiejar
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

PASSED = []
FAILED = []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("         %s" % detail)
    return ok


def http_json(url, method="GET", body=None, token=None, opener=None, timeout=8):
    """发一个 JSON 请求。opener 决定走哪个代理、带哪份 Cookie。"""
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    op = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with op.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return -1, str(e)


def make_opener(proxy_port):
    """带 Cookie 罐的 opener。Cookie 是采集器识别操作员的第二来源，
    浏览器场景下靠它；脚本场景下 x-af-operator 头会优先命中。"""
    cj = http.cookiejar.CookieJar()
    handler = urllib.request.ProxyHandler({"http": "http://127.0.0.1:%d" % proxy_port})
    return urllib.request.build_opener(handler, urllib.request.HTTPCookieProcessor(cj)), cj


def port_listening(port):
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def lan_ip():
    """取一个本机局域网地址。连的是 8.8.8.8 但不会真的发包，
    只是为了问操作系统"你走哪张网卡出去"。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


def login(book, user, pwd, opener):
    st, js = http_json(book + "/api/auth/login", "POST",
                       {"username": user, "password": pwd}, opener=opener)
    if st != 200 or not isinstance(js, dict):
        return None, "HTTP %s %s" % (st, str(js)[:120])
    data = js.get("data") or {}
    tok = data.get("token")
    if not tok:
        return None, "响应里没有 token：%s" % str(js)[:120]
    return tok, "ok"


def probe_capture(proxy_port, book, tag, wait=40):
    """发一个带标记的请求，确认它真的落进了服务端的操作日志。

    这一步是在排两类最容易误判成"检测失效"的坑：
      1. 目标 IP 不在采集器的 target_hosts 里 —— 请求成功，但一条都不采；
      2. 采集器刚启动，端口已经在听，remote 通道还没就绪 —— 同样采不到。
    这两种情况下接口都返回 200，光看返回码永远发现不了。

    第 2 种情况会自己恢复（客户端重连退避），所以要轮询着等，
    而不是发完一次就下结论。等待上限由 wait 控制。
    """
    url = "%s/api/books?%s=%d" % (book, tag, int(time.time() * 1000))
    opener, _ = make_opener(proxy_port)
    st, _ = http_json(url, opener=opener)
    if st != 200:
        return False, "探针请求失败 HTTP %s" % st

    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "server", "operation_logs")

    def seen():
        if not os.path.isdir(base):
            return None
        for host in os.listdir(base):
            f = os.path.join(base, host, "http_proxy.jsonl")
            if not os.path.isfile(f):
                continue
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if tag in line:
                            return host
            except Exception:
                pass
        return None

    for i in range(wait):
        host = seen()
        if host:
            return True, "已采到（主机 %s，等待 %d 秒）" % (host, i)
        if i and i % 5 == 0:
            print("         等待采集器就绪 ... %d 秒" % i)
        # 每 5 秒补发一次：早期那次请求可能在通道就绪前就被丢了
        if i and i % 5 == 0:
            http_json("%s/api/books?%s=%d" % (book, tag, int(time.time() * 1000)),
                      opener=make_opener(proxy_port)[0])
        time.sleep(1)
    return False, ("请求成功但 %d 秒内没被采集：目标 IP 可能不在 target_hosts 里，"
                   "或采集器没能连上服务端（看 data\\lab_client*.log）" % wait)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--book", default="", help="图书系统所在机器的局域网 IP")
    ap.add_argument("--server", default="http://127.0.0.1:8443", help="服务端地址")
    ap.add_argument("--proxy-a", type=int, default=8888)
    ap.add_argument("--proxy-b", type=int, default=8889)
    ap.add_argument("--skip-trigger", action="store_true", help="只检查环境，不发操作")
    args = ap.parse_args()

    ip = lan_ip()
    book_ip = args.book or ip
    book = "http://%s:18080" % book_ip
    server = args.server.rstrip("/")

    print("=" * 66)
    print(" 局域网双机合谋检测自检")
    print("=" * 66)
    print(" 本机局域网 IP : %s" % (ip or "(探测失败)"))
    print(" 图书系统      : %s" % book)
    print(" 服务端        : %s" % server)
    print(" 采集代理 A/B  : %d / %d" % (args.proxy_a, args.proxy_b))

    # 15 分钟固定窗口是硬边界：两人的操作如果正好横跨 :00/:15/:30/:45，
    # 会被切进两个不同的聚合集合，序列永远凑不齐。这是设计口径，不是 bug，
    # 但演示时踩到会非常像"检测失效"，所以提前算出来提醒。
    win = 15 * 60 * 1000
    elapsed = int(time.time() * 1000) % win
    left = win - elapsed
    print(" 当前窗口      : 已过 %d分%02d秒，距边界还有 %d分%02d秒"
          % (elapsed // 60000, elapsed % 60000 // 1000, left // 60000, left % 60000 // 1000))
    if left < 120000:
        print("                 ^ 不足 2 分钟。现在开始的话，后半段操作会落到下一个窗口，")
        print("                   两个窗口各缺几步，合谋就串不起来。等过了边界再开始更稳。")
    print()

    # ---- 1. 服务端必须监听在局域网地址上 ----
    print("第 1 组：服务端能不能被其他机器访问")
    st_local = http_json(server + "/collusion/overview")[0]
    check("服务端本机可达", st_local == 200, "127.0.0.1:8443 -> HTTP %s" % st_local)

    if book_ip and book_ip != "127.0.0.1":
        st_lan = http_json("http://%s:8443/collusion/overview" % book_ip)[0]
        check("服务端在局域网 IP 上可达", st_lan == 200,
              "http://%s:8443 -> HTTP %s（不是 200 说明服务端还绑着 127.0.0.1，"
              "要用 --listen 0.0.0.0:8443 启动）" % (book_ip, st_lan))
    else:
        check("服务端在局域网 IP 上可达", False,
              "没探测到局域网 IP，改用 --book <IP> 手动指定")

    # ---- 2. 图书系统必须能被局域网访问 ----
    print()
    print("第 2 组：图书系统能不能被两台机器访问")
    st_console = http_json(book + "/console")[0]
    check("操作台可访问", st_console == 200, "%s/console -> HTTP %s" % (book, st_console))

    # ---- 3. 两个采集代理都要在本机监听 ----
    print()
    print("第 3 组：两个采集器是否各自在监听")
    check("采集代理 A (%d) 在监听" % args.proxy_a, port_listening(args.proxy_a))
    check("采集代理 B (%d) 在监听" % args.proxy_b, port_listening(args.proxy_b),
          "两台真机时两边都用 8888；本机预演才需要 B 换成 8889")

    # ---- 4. 探针：确认这个 IP 的流量真的会被采集 ----
    print()
    print("第 4 组：目标 IP 是否在采集白名单内、采集器是否已就绪")
    ok_a, msg_a = probe_capture(args.proxy_a, book, "lanprobea")
    check("A 路（%d）流量能被采集" % args.proxy_a, ok_a, msg_a)
    ok_b, msg_b = probe_capture(args.proxy_b, book, "lanprobeb")
    check("B 路（%d）流量能被采集" % args.proxy_b, ok_b, msg_b)
    if not (ok_a and ok_b):
        print("         ^ 后面不用测了：请求能返回 200，但日志进不了服务端，")
        print("           合谋检测永远看不到这两台机器，先解决这一条。")
        return report()

    # ---- 5. 记录基线 ----
    print()
    print("第 5 组：跨机跨人聚合")
    st, ov = http_json(server + "/collusion/overview")
    if st != 200 or not isinstance(ov, dict):
        check("读取服务端总览", False, str(ov)[:150])
        return report()
    before_high = (ov.get("event_counts") or {}).get("HIGH", 0)
    print("         基线：高风险 %d 条" % before_high)

    if args.skip_trigger:
        print("         --skip-trigger：不发操作，只报告环境")
        return report()

    # ---- 6. 两路 HTTP，分别走两个代理 ----
    op_a, cj_a = make_opener(args.proxy_a)
    op_b, cj_b = make_opener(args.proxy_b)

    tok_a, msg_a = login(book, "admin", "admin123", op_a)
    if not check("A 路（代理 %d）以 admin 登录" % args.proxy_a, bool(tok_a), msg_a):
        return report()
    tok_b, msg_b = login(book, "admin2", "admin123", op_b)
    if not check("B 路（代理 %d）以 admin2 登录" % args.proxy_b, bool(tok_b), msg_b):
        return report()

    # R-003：改配置 -> 重启服务 -> 清日志。admin 走 A，admin2 走 B。
    st1, r1 = http_json(book + "/api/system/config", "PUT",
                        {"retention_days": 3650}, tok_a, op_a)
    check("A 路执行「修改系统配置」", st1 == 200, "HTTP %s %s" % (st1, str(r1)[:90]))

    st2, r2 = http_json(book + "/api/system/service/restart", "POST",
                        None, tok_b, op_b)
    check("B 路执行「重启服务」", st2 == 200, "HTTP %s %s" % (st2, str(r2)[:90]))

    st3, r3 = http_json(book + "/api/system/logs/clear", "DELETE",
                        None, tok_b, op_b)
    check("B 路执行「清除系统日志」", st3 == 200, "HTTP %s %s" % (st3, str(r3)[:90]))

    # ---- 7. 等判定 ----
    print()
    print("         等待服务端判定（eager 模式下 2~6 秒）...")
    hit = None
    for _ in range(12):
        time.sleep(1)
        st, ov2 = http_json(server + "/collusion/overview")
        if st == 200 and isinstance(ov2, dict):
            high = (ov2.get("event_counts") or {}).get("HIGH", 0)
            if high > before_high:
                break
    st, ev = http_json(server + "/collusion/events?limit=5")
    events = (ev.get("events") or []) if isinstance(ev, dict) else []
    new_high = [e for e in events if e.get("risk_level") == "HIGH"]
    if new_high:
        hit = new_high[0]

    check("产生了新的 HIGH 告警", bool(hit),
          "" if hit else "等不到新告警，先看两个客户端日志有没有 target_hosts 命中")

    if hit:
        ops = hit.get("operators") or []
        print()
        print("         命中规则：%s  %s 分" % (hit.get("matched_rules"), hit.get("risk_score")))
        print("         涉及操作员：%s" % (", ".join(ops) if ops else "(未返回)"))

        # 主机信息要查详情才有：列表接口只给操作员，不给每条事件的 host_id。
        hosts = []
        eid = hit.get("event_id") or ""
        if eid:
            st, det = http_json(server + "/collusion/events/detail?id=" + eid)
            if st == 200 and isinstance(det, dict):
                for item in det.get("evidence_timeline") or []:
                    h = item.get("server_id") or item.get("host_id") or ""
                    if h and h not in hosts:
                        hosts.append(h)
                print("         涉及主机  ：%s" % (", ".join(hosts) if hosts else "(未返回)"))
                print("         证据时间线：")
                for item in det.get("evidence_timeline") or []:
                    print("           %-8s %-16s %-30s @ %s" % (
                        item.get("oper_id", ""),
                        item.get("action_norm") or item.get("op_type") or "",
                        (item.get("res_key") or "")[:30],
                        item.get("server_id") or item.get("host_id") or "?"))

        check("涉及两个不同操作员", len(ops) >= 2, "operators=%s" % ops)
        if hosts:
            check("涉及两台不同主机", len(set(hosts)) >= 2, "hosts=%s" % hosts)

    return report()


def report():
    print()
    print("=" * 66)
    total = len(PASSED) + len(FAILED)
    print(" 结果：%d/%d 通过" % (len(PASSED), total))
    if FAILED:
        print(" 未通过：")
        for f in FAILED:
            print("   - " + f)
    else:
        print(" 跨机跨人聚合成立：两台机器的日志被合并判定为同一次合谋。")
    print("=" * 66)
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
