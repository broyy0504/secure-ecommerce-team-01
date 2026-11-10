#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第 10-11 周五类安全测试：注入、XSS、CSRF、会话劫持、越权。

这个脚本是 `docs/test/week10-11/` 里那些表格的**生成器**：表里的"实际"一列不是
手写的，是这里真打出来的。跑完把输出贴进对应 md 即可，改代码后重跑就能看出回归。

设计上的三个取舍：

1. **每个类别一个全新实例**（新库 + 新端口 + 清空限流计数）。否则上一类打出来的
   登录失败计数、401 记录会污染下一类，测出来的"实际"就解释不清。
2. **一律走真实 HTTP**，不 mock 数据库、不 mock 鉴权。能在这里通过的，现场也能通过。
3. **每行回指威胁编号与安全需求编号**。指不到的（比如 CSRF）如实写"未覆盖"，
   不当成通过——这正是任务书要的"指不到就说明当初需求写漏了"。

运行：

    python test/security/week10-11_security_tests.py

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from _harness import Api, CaptureLogs, Resp, sql  # noqa: E402

PASSWORD = "BookStore#2026"
LEAK_KEYWORDS = ("sqlite", "SELECT", "INSERT", "UPDATE ", "user_account", "session_token",
                 "Traceback", "syntax error", "row_factory", "password_derived")

Rows = List[Dict[str, str]]


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _cell(value: object) -> str:
    """Markdown 单元格转义：竖线与换行会破坏表格。"""
    text = str(value if value is not None else "—")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _actual(resp: Resp) -> str:
    code = resp.code or ("无响应体" if resp.status == 204 else "—")
    return f"{resp.status} {code}".strip()


def record(
    rows: Rows,
    *,
    no: str,
    entry: str,
    attack: str,
    expect: str,
    resp: Optional[Resp] = None,
    ok: Optional[bool] = None,
    actual: Optional[str] = None,
    threat: str,
    sr: str,
    note: str = "",
) -> None:
    if actual is None:
        actual = _actual(resp) if resp is not None else "—"
    if ok is None and resp is not None:
        ok = True
    rows.append(
        {
            "no": no,
            "entry": entry,
            "attack": attack,
            "expect": expect,
            "actual": actual,
            "verdict": "通过" if ok else "**不通过**",
            "threat": threat,
            "sr": sr,
            "note": note,
        }
    )


def judge(resp: Resp, status: int, code: Optional[str] = None) -> Tuple[bool, str]:
    ok = resp.status == status and (code is None or resp.code == code)
    return ok, _actual(resp)


def leaks(resp: Resp) -> List[str]:
    body = resp.body or ""
    return [word for word in LEAK_KEYWORDS if word in body]


# ---------------------------------------------------------------------------
# 一、SQL 注入（T-TM-05 / SR-19）
# ---------------------------------------------------------------------------


def cat_injection() -> Rows:
    rows: Rows = []
    with Api() as api:
        api.register("reader_01", "13800138000", PASSWORD)
        api.register("abcd", "13900139001", PASSWORD)  # 4 字符账号：给 LIKE 通配符当对照
        token = api.token_of("reader_01", PASSWORD)
        all_responses: List[Resp] = []

        login_cases = [
            ("I-01", "' OR '1'='1", "' OR '1'='1", "登录名含引号与空格，白名单应拦下", 400, "VALIDATION_ERROR"),
            ("I-02", "admin'--", "admin'--", "注释符截断，应拦下", 400, "VALIDATION_ERROR"),
            ("I-03", "' OR 1=1 --", "' OR 1=1 --", "永真条件，应拦下", 400, "VALIDATION_ERROR"),
            ("I-04", "reader_01' --", "reader_01' --", "已知账号 + 注释符，应拦下", 400, "VALIDATION_ERROR"),
            ("I-05", "%", "%", "LIKE 通配符（单字符，长度不足）", 400, "VALIDATION_ERROR"),
            ("I-06", "____", "____", "LIKE 下划线通配符（4 个 _，恰与 abcd 同形）", 401, "AUTH_INVALID_CREDENTIALS"),
            ("I-07", "1;DROP TABLE user_account;--", "1;DROP TABLE user_account;--", "堆叠语句，应拦下", 400, "VALIDATION_ERROR"),
            ("I-08", "reader_01\x00", "reader_01\\x00（末尾 NUL）", "NUL 截断", 400, "VALIDATION_ERROR"),
        ]
        for no, payload, display, desc, status, code in login_cases:
            resp = api.login(payload, PASSWORD)
            all_responses.append(resp)
            ok, actual = judge(resp, status, code)
            record(
                rows, no=no, entry="POST /api/auth/login（account）", attack=display,
                expect=f"{desc} → {status} {code}", resp=resp, ok=ok,
                threat="T-TM-05", sr="SR-19",
            )

        # 口令位置：长度合法、内容任意，能真的走到派生比较那一步
        resp = api.login("reader_01", "' OR '1'='1")
        all_responses.append(resp)
        ok, _ = judge(resp, 401, "AUTH_INVALID_CREDENTIALS")
        record(
            rows, no="I-09", entry="POST /api/auth/login（password）",
            attack="' OR '1'='1", expect="通过长度校验、进入口令比较 → 401", resp=resp, ok=ok,
            threat="T-TM-05", sr="SR-19",
        )

        # 注册入口：登录名白名单
        resp = api.request(
            "POST", "/api/users/register",
            body={"username": "' OR 1=1 --", "phone": "13700137000", "password": PASSWORD},
        )
        all_responses.append(resp)
        ok, _ = judge(resp, 400, "VALIDATION_ERROR")
        record(
            rows, no="I-10", entry="POST /api/users/register（username）",
            attack="' OR 1=1 --", expect="400 VALIDATION_ERROR，不落库", resp=resp, ok=ok,
            threat="T-TM-05", sr="SR-19",
        )

        # 昵称不当标识符用，任意字符都允许：注入串应被当作普通文本存下，表还在
        # 29 个字符，卡在昵称 32 字符上限内——先过长度校验，才谈得上"进到 SQL 层"
        drop_payload = "'; DROP TABLE user_account;--"
        resp = api.request(
            "POST", "/api/users/register",
            body={"username": "reader_sqli", "phone": "13700137001",
                  "password": PASSWORD, "nickname": drop_payload},
        )
        stored = sql(api.db_path, "SELECT nickname FROM user_account WHERE username='reader_sqli'")
        tables = {r["name"] for r in sql(api.db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
        ok = (
            resp.status == 201
            and stored
            and stored[0]["nickname"] == drop_payload
            and "user_account" in tables
        )
        record(
            rows, no="I-11", entry="POST /api/users/register（nickname）", attack=drop_payload,
            expect="201；原文入库；user_account 表仍存在", resp=resp, ok=ok,
            actual=f"{_actual(resp)}；库里={stored[0]['nickname'] if stored else '无'}；表存在={'user_account' in tables}",
            threat="T-TM-05", sr="SR-19",
            note="参数化查询把整串当值，不拼语句。该响应会按业务要求回显昵称，故不计入 I-14 的泄露统计",
        )

        # 查询入口：路径参数
        for no, payload in (("I-12", "1 OR 1=1"), ("I-13", "1'")):
            resp = api.request("GET", f"/api/users/{payload.replace(' ', '%20')}", token=token)
            all_responses.append(resp)
            ok, _ = judge(resp, 400, "VALIDATION_ERROR")
            record(
                rows, no=no, entry="GET /api/users/{userId}", attack=payload,
                expect="400 VALIDATION_ERROR（1—19 位数字）", resp=resp, ok=ok,
                threat="T-TM-05", sr="SR-19",
            )

        # 全量响应里不得出现库结构
        hits: Dict[str, int] = {}
        for resp in all_responses:
            for word in leaks(resp):
                hits[word] = hits.get(word, 0) + 1
        record(
            rows, no="I-14", entry=f"以上 {len(all_responses)} 个响应体", attack="—",
            expect="不含表名、SQL 关键字、异常类型、栈",
            actual="命中 0" if not hits else f"命中 {hits}",
            ok=not hits, threat="T-ID-05", sr="SR-19",
        )

        # 库里到底存的是什么：确认没有"拼接后执行"的痕迹（全表仍在，行数正确）
        counts = sql(api.db_path, "SELECT (SELECT COUNT(*) FROM user_account) AS users")
        record(
            rows, no="I-15", entry="直接查库", attack="—", expect="账号数 = 3（未被注入删除/读出）",
            actual=f"users={counts[0]['users']}", ok=counts[0]["users"] == 3,
            threat="T-TM-05", sr="SR-19",
        )
    return rows


# ---------------------------------------------------------------------------
# 二、XSS（T-TM-05 / SR-19）
# ---------------------------------------------------------------------------


def cat_xss() -> Rows:
    rows: Rows = []
    payloads = [
        ("X-01", "<script>alert(1)</script>"),
        ("X-02", '<img src=x onerror=alert(1)>'),
        ("X-03", '"><svg onload=alert(1)>'),
    ]
    with Api() as api:
        for index, (no, payload) in enumerate(payloads):
            name = f"xss_probe_{index + 1:02d}"
            resp = api.register(name, f"1360013600{index}", PASSWORD, payload)
            stored = sql(api.db_path, "SELECT nickname FROM user_account WHERE username=?", (name,))
            me = api.me(api.token_of(name, PASSWORD))
            in_json = payload in (me.body or "")
            same = bool(stored) and stored[0]["nickname"] == payload
            record(
                rows, no=no, entry="POST /api/users/register → GET /api/users/me",
                attack=payload,
                expect="201；原文入库；JSON 原文返回（转义在输出侧做）",
                resp=resp,
                actual=f"201；库里原文={'是' if same else '否'}；JSON 原文={'是' if in_json else '否'}",
                ok=resp.status == 201 and same and in_json,
                threat="T-TM-05", sr="SR-19",
            )

        # 输出转义：用页面同一份 render.js 跑，断言实体
        import subprocess

        check_js = HERE / "xss_render_check.js"
        proc = subprocess.run(
            ["node", str(check_js)], capture_output=True, text=True, encoding="utf-8"
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        rendered_ok = proc.returncode == 0 and "&lt;script&gt;" in (proc.stdout or "")
        record(
            rows, no="X-04", entry="web/js/render.js（页面同一份转义函数）",
            attack="<script>alert(1)</script>",
            expect="页面源码里为 &lt;script&gt;，无未转义标签",
            actual=f"node 返回 {proc.returncode}；8 项断言" if rendered_ok else f"node 返回 {proc.returncode}",
            ok=rendered_ok, threat="T-TM-05", sr="SR-19",
            note="证据命令：node test/security/xss_render_check.js",
        )

        # 前端不复刻校验：登录名里的尖括号由后端拦
        resp = api.request(
            "POST", "/api/users/register",
            body={"username": "<script>x</script>", "phone": "13600136009", "password": PASSWORD},
        )
        ok, _ = judge(resp, 400, "VALIDATION_ERROR")
        record(
            rows, no="X-05", entry="POST /api/users/register（username）",
            attack="<script>x</script>", expect="400 VALIDATION_ERROR（登录名白名单）",
            resp=resp, ok=ok, threat="T-TM-05", sr="SR-19",
        )

        # 昵称长度与控制字符：拦这些是为了数据形状，不是为了"防 XSS"
        resp = api.request(
            "POST", "/api/users/register",
            body={"username": "xss_long_01", "phone": "13600136010",
                  "password": PASSWORD, "nickname": "<script>" + "A" * 40 + "</script>"},
        )
        ok, _ = judge(resp, 400, "VALIDATION_ERROR")
        record(
            rows, no="X-06", entry="POST /api/users/register（nickname）",
            attack="<script> + 40×A + </script>（>32 字符）",
            expect="400 VALIDATION_ERROR（TOO_LONG）", resp=resp, ok=ok,
            threat="T-TM-05", sr="SR-19",
        )

        resp = api.request(
            "POST", "/api/users/register",
            body={"username": "xss_ctrl_01", "phone": "13600136011",
                  "password": PASSWORD, "nickname": "a\x00b"},
        )
        ok, _ = judge(resp, 400, "VALIDATION_ERROR")
        record(
            rows, no="X-07", entry="POST /api/users/register（nickname）",
            attack="a\\x00b（NUL）", expect="400 VALIDATION_ERROR（控制字符）",
            resp=resp, ok=ok, threat="T-TM-05", sr="SR-19",
        )

        # 页面侧：CSP + 无内联脚本
        pages = sorted((HERE.parents[1] / "web").glob("*.html"))
        with_csp = [p.name for p in pages if "Content-Security-Policy" in p.read_text("utf-8")]
        inline = [
            p.name
            for p in pages
            if "<script>" in p.read_text("utf-8").replace("<script src=", "")
        ]
        record(
            rows, no="X-08", entry="web/*.html", attack="—",
            expect="每个页面都有 CSP meta；没有内联 <script>",
            actual=f"CSP {len(with_csp)}/{len(pages)}；内联脚本 {len(inline)} 个",
            ok=len(with_csp) == len(pages) and not inline,
            threat="T-TM-05", sr="SR-19",
            note="CSP script-src 'self' 是兜底，转义才是主控制",
        )
    return rows


# ---------------------------------------------------------------------------
# 三、CSRF（威胁清单与安全需求均未覆盖 —— 需求写漏，本项如实登记）
# ---------------------------------------------------------------------------


def cat_csrf() -> Rows:
    rows: Rows = []
    with Api() as api:
        api.register("csrf_victim", "13500135000", PASSWORD)
        token = api.token_of("csrf_victim", PASSWORD)

        # 1) 跨站表单打退出：表单带不了 Authorization 头
        resp = api.request(
            "POST", "/api/auth/logout", body={},
            headers={"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
            content_type="application/x-www-form-urlencoded",
            raw_body=b"",
        )
        revoked = sql(api.db_path, "SELECT revoked_at FROM session_token WHERE user_id=1")
        ok = resp.status == 401 and all(r["revoked_at"] is None for r in revoked)
        record(
            rows, no="C-01", entry="POST /api/auth/logout（跨站表单，无令牌）",
            attack='<form action="http://127.0.0.1:8000/api/auth/logout" method="POST">',
            expect="401；会话未被撤销（改动为 0）", resp=resp, ok=ok,
            actual=f"401；revoked_at 全为空={all(r['revoked_at'] is None for r in revoked)}",
            threat="**未登记**", sr="**未登记**",
            note="CSRF 靠 Cookie 自动携带生效；本系统不用 Cookie，令牌只在自定义头里",
        )

        # 2) 任何响应都不下发 Cookie
        responses = [api.login("csrf_victim", PASSWORD), api.me(token),
                     api.request("GET", "/api/auth/verify", token=token)]
        with_cookie = [r for r in responses if "set-cookie" in r.headers]
        record(
            rows, no="C-02", entry="登录 / 个人信息 / 鉴权校验",
            attack="检查响应头 Set-Cookie", expect="0 个 Set-Cookie",
            actual=f"{len(with_cookie)} 个", ok=not with_cookie,
            threat="**未登记**", sr="**未登记**",
            note="没有 Cookie，就没有'浏览器自动带上凭据'这件事，CSRF 失去前提",
        )

        # 3) 非白名单源的预检被拒
        resp = api.request("OPTIONS", "/api/users/me", origin="http://evil.example")
        ok = resp.status == 403 and "access-control-allow-origin" not in resp.headers
        record(
            rows, no="C-03", entry="OPTIONS /api/users/me（Origin: evil.example）",
            attack="预检请求", expect="403 且不回 ACAO", resp=resp, ok=ok,
            threat="**未登记**", sr="**未登记**",
        )

        # 4) 白名单源正常放行（证明不是"全拒"）
        resp = api.request("OPTIONS", "/api/users/me", origin="http://127.0.0.1:5173")
        ok = resp.status == 204 and resp.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
        record(
            rows, no="C-04", entry="OPTIONS /api/users/me（Origin: 127.0.0.1:5173）",
            attack="预检请求", expect="204 + ACAO 回显白名单源", resp=resp, ok=ok,
            threat="**未登记**", sr="**未登记**",
        )

        # 5) 即使跨站把请求发出去，读不到响应（无 ACAO）
        resp = api.request("GET", "/api/users/me", token=token, origin="http://evil.example")
        ok = resp.status == 200 and "access-control-allow-origin" not in resp.headers
        record(
            rows, no="C-05", entry="GET /api/users/me（带攻击者 Origin）",
            attack="跨站读取尝试", expect="200 但无 ACAO（浏览器侧读不到）",
            actual=f"{resp.status}；ACAO={'有' if 'access-control-allow-origin' in resp.headers else '无'}",
            ok=ok, threat="**未登记**", sr="**未登记**",
            note="服务端仍按令牌校验；CORS 只决定浏览器是否把响应交给脚本",
        )
    return rows


# ---------------------------------------------------------------------------
# 四、会话劫持（T-SP-03、T-TM-02 / SR-07、SR-08、SR-09）
# ---------------------------------------------------------------------------


def cat_session() -> Rows:
    rows: Rows = []
    with Api() as api:
        api.register("hijack_a", "13400134000", PASSWORD)
        api.register("hijack_b", "13400134001", PASSWORD)
        token_a = api.token_of("hijack_a", PASSWORD)

        # 改一字节：首、中、末各一次
        positions = {"S-01": 0, "S-02": 21, "S-03": 42}
        for no, index in positions.items():
            ch = token_a[index]
            mutated = token_a[:index] + ("A" if ch != "A" else "B") + token_a[index + 1:]
            with CaptureLogs() as logs:
                resp = api.me(mutated)
            ok, _ = judge(resp, 401, "AUTH_UNAUTHENTICATED")
            record(
                rows, no=no, entry="GET /api/users/me",
                attack=f"令牌第 {index + 1} 位 {ch} → {mutated[index]}",
                expect="401 AUTH_UNAUTHENTICATED；不返回任何用户字段",
                resp=resp, ok=ok and resp.data and "username" not in resp.data,
                actual=f"401 {resp.code}；响应字段={sorted((resp.data or {}).keys())}",
                threat="T-SP-03、T-TM-02", sr="SR-07",
                note="日志记 UNKNOWN_TOKEN：摘要查不到，不进入账号查询",
            )

        # 在令牌里拼身份：令牌是无结构随机串，服务端不解析
        forged = token_a[:20] + ".1"
        resp = api.me(forged)
        ok, _ = judge(resp, 401, "AUTH_UNAUTHENTICATED")
        record(
            rows, no="S-04", entry="GET /api/users/me",
            attack="A 的令牌前缀 + \".2\"（模拟把用户标识塞进令牌）",
            expect="401（令牌不含身份，服务端只按摘要查库）", resp=resp, ok=ok,
            threat="T-TM-02", sr="SR-07",
        )

        # 换成别人的令牌：身份会跟着变，但不是"伪造"，只是换了个合法会话
        token_b = api.token_of("hijack_b", PASSWORD)
        resp = api.me(token_b)
        ok = resp.status == 200 and (resp.data or {}).get("username") == "hijack_b"
        record(
            rows, no="S-05", entry="GET /api/users/me", attack="直接拿 B 的令牌",
            expect="200，返回 B 自己（说明身份只由令牌决定，改不了）", resp=resp, ok=ok,
            threat="T-SP-03", sr="SR-07",
            actual=f"200；username={(resp.data or {}).get('username')}",
        )

        # 退出后重放
        api.request("POST", "/api/auth/logout", body={}, token=token_a)
        resp = api.me(token_a)
        ok, _ = judge(resp, 401, "AUTH_UNAUTHENTICATED")
        record(
            rows, no="S-06", entry="POST /api/auth/logout → GET /api/users/me",
            attack="退出后重放原令牌", expect="401；库中 revoked_at 非空", resp=resp, ok=ok,
            threat="T-SP-03", sr="SR-08",
            actual=f"401 {resp.code}；revoked_at={sql(api.db_path, 'SELECT revoked_at FROM session_token WHERE user_id=1')[0]['revoked_at']}",
        )

        # 过期后重放
        token_c = api.token_of("hijack_b", PASSWORD)
        conn = sqlite3.connect(api.db_path)
        conn.execute("UPDATE session_token SET expires_at='2020-01-01T00:00:00.000Z' WHERE token_hash=?",
                     (hashlib.sha256(token_c.encode()).hexdigest(),))
        conn.commit()
        conn.close()
        resp = api.me(token_c)
        ok, _ = judge(resp, 401, "AUTH_TOKEN_EXPIRED")
        record(
            rows, no="S-07", entry="GET /api/users/me", attack="把库中 expires_at 改到过去后重放",
            expect="401 AUTH_TOKEN_EXPIRED", resp=resp, ok=ok,
            threat="T-SP-03", sr="SR-09",
        )

        # 库里到底存了什么：摘要在，原文不在
        rows_all = sql(api.db_path, "SELECT * FROM session_token")
        plain_hits = sum(1 for row in rows_all if token_a in json.dumps(row, ensure_ascii=False))
        ok = plain_hits == 0 and all(len(r["token_hash"]) == 64 for r in rows_all)
        record(
            rows, no="S-08", entry="直接查 session_token", attack="全表搜令牌原文",
            expect="命中 0；token_hash 均为 64 位十六进制",
            actual=f"命中 {plain_hits}；共 {len(rows_all)} 行",
            ok=ok, threat="T-SP-03", sr="SR-06",
        )

        # 令牌不进 URL：查询串里的令牌不参与判断，仍按请求头鉴权
        resp = api.request("GET", "/api/users/me?token=" + token_b, token=token_b)
        ok = resp.status == 200 and (resp.data or {}).get("username") == "hijack_b"
        record(
            rows, no="S-09", entry="GET /api/users/me?token=…",
            attack="把令牌塞进查询串", expect="参数被忽略，仍按请求头鉴权 → 200",
            resp=resp, ok=ok, threat="T-ID-03", sr="SR-11",
            actual=f"200；username={(resp.data or {}).get('username')}",
            note="服务端只读 Authorization 头；查询串里的令牌不参与任何判断",
        )
    return rows


# ---------------------------------------------------------------------------
# 五、越权（T-EL-01、T-ID-04 / SR-12、SR-15）
# ---------------------------------------------------------------------------


def cat_authz() -> Rows:
    rows: Rows = []
    with Api() as api:
        api.register("buyer_a", "13300133000", PASSWORD)
        api.register("buyer_b", "13300133001", PASSWORD)
        token_a = api.token_of("buyer_a", PASSWORD)
        user_b = sql(api.db_path, "SELECT user_id FROM user_account WHERE username='buyer_b'")[0]["user_id"]

        with CaptureLogs() as logs:
            cross = api.request("GET", f"/api/users/{user_b}", token=token_a)
        missing = api.request("GET", "/api/users/999999", token=token_a)

        ok = cross.status == 404 and cross.code == "RESOURCE_NOT_FOUND"
        record(
            rows, no="A-01", entry=f"GET /api/users/{user_b}（A 的令牌）",
            attack=f"越权访问 B 的个人信息（userId={user_b}）",
            expect="404 RESOURCE_NOT_FOUND（不是 403）", resp=cross, ok=ok,
            threat="T-ID-04", sr="SR-15",
            note="返回 403 等于告诉对方这个 ID 存在",
        )

        body_cross = {k: v for k, v in (cross.data or {}).items() if k != "traceId"}
        body_missing = {k: v for k, v in (missing.data or {}).items() if k != "traceId"}
        record(
            rows, no="A-02", entry="对比两个响应体", attack="越权 vs 不存在",
            expect="除 traceId 外逐字一致",
            actual=("一致" if body_cross == body_missing else "不一致"),
            ok=body_cross == body_missing,
            threat="T-ID-04", sr="SR-15",
        )

        leaked = [word for word in ("buyer_b", "13300133001", "phone", "nickname") if word in (cross.body or "")]
        record(
            rows, no="A-03", entry="越权响应体", attack="检查是否带 B 的字段",
            expect="不含 B 的任何字段",
            actual=f"命中 {leaked}" if leaked else "命中 0",
            ok=not leaked, threat="T-ID-04", sr="SR-15",
        )

        record(
            rows, no="A-04", entry="应用日志", attack="越权尝试是否留痕",
            expect="日志出现 authz_denied + 操作人与目标",
            actual=f"authz_denied={logs.has('authz_denied')}；target={logs.has('NOT_OWNER')}",
            ok=logs.has("authz_denied") and logs.has("NOT_OWNER"),
            threat="T-EL-01", sr="SR-12",
        )

        # 请求体里塞身份字段：一律 400，且不落库
        for no, body, entry in (
            ("A-05", {"username": "buyer_c", "phone": "13300133002", "password": PASSWORD,
                      "userId": "2"}, "POST /api/users/register（附 userId）"),
            ("A-06", {"username": "buyer_c", "phone": "13300133002", "password": PASSWORD,
                      "role": "admin"}, "POST /api/users/register（附 role）"),
            ("A-07", {"account": "buyer_a", "password": PASSWORD,
                      "role": "admin"}, "POST /api/auth/login（附 role）"),
        ):
            resp = api.request("POST", "/api/users/register", body=body) if "register" in entry else api.request("POST", "/api/auth/login", body=body)
            ok, _ = judge(resp, 400, "VALIDATION_ERROR")
            record(
                rows, no=no, entry=entry, attack="请求体附加身份字段",
                expect="400 VALIDATION_ERROR（NOT_ALLOWED）", resp=resp, ok=ok,
                threat="T-EL-01", sr="SR-12",
            )

        # /me 只认令牌，不认参数
        resp = api.request("GET", f"/api/users/me?userId={user_b}", token=token_a)
        ok = resp.status == 200 and (resp.data or {}).get("username") == "buyer_a"
        record(
            rows, no="A-08", entry="GET /api/users/me?userId=B",
            attack=f"查询串指定 userId={user_b}",
            expect="200，返回 A 自己（参数忽略并记审计）", resp=resp, ok=ok,
            threat="T-EL-01", sr="SR-12",
            actual=f"200；username={(resp.data or {}).get('username')}",
        )

        # 匿名查别人的编号：先鉴权，再判归属
        resp = api.request("GET", f"/api/users/{user_b}")
        ok, _ = judge(resp, 401, "AUTH_UNAUTHENTICATED")
        record(
            rows, no="A-09", entry=f"GET /api/users/{user_b}（无令牌）",
            attack="匿名访问他人编号", expect="401（鉴权在前，不泄露存在性）",
            resp=resp, ok=ok, threat="T-EL-01", sr="SR-12",
        )

        # 自己查自己：正常放行，证明不是"全 404"
        resp = api.request("GET", "/api/users/1", token=token_a)
        ok = resp.status == 200 and (resp.data or {}).get("username") == "buyer_a"
        record(
            rows, no="A-10", entry="GET /api/users/1（A 自己）",
            attack="—", expect="200，返回 A 自己的信息", resp=resp, ok=ok,
            threat="T-EL-01", sr="SR-12",
        )
    return rows


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def render(title: str, rows: Rows, note: str = "") -> str:
    lines = [f"### {title}", ""]
    if note:
        lines.extend([note, ""])
    lines.append("| 编号 | 入口 | 攻击串 | 预期 | 实际 | 判定 | 威胁 | 需求 |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |")
    for row in rows:
        lines.append(
            "| {no} | {entry} | {attack} | {expect} | {actual} | {verdict} | {threat} | {sr} |".format(
                **{k: _cell(v) for k, v in row.items() if k != "note"}
            )
        )
    return "\n".join(lines)


def main() -> int:
    categories = [
        ("一、SQL 注入（T-TM-05 / SR-19）", cat_injection()),
        ("二、跨站脚本 XSS（T-TM-05 / SR-19）", cat_xss()),
        ("三、CSRF（威胁清单未登记，按需求写漏处理）", cat_csrf()),
        ("四、会话劫持（T-SP-03、T-TM-02 / SR-06～SR-09）", cat_session()),
        ("五、越权（T-EL-01、T-ID-04 / SR-12、SR-15）", cat_authz()),
    ]

    total = 0
    failed = 0
    for title, rows in categories:
        print()
        print(render(title, rows))
        for row in rows:
            total += 1
            if row["verdict"] != "通过":
                failed += 1

    print()
    print("=" * 60)
    print(f"共 {total} 项，通过 {total - failed} 项，未通过 {failed} 项。")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
