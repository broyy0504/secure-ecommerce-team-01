#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第 10-11 周主流程验收脚本：一条命令跑完"建表 → 注册 → 登录 → 鉴权 → 退出"。

与 `test/test_input_validation.py`（第 9 周，只测校验层）分工不同：这里测的是
**接起来的整条链路**，全部走真实 HTTP + 真实 SQLite 文件，不做 mock：

| 组 | 验的点 | 对应验收口径 |
| :--- | :--- | :--- |
| 1 | 空库建表、三张表齐全 | 空库一条命令建场景 |
| 2 | 注册成功、重复注册 409、库里只有口令四列 | SR-01/SR-02 |
| 3 | 登录拿令牌、令牌是随机串、库里只存摘要 | SR-06 |
| 4 | 个人信息只返回本人字段、不含派生值 | SR-12 |
| 5 | 不带令牌 / 改一字节 / 过期 → 401 | SR-07、SR-09 |
| 6 | 退出后旧令牌 401、重复退出仍 204 | SR-08 |
| 7 | 拿 A 的令牌查 B → 404 且响应体一致 | SR-15 |
| 8 | 连续失败 5 次后正确口令也 401、审计记锁定 | SR-05 |
| 9 | 单 IP 高频登录 → 429 | SR-20 |

运行：`python test/test_user_flow.py`

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(HERE / "security") not in sys.path:
    sys.path.insert(0, str(HERE / "security"))

from _harness import Api, sql  # noqa: E402

PASSWORD = "BookStore#2026"
results = []


def check(ok: bool, name: str, detail: object = "") -> None:
    results.append((bool(ok), name, detail))


def expect(resp, status: int, code: str | None, name: str) -> None:
    ok = resp.status == status and (code is None or resp.code == code)
    check(ok, name, f"实际 status={resp.status} code={resp.code}")


# ---------------------------------------------------------------------------
def test_schema(api: Api) -> None:
    names = {row["name"] for row in sql(api.db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("user_account", "session_token", "login_log"):
        check(table in names, f"建表：{table} 存在", sorted(names))


def test_register(api: Api) -> None:
    resp = api.register("reader_01", "13800138000", PASSWORD, "书虫")
    expect(resp, 201, None, "注册成功返回 201")
    data = resp.data or {}
    check(data.get("userId") == "1", "注册返回 userId", data.get("userId"))
    check(data.get("phoneMasked") == "138****8000", "手机号脱敏返回", data.get("phoneMasked"))
    check("password" not in str(data).lower(), "注册响应不含口令相关字段")

    rows = sql(api.db_path, "SELECT * FROM user_account WHERE username='reader_01'")
    check(len(rows) == 1, "库里只有一行账号")
    row = rows[0]
    columns = set(row)
    check(
        {"password_algo", "password_iterations", "password_salt", "password_derived"} <= columns,
        "口令四列齐全",
    )
    check(PASSWORD not in str(row.values()), "库行里不含口令明文")
    check(row["password_algo"] == "pbkdf2_sha256", "算法标识为 pbkdf2_sha256", row["password_algo"])
    check(int(row["password_iterations"]) >= 600000, "迭代次数 ≥ 600000", row["password_iterations"])
    check(len(row["password_salt"]) == 22 and len(row["password_derived"]) == 43, "盐/派生值长度符合建库约束")
    check(row["nickname"] == "书虫", "昵称原文入库", row["nickname"])

    # 同口令注册第二个账号：盐与派生值必须不同
    api.register("reader_02", "13800138001", PASSWORD)
    rows2 = sql(api.db_path, "SELECT * FROM user_account WHERE username='reader_02'")
    check(rows2[0]["password_salt"] != row["password_salt"], "同口令两账号的盐不同")
    check(rows2[0]["password_derived"] != row["password_derived"], "同口令两账号的派生值不同")

    dup = api.register("reader_01", "13800138002", PASSWORD)
    expect(dup, 409, "USER_ALREADY_EXISTS", "重复登录名 → 409")
    dup2 = api.register("reader_03", "13800138000", PASSWORD)
    expect(dup2, 409, "USER_ALREADY_EXISTS", "重复手机号 → 409")
    check(dup.message == dup2.message, "两种冲突的文案一致（不指出是哪一项）", dup.message)


def test_login_and_profile(api: Api) -> None:
    resp = api.login("reader_01", PASSWORD)
    expect(resp, 200, None, "登录成功返回 200")
    token = (resp.data or {}).get("accessToken", "")
    check(len(token) == 43, "令牌为 43 字符 base64url（256 位熵）", len(token))
    check((resp.data or {}).get("tokenType") == "Bearer", "tokenType 为 Bearer")
    check((resp.data or {}).get("expiresIn") == 7200, "有效期为 7200 秒")

    rows = sql(api.db_path, "SELECT * FROM session_token")
    check(len(rows) == 1, "登录写入一条会话")
    check(rows[0]["token_hash"] != token, "库里不存令牌原文")
    import hashlib

    check(rows[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest(), "库里存的是令牌的 SHA-256")
    check(token not in str(rows[0].values()), "会话行里搜不到令牌原文")

    me = api.me(token)
    expect(me, 200, None, "带令牌查个人信息 → 200")
    data = me.data or {}
    check(data.get("username") == "reader_01", "返回的是令牌对应用户", data.get("username"))
    for field in ("userId", "nickname", "phoneMasked", "status", "createdAt"):
        check(field in data, f"个人信息含字段 {field}")
    check("password_derived" not in str(data) and "passwordDerived" not in str(data), "个人信息不含派生值")

    verify = api.request("GET", "/api/auth/verify", token=token)
    expect(verify, 200, None, "鉴权校验 → 200")
    check((verify.data or {}).get("valid") is True, "鉴权校验返回 valid=true")
    check(0 < int((verify.data or {}).get("expiresIn", 0)) <= 7200, "鉴权校验给出剩余有效期")

    for field in ("cache-control", "x-content-type-options"):
        check(field in me.headers, f"响应头含 {field}")
    check(me.headers.get("cache-control") == "no-store", "Cache-Control 为 no-store（SR-11）")


def test_token_rejection(api: Api) -> None:
    token = api.token_of("reader_01", PASSWORD)

    expect(api.me(None), 401, "AUTH_UNAUTHENTICATED", "不带令牌 → 401")
    expect(api.me(""), 401, "AUTH_UNAUTHENTICATED", "空令牌 → 401")
    expect(api.request("GET", "/api/auth/verify"), 401, "AUTH_UNAUTHENTICATED", "鉴权校验不带令牌 → 401")

    bad_scheme = api.request("GET", "/api/users/me", headers={"Authorization": "Token " + token})
    expect(bad_scheme, 401, "AUTH_UNAUTHENTICATED", "认证方案不是 Bearer → 401")

    flipped_mid = token[:20] + ("A" if token[20] != "A" else "B") + token[21:]
    expect(api.me(flipped_mid), 401, "AUTH_UNAUTHENTICATED", "令牌中间改一字节 → 401")

    flipped_last = token[:-1] + ("A" if token[-1] != "A" else "B")
    expect(api.me(flipped_last), 401, "AUTH_UNAUTHENTICATED", "令牌末位改一字节 → 401")

    # 把"用户标识"拼进令牌：令牌是无结构随机串，服务端不解析，只查摘要
    forged = token[:22] + ".2"
    expect(api.me(forged), 401, "AUTH_UNAUTHENTICATED", "伪造'令牌.用户标识'结构 → 401")

    # 服务端判过期：把库里的 expires_at 改到过去
    conn = sqlite3.connect(api.db_path)
    conn.execute("UPDATE session_token SET expires_at='2020-01-01T00:00:00.000Z' WHERE user_id=1")
    conn.commit()
    conn.close()
    expect(api.me(token), 401, "AUTH_TOKEN_EXPIRED", "令牌过期 → 401 AUTH_TOKEN_EXPIRED")


def test_logout(api: Api) -> None:
    token = api.token_of("reader_01", PASSWORD)
    before = api.me(token)
    check(before.status == 200, "退出前令牌可用")

    out = api.request("POST", "/api/auth/logout", body={}, token=token)
    check(out.status == 204 and not out.body, "退出返回 204 且无响应体", out.status)
    check(sql(api.db_path, "SELECT * FROM session_token WHERE revoked_at IS NOT NULL"), "库里有撤销记录")

    expect(api.me(token), 401, "AUTH_UNAUTHENTICATED", "退出后旧令牌 → 401")
    again = api.request("POST", "/api/auth/logout", body={}, token=token)
    check(again.status == 204, "同一令牌再退一次仍是 204（幂等）", again.status)

    # 其它会话不受影响：另一台设备仍可用（多设备并存）
    other = api.token_of("reader_01", PASSWORD)
    check(api.me(other).status == 200, "撤销只影响当前会话，其它会话仍有效")


def test_cross_user(api: Api) -> None:
    a = api.token_of("reader_01", PASSWORD)
    b = api.token_of("reader_02", PASSWORD)

    own = api.request("GET", "/api/users/1", token=a)
    expect(own, 200, None, "A 查自己（/api/users/1）→ 200")

    cross = api.request("GET", "/api/users/2", token=a)
    expect(cross, 404, "RESOURCE_NOT_FOUND", "A 的令牌查 B → 404（不是 403）")
    missing = api.request("GET", "/api/users/999999", token=a)
    expect(missing, 404, "RESOURCE_NOT_FOUND", "查不存在的编号 → 404")

    same_body = (
        {k: v for k, v in (cross.data or {}).items() if k != "traceId"}
        == {k: v for k, v in (missing.data or {}).items() if k != "traceId"}
    )
    check(same_body, "越权响应与'不存在'响应除 traceId 外逐字一致", cross.data)
    check("reader_02" not in cross.body, "越权响应体不含 B 的任何字段", cross.body)

    ignored = api.request("GET", "/api/users/me?userId=2", token=a)
    expect(ignored, 200, None, "/me 带 userId 参数被忽略（仍返回 A 自己）")
    check((ignored.data or {}).get("username") == "reader_01", "忽略参数后返回的仍是令牌对应用户")

    check(api.me(b).status == 200, "B 自己的令牌不受影响")


def test_lockout(api: Api) -> None:
    api.register("reader_lock", "13900139000", PASSWORD)
    for index in range(5):
        resp = api.login("reader_lock", "WrongPass#2026")
        expect(resp, 401, "AUTH_INVALID_CREDENTIALS", f"第 {index + 1} 次错口令 → 401")

    locked = api.login("reader_lock", PASSWORD)
    expect(locked, 401, "AUTH_INVALID_CREDENTIALS", "锁定后用正确口令仍 401")
    check(locked.message == "账号或密码错误", "锁定时的文案与普通失败一致", locked.message)

    logs = sql(api.db_path, "SELECT result, failure_code FROM login_log WHERE failure_code='ACCOUNT_LOCKED'")
    check(bool(logs), "审计里记下锁定事实（内部可见）", logs)
    rows = sql(api.db_path, "SELECT failed_login_count, locked_until FROM user_account WHERE username='reader_lock'")
    check(int(rows[0]["failed_login_count"]) >= 5, "失败计数已累加", rows[0]["failed_login_count"])
    check(rows[0]["locked_until"] is not None, "locked_until 已写入", rows[0]["locked_until"])


def test_rate_limit() -> None:
    saved = {k: os.environ.get(k) for k in ("AUTH_RL_LOGIN_IP_LIMIT", "AUTH_RL_ENABLED")}
    os.environ["AUTH_RL_LOGIN_IP_LIMIT"] = "3"
    try:
        with Api() as api:
            api.register("reader_rl", "13700137000", PASSWORD)
            codes = []
            for _ in range(5):
                codes.append(api.login("reader_rl", "WrongPass#2026").status)
            check(429 in codes, "同 IP 高频登录触发 429", codes)
            check(codes.count(401) >= 1, "限流之前的请求仍是 401", codes)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ---------------------------------------------------------------------------
def main() -> int:
    with Api() as api:
        test_schema(api)
        test_register(api)
        test_login_and_profile(api)
        test_token_rejection(api)
        test_logout(api)
        test_cross_user(api)
        test_lockout(api)
    test_rate_limit()

    passed = sum(1 for ok, _, _ in results if ok)
    failed = [(name, detail) for ok, name, detail in results if not ok]
    for name, detail in failed:
        print(f"  FAIL  {name}  {detail}")
    print(f"\n共 {len(results)} 项，通过 {passed} 项，未通过 {len(failed)} 项。")
    if failed:
        print("结果：主流程验收未通过。")
        return 1
    print("结果：建表、注册、登录、鉴权、退出、越权、锁定、限流全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
