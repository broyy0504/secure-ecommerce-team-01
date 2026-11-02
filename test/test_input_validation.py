#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""输入校验与说明的可执行验收脚本。

把第 6-9 周阶段二「输入校验与说明」的三条要求变成可跑的检查：

  1. 每个入口校验类型、长度、格式（注册 / 登录 / 退出 / 本人信息）；
  2. 错误与日志不出现口令、派生值、密钥、栈信息；
  3. 说明里"调用了第 5 周 src/crypto/ 的哪个函数"能被本脚本复算出来。

用法：
    python test/test_input_validation.py

退出码 0 表示全部通过，1 表示有检查未通过。无第三方依赖。
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from user import password_port  # noqa: E402
from user.errors import (  # noqa: E402
    ERROR_CODES,
    RESPONSE_KEYS,
    ApiError,
    assert_closed_response,
    new_trace_id,
)
from user.logging_utils import (  # noqa: E402
    get_logger,
    handle_unexpected,
    log_event,
    mask_account,
    mask_email,
    mask_phone,
    redact_text,
)
from user.validation import (  # noqa: E402
    LoginInput,
    RegisterInput,
    Secret,
    validate_login,
    validate_logout,
    validate_me,
    validate_register,
)

# ---------------------------------------------------------------------------
# 测试脚手架
# ---------------------------------------------------------------------------

results: List[Tuple[bool, str, str]] = []

# 所有日志统一收进这里，方便检索"日志里到底有没有口令"
LOG_BUFFER = io.StringIO()


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((bool(ok), name, detail))


def reset_logs() -> None:
    LOG_BUFFER.seek(0)
    LOG_BUFFER.truncate(0)


def logs() -> str:
    return LOG_BUFFER.getvalue()


def setup_logging() -> None:
    class _TraceFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            if not hasattr(record, "trace_id"):
                record.trace_id = "-"
            return super().format(record)

    handler = logging.StreamHandler(LOG_BUFFER)
    # 与线上格式一致地把 traceId 打在行首，便于检查"响应与日志同一编号"
    handler.setFormatter(_TraceFormatter("%(trace_id)s %(message)s"))
    logger = get_logger()
    logger.handlers = [handler]
    logger.propagate = False


def body(**fields: Any) -> bytes:
    return json.dumps(fields, ensure_ascii=False).encode("utf-8")


def expect_error(
    fn,
    *,
    code: str,
    reasons: Optional[Dict[str, str]] = None,
    trace_id: str = "",
) -> Optional[ApiError]:
    """调用 fn，断言它抛指定错误码；返回异常供后续检查响应体。"""
    try:
        fn()
    except ApiError as exc:
        check(exc.code == code, f"错误码应为 {code}", f"实际 {exc.code}")
        if trace_id:
            response = exc.to_response(trace_id)
            check(
                response["traceId"] == trace_id,
                "响应 traceId 与日志编号一致",
                f"响应 {response['traceId']}",
            )
        for field, reason in (reasons or {}).items():
            got = {d["field"]: d["reason"] for d in exc.details}
            check(
                got.get(field) == reason,
                f"details 应为 {field}:{reason}",
                f"实际 {got}",
            )
        return exc
    except Exception as exc:  # noqa: BLE001
        check(False, f"应抛 ApiError({code})", f"实际抛 {type(exc).__name__}")
        return None
    check(False, f"应抛 ApiError({code})", "未抛异常")
    return None


# ---------------------------------------------------------------------------
# 1. 结构层：Content-Type / 体积 / JSON 形状
# ---------------------------------------------------------------------------


def test_structure() -> None:
    ok_body = body(username="reader_01", phone="13800138000", password="BookStore#2026")

    exc = expect_error(
        lambda: validate_register(ok_body, content_type="text/plain"),
        code="VALIDATION_ERROR",
    )
    if exc:
        check(not exc.details, "Content-Type 错误不带 details", str(exc.details))

    huge = json.dumps(
        {"username": "reader_01", "phone": "13800138000", "password": "BookStore#2026", "x": "a" * 5000}
    ).encode("utf-8")
    expect_error(
        lambda: validate_register(huge), code="PAYLOAD_TOO_LARGE"
    )
    big_login = json.dumps({"account": "reader_01", "password": "x" * 3000}).encode("utf-8")
    expect_error(lambda: validate_login(big_login), code="PAYLOAD_TOO_LARGE")

    expect_error(lambda: validate_register(b"{not json"), code="VALIDATION_ERROR")
    expect_error(lambda: validate_register(b"[1,2,3]"), code="VALIDATION_ERROR")
    expect_error(lambda: validate_register(b""), code="VALIDATION_ERROR")
    expect_error(
        lambda: validate_register(b'{"username":"a","username":"b"}'),
        code="VALIDATION_ERROR",
    )
    # 非 UTF-8 字节：严格解码失败，不猜编码
    expect_error(
        lambda: validate_register('{"username":"读者01"}'.encode("gbk")),
        code="VALIDATION_ERROR",
    )


# ---------------------------------------------------------------------------
# 2. 注册入口
# ---------------------------------------------------------------------------


def test_register_fields() -> None:
    # 合法：去首尾空白、手机号去连字符
    parsed = validate_register(
        body(username="  reader_01  ", phone="138-0013-8000", password="BookStore#2026")
    )
    check(isinstance(parsed, RegisterInput), "合法注册返回 RegisterInput")
    check(parsed.username == "reader_01", "username 去首尾空白", parsed.username)
    check(parsed.phone == "13800138000", "phone 去空格与连字符", parsed.phone)
    check(isinstance(parsed.password, Secret), "口令被包成 Secret")

    # 长度与格式
    expect_error(
        lambda: validate_register(body(phone="13800138000", password="BookStore#2026")),
        code="VALIDATION_ERROR",
        reasons={"username": "REQUIRED"},
    )
    expect_error(
        lambda: validate_register(body(username="ab", phone="13800138000", password="BookStore#2026")),
        code="VALIDATION_ERROR",
        reasons={"username": "TOO_SHORT"},
    )
    expect_error(
        lambda: validate_register(body(username="a" * 33, phone="13800138000", password="BookStore#2026")),
        code="VALIDATION_ERROR",
        reasons={"username": "TOO_LONG"},
    )
    for bad in ("reader 01", "读者reader", "reader-01", "reader\n01", "reader01!"):
        expect_error(
            lambda bad=bad: validate_register(
                body(username=bad, phone="13800138000", password="BookStore#2026")
            ),
            code="VALIDATION_ERROR",
            reasons={"username": "FORMAT_INVALID"},
        )

    # 类型：数字、布尔、null、数组都不是字符串
    for bad_type in (12345678, True, None, ["a"], {"a": 1}):
        expect_error(
            lambda bad_type=bad_type: validate_register(
                body(username=bad_type, phone="13800138000", password="BookStore#2026")
            ),
            code="VALIDATION_ERROR",
            reasons={"username": "TYPE_MISMATCH"},
        )

    # 手机号
    for bad_phone in ("12345678901", "1380013800", "138001380000", "+8613800138000", "1380013800a"):
        expect_error(
            lambda bad_phone=bad_phone: validate_register(
                body(username="reader_01", phone=bad_phone, password="BookStore#2026")
            ),
            code="VALIDATION_ERROR",
            reasons={"phone": "FORMAT_INVALID"},
        )


def test_register_password() -> None:
    base = {"username": "reader_01", "phone": "13800138000"}

    expect_error(
        lambda: validate_register(body(username="reader_01", phone="13800138000")),
        code="VALIDATION_ERROR",
        reasons={"password": "REQUIRED"},
    )
    expect_error(
        lambda: validate_register(body(**base, password="short1")),
        code="VALIDATION_ERROR",
        reasons={"password": "TOO_SHORT"},
    )
    expect_error(
        lambda: validate_register(body(**base, password="A1" * 40)),
        code="VALIDATION_ERROR",
        reasons={"password": "TOO_LONG"},
    )
    expect_error(
        lambda: validate_register(body(**base, password="aaaaaaaaaa")),
        code="VALIDATION_ERROR",
        reasons={"password": "FORMAT_INVALID"},
    )
    expect_error(
        lambda: validate_register(body(username="reader_01", phone="13800138000", password="reader_01")),
        code="VALIDATION_ERROR",
        reasons={"password": "FORMAT_INVALID"},
    )
    expect_error(
        lambda: validate_register(body(username="reader_01", phone="13800138000", password="13800138000")),
        code="VALIDATION_ERROR",
        reasons={"password": "FORMAT_INVALID"},
    )

    # 边界：64 个汉字（192 字节）应通过；65 个 4 字节字符应拒
    validate_register(body(**base, password="书" * 63 + "店"))
    check(True, "64 个汉字的口令通过（字符 64 / 字节 192）")
    expect_error(
        lambda: validate_register(body(**base, password="📕" * 65)),
        code="VALIDATION_ERROR",
        reasons={"password": "TOO_LONG"},
    )


def test_register_forbidden_and_unknown() -> None:
    exc = expect_error(
        lambda: validate_register(
            body(username="reader_01", phone="13800138000", password="BookStore#2026", role="admin")
        ),
        code="VALIDATION_ERROR",
        reasons={"role": "NOT_ALLOWED"},
    )
    if exc:
        check(True, "禁用字段 role 被拒并点名")

    # 任意未知字段：拒绝，但不回显字段名（名字是调用方构造的）
    hostile_key = "Role' OR 1=1--"
    exc = expect_error(
        lambda: validate_register(
            json.dumps(
                {
                    "username": "reader_01",
                    "phone": "13800138000",
                    "password": "BookStore#2026",
                    hostile_key: "x",
                }
            ).encode("utf-8")
        ),
        code="VALIDATION_ERROR",
    )
    if exc:
        dumped = json.dumps(exc.to_response(), ensure_ascii=False)
        check(hostile_key not in dumped, "响应不回显攻击者构造的字段名")
        check(not exc.details, "未知字段不带 details", str(exc.details))

    # 多个字段同时错：一次返回多条
    exc = expect_error(
        lambda: validate_register(body(username="ab", phone="123", password="x")),
        code="VALIDATION_ERROR",
    )
    if exc:
        got = {d["field"] for d in exc.details}
        check(
            got == {"username", "phone", "password"},
            "多处错误一次返回",
            str(sorted(got)),
        )


# ---------------------------------------------------------------------------
# 3. 登录入口
# ---------------------------------------------------------------------------


def test_login() -> None:
    parsed = validate_login(body(account=" 138-0013-8000 ", password="BookStore#2026"))
    check(isinstance(parsed, LoginInput), "合法登录返回 LoginInput")
    check(parsed.account == "13800138000", "账号归一化为手机号", parsed.account)
    check(parsed.account_kind == "phone", "识别为手机号登录", parsed.account_kind)

    parsed = validate_login(body(account="reader_01", password="BookStore#2026"))
    check(parsed.account_kind == "username", "识别为登录名登录", parsed.account_kind)

    expect_error(
        lambda: validate_login(body(account="abc", password="BookStore#2026")),
        code="VALIDATION_ERROR",
        reasons={"account": "TOO_SHORT"},
    )
    expect_error(
        lambda: validate_login(body(account="reader 01!", password="BookStore#2026")),
        code="VALIDATION_ERROR",
        reasons={"account": "FORMAT_INVALID"},
    )
    expect_error(
        lambda: validate_login(body(account="reader_01", password="short")),
        code="VALIDATION_ERROR",
        reasons={"password": "TOO_SHORT"},
    )
    # 登录只校长度：全同字符在这里放行，交给认证流程统一回 401
    validate_login(body(account="reader_01", password="aaaaaaaa"))
    check(True, "登录不做强度判断（全同字符放行到认证）")

    expect_error(
        lambda: validate_login(body(account="reader_01", password="BookStore#2026", rememberMe=True)),
        code="VALIDATION_ERROR",
        reasons={"rememberMe": "NOT_ALLOWED"},
    )
    expect_error(
        lambda: validate_login(body(account="reader_01", password="BookStore#2026", role="admin")),
        code="VALIDATION_ERROR",
        reasons={"role": "NOT_ALLOWED"},
    )


# ---------------------------------------------------------------------------
# 4. 退出与本人信息
# ---------------------------------------------------------------------------


def test_logout_and_me() -> None:
    validate_logout(None)
    check(True, "退出：无请求体通过")
    validate_logout(b"")
    check(True, "退出：空字节通过")
    validate_logout(b"{}")
    check(True, "退出：空对象通过")

    exc = expect_error(
        lambda: validate_logout(body(userId="10001")), code="VALIDATION_ERROR"
    )
    if exc:
        check(not exc.details, "退出带字段时不回显字段名", str(exc.details))
    expect_error(lambda: validate_login(b'{"account":"reader_01","password":"BookStore#2026","x":1}'),
                 code="VALIDATION_ERROR")

    ignored = validate_me(query={"userId": "10001", "role": "admin"})
    check(
        ignored == ["userId", "role"],
        "本人信息：查询参数被忽略并记审计",
        str(ignored),
    )
    check("ignored_query_param" in logs(), "审计日志记录了被忽略的参数")
    check("10001" not in logs(), "审计日志不记参数值")

    expect_error(lambda: validate_me(body(userId="10001")), code="VALIDATION_ERROR")


# ---------------------------------------------------------------------------
# 5. 错误响应契约
# ---------------------------------------------------------------------------


def test_error_contract() -> None:
    tid = new_trace_id()
    check(len(tid) == 16 and all(c in "0123456789abcdef" for c in tid), "traceId 为 16 位十六进制", tid)

    exc = ApiError("VALIDATION_ERROR", [{"field": "password", "reason": "TOO_LONG"}])
    response = exc.to_response(tid)
    check(set(response) <= set(RESPONSE_KEYS), "响应只含契约字段", str(sorted(response)))
    assert_closed_response(response)
    check(exc.status == 400, "VALIDATION_ERROR 对应 400", str(exc.status))
    check(response["message"] == "请求参数不合法", "文案为契约固定文案", str(response["message"]))

    # 八类错误的响应体逐条检查
    for code in (
        "VALIDATION_ERROR",
        "AUTH_INVALID_CREDENTIALS",
        "AUTH_UNAUTHENTICATED",
        "AUTH_FORBIDDEN",
        "RESOURCE_NOT_FOUND",
        "USER_ALREADY_EXISTS",
        "RATE_LIMITED",
        "INTERNAL_ERROR",
    ):
        body_ = ApiError(code).to_response(new_trace_id())
        assert_closed_response(body_)
        status = ERROR_CODES[code][0]
        check(
            body_["message"] == ERROR_CODES[code][1],
            f"{code} 文案与契约一致",
            body_["message"],
        )
        check(status in (400, 401, 403, 404, 409, 413, 429, 500), f"{code} 状态码合法", str(status))

    # 500 只有三样东西
    internal = ApiError("INTERNAL_ERROR").to_response(tid)
    check("details" not in internal, "500 响应不含 details")

    # 非法错误码拼写不得成为对外响应
    try:
        ApiError("VALIDATION_ERR0R")
        check(False, "未登记错误码被拒绝", "未抛异常")
    except ValueError:
        check(True, "未登记错误码被拒绝（编码错误不变成对外响应）")

    # detail 只接受枚举与合法字段名（形状检查；列名拦截靠调用点的字段白名单）
    for bad_field in ("password;DROP", "", "口令", "a b", "1password", "password\x00"):
        try:
            ApiError("VALIDATION_ERROR", [{"field": bad_field, "reason": "REQUIRED"}])
            check(False, f"非法 detail.field 被拒: {bad_field!r}", "未抛异常")
        except ValueError:
            check(True, f"非法 detail.field 被拒: {bad_field!r}")

    try:
        ApiError("VALIDATION_ERROR", [{"field": "password", "reason": "TOO_WEAK"}])
        check(False, "detail.reason 只接受封闭枚举", "未抛异常")
    except ValueError:
        check(True, "detail.reason 只接受封闭枚举")


# ---------------------------------------------------------------------------
# 6. 日志与异常：不出现口令、派生值、密钥、栈信息
# ---------------------------------------------------------------------------


def test_log_redaction() -> None:
    password = "BookStore#2026!"
    stored = password_port.hash_password(password)
    salt_segment = password_port.split_stored(stored)["salt"]

    # 6.1 校验失败的日志里没有口令
    reset_logs()
    expect_error(
        lambda: validate_register(body(username="ab", phone="13800138000", password=password)),
        code="VALIDATION_ERROR",
    )
    log_text = logs()
    check("validation_failed" in log_text, "校验失败留下日志")
    check(password not in log_text, "日志不含口令明文")
    check("pbkdf2_sha256$" not in log_text, "日志不含派生值存储串")

    # 6.2 直接 print / 格式化 Secret 也不泄露
    reset_logs()
    secret = Secret(password)
    check(password not in repr(secret), "Secret 的 repr 不含明文", repr(secret))
    check(password not in str(secret), "Secret 的 str 不含明文", str(secret))
    check(password not in f"{secret}", "Secret 的格式化不含明文", f"{secret}")
    parsed = validate_register(
        body(username="reader_01", phone="13800138000", password=password)
    )
    check(password not in repr(parsed), "校验结果对象的 repr 不含明文", repr(parsed))

    # 6.3 有人硬要记口令：键级与值级脱敏都要挡住
    logger = get_logger()
    log_event(logger, "login_attempt", password=password, account="reader_01")
    logger.info("raw password is %s", password)
    logger.info("stored hash: %s", stored)
    logger.info("salt segment: %s", salt_segment)
    log_text = logs()
    check(password not in log_text, "日志不含口令（键级 + 值级脱敏）", log_text[:120])
    check("pbkdf2_sha256$" not in log_text, "日志不含派生值存储串")
    check(salt_segment not in log_text, "日志不含盐")
    check(log_text.count("<redacted>") >= 3, "敏感值被替换为 <redacted>")

    # 6.4 未预期异常：不记栈、不记异常消息、响应只有三样
    reset_logs()
    tid = new_trace_id()
    boom = ValueError("SELECT * FROM user_account WHERE password='x'")
    response = handle_unexpected(boom, stage="register", trace_id=tid)
    log_text = logs()
    check(response["code"] == "INTERNAL_ERROR", "未预期异常对外为 INTERNAL_ERROR")
    check(response["traceId"] == tid, "500 响应带同一个 traceId")
    check("details" not in response, "500 响应不含 details")
    check(set(response) <= set(RESPONSE_KEYS), "500 响应只含契约字段")
    check(tid in log_text, "日志与响应共用同一个 traceId")
    check("ValueError" in log_text, "日志记异常类型便于定位")
    for needle in ("SELECT", "user_account", "Traceback", "File \"", "line "):
        check(needle not in logs(), f"日志不含 {needle}")
        check(
            needle not in json.dumps(response, ensure_ascii=False),
            f"500 响应不含 {needle}",
        )

    # 6.5 审计脱敏
    check(mask_phone("13800138000") == "138****8000", "手机号脱敏", mask_phone("13800138000"))
    check(mask_email("reader01@example.com").endswith("@example.com"), "邮箱脱敏保留域名", mask_email("reader01@example.com"))
    check("13800138000" not in mask_account("13800138000"), "账号脱敏不返回完整手机号", mask_account("13800138000"))
    check(redact_text("token=abc123def456") == "token=<redacted>", "键值形态的令牌被替换", redact_text("token=abc123def456"))


# ---------------------------------------------------------------------------
# 7. 说明里的"调用第 5 周哪个函数"可复算
# ---------------------------------------------------------------------------


def test_crypto_port() -> None:
    params = password_port.parameters()
    check(params["algo"] == "pbkdf2_sha256", "算法标识为 pbkdf2_sha256", str(params["algo"]))
    check(params["iterations"] == 600000, "迭代次数 600000", str(params["iterations"]))
    check(params["salt_bytes"] == 16, "盐 16 字节", str(params["salt_bytes"]))
    check(params["derived_bytes"] == 32, "派生值 32 字节", str(params["derived_bytes"]))

    password = "BookStore#2026"
    stored = password_port.hash_password(password)
    columns = password_port.split_stored(stored)
    check(set(columns) == {"algo", "iterations", "salt", "derived"}, "存储串可拆成四列", str(sorted(columns)))
    check(columns["iterations"] == "600000", "四列中的迭代次数正确", columns["iterations"])
    check(password not in stored, "存储串不含口令明文")

    check(password_port.verify_password(password, stored) is True, "正确口令验证通过")
    check(password_port.verify_password(password + "x", stored) is False, "错误口令验证失败")
    check(password_port.verify_password(password, "broken") is False, "损坏的存储串不抛异常")
    check(
        password_port.hash_password(password) != stored,
        "同一口令两次哈希不同（盐随机）",
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main() -> int:
    setup_logging()

    test_structure()
    test_register_fields()
    test_register_password()
    test_register_forbidden_and_unknown()
    test_login()
    test_logout_and_me()
    test_error_contract()
    test_log_redaction()
    test_crypto_port()

    passed = sum(1 for ok, _, _ in results if ok)
    failed = [(name, detail) for ok, name, detail in results if not ok]

    for ok, name, detail in results:
        if not ok:
            print(f"  FAIL  {name}  {detail}")
    print(f"\n共 {len(results)} 项，通过 {passed} 项，未通过 {len(failed)} 项。")
    if failed:
        print("结果：有检查未通过。")
        return 1
    print("结果：输入校验、错误与日志脱敏、第 5 周密码学调用口径全部通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
