#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""注册、登录、退出、个人信息、鉴权校验的业务实现。

本文件只做业务判断与落库，不做三件已由别人做过的事：

| 不在这里做 | 在哪 |
| :--- | :--- |
| 请求体类型/长度/格式/禁用字段 | `validation.py`（第 9 周，169 项自测覆盖） |
| 令牌校验 | `auth.py` 的 `require_auth()`，唯一入口 |
| 错误码与对外文案 | `errors.py` 的封闭集，本文件只挑码，不改文案 |

两条安全语义在本层落地：

1. **登录失败四合一**（SR-04/SR-05）：账号不存在、口令错、被锁定、被停用，对外
   一律 `401 AUTH_INVALID_CREDENTIALS`，文案逐字相同；前三种还会各跑一次
   PBKDF2，让耗时也同量级。
2. **越权不泄露存在性**（SR-15）：按 id 查别人 → `404 RESOURCE_NOT_FOUND`，
   与"这个 id 不存在"是同一个响应，不用 `403`（`403` 等于告诉对方这个人存在）。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Dict, Mapping, Optional

from . import password, ratelimit, timeutil, tokens
from .auth import AuthContext
from .db import get_conn
from .errors import ApiError
from .logging_utils import get_logger, log_event, mask_account, mask_phone
from .validation import LoginInput, RegisterInput

# 连续失败 5 次锁 10 分钟。契约 §4.2 的锁定阈值本身还在 C-04 待裁决
# （SR-AUTH-002 取 5、FR-USER-007 取 10），这里取小值并对 IP 维度单独限流：
# 阈值越小，越不容易被"知道目标账号的人"用来锁死别人的账号（T-DN-01）。
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 600

# 角色：本期只有买家。角色表（app_role / user_role_relation）留到 II 阶段与管理端，
# 见 docs/handover/01 §5——现在写死一个常量，好过提前塞一张没人用的表。
DEFAULT_ROLE = "buyer"


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _phone_digest(phone: str) -> str:
    """手机号 → 查库/限流用的摘要。库里不存手机号明文。

    域分隔符 `bookstore:phone:` 的作用是让同一个串在不同用途下的摘要不同，
    避免"手机号摘要"被当成"账号摘要"复用。
    """
    return hashlib.sha256(f"bookstore:phone:{phone}".encode("utf-8")).hexdigest()


def _account_digest(account: str) -> str:
    return hashlib.sha256(f"bookstore:account:{account}".encode("utf-8")).hexdigest()


def _public_user(row: Mapping[str, object]) -> Dict[str, object]:
    """个人信息对外结构。**只**给这些字段，派生值、盐、手机号摘要一律不出库。"""
    return {
        "userId": str(row["user_id"]),
        "username": row["username"],
        "nickname": row["nickname"],
        "phoneMasked": row["phone_masked"],
        # 本期不采集邮箱；字段留着占位，II 阶段加 email 列后才有值（只能加不能改名）
        "emailMasked": None,
        "status": row["status"],
        "lastLoginAt": row["last_login_at"],
        "createdAt": row["created_at"],
    }


def _fetch_user(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM user_account WHERE user_id = ?", (user_id,)).fetchone()


def _audit_login(
    conn: sqlite3.Connection,
    *,
    result: str,
    trace_id: str,
    user_id: Optional[int],
    account: str,
    client_ip: Optional[str],
    failure_code: Optional[str] = None,
) -> None:
    """写 `login_log`。账号只存摘要与脱敏串，不存明文（SR-03）。"""
    conn.execute(
        "INSERT INTO login_log (user_id, account_ref_hash, account_masked, result, "
        "failure_code, client_ip, trace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            _account_digest(account),
            mask_account(account),
            result,
            failure_code,
            client_ip,
            trace_id,
            timeutil.now_iso(),
        ),
    )


# ---------------------------------------------------------------------------
# API-USER-001 注册
# ---------------------------------------------------------------------------


def register(inp: RegisterInput, *, trace_id: str) -> Dict[str, object]:
    """建账号。唯一约束冲突一律 `409 USER_ALREADY_EXISTS`，不说是哪一项冲突。"""
    fields = password.create_password_fields(inp.password)
    phone_hash = _phone_digest(inp.phone)
    masked = mask_phone(inp.phone)
    now = timeutil.now_iso()

    conn = get_conn()
    try:
        exists = conn.execute(
            "SELECT 1 FROM user_account WHERE username = ? OR phone_hash = ?",
            (inp.username, phone_hash),
        ).fetchone()
        if exists:
            log_event(
                get_logger(),
                "register_rejected",
                trace_id=trace_id,
                reason="DUPLICATE",
                account=mask_account(inp.username),
            )
            raise ApiError("USER_ALREADY_EXISTS", None, trace_id)

        try:
            cursor = conn.execute(
                "INSERT INTO user_account (username, password_algo, password_iterations, "
                "password_salt, password_derived, phone_hash, phone_masked, nickname, "
                "status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    inp.username,
                    fields["algo"],
                    int(fields["iterations"]),
                    fields["salt"],
                    fields["derived"],
                    phone_hash,
                    masked,
                    inp.nickname,
                    now,
                    now,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # 并发下两个人同时过掉上面的 SELECT：由唯一索引兜底，语义不变
            conn.rollback()
            log_event(
                get_logger(),
                "register_rejected",
                trace_id=trace_id,
                reason="UNIQUE_CONFLICT",
                account=mask_account(inp.username),
            )
            raise ApiError("USER_ALREADY_EXISTS", None, trace_id)

        user_id = int(cursor.lastrowid)
        log_event(
            get_logger(),
            "user_registered",
            trace_id=trace_id,
            user_id=user_id,
            account=mask_account(inp.username),
        )

        return {
            "userId": str(user_id),
            "username": inp.username,
            "nickname": inp.nickname,
            "phoneMasked": masked,
            "status": "active",
            "createdAt": now,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# API-AUTH-001 登录
# ---------------------------------------------------------------------------


def _invalid_credentials(trace_id: str) -> ApiError:
    return ApiError("AUTH_INVALID_CREDENTIALS", None, trace_id)


def _fail_login(
    conn: sqlite3.Connection,
    row: Mapping[str, object],
    *,
    trace_id: str,
    account: str,
    client_ip: Optional[str],
    ip_digest: str,
    account_digest: str,
) -> None:
    """记一次失败：累加计数、必要时上锁、写审计，然后统一 401。"""
    failed = int(row["failed_login_count"]) + 1
    locked = failed >= MAX_FAILED_LOGINS
    locked_until = timeutil.iso_after(LOCK_SECONDS) if locked else row["locked_until"]

    conn.execute(
        "UPDATE user_account SET failed_login_count = ?, locked_until = ?, updated_at = ? "
        "WHERE user_id = ?",
        (failed, locked_until, timeutil.now_iso(), row["user_id"]),
    )
    _audit_login(
        conn,
        result="locked" if locked else "failure",
        trace_id=trace_id,
        user_id=int(row["user_id"]),
        account=account,
        client_ip=client_ip,
        failure_code="ACCOUNT_LOCKED" if locked else "BAD_PASSWORD",
    )
    conn.commit()

    ratelimit.LIMITER.hit("login_account", account_digest, trace_id=trace_id)

    log_event(
        get_logger(),
        "login_failed",
        trace_id=trace_id,
        user_id=row["user_id"],
        reason="ACCOUNT_LOCKED" if locked else "BAD_PASSWORD",
        failed_count=failed,
    )
    raise _invalid_credentials(trace_id)


def login(inp: LoginInput, *, client_ip: Optional[str], trace_id: str) -> Dict[str, object]:
    """登录成功返回令牌；任何失败都返回同一个 401。"""
    account_digest = _account_digest(inp.account)
    ip_digest = hashlib.sha256(f"bookstore:ip:{client_ip or '-'}".encode("utf-8")).hexdigest()

    # 单 IP 维度：先卡住"高频打登录接口"，避免每次请求都跑 60 万次 PBKDF2（T-DN-03）
    ratelimit.LIMITER.hit("login_ip", ip_digest, trace_id=trace_id)

    conn = get_conn()
    try:
        if inp.account_kind == "phone":
            row = conn.execute(
                "SELECT * FROM user_account WHERE phone_hash = ?", (_phone_digest(inp.account),)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM user_account WHERE username = ?", (inp.account,)
            ).fetchone()

        if row is None:
            # SR-04：账号不存在也要跑一次同参数的派生，让耗时与"口令错"同量级
            password.dummy_check(inp.password)
            ratelimit.LIMITER.hit("login_account", account_digest, trace_id=trace_id)
            _audit_login(
                conn,
                result="failure",
                trace_id=trace_id,
                user_id=None,
                account=inp.account,
                client_ip=client_ip,
                failure_code="UNKNOWN_ACCOUNT",
            )
            conn.commit()
            log_event(
                get_logger(), "login_failed", trace_id=trace_id, reason="UNKNOWN_ACCOUNT"
            )
            raise _invalid_credentials(trace_id)

        # 锁定与停用：仍然完整跑一次口令校验再拒，耗时与普通失败保持一致
        locked = not timeutil.is_past(row["locked_until"])
        disabled = row["status"] != "active"
        verified = password.check_password(inp.password, row)

        if disabled:
            _audit_login(
                conn,
                result="blocked",
                trace_id=trace_id,
                user_id=int(row["user_id"]),
                account=inp.account,
                client_ip=client_ip,
                failure_code="ACCOUNT_DISABLED",
            )
            conn.commit()
            log_event(
                get_logger(), "login_failed", trace_id=trace_id, reason="ACCOUNT_DISABLED"
            )
            raise _invalid_credentials(trace_id)

        if locked:
            _audit_login(
                conn,
                result="locked",
                trace_id=trace_id,
                user_id=int(row["user_id"]),
                account=inp.account,
                client_ip=client_ip,
                failure_code="ACCOUNT_LOCKED",
            )
            conn.commit()
            log_event(get_logger(), "login_failed", trace_id=trace_id, reason="ACCOUNT_LOCKED")
            raise _invalid_credentials(trace_id)

        if not verified:
            _fail_login(
                conn,
                row,
                trace_id=trace_id,
                account=inp.account,
                client_ip=client_ip,
                ip_digest=ip_digest,
                account_digest=account_digest,
            )

        # --- 成功 ---
        issued = tokens.issue()
        now = timeutil.now_iso()
        conn.execute(
            "UPDATE user_account SET failed_login_count = 0, locked_until = NULL, "
            "last_login_at = ?, updated_at = ? WHERE user_id = ?",
            (now, now, row["user_id"]),
        )
        conn.execute(
            "INSERT INTO session_token (user_id, token_hash, issued_at, expires_at, client_ip) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                int(row["user_id"]),
                issued.digest,
                issued.issued_at,
                issued.expires_at,
                client_ip,
            ),
        )
        _audit_login(
            conn,
            result="success",
            trace_id=trace_id,
            user_id=int(row["user_id"]),
            account=inp.account,
            client_ip=client_ip,
        )
        conn.commit()

        ratelimit.LIMITER.reset("login_account", account_digest)
        log_event(
            get_logger(),
            "login_succeeded",
            trace_id=trace_id,
            user_id=row["user_id"],
            expires_at=issued.expires_at,
        )

        return {
            "accessToken": issued.raw,
            "tokenType": "Bearer",
            "expiresIn": tokens.TOKEN_TTL_SECONDS,
            "user": {
                "userId": str(row["user_id"]),
                "username": row["username"],
                "nickname": row["nickname"],
                "role": DEFAULT_ROLE,
            },
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# API-AUTH-002 退出
# ---------------------------------------------------------------------------


def logout(ctx: AuthContext, *, trace_id: str) -> None:
    """撤销当前令牌对应的那一个会话；重复调用不改结果（幂等）。"""
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE session_token SET revoked_at = ?, revoke_reason = 'logout' "
            "WHERE token_hash = ? AND revoked_at IS NULL",
            (timeutil.now_iso(), ctx.token_digest),
        )
        conn.commit()
    finally:
        conn.close()

    log_event(
        get_logger(),
        "logout",
        trace_id=trace_id,
        user_id=ctx.user_id,
        already_revoked=ctx.revoked,
    )


# ---------------------------------------------------------------------------
# API-USER-002 个人信息 / 越权校验
# ---------------------------------------------------------------------------


def get_profile(ctx: AuthContext, *, target_user_id: Optional[int], trace_id: str) -> Dict[str, object]:
    """查个人信息。

    `target_user_id` 只用来做归属比对，**不**作为查询条件：真正查的是令牌里的人。
    与令牌不一致时返回 404（不是 403），响应体与"这个 id 根本不存在"一致。
    """
    if target_user_id is not None and target_user_id != ctx.user_id:
        log_event(
            get_logger(),
            "authz_denied",
            trace_id=trace_id,
            actor_user_id=ctx.user_id,
            target_user_id=target_user_id,
            reason="NOT_OWNER",
        )
        raise ApiError("RESOURCE_NOT_FOUND", None, trace_id)

    conn = get_conn()
    try:
        row = _fetch_user(conn, ctx.user_id)
        if row is None:
            raise ApiError("RESOURCE_NOT_FOUND", None, trace_id)
        return _public_user(row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 鉴权校验（第五个接口）
# ---------------------------------------------------------------------------


def verify_payload(ctx: AuthContext) -> Dict[str, object]:
    """令牌有效时返回"这枚令牌还能用多久"，供前端启动时判断是否要跳登录。"""
    return {
        "valid": True,
        "userId": str(ctx.user_id),
        "username": ctx.username,
        "issuedAt": ctx.issued_at,
        "expiresAt": ctx.expires_at,
        "expiresIn": timeutil.seconds_until(ctx.expires_at),
    }


__all__ = [
    "DEFAULT_ROLE",
    "LOCK_SECONDS",
    "MAX_FAILED_LOGINS",
    "get_profile",
    "login",
    "logout",
    "register",
    "verify_payload",
]
