#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""鉴权：全模块**唯一**的令牌校验入口。

交付要求原话是"令牌校验抽成一个函数，所有受保护接口统一调用，不在每个接口里
各写一遍"。所以这里只有 `require_auth()` 一个函数做这件事，`server.py` 里每个
受保护路由的第一行都是它，没有第二处解析 `Authorization` 的代码。

它一次做完五件事（顺序固定，任何一步不过就抛 `ApiError`）：

1. 取头：`Authorization: Bearer <token>`，方案名大小写不敏感、值的形状固定；
2. 查形状：43 个 base64url 字符，不像令牌的直接拒，省一次查库；
3. 查库：用 SHA-256 摘要查 `session_token`，**不解析令牌内容**（令牌里没有身份）；
4. 查状态：`revoked_at` 非空 → 无效；`expires_at` 已过 → `AUTH_TOKEN_EXPIRED`；
5. 查人：按令牌行里的 `user_id` 取账号，账号非 `active` 一律无效。

两条容易写错的边界，写在这里免得各接口各写一遍：

- **401 的三种情形对外完全同形**：没带令牌、令牌形状不对、令牌查不到，都是
  `AUTH_UNAUTHENTICATED` + 逐字相同的文案。`AUTH_TOKEN_EXPIRED` 单列，是因为
  契约要求"过期"可被前端识别并引导重新登录，且它只在令牌确实存在时才出现。
- **`allow_revoked` 只给退出接口用**。退出是幂等的：同一枚令牌再退一次仍返回
  `204`，返回 `401` 等于额外确认"这枚令牌曾经有效"（DES-03 §4.3 / D-02）。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Optional

from . import timeutil, tokens
from .db import get_conn
from .errors import ApiError
from .logging_utils import get_logger, log_event

_AUTH_HEADER_RE = re.compile(r"Bearer\s+(\S+)\Z", re.IGNORECASE)


@dataclass(frozen=True)
class AuthContext:
    """一次已通过校验的调用者身份。身份只来自令牌，不来自请求体或查询串。"""

    user_id: int
    username: str
    nickname: Optional[str]
    token_digest: str
    issued_at: str
    expires_at: str
    revoked: bool = False

    def __repr__(self) -> str:
        return f"AuthContext(user_id={self.user_id}, username={self.username!r})"


def _unauthenticated(trace_id: str) -> ApiError:
    return ApiError("AUTH_UNAUTHENTICATED", None, trace_id)


def bearer_from(headers: Mapping[str, str], trace_id: str) -> str:
    """从请求头取令牌原文；取不到就按"未登录"拒。"""
    raw = (headers.get("Authorization") or "").strip()
    if not raw:
        log_event(get_logger(), "auth_rejected", trace_id=trace_id, reason="NO_TOKEN")
        raise _unauthenticated(trace_id)

    matched = _AUTH_HEADER_RE.match(raw)
    if not matched:
        # 不记录头里的原文：可能是攻击者构造的串，也可能是用户误贴的其它凭据
        log_event(get_logger(), "auth_rejected", trace_id=trace_id, reason="BAD_SCHEME")
        raise _unauthenticated(trace_id)

    return matched.group(1)


def require_auth(
    headers: Mapping[str, str],
    trace_id: str,
    *,
    allow_revoked: bool = False,
) -> AuthContext:
    """校验令牌并返回调用者身份。所有受保护接口都调用这一个函数。"""
    raw_token = bearer_from(headers, trace_id)

    if not tokens.looks_like_token(raw_token):
        log_event(get_logger(), "auth_rejected", trace_id=trace_id, reason="BAD_SHAPE")
        raise _unauthenticated(trace_id)

    digest = tokens.digest_of(raw_token)

    conn = get_conn()
    try:
        session = conn.execute(
            "SELECT user_id, issued_at, expires_at, revoked_at "
            "FROM session_token WHERE token_hash = ?",
            (digest,),
        ).fetchone()

        if session is None:
            # 三枪里的两枪落在这里：改一字节、换别人的令牌。库里没有这一行。
            log_event(get_logger(), "auth_rejected", trace_id=trace_id, reason="UNKNOWN_TOKEN")
            raise _unauthenticated(trace_id)

        revoked = session["revoked_at"] is not None
        if revoked and not allow_revoked:
            log_event(
                get_logger(),
                "auth_rejected",
                trace_id=trace_id,
                reason="REVOKED_TOKEN",
                user_id=session["user_id"],
            )
            raise _unauthenticated(trace_id)

        if timeutil.is_past(session["expires_at"]):
            log_event(
                get_logger(),
                "auth_rejected",
                trace_id=trace_id,
                reason="EXPIRED_TOKEN",
                user_id=session["user_id"],
            )
            raise ApiError("AUTH_TOKEN_EXPIRED", None, trace_id)

        # 只有令牌行存在且未过期，才会查到账号——SR-07 要求"改一字节后不产生用户数据查询"
        user = conn.execute(
            "SELECT user_id, username, nickname, status FROM user_account WHERE user_id = ?",
            (session["user_id"],),
        ).fetchone()

        if user is None or user["status"] != "active":
            # 账号被停用/注销：令牌一并视为无效，不另给错误码（否则等于确认账号存在）
            log_event(
                get_logger(),
                "auth_rejected",
                trace_id=trace_id,
                reason="INACTIVE_ACCOUNT",
                user_id=session["user_id"],
            )
            raise _unauthenticated(trace_id)

        return AuthContext(
            user_id=int(user["user_id"]),
            username=user["username"],
            nickname=user["nickname"],
            token_digest=digest,
            issued_at=session["issued_at"],
            expires_at=session["expires_at"],
            revoked=revoked,
        )
    finally:
        conn.close()


__all__ = ["AuthContext", "bearer_from", "require_auth"]
