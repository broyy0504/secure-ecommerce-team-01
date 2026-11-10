#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""会话令牌的生成与摘要（SR-06、SR-09）。

四条约定：

1. 令牌是**不透明随机串**，不编码用户名、角色、过期时间——服务端没有"解析令牌"
   这一步，唯一能做的动作是拿摘要查库。所以"改令牌里的用户标识"这类攻击
   在结构上无处落脚（T-TM-02 的处置方式）。
2. 库里只存 SHA-256 摘要，原文只在登录响应里出现一次；摘要不随任何响应返回。
3. 有效期由服务端判定，固定 2 小时，客户端不能延长（请求里的任何过期字段都被
   `validation.py` 当未知字段拒掉）。
4. 令牌不进 URL：只从 `Authorization` 头读，见 `auth.py`。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass

from . import timeutil

TOKEN_TTL_SECONDS = 7200  # 2 小时（SR-09 上限）
TOKEN_BYTES = 32  # 256 位熵，远超 SR-06 的 128 位下限

# token_urlsafe(32) → 43 个 base64url 字符，无填充
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


@dataclass(frozen=True)
class IssuedToken:
    """一次签发的结果。`raw` 用完即弃，只有 `digest` 落库。"""

    raw: str
    digest: str
    issued_at: str
    expires_at: str

    def __repr__(self) -> str:  # 防止顺手打印带出明文令牌
        return f"IssuedToken(digest={self.digest[:8]}…, expires_at={self.expires_at})"


def digest_of(raw_token: str) -> str:
    """令牌原文 → 库里存的摘要（64 位十六进制）。"""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def looks_like_token(raw_token: str) -> bool:
    """形状检查。只是"值不值得查库"的前置判断，**不是**鉴权依据。

    形状不对直接拒，省一次数据库查询；形状对但不存在的令牌一样拒，
    两者对外都是同一个 `AUTH_UNAUTHENTICATED`，不透露差在哪一步。
    """
    return isinstance(raw_token, str) and bool(TOKEN_RE.match(raw_token))


def issue() -> IssuedToken:
    """签发一枚新令牌。多设备并存：每次登录各签一枚，互不影响。"""
    raw = secrets.token_urlsafe(TOKEN_BYTES)
    return IssuedToken(
        raw=raw,
        digest=digest_of(raw),
        issued_at=timeutil.now_iso(),
        expires_at=timeutil.iso_after(TOKEN_TTL_SECONDS),
    )


__all__ = [
    "IssuedToken",
    "TOKEN_BYTES",
    "TOKEN_RE",
    "TOKEN_TTL_SECONDS",
    "digest_of",
    "issue",
    "looks_like_token",
]
