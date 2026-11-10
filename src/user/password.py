#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""口令派生的业务侧封装：四列拆分、校验、等时假校验。

第 10-11 周把调用口径统一到 `password_port.py`：算法与参数只有一处来源
（`src/crypto/加盐哈希.py`），本文件只负责"落库前怎么拆、登录时怎么拼回去"。

```text
注册：create_password_fields(口 plain)  → {algo, iterations, salt, derived}  写四列
登录：check_password(口 plain, 行)      → True/False                       拼回存储串比对
防枚举：dummy_check(口 plain)           → None                            账号不存在时也跑一遍
```

`dummy_check` 的意义（SR-04）：账号不存在时若直接返回，响应会明显快于"账号存在
但口令错"，攻击者按耗时就能筛出真实账号。这里对假数据跑一次同等参数的派生，
让两条路径耗时同量级。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

from functools import lru_cache
from typing import Mapping, Union

from .password_port import SEP, hash_password, split_stored, verify_password
from .validation import Secret

PasswordLike = Union[str, Secret]

# 用于等时失败的假数据（SR-04）。惰性生成：只在第一次需要时跑一次 PBKDF2，
# 不让每次启动都为一个可能用不到的分支付 60 万次迭代。
_DUMMY_PASSWORD = "dummy_password_for_timing_only"


@lru_cache(maxsize=1)
def dummy_stored() -> str:
    """假账号的存储串（进程内只生成一次）。"""
    return hash_password(_DUMMY_PASSWORD)


def create_password_fields(password: PasswordLike) -> dict:
    """注册时调用：口令 → 建库脚本要求的四列。"""
    return split_stored(hash_password(password))


def _stored_from_row(row: Mapping[str, object]) -> str:
    """把库里的四列拼回 `algo$iterations$salt$derived`。"""
    return SEP.join(
        [
            str(row["password_algo"]),
            str(row["password_iterations"]),
            str(row["password_salt"]),
            str(row["password_derived"]),
        ]
    )


def check_password(password: PasswordLike, user_row: Mapping[str, object]) -> bool:
    """登录时调用：常数时间比较，返回 True/False，不抛异常。"""
    try:
        stored = _stored_from_row(user_row)
    except (KeyError, TypeError):
        return False
    return verify_password(password, stored)


def dummy_check(password: PasswordLike) -> None:
    """账号不存在（或不可用）时调用：消耗与真实校验同量级的时间。"""
    verify_password(password, dummy_stored())


__all__ = [
    "check_password",
    "create_password_fields",
    "dummy_check",
    "dummy_stored",
]
