#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第 5 周密码学模块的调用口径（说明配套，不含任何算法实现）。

交付要求"说明写清调用了第 5 周 `src/crypto/` 的哪个函数"。本文件把那句话变成
可执行的东西，避免说明与代码对不上：

- 口令派生：`src/crypto/加盐哈希.py` 的 `hash_password(password, ...)`
- 口令校验：同文件的 `verify_password(password, stored)`

为什么需要这层 12 行的壳：该文件名带中文，`import 加盐哈希` 不可用，必须用
`importlib` 按文件路径加载。组内每个人都要 import 一次，容易各写各的参数；
在这里集中一次，参数就只有一份。

**本文件不实现、不改写任何密码学算法**；迭代次数、盐长度、派生长度全部读自
第 5 周模块的模块级常量，改动源头在那边。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Dict, Optional, Union

from .logging_utils import register_secret
from .validation import Secret

# 仓库里的相对位置：src/user/password_port.py → src/crypto/加盐哈希.py
CRYPTO_FILE = Path(__file__).resolve().parents[1] / "crypto" / "加盐哈希.py"

PasswordLike = Union[str, Secret]


def _reveal(password: PasswordLike) -> str:
    return password.reveal() if isinstance(password, Secret) else password


@lru_cache(maxsize=1)
def load_crypto_module() -> ModuleType:
    """按路径加载第 5 周的模块（中文文件名不能直接 import）。"""
    if not CRYPTO_FILE.is_file():
        raise FileNotFoundError(f"找不到第 5 周密码学模块: {CRYPTO_FILE}")

    spec = importlib.util.spec_from_file_location("bookstore_crypto_pbkdf2", CRYPTO_FILE)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载模块: {CRYPTO_FILE}")

    module = importlib.util.module_from_spec(spec)
    # 注册进 sys.modules，dataclass/typing 一类自省会用到
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def parameters() -> Dict[str, object]:
    """当前生效的派生参数（全部来自第 5 周模块的常量）。"""
    module = load_crypto_module()
    return {
        "algo": module.ALGO,
        "iterations": module.DEFAULT_ITERATIONS,
        "salt_bytes": module.SALT_BYTES,
        "derived_bytes": module.DK_LEN,
    }


def hash_password(password: PasswordLike, *, salt: Optional[bytes] = None) -> str:
    """注册时调用：返回 `algo$iterations$salt$derived` 形式的存储串。

    返回值就是要落库的内容；口令明文到此为止，不再往下传。
    """
    module = load_crypto_module()
    if salt is None:
        return module.hash_password(_reveal(password))
    return module.hash_password(_reveal(password), salt=salt)


def verify_password(password: PasswordLike, stored: str) -> bool:
    """登录时调用：常数时间比较，返回 True/False，不抛异常。"""
    module = load_crypto_module()
    try:
        return bool(module.verify_password(_reveal(password), stored))
    except Exception:
        # 存储串损坏不能变成 500，也不能泄露"这一行数据有问题"
        return False


def split_stored(stored: str) -> Dict[str, str]:
    """把存储串拆成建库脚本要求的四列。

    返回 `{algo, iterations, salt, derived}`；格式不符抛 `ValueError`。
    本函数只做字符串切分，不接触明文。
    """
    parts = (stored or "").split("$")
    if len(parts) != 4:
        raise ValueError("存储串格式不是 algo$iterations$salt$derived")
    algo, iterations, salt, derived = parts
    if not algo or not iterations.isdigit() or not salt or not derived:
        raise ValueError("存储串有空段或迭代次数不是整数")

    # 盐与派生值都是 SR-03 点名"不得出现在日志里"的东西，拆出来顺手登记到
    # 脱敏表：之后即使有人把某一列直接拼进日志，也会被替换成 <redacted>。
    register_secret(salt)
    register_secret(derived)
    register_secret(stored)

    return {
        "algo": algo,
        "iterations": iterations,
        "salt": salt,
        "derived": derived,
    }


__all__ = [
    "CRYPTO_FILE",
    "hash_password",
    "load_crypto_module",
    "parameters",
    "split_stored",
    "verify_password",
]
