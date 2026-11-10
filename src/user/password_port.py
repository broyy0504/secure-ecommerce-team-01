#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第 5 周密码学模块的调用口径（说明配套，不含任何算法实现）。

交付要求"说明写清调用了第 5 周 `src/crypto/` 的哪个函数"。本文件把那句话变成
可执行的东西，避免说明与代码对不上：

- 口令派生：`src/crypto/加盐哈希.py` 的 `generate_pbkdf2_derived(password, iterations)`
- 口令校验：同文件的 `verify_pbkdf2_derived(password, algo, iterations, salt, derived)`

第 10-11 周修正：此前的版本按 `hash_password` / `verify_password` 两个函数名调用，
而第 5 周模块实际只提供上面两个 `*_pbkdf2_derived` 函数，导致
`test/test_input_validation.py` 第 7 节直接 `AttributeError`。此处按真实签名重写，
对外函数名保持不变。

为什么需要这层壳：该文件名带中文，`import 加盐哈希` 不可用，必须用 `importlib`
按文件路径加载。组内每个人都要 import 一次，容易各写各的参数；在这里集中一次，
参数就只有一份——盐长度、派生长度、迭代次数全部实测自第 5 周模块的返回值，
不在本文件里另写常量。

**本文件不实现、不改写任何密码学算法。**

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Dict, Union

from .logging_utils import register_secret
from .validation import Secret

# 仓库里的相对位置：src/user/password_port.py → src/crypto/加盐哈希.py
CRYPTO_FILE = Path(__file__).resolve().parents[1] / "crypto" / "加盐哈希.py"

# 四列存储串的分隔符：algo$iterations$salt$derived
SEP = "$"

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


def _b64d(text: str) -> bytes:
    """把第 5 周模块输出的无填充 base64url 还原成字节（仅用于量长度）。"""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@lru_cache(maxsize=1)
def _probe() -> Dict[str, object]:
    """向第 5 周模块要一组样本，用它量出真实参数。

    迭代次数要跑 60 万次，所以只跑一次并缓存；`parameters()` 与四列长度校验
    都读这份缓存，不在这里另写 600000 / 16 / 32 这些魔数。
    """
    module = load_crypto_module()
    sample = module.generate_pbkdf2_derived("__parameter_probe__")
    return {
        "algo": sample["algo"],
        "iterations": sample["iterations"],
        "salt_bytes": len(_b64d(sample["salt"])),
        "derived_bytes": len(_b64d(sample["derived"])),
    }


def parameters() -> Dict[str, object]:
    """当前生效的派生参数（实测自第 5 周模块，不是本文件写死的）。"""
    return dict(_probe())


def hash_password(password: PasswordLike) -> str:
    """注册时调用：返回 `algo$iterations$salt$derived` 形式的存储串。

    返回值就是要落库的内容；口令明文到此为止，不再往下传。
    盐由第 5 周模块内部的 `secrets.token_bytes` 生成，调用方无法指定——
    这正好满足 SR-02"迭代次数与盐不接受请求传入"。
    """
    module = load_crypto_module()
    derived = module.generate_pbkdf2_derived(_reveal(password))
    stored = SEP.join(
        (
            str(derived["algo"]),
            str(derived["iterations"]),
            str(derived["salt"]),
            str(derived["derived"]),
        )
    )
    # 存储串整体登记到脱敏表：之后任何人把它拼进日志都会被替换
    register_secret(stored)
    return stored


def verify_password(password: PasswordLike, stored: str) -> bool:
    """登录时调用：常数时间比较，返回 True/False，不抛异常。

    存储串损坏（少一段、迭代次数不是整数）时返回 False：不能变成 500，
    也不能对外透露"这一行数据有问题"——那等于告诉对方库里有一条坏记录。
    """
    try:
        columns = split_stored(stored)
        iterations = int(columns["iterations"])
    except (ValueError, TypeError):
        return False

    module = load_crypto_module()
    try:
        return bool(
            module.verify_pbkdf2_derived(
                _reveal(password),
                columns["algo"],
                iterations,
                columns["salt"],
                columns["derived"],
            )
        )
    except Exception:
        return False


def split_stored(stored: str) -> Dict[str, str]:
    """把存储串拆成建库脚本要求的四列。

    返回 `{algo, iterations, salt, derived}`；格式不符抛 `ValueError`。
    本函数只做字符串切分，不接触明文。
    """
    parts = (stored or "").split(SEP)
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


def stored_matches_schema(stored: str) -> bool:
    """四列是否与建库脚本的长度约束一致（salt 22 / derived 43 字符）。

    `db/schema.sql` 用 CHECK 约束卡这两个长度，Python 侧落库前先自证一次，
    免得把 MySQL 能收、SQLite 收不住的串写进去。
    """
    try:
        columns = split_stored(stored)
    except ValueError:
        return False
    return (
        len(columns["salt"]) == 22
        and len(columns["derived"]) == 43
        and columns["algo"] == _probe()["algo"]
    )


__all__ = [
    "CRYPTO_FILE",
    "SEP",
    "hash_password",
    "load_crypto_module",
    "parameters",
    "split_stored",
    "stored_matches_schema",
    "verify_password",
]
