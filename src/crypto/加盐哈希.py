#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加盐哈希演示：PBKDF2-HMAC-SHA256

仅用于教学，不得用于任何真实数据。

存储格式：
    pbkdf2_sha256$<iterations>$<salt_b64url>$<hash_b64url>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import random
import secrets
from typing import Optional

DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16
DK_LEN = 32
ALGO = "pbkdf2_sha256"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _make_salt(seed: Optional[int] = None) -> bytes:
    """
    生成盐。
    seed 仅用于可复现演示；生产必须使用 secrets。
    """
    if seed is None:
        return secrets.token_bytes(SALT_BYTES)

    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(SALT_BYTES))


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    salt: Optional[bytes] = None,
    seed: Optional[int] = None,
) -> str:
    """对口径加盐哈希，返回可存储字符串。"""
    if salt is None:
        salt = _make_salt(seed)

    if len(salt) < 8:
        raise ValueError("盐长度过短，建议至少 16 字节")

    pwd_bytes = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        pwd_bytes,
        salt,
        iterations,
        dklen=DK_LEN,
    )
    return f"{ALGO}${iterations}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """验证口令是否与存储的加盐哈希匹配。"""
    try:
        algo, iter_s, salt_b64, hash_b64 = stored.split("$")
        if algo != ALGO:
            return False

        iterations = int(iter_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
    except Exception:
        return False

    pwd_bytes = password.encode("utf-8")
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        pwd_bytes,
        salt,
        iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="加盐哈希演示（PBKDF2-HMAC-SHA256），仅用于教学"
    )
    parser.add_argument(
        "--password",
        default="我的密码123",
        help="要哈希的口令，默认：我的密码123",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 迭代次数，默认 {DEFAULT_ITERATIONS}",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="固定盐种子，仅用于可复现演示；不提供则使用密码学安全随机盐",
    )
    args = parser.parse_args(argv)

    pwd = args.password

    print("加盐哈希演示：PBKDF2-HMAC-SHA256")
    print("仅用于教学，不得用于任何真实数据。")
    print(f"口令：{pwd!r}")
    print(f"迭代次数：{args.iterations}")

    salt_source = (
        f"固定种子 {args.seed} / {args.seed + 1}"
        if args.seed is not None
        else "secrets 安全随机"
    )
    print(f"盐来源：{salt_source}")
    print("-" * 72)

    if args.seed is not None:
        stored1 = hash_password(pwd, iterations=args.iterations, seed=args.seed)
        stored2 = hash_password(pwd, iterations=args.iterations, seed=args.seed + 1)
    else:
        stored1 = hash_password(pwd, iterations=args.iterations)
        stored2 = hash_password(pwd, iterations=args.iterations)

    print("第 1 次哈希：")
    print(stored1)
    print("第 2 次哈希：")
    print(stored2)
    print("-" * 72)

    print(f"两次哈希是否相同：{stored1 == stored2}")
    print(f"用正确口令验证第 1 次哈希：{verify_password(pwd, stored1)}")
    print(f"用正确口令验证第 2 次哈希：{verify_password(pwd, stored2)}")
    print(f"用错误口令验证第 1 次哈希：{verify_password('错误口令', stored1)}")
    print("-" * 72)

    print("结论：同一口令两次加盐哈希结果不同，但正确口令均可验证通过。")
    print("盐随哈希一起存储；盐不需要保密，但必须每个用户唯一、随机。")
    print("哈希不可逆；加密可逆，二者本质不同。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())