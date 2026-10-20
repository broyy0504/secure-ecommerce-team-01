#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""标准库交叉验证（第二条路径）

用 Python 标准库的 ``pow`` / ``math.gcd`` 等对 ``bigint_ops.py`` 与
``rsa.py`` 的主实现做独立复算。核心原则：

* 本文件**不参与主实现**，主实现也不导入本文件；
* 期望值一律由标准库重新计算，不复用 ``bigint_ops.mod_pow`` 等被测函数；
* 随机用例使用固定种子，保证可复现。

运行（仓库根目录）::

    python src/crypto/verify_with_stdlib.py

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import math
import random

try:                                   # 作为包导入时
    from . import bigint_ops, rsa
except ImportError:                    # 直接运行 / 同目录导入时
    import bigint_ops
    import rsa


passed = 0
failed = 0


def check(label, actual, expected):
    """断言实际值等于期望值。"""
    global passed, failed
    if actual == expected:
        passed += 1
        print(f"  [通过] {label}")
        return True
    failed += 1
    print(f"  [失败] {label}")
    print(f"         实际 = {actual}")
    print(f"         期望 = {expected}")
    return False


def check_true(label, condition):
    return check(label, bool(condition), True)


def banner(title):
    print()
    print("=" * 76)
    print(f"  {title}")
    print("=" * 76)


# =====================================================================
# 一、独立的“第二条路径”：只依赖标准库
# =====================================================================


def std_mod_pow(base, exp, mod):
    """标准库模幂：``pow(base, exp, mod)``。"""
    return pow(base, exp, mod)


def std_gcd(a, b):
    """标准库最大公约数。"""
    return math.gcd(a, b)


def std_mod_inverse(a, m):
    """标准库模逆：``pow(a, -1, m)``（Python 3.8+）。"""
    if m == 1:                          # 模 1 下唯一剩余类为 0
        return 0
    return pow(a % m, -1, m)


# 与主实现 deliberately 不同的见证集：取 37 之后的 40 个素数。
# 主实现用 {2,3,...,37}；这里换一组，避免“同一套见证集自证”。
STD_WITNESSES = (
    41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
    83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
)


def std_is_probable_prime(n):
    """独立 Miller-Rabin：用标准库 ``pow`` + 不同的见证集。"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in STD_WITNESSES:
        if a >= n - 1:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def std_block_size(n):
    """独立推导每块明文容量：``floor((b-1)/8) - 1``。"""
    return (n.bit_length() - 1) // 8 - 1


def std_encrypt_string(pub, message):
    """独立的分块 + 哨兵编码 + 标准库模幂。"""
    data = message.encode("utf-8")
    bs = std_block_size(pub.n)
    out = []
    for i in range(0, len(data), bs):
        block = b"\x01" + data[i:i + bs]
        out.append(pow(int.from_bytes(block, "big"), pub.e, pub.n))
    return out


def std_decrypt_blocks(priv, blocks):
    """独立解密：标准库模幂 + 去哨兵。"""
    out = bytearray()
    for c in blocks:
        m = pow(c, priv.d, priv.n)
        length = max(1, (m.bit_length() + 7) // 8)
        raw = m.to_bytes(length, "big")
        if not raw or raw[0] != 0x01:
            raise ValueError("哨兵校验失败")
        out += raw[1:]
    return bytes(out)


def std_decrypt_crt(priv, c):
    """独立 CRT 合并，模幂用标准库 ``pow``。"""
    m1 = pow(c, priv.dp, priv.p)
    m2 = pow(c, priv.dq, priv.q)
    h = (priv.q_inv * (m1 - m2)) % priv.p
    return m2 + h * priv.q


def make_key(p, q, e):
    """用给定 p、q、e 组装密钥对象（d 由标准库求逆）。"""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = std_mod_inverse(e, phi)
    pub = rsa.PublicKey(n, e)
    priv = rsa.PrivateKey(
        n, e, d, p, q, phi,
        d % (p - 1), d % (q - 1), std_mod_inverse(q, p),
    )
    return pub, priv


# =====================================================================
# 二、基础算法模块交叉验证
# =====================================================================


def section_mod_pow():
    banner("【一】mod_pow：主实现 vs 标准库 pow")

    known = [
        (4, 13, 497, 445),
        (65, 17, 3233, 2790),
        (2790, 2753, 3233, 65),
        (2, 10, 1000, 24),
        (3, 100, 1000000007, 886041711),
        (2, 644, 645, 1),
    ]
    for base, exp, mod, expected in known:
        actual = bigint_ops.mod_pow(base, exp, mod)
        check(f"mod_pow({base}, {exp}, {mod}) = {expected}", actual, expected)
        check_true("  与标准库 pow 一致", actual == pow(base, exp, mod))

    m128 = 340282366920938463463374607431768211297
    check(
        "mod_pow(2, 2^64, 2^64-59) 与 pow 一致",
        bigint_ops.mod_pow(2, 2 ** 64, 2 ** 64 - 59),
        pow(2, 2 ** 64, 2 ** 64 - 59),
    )
    check(
        "mod_pow(3, 10^30, M128) 与 pow 一致",
        bigint_ops.mod_pow(3, 10 ** 30, m128),
        pow(3, 10 ** 30, m128),
    )

    rng = random.Random(2026)
    mismatches = 0
    for _ in range(200):
        bits = rng.choice((8, 32, 64, 128, 256, 512, 1024))
        mod = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        base = rng.getrandbits(bits + 8) - (1 << (bits + 7))
        exp = rng.getrandbits(bits)
        if bigint_ops.mod_pow(base, exp, mod) != pow(base, exp, mod):
            mismatches += 1
    check("200 组随机输入（8~1024 位）与 pow 全部一致", mismatches, 0)

    inverse_mismatches = 0
    for _ in range(50):
        m = rng.getrandbits(64) | 1
        a = rng.randrange(1, m)
        try:
            expected = pow(a, -1, m)
        except ValueError:
            continue
        if bigint_ops.mod_pow(a, -1, m) != expected:
            inverse_mismatches += 1
    check("负指数（模逆）随机输入全部一致", inverse_mismatches, 0)
    check("mod_pow(5, 7, 1) 与 pow 一致", bigint_ops.mod_pow(5, 7, 1), pow(5, 7, 1))


def section_gcd_and_inverse():
    banner("【二】gcd / ext_gcd / mod_inverse")
    rng = random.Random(7)

    mismatches = 0
    for _ in range(200):
        a = rng.getrandbits(rng.choice((8, 32, 64, 128)))
        b = rng.getrandbits(rng.choice((8, 32, 64, 128)))
        if rng.random() < 0.3:
            a = -a
        if rng.random() < 0.3:
            b = -b
        if bigint_ops.gcd(a, b) != math.gcd(a, b):
            mismatches += 1
    check("200 组随机 gcd 与 math.gcd 一致", mismatches, 0)

    mismatches = 0
    for _ in range(100):
        a = rng.getrandbits(rng.choice((8, 32, 64, 128)))
        b = rng.getrandbits(rng.choice((8, 32, 64, 128)))
        if rng.random() < 0.3:
            a = -a
        g, x, y = bigint_ops.ext_gcd(a, b)
        if not (g == math.gcd(a, b) and g >= 0 and a * x + b * y == g):
            mismatches += 1
    check("100 组随机 ext_gcd 满足 Bézout 且 g = math.gcd", mismatches, 0)

    mismatches = 0
    for _ in range(100):
        m = rng.getrandbits(rng.choice((8, 32, 64, 128))) | 3
        a = rng.randrange(0, m)
        try:
            expected = std_mod_inverse(a, m)
        except ValueError:
            try:
                bigint_ops.mod_inverse(a, m)
                mismatches += 1       # 主实现本应抛 ArithmeticError
            except ArithmeticError:
                pass
            continue
        if bigint_ops.mod_inverse(a, m) != expected:
            mismatches += 1
    check("100 组随机 mod_inverse 与 pow(a, -1, m) 一致", mismatches, 0)
    check("mod_inverse(5, 1) 与标准库约定一致",
          bigint_ops.mod_inverse(5, 1), std_mod_inverse(5, 1))


def section_primality():
    banner("【三】Miller-Rabin 与随机素数")

    primes = [
        2, 3, 5, 7, 13, 7919, 104729,
        2147483647, 2305843009213693951, 2 ** 127 - 1,
    ]
    for n in primes:
        actual = bigint_ops.is_probable_prime(n, 40, bigint_ops.JavaRandom(123))
        check_true(f"is_probable_prime({n}) 与独立 MR 一致",
                   actual == std_is_probable_prime(n))

    composites = [
        0, 1, 4, 9, 15, 21, 25, 100,
        341, 561, 1105, 1729, 2047,
        1000000007 * 1000000009,
    ]
    for n in composites:
        actual = bigint_ops.is_probable_prime(n, 40, bigint_ops.JavaRandom(123))
        check(f"is_probable_prime({n}) = False", actual, False)

    p32 = bigint_ops.random_prime(32, bigint_ops.JavaRandom(42))
    p64 = bigint_ops.random_prime(64, bigint_ops.JavaRandom(2026))
    check("random_prime(32, seed=42) 与向量一致", p32, 4153081357)
    check("random_prime(64, seed=2026) 与向量一致", p64, 15914823978284633399)
    check_true("种子 42 生成的 32 位素数通过独立 MR", std_is_probable_prime(p32))
    check_true("种子 2026 生成的 64 位素数通过独立 MR", std_is_probable_prime(p64))
    check("32 位素数位长", p32.bit_length(), 32)
    check("64 位素数位长", p64.bit_length(), 64)


# =====================================================================
# 三、RSA 交叉验证
# =====================================================================


def section_rsa_classic():
    banner("【四】教科书 RSA 经典向量（n = 3233）")
    p, q, e = 61, 53, 17
    n = p * q
    pub, priv = make_key(p, q, e)

    check("φ(n) = (p-1)(q-1)", priv.phi, 3120)
    check("d = e⁻¹ mod φ(n)", priv.d, 2753)
    check("加密 c = 65^17 mod 3233", rsa.encrypt(pub, 65), pow(65, 17, n))
    check("解密 m = 2790^2753 mod 3233", rsa.decrypt(priv, 2790), pow(2790, 2753, n))
    check("CRT 解密与 pow 一致", rsa.decrypt_crt(priv, 2790), pow(2790, 2753, n))
    check("e·d ≡ 1 (mod φ(n))", (e * priv.d) % priv.phi, 1)


def section_deterministic_keys():
    banner("【五】固定种子密钥 K1 / K2 / K3 与加解密")
    cases = [
        ("K1", 64, 2025,
         3955599587, 2878846133, 11387562574731347071,
         11387562567896901352, 376880589739664297),
        ("K2", 64, 7,
         3667184063, 3999354053, 14666367445456057339,
         14666367437789519224, 9288527806779251185),
        ("K3", 128, 20250909,
         15438973180112575271, 16256863097279487271,
         250989273351659855709906529422273875441,
         250989273351659855678210693144881812900,
         30243408939348122133921751739706298373),
    ]

    keys = {}
    for label, bits, seed, ep, eq, en, ephi, ed in cases:
        kp = rsa.generate_key_pair(bits, bigint_ops.JavaRandom(seed))
        pub, priv = kp.public_key, kp.private_key
        keys[(bits, seed)] = kp

        check(f"{label} p", priv.p, ep)
        check(f"{label} q", priv.q, eq)
        check(f"{label} n", pub.n, en)
        check(f"{label} φ(n)", priv.phi, ephi)
        check(f"{label} e", pub.e, 65537)
        check(f"{label} d", priv.d, ed)
        check(f"{label} p·q = n", priv.p * priv.q, pub.n)
        check(f"{label} e·d ≡ 1 (mod φ)", (priv.e * priv.d) % priv.phi, 1)
        check(f"{label} n 位宽", pub.n.bit_length(), bits)
        check(f"{label} dp = d mod (p-1)", priv.dp, priv.d % (priv.p - 1))
        check(f"{label} dq = d mod (q-1)", priv.dq, priv.d % (priv.q - 1))
        check(f"{label} q·qInv ≡ 1 (mod p)", (priv.q * priv.q_inv) % priv.p, 1)

        rng = random.Random(seed)
        messages = [0, 1, 2, 42, pub.n - 1]
        messages += [rng.randrange(0, pub.n) for _ in range(20)]
        mismatches = 0
        for m in messages:
            c = rsa.encrypt(pub, m)
            if c != pow(m, pub.e, pub.n):
                mismatches += 1
            if rsa.decrypt(priv, c) != pow(c, priv.d, pub.n):
                mismatches += 1
            if rsa.decrypt_crt(priv, c) != pow(c, priv.d, pub.n):
                mismatches += 1
        check(f"{label} 25 组明文：加密 / 解密 / CRT 均与 pow 一致", mismatches, 0)

    return keys


def section_strings(keys):
    banner("【六】字符串 / 中文分块编码")
    kp1 = keys[(64, 2025)]
    pub, priv = kp1.public_key, kp1.private_key

    messages = ["", "A", "Online BookStore", "在线书店",
                "安全电子商务系统——第5周RSA演示"]
    for message in messages:
        mine = rsa.encrypt_string(pub, message)
        independent = std_encrypt_string(pub, message)
        check(f"encrypt_string 与独立编码一致：{message!r}", mine, independent)
        check(f"decrypt_string 往返：{message!r}",
              rsa.decrypt_string(priv, mine), message)
        check(f"独立解密还原：{message!r}",
              std_decrypt_blocks(priv, mine).decode("utf-8"), message)

    check("K1 m=2 密文向量", rsa.encrypt(pub, 2), 4208667619380246267)
    check("K1 m=42 密文向量", rsa.encrypt(pub, 42), 10689628196788140947)
    check("K1 m=n-1 密文向量", rsa.encrypt(pub, pub.n - 1), pub.n - 1)

    kp3 = keys[(128, 20250909)]
    blocks = rsa.encrypt_string(kp3.public_key, "Secure E-Commerce")
    check("128 位 Secure E-Commerce 密文块",
          [hex(x) for x in blocks],
          ["0xb73fb66af58ac79ce67cdd5b11634c67",
           "0x31fa591a0d893b659bc05f0b25d3680d"])
    check("128 位 CRT 与 pow 一致",
          rsa.decrypt_crt(kp3.private_key, blocks[0]),
          pow(blocks[0], kp3.private_key.d, kp3.public_key.n))


def section_boundaries(keys):
    banner("【七】边界与非法输入")
    kp = keys[(64, 7)]
    pub, priv = kp.public_key, kp.private_key
    n = pub.n

    check("encrypt(0) 与 pow 一致", rsa.encrypt(pub, 0), pow(0, pub.e, n))
    check("encrypt(1)", rsa.encrypt(pub, 1), 1)
    check("decrypt(0)", rsa.decrypt(priv, 0), 0)
    check("CRT decrypt(0)", rsa.decrypt_crt(priv, 0), 0)

    def raises(exc_type, action):
        try:
            action()
        except exc_type:
            return True
        except Exception:
            return False
        return False

    check_true("encrypt(n) 抛 ValueError", raises(ValueError, lambda: rsa.encrypt(pub, n)))
    check_true("encrypt(n+1) 抛 ValueError", raises(ValueError, lambda: rsa.encrypt(pub, n + 1)))
    check_true("encrypt(-1) 抛 ValueError", raises(ValueError, lambda: rsa.encrypt(pub, -1)))
    check_true("decrypt(n) 抛 ValueError", raises(ValueError, lambda: rsa.decrypt(priv, n)))
    check_true("decrypt(-5) 抛 ValueError", raises(ValueError, lambda: rsa.decrypt(priv, -5)))
    check_true("mod_pow(2, 3, 0) 抛 ValueError",
               raises(ValueError, lambda: bigint_ops.mod_pow(2, 3, 0)))
    check_true("mod_inverse(6, 9) 抛 ArithmeticError",
               raises(ArithmeticError, lambda: bigint_ops.mod_inverse(6, 9)))

    tampered = rsa.encrypt_string(pub, "RSA")
    tampered[0] += 1
    check_true("篡改密文块被拒绝",
               raises(ValueError, lambda: rsa.decrypt_string(priv, tampered)))


def main():
    banner("标准库交叉验证（第二条路径）")
    print("  被测主实现：src/crypto/bigint_ops.py、src/crypto/rsa.py")
    print("  复算工具：Python 标准库 pow / math.gcd（不复用被测函数）")
    print("  说明：本文件不参与主实现，也不被主实现导入。")

    section_mod_pow()
    section_gcd_and_inverse()
    section_primality()
    section_rsa_classic()
    keys = section_deterministic_keys()
    section_strings(keys)
    section_boundaries(keys)

    banner("小结")
    total = passed + failed
    print(f"  断言通过 {passed} / {total} 项，失败 {failed} 项")
    print("  结论：" + ("全部一致，主实现与标准库交叉验证通过。"
                       if failed == 0 else "存在不一致，请检查。"))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
