#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小位宽 RSA 实现（64 / 128 / 256 位）

=========================================================================
交付物：小位宽 RSA 实现（源码）
位置　：src/crypto/rsa.py
阶段　：第 5 周 —— 密码学基础算法与 RSA 实现

本模块实现「教科书式 RSA」（Textbook RSA）的完整流程：
    1. 密钥生成   p, q, n = p·q, φ(n) = (p-1)(q-1), e, d = e⁻¹ mod φ(n)
    2. 加密       c = m^e mod n
    3. 解密       m = c^d mod n
    4. CRT 加速   m = m2 + q·(q⁻¹·(m1 - m2) mod p)，m1 = c^dp mod p, m2 = c^dq mod q
    5. 字符串/中文  按模数位宽分块，块首加 0x01 哨兵字节以保留前导 0

依赖
-------------------------------------------------------------------------
复用同目录的 bigint_ops（模幂 mod_pow、模逆 mod_inverse、素数生成
random_prime 等）。主实现**不**调用标准库的 pow(a, b, m)，这些只允许
出现在交叉验证脚本（verify_with_stdlib.py）中。

可复现性
-------------------------------------------------------------------------
所有随机性都来自调用方传入的随机源。传入 JavaRandom(固定种子) 即可得到
完全相同的密钥与密文 —— 且因 bigint_ops.JavaRandom 精确复刻了
java.util.Random，此处用种子 2025 生成的密钥与原先 Java 版**逐位相同**，
既有测试向量表无需重算。模块的 main() 即按固定种子运行，其输出即为
测试向量的「期望值」来源。

安全边界警示
-------------------------------------------------------------------------
【仅用于教学，不得用于任何真实数据】
本模块刻意实现小位宽 RSA，目的是**演示它为什么不安全**，而不是提供安全能力：
  · 64 位模数可在毫秒级被 Pollard ρ 分解（见 main() 第 6 节实测）；
  · 无填充的 RSA 是确定性的，存在选择明文攻击、乘法同态攻击；
  · 非常数时间实现，存在计时侧信道；
  · 密钥生成的随机源是 JavaRandom（LCG），非密码学安全。
生产环境必须使用经审计的标准密码库（cryptography / PyCryptodome），
密钥长度 >= 2048 位，加密用 RSA-OAEP，签名用 RSA-PSS。

如何直接运行
-------------------------------------------------------------------------
    python src/crypto/rsa.py

如何被其他脚本调用
-------------------------------------------------------------------------
    import rsa
    kp = rsa.generate_key_pair(64, bigint_ops.JavaRandom(2025))
    c = rsa.encrypt(kp.public_key, 42)

:since: 第 5 周
"""

from __future__ import annotations

import sys
import time

try:                                   # 作为包导入时
    from . import bigint_ops
    from .bigint_ops import JavaRandom
except ImportError:                    # 直接运行/同目录导入时
    import bigint_ops
    from bigint_ops import JavaRandom

__all__ = [
    "DEFAULT_E",
    "FALLBACK_EXPONENTS",
    "MIN_BITLENGTH",
    "PublicKey",
    "PrivateKey",
    "KeyPair",
    "generate_key_pair",
    "encrypt",
    "decrypt",
    "decrypt_crt",
    "block_size_bytes",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_string",
    "decrypt_string",
    "hex_blocks",
    "pollard_rho",
]

#: 常用公开指数 65537 = 2^16 + 1，兼具安全性与运算效率。
DEFAULT_E = 65537

#: 备选公开指数（Fermat 素数），当 65537 与 φ(n) 不互素时依次尝试。
FALLBACK_EXPONENTS = (3, 5, 17, 257)

#: 允许的最小 RSA 位宽。太小的模数无法承载分块，且失去演示意义。
MIN_BITLENGTH = 32


# =====================================================================
# 一、密钥对象
# =====================================================================


class PublicKey:
    """RSA 公钥：模数 n 与公开指数 e。``c = m^e mod n``。"""

    __slots__ = ("n", "e", "bit_length")

    def __init__(self, n, e):
        if n is None or e is None:
            raise ValueError("n / e 不能为 None")
        if n <= 0:
            raise ValueError("模数 n 必须为正")
        if e <= 0:
            raise ValueError("公开指数 e 必须为正")
        self.n = n
        self.e = e
        self.bit_length = n.bit_length()

    def block_size_bytes(self):
        """每个明文分块可承载的字节数（见 :func:`block_size_bytes`）。"""
        return block_size_bytes(self.n)

    def __repr__(self):
        return (f"RSA公钥{{ 位宽={self.bit_length},\n"
                f"  n = {self.n}\n"
                f"  e = {self.e} }}")


class PrivateKey:
    """RSA 私钥：模数 n、私钥指数 d，以及 CRT 加速参数。``m = c^d mod n``。"""

    __slots__ = ("n", "e", "d", "p", "q", "phi", "dp", "dq", "q_inv")

    def __init__(self, n, e, d, p, q, phi, dp, dq, q_inv):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.phi = phi
        self.dp = dp
        self.dq = dq
        self.q_inv = q_inv

    def public_key(self):
        """对应的公钥。"""
        return PublicKey(self.n, self.e)

    def __repr__(self):
        return ("RSA私钥{\n"
                f"  n    = {self.n}\n"
                f"  e    = {self.e}\n"
                f"  d    = {self.d}\n"
                f"  p    = {self.p}\n"
                f"  q    = {self.q}\n"
                f"  φ(n) = {self.phi}\n"
                f"  dp   = {self.dp}\n"
                f"  dq   = {self.dq}\n"
                f"  qInv = {self.q_inv} }}")


class KeyPair:
    """一对 RSA 密钥。"""

    __slots__ = ("public_key", "private_key")

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def __repr__(self):
        return "KeyPair(public_key=…, private_key=…)"


# =====================================================================
# 二、密钥生成
# =====================================================================


def generate_key_pair(bit_length, rnd):
    """生成指定位宽的 RSA 密钥对。

    步骤：
        1. 取两个位宽约各半的随机素数 p、q（p ≠ q），由
           :func:`bigint_ops.random_prime` 生成，素性由 Miller-Rabin 判定；
        2. n = p·q，若 n 的位宽不等于目标位宽则重挑（p、q 最高位均为 1 时，
           n 可能是 bit_length 或 bit_length-1 位）；
        3. φ(n) = (p-1)(q-1)；
        4. 选 e：优先 65537，若 gcd(e, φ(n)) ≠ 1 则依次尝试 3/5/17/257，
           再退化为从 3 起的奇数搜索；
        5. d = e⁻¹ mod φ(n)（扩展欧几里得）；
        6. 计算 CRT 参数 dp、dq、qInv。

    可复现性：随机性完全来自参数 rnd。传 ``JavaRandom(seed)`` 时，可重跑
    得到完全相同的密钥。

    复杂度：时间由素数搜索主导，期望 O(bit_length × log n × M(n))；
    空间 O(bit_length) 位。

    :raises ValueError: bit_length 过小或 rnd 为 None
    """
    if rnd is None:
        raise ValueError("随机源不能为 None")
    if bit_length < MIN_BITLENGTH:
        raise ValueError(f"位宽至少为 {MIN_BITLENGTH}，收到 {bit_length}")

    p_bits = bit_length // 2
    q_bits = bit_length - p_bits

    while True:
        p = bigint_ops.random_prime(p_bits, rnd)
        while True:
            q = bigint_ops.random_prime(q_bits, rnd)
            if q != p:                 # 必须互异
                break
        n = p * q
        if n.bit_length() == bit_length:    # 保证模数达到目标位宽
            break

    phi = (p - 1) * (q - 1)
    e = _choose_public_exponent(phi)
    d = bigint_ops.mod_inverse(e, phi)

    # CRT 加速参数
    p_minus_1 = p - 1
    q_minus_1 = q - 1
    dp = d % p_minus_1
    dq = d % q_minus_1
    q_inv = bigint_ops.mod_inverse(q, p)

    return KeyPair(PublicKey(n, e),
                   PrivateKey(n, e, d, p, q, phi, dp, dq, q_inv))


def _choose_public_exponent(phi):
    """选择与 φ(n) 互素的公开指数 e。

    优先 65537（2^16+1，二进制仅两个 1，模幂运算快），否则尝试小 Fermat
    素数，最后从 3 起搜索奇数。
    """
    if bigint_ops.gcd(DEFAULT_E, phi) == 1:
        return DEFAULT_E
    for candidate in FALLBACK_EXPONENTS:
        if bigint_ops.gcd(candidate, phi) == 1:
            return candidate
    e = 3
    while bigint_ops.gcd(e, phi) != 1:
        e += 2
    return e


# =====================================================================
# 三、加密与解密（整型）
# =====================================================================


def encrypt(pub, m):
    """加密单个整数：``c = m^e mod n``。

    要求：``0 <= m < n``。明文是「一个剩余类代表的整数」，不是任意大数。

    复杂度：时间 O(log e × M(n))；空间 O(n)。

    :raises ValueError: m 不在 [0, n) 内
    """
    _require_in_range(m, pub.n, "明文 m")
    return bigint_ops.mod_pow(m, pub.e, pub.n)


def decrypt(priv, c):
    """解密单个整数：``m = c^d mod n``（直接法，不使用 CRT）。

    复杂度：时间 O(log d × M(n))；空间 O(n)。

    :raises ValueError: c 不在 [0, n) 内
    """
    _require_in_range(c, priv.n, "密文 c")
    return bigint_ops.mod_pow(c, priv.d, priv.n)


def decrypt_crt(priv, c):
    """解密单个整数（CRT 加速）。

    原理（中国剩余定理）：设 ``m1 = c^dp mod p``、``m2 = c^dq mod q``，则

        h = q⁻¹·(m1 - m2) mod p
        m = m2 + h·q

    因 dp、dq 各只有 d 的一半位长，两半模幂的总代价约为直接法的 1/4
    （模乘 O(n²) 下），再叠加小模数运算的常数优势。

    复杂度：时间约为直接法的 1/4；空间 O(n)。
    """
    _require_in_range(c, priv.n, "密文 c")
    m1 = bigint_ops.mod_pow(c, priv.dp, priv.p)
    m2 = bigint_ops.mod_pow(c, priv.dq, priv.q)
    h = (priv.q_inv * (m1 - m2)) % priv.p
    return m2 + h * priv.q


# =====================================================================
# 四、字符串 / 中文明文的分块加解密
# =====================================================================


def block_size_bytes(n):
    """计算在模数 n 下每个明文分块可承载的字节数。

    推导：块首插入 1 个 0x01 哨兵字节（用于解密时还原被整数编码吞掉的
    前导 0）。设 n 的位宽为 b，则能安全落入 [0, n) 的最大编码字节数为
    ``floor((b-1)/8)``，扣掉哨兵 1 字节后即为本值。

    例：64 位模数 → 6 字节/块；128 位 → 14 字节/块；256 位 → 30 字节/块。
    """
    if n is None:
        raise ValueError("模数不能为 None")
    max_encoded_bytes = (n.bit_length() - 1) // 8
    block_bytes = max_encoded_bytes - 1
    if block_bytes < 1:
        raise ValueError(f"模数过小（位宽 {n.bit_length()}），无法承载分块加密")
    return block_bytes


def _to_byte_array(x):
    """复刻 Java ``BigInteger.toByteArray()`` 对非负数的语义。

    返回**补码最小大端字节数组**：正数若最高字节 >= 0x80 会补一个 0x00
    前导字节（符号位），0 返回 b'\\x00'。本模块的输入恒为非负。
    """
    if x < 0:
        raise ValueError("本模块仅处理非负整数的字节编码")
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    b = x.to_bytes(length, "big")
    if b[0] & 0x80:                    # 需补符号位 0
        b = b"\x00" + b
    return b


def encrypt_bytes(pub, data):
    """加密任意字节串，按模数位宽自动分块。

    编码：每个分块前加 1 字节 0x01 哨兵，再整体解释为非负整数。
    空输入返回长度为 0 的列表。

    :param data: 明文字节（bytes / bytearray）
    :return: 密文分块列表
    """
    if data is None:
        raise ValueError("明文不能为 None")
    if len(data) == 0:
        return []
    bs = block_size_bytes(pub.n)
    count = (len(data) + bs - 1) // bs
    out = []
    for i in range(count):
        off = i * bs
        length = min(bs, len(data) - off)
        block = b"\x01" + bytes(data[off:off + length])     # 哨兵：保证前导 0 不丢失
        out.append(encrypt(pub, int.from_bytes(block, "big")))
    return out


def decrypt_bytes(priv, blocks):
    """解密字节分块并还原为原始字节串。

    每个分块解密后校验首字节必须为哨兵 0x01，否则说明密文被篡改或密钥不匹配。

    :raises ValueError: 分块格式非法（哨兵缺失）
    """
    if blocks is None:
        raise ValueError("密文分块不能为 None")
    out = bytearray()
    for block in blocks:
        m = decrypt(priv, block)
        raw = _to_byte_array(m)
        if len(raw) < 1 or raw[0] != 0x01:
            raise ValueError("密文分块格式非法：缺失哨兵字节（可能被篡改或密钥不匹配）")
        out += raw[1:]
    return bytes(out)


def encrypt_string(pub, message):
    """加密字符串（UTF-8 编码），支持中文等多字节字符。"""
    if message is None:
        raise ValueError("明文不能为 None")
    return encrypt_bytes(pub, message.encode("utf-8"))


def decrypt_string(priv, blocks):
    """解密回字符串（UTF-8 解码）。"""
    return decrypt_bytes(priv, blocks).decode("utf-8")


# =====================================================================
# 五、工具方法
# =====================================================================


def _require_in_range(x, n, label):
    """校验 x 落在 [0, n) 内，否则抛出异常（「非法输入明确拒绝」）。"""
    if x is None:
        raise ValueError(f"{label} 不能为 None")
    if x < 0 or x >= n:
        raise ValueError(f"{label} 必须落在 [0, n) 内，n = {n}，收到 {x}")


def hex_blocks(blocks):
    """密文分块列表转十六进制字符串，便于写入测试向量表。"""
    return "[" + ", ".join("0x" + format(b, "x") for b in blocks) + "]"


# =====================================================================
# 六、直接运行：自检 + 边界 + 性能 + 安全边界
# =====================================================================

_passed = 0
_failed = 0


def _brief(s):
    """过长数字截断显示，便于阅读。"""
    if s is None:
        return "null"
    s = str(s)
    if len(s) <= 46:
        return s
    return s[:22] + f"…({len(s)}位)…" + s[-12:]


def check(label, actual, expected):
    """断言实际值等于期望值。"""
    global _passed, _failed
    a, e = str(actual), str(expected)
    if a == e:
        _passed += 1
        print(f"  [通过] {label:<56} = {_brief(a)}")
    else:
        _failed += 1
        print(f"  [失败] {label:<56} = {_brief(a)}")
        print(f"         {'':<56} 期望 {_brief(e)}")


def check_true(label, actual):
    """断言布尔结果为真。"""
    check(label, actual, True)


def check_throws(label, exc_type, action):
    """断定期望抛出指定异常（用于非法输入用例）。"""
    global _passed, _failed
    try:
        action()
        _failed += 1
        print(f"  [失败] {label:<56} 未抛出异常（期望 {exc_type.__name__}）")
    except BaseException as exc:            # noqa: BLE001
        if isinstance(exc, exc_type):
            _passed += 1
            print(f"  [通过] {label:<56} 抛出 {exc_type.__name__}")
        else:
            _failed += 1
            print(f"  [失败] {label:<56} 抛出 {type(exc).__name__}"
                  f"（期望 {exc_type.__name__}）")


def _time_best_ns(repeats, task):
    """统计最佳单次耗时（纳秒），用于微基准。"""
    best = None
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        task()
        dt = time.perf_counter_ns() - t0
        if best is None or dt < best:
            best = dt
    return best


def _fmt_ns(ns):
    """格式化耗时。"""
    if ns < 1_000:
        return f"{ns} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000.0:.2f} μs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000.0:.2f} ms"
    return f"{ns / 1_000_000_000.0:.3f} s"


def _banner(title):
    print()
    print("═" * 68)
    print(f"  {title}")
    print("═" * 68)


def pollard_rho(n):
    """Pollard ρ 分解算法（仅用于演示小位宽模数可被分解）。

    用固定的随机种子保证演示可复现。对 64 位模数通常毫秒级命中。

    :param n: 待分解的合数
    :return: n 的一个非平凡因子
    """
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    rnd = JavaRandom(0xC0FFEE)
    while True:
        c = (bigint_ops._random_big_int(n.bit_length(), rnd) % (n - 1)) + 1
        x = (bigint_ops._random_big_int(n.bit_length(), rnd) % (n - 2)) + 2
        y = x
        d = 1
        while d == 1:
            x = _rho_step(x, c, n)
            y = _rho_step(_rho_step(y, c, n), c, n)
            d = bigint_ops.gcd(abs(x - y), n)
        if d != n:
            return d                       # 非平凡因子
        # d == n 说明本轮退化为平凡，换一组参数重试


def _rho_step(x, c, n):
    """ρ 迭代函数 ``f(x) = x² + c (mod n)``。"""
    return (x * x + c) % n


# ---------- 1. 公开教科书向量 ----------

def section1_classic_vector():
    _banner("【一】已知公开向量自检（教科书经典参数，可被任何实现交叉核对）")
    print("  p=61, q=53, n=3233, φ(n)=3120, e=17, d=2753")
    p, q = 61, 53
    n = p * q                          # 3233
    phi = (p - 1) * (q - 1)
    e = 17
    d = bigint_ops.mod_inverse(e, phi)
    pub = PublicKey(n, e)
    priv = PrivateKey(n, e, d, p, q, phi,
                      d % (p - 1), d % (q - 1),
                      bigint_ops.mod_inverse(q, p))

    check("φ(n) = (p-1)(q-1)", phi, 3120)
    check("d = e⁻¹ mod φ(n)", d, 2753)
    c = encrypt(pub, 65)
    check("加密 c = 65^17 mod 3233", c, 2790)
    check("解密 m = 2790^2753 mod 3233", decrypt(priv, c), 65)
    check("CRT 解密与直接解密一致", decrypt_crt(priv, c), decrypt(priv, c))
    check("e·d ≡ 1 (mod φ(n))", (e * d) % phi, 1)


# ---------- 2. 固定种子的确定性向量 ----------

def section2_deterministic_vectors():
    _banner("【二】固定种子可复现 —— 64 位与 128 位 RSA 往返")
    print("  同一 seed 重复生成两次，密钥与密文应完全一致。")

    # 64 位
    k64a = generate_key_pair(64, JavaRandom(2025))
    k64b = generate_key_pair(64, JavaRandom(2025))
    check("64 位：seed=2025 两次 n 相同", k64a.public_key.n, k64b.public_key.n)
    check("64 位：seed=2025 两次 e 相同", k64a.public_key.e, k64b.public_key.e)
    check("64 位：seed=2025 两次 d 相同", k64a.private_key.d, k64b.private_key.d)
    check("64 位：n 位宽", k64a.public_key.bit_length, 64)
    print(f"    p    = {k64a.private_key.p}")
    print(f"    q    = {k64a.private_key.q}")
    print(f"    n    = {k64a.public_key.n}")
    print(f"    φ(n) = {k64a.private_key.phi}")
    print(f"    e    = {k64a.public_key.e}")
    print(f"    d    = {k64a.private_key.d}")

    ms = [0, 1, 2, 42, k64a.public_key.n - 1]
    print("    ── 单块确定性向量（64 位密钥，seed=2025）──")
    print(f"    {'明文 m':<22} {'密文 c = m^e mod n':<24} 解密回 m")
    for m in ms:
        c = encrypt(k64a.public_key, m)
        back = decrypt(k64a.private_key, c)
        _tally(back == m)
        print(f"    {m:<22} {_brief(c):<24} {_brief(back)}   {'✓' if back == m else '✗'}")

    # 128 位
    k128 = generate_key_pair(128, JavaRandom(20250909))
    check("128 位：n 位宽", k128.public_key.bit_length, 128)
    s128 = encrypt_string(k128.public_key, "Secure E-Commerce")
    check("128 位：字符串往返", decrypt_string(k128.private_key, s128), "Secure E-Commerce")
    check("128 位：CRT 解密一致",
          decrypt_crt(k128.private_key, s128[0]), decrypt(k128.private_key, s128[0]))


def _tally(ok):
    """手工记账（用于那些自行打印而非走 check 的用例）。"""
    global _passed, _failed
    if ok:
        _passed += 1
    else:
        _failed += 1


# ---------- 3. 字符串与中文 ----------

def section3_string_and_chinese():
    _banner("【三】字符串与中文明文的加解密（UTF-8 分块）")

    kp = generate_key_pair(64, JavaRandom(2025))
    print("  使用 64 位密钥（seed=2025），每块可承载 "
          f"{kp.public_key.block_size_bytes()} 字节明文。")

    messages = [
        "",                                # 空串
        "A",                               # 单字节
        "Online BookStore",                # 纯英文，跨块
        "在线书店",                          # 中文，1 块
        "安全电子商务系统——第5周RSA演示",       # 中文混合，跨块
    ]
    for msg in messages:
        ct = encrypt_string(kp.public_key, msg)
        back = decrypt_string(kp.private_key, ct)
        ok = back == msg
        _tally(ok)
        print(f"  [{'通过' if ok else '失败'}] 明文=「{msg}」 UTF-8 "
              f"{len(msg.encode('utf-8'))} 字节 → {len(ct)} 块 → 还原「{back}」")
        if 0 < len(ct) <= 3:
            print(f"        密文块 = {hex_blocks(ct)}")


# ---------- 4. 边界与非法输入 ----------

def section4_boundaries():
    _banner("【四】边界与非法输入 —— 明确预期行为")

    kp = generate_key_pair(64, JavaRandom(7))
    pub, priv = kp.public_key, kp.private_key
    n = pub.n

    print("  4.1 明文取值边界")
    check("m = 0 → c = 0", encrypt(pub, 0), 0)
    check("m = 1 → c = 1", encrypt(pub, 1), 1)
    check("m = n-1 往返", decrypt(priv, encrypt(pub, n - 1)), n - 1)
    check("c = 0 → m = 0", decrypt(priv, 0), 0)
    check("CRT: c = 0 → m = 0", decrypt_crt(priv, 0), 0)

    print()
    print("  4.2 非法输入 —— 明确拒绝而非静默出错")
    check_throws("encrypt(m = n) 明文越界", ValueError, lambda: encrypt(pub, n))
    check_throws("encrypt(m = n+1) 明文越界", ValueError, lambda: encrypt(pub, n + 1))
    check_throws("encrypt(m = -1) 明文为负", ValueError, lambda: encrypt(pub, -1))
    check_throws("decrypt(c = n) 密文越界", ValueError, lambda: decrypt(priv, n))
    check_throws("decrypt(c = -5) 密文为负", ValueError, lambda: decrypt(priv, -5))
    check_throws("encrypt_string(None)", ValueError, lambda: encrypt_string(pub, None))
    check_throws("generate_key_pair(16, rnd) 位宽过小",
                 ValueError, lambda: generate_key_pair(16, JavaRandom(1)))

    print()
    print("  4.3 篡改检测 —— 分块哨兵校验")
    ct = encrypt_string(pub, "RSA")
    ct[0] = ct[0] + 1                      # 人为篡改一个密文块
    check_throws("篡改密文块后解密应被拒绝", ValueError, lambda: decrypt_string(priv, ct))

    print()
    print("  4.4 空串与超长输入")
    check("空串 → 0 块", len(encrypt_string(pub, "")), 0)
    check("空串往返", decrypt_string(priv, encrypt_string(pub, "")), "")
    long_msg = "".join(f"超长输入测试-{i};" for i in range(200))
    check_true(f"超长输入({len(long_msg.encode('utf-8'))}字节)往返一致",
               decrypt_string(priv, encrypt_string(pub, long_msg)) == long_msg)


# ---------- 5. CRT 与直接解密性能对比 ----------

def section5_crt_vs_direct():
    _banner("【五】复杂度与性能实测")
    print("  直接解密 m = c^d mod n：指数 d 约 n 位，1 次全宽模幂。")
    print("  CRT 解密：dp、dq 各约 n/2 位，2 次半宽模幂 + 合并。")
    print("  理论上模乘 O(n²) 时，CRT 约为直接法的 1/4 耗时。")
    print()
    print(f"  {'位宽':<10} {'直接解密':<18} {'CRT 解密':<18} 加速比")

    widths = (128, 256, 512, 1024)
    for w in widths:
        kp = generate_key_pair(w, JavaRandom(1000 + w))
        c = encrypt(kp.public_key, 123456789)
        t_direct = _time_best_ns(50, lambda kp=kp, c=c: decrypt(kp.private_key, c))
        t_crt = _time_best_ns(50, lambda kp=kp, c=c: decrypt_crt(kp.private_key, c))
        t_enc = _time_best_ns(50, lambda kp=kp: encrypt(kp.public_key, 123456789))
        print(f"  {str(w) + ' 位':<10} {_fmt_ns(t_direct):<18} {_fmt_ns(t_crt):<18} "
              f"{t_direct / max(1, t_crt):.2f}×")
        if w == widths[0]:
            print(f"  {'':<10} 加密(e={kp.public_key.e})耗时 {_fmt_ns(t_enc)}"
                  "（e 位长远小于 d，故远快于解密）")
    print()
    print("  说明：位宽每次 ×2，直接解密耗时约 ×4（模乘 O(n²)），")
    print("        CRT 通过把一次全宽模幂拆成两次半宽模幂，取得约 3~4 倍加速。")


# ---------- 6. 安全边界 ----------

def section6_security_boundary():
    _banner("【六】安全边界 —— 小位宽 RSA 为什么不能用于生产")

    print("  6.1 实测：64 位模数可在毫秒级被分解（Pollard ρ）")
    kp = generate_key_pair(64, JavaRandom(2025))
    n = kp.public_key.n
    t0 = time.perf_counter_ns()
    factor = pollard_rho(n)
    dt = time.perf_counter_ns() - t0
    print(f"      模数 n      = {n}")
    print(f"      分解得到     = {factor}")
    print(f"      真实素因子 p = {kp.private_key.p}")
    print(f"      分解耗时     = {_fmt_ns(dt)}")
    check("分解结果确为 n 的因子", n % factor, 0)
    print("      → 分解出 p、q 后，由公开的 e 求 d 毫无障碍，私钥即刻泄露。")

    print()
    print("  6.2 实测：无填充 RSA 是确定性的，且具有乘法同态性")
    m1, m2 = 1234567, 7654321
    c1 = encrypt(kp.public_key, m1)
    c2 = encrypt(kp.public_key, m2)
    c11 = encrypt(kp.public_key, m1)
    check("同一明文两次加密得到同一密文（确定性）", c11, c1)
    c_prod = (c1 * c2) % n
    c_mul = encrypt(kp.public_key, (m1 * m2) % n)
    check("E(m1)·E(m2) ≡ E(m1·m2) (mod n)（乘法同态）", c_prod, c_mul)
    print("      → 攻击者可对密文做乘法，无需私钥即可让明文翻倍；")
    print("        更狡猾地，可通过选择明文攻击逐位恢复消息。")

    print()
    print("  6.3 计时侧信道")
    print("      mod_pow 按指数二进制位分支（为 1 才多一次模乘），")
    print("      运算次数与内存访问随密钥位变化，可被计时推断私钥比特。")
    print("      生产做法：常数时间实现，或对密文做盲化（blinding）。")

    print()
    print("  6.4 随机源不满足密码学安全")
    print("      密钥生成用 JavaRandom（LCG），其序列可被预测；")
    print("      本模块保留它是为了「固定种子即可复现」的教学取舍。")
    print("      生产做法：改用 CSPRNG（os.urandom / secrets / SystemRandom）。")

    print()
    print("  ── 生产环境应当怎么做 ──")
    print("  ① 密钥长度：RSA ≥ 2048 位（NIST 建议 3072 位，长期数据更长）；")
    print("  ② 填充：加密用 RSA-OAEP，签名用 RSA-PSS，绝不裸用模幂；")
    print("  ③ 实现：委托给经审计的标准库（cryptography / PyCryptodome），")
    print("     不要自行实现密钥生成、填充与常数时间运算；")
    print("  ④ 随机数：一律使用 CSPRNG（os.urandom / secrets）。")
    print()
    print("  结论：本模块可以回答「RSA 加解密为什么正确、代价是多少」，")
    print("        但它的一切设计都为教学复现服务，不能承担任何真实数据的机密性。")


def main(argv=None):
    """主入口。"""
    _banner("小位宽 RSA 实现 · 自检 / 边界 / 性能 / 安全边界")

    section1_classic_vector()
    section2_deterministic_vectors()
    section3_string_and_chinese()
    section4_boundaries()
    section5_crt_vs_direct()
    section6_security_boundary()

    _banner("小结")
    print(f"  断言通过 {_passed} 项，失败 {_failed} 项")
    print("  结论：全部用例通过，加解密结果可复现且与已知向量一致。"
          if _failed == 0 else "  结论：存在失败用例，请检查实现。")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
