#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密码学基础算法模块

=========================================================================
交付物：密码学基础算法模块（源码）
位置　：src/crypto/bigint_ops.py
阶段　：第 5 周 —— 密码学基础算法与 RSA 实现

本模块提供四组能力：
    1. 模运算基础          mod / mod_add / mod_sub / mod_mul
    2. 快速幂（模幂）      mod_pow        重复平方乘，O(log e)
                           mod_pow_naive  朴素连续乘法，O(e)，仅供性能对比
    3. 最大公约数与模逆    gcd / ext_gcd（扩展欧几里得）/ mod_inverse
    4. 素性检测与素数生成  is_probable_prime（Miller-Rabin）/ random_prime

设计约束
-------------------------------------------------------------------------
· 本模块是 RSA 的「运算基础」，需被同目录下的 rsa.py 调用，故全部
  以模块级函数导出，无状态、无副作用。
· 主实现不调用 Python 内置的 pow(a, b, m)，快速幂、gcd、素性检测均自行
  实现；标准库按任务书要求只允许出现在交叉验证脚本
  （verify_with_stdlib.py）中，与主实现分开存放。
· 以 Python 内置任意精度整数 int 作为大整数载体
  （任务书明确许可：「Python 的 int、Java 的 BigInteger 可以直接使用，
  把时间花在算法本身上」）。

关于随机源（重要）
-------------------------------------------------------------------------
本模块内置 JavaRandom —— 精确复刻 java.util.Random 的 48 位 LCG。
之所以不使用 random.Random（梅森旋转），是为了**保持与本组既有测试
向量表完全一致**：此前 Java 版用 new Random(seed) 生成的 K1/K2/K3
密钥、以及全部固定种子密文向量，在 Python 版下仍逐位相同，无需重算。

这一复刻本身也构成一条交叉验证证据：同一份 LCG 在 Java 与 Python
两种语言下产出完全相同的随机序列。

安全边界警示
-------------------------------------------------------------------------
【仅用于教学，不得用于任何真实数据】
本模块面向算法原理演示，其自身不构成密码学安全实现：
  · 未做常数时间实现，快速幂的分支与运算次数随指数位变化，存在计时侧信道；
  · random_prime 默认接收 JavaRandom（LCG），可复现但不是密码学安全随机源；
  · 小位宽（64/128 位）RSA 的模数可在单机数秒内分解。
生产环境必须调用经审计的标准库（cryptography / PyCryptodome），并使用足够
密钥长度与正确填充。详见 main() 末节「安全边界」。

如何直接运行
-------------------------------------------------------------------------
    python src/crypto/bigint_ops.py

如何被其他脚本调用
-------------------------------------------------------------------------
    # 同目录下（如 rsa.py）
    import bigint_ops
    c = bigint_ops.mod_pow(m, e, n)

    # 或按包路径
    from crypto.bigint_ops import mod_pow, random_prime

:since: 第 5 周
"""

from __future__ import annotations

import sys
import time

__all__ = [
    "JavaRandom",
    "DETERMINISTIC_MR_BOUND",
    "SMALL_WITNESSES",
    "MAX_NAIVE_EXPONENT",
    "mod",
    "mod_add",
    "mod_sub",
    "mod_mul",
    "mod_pow",
    "mod_pow_naive",
    "bit_length",
    "gcd",
    "ext_gcd",
    "mod_inverse",
    "random_in_range",
    "is_probable_prime",
    "random_prime",
]


# =====================================================================
# 常量
# =====================================================================

ZERO = 0
ONE = 1
TWO = 2

#: 确定性 Miller-Rabin 判决上界：3 317 044 064 679 887 385 961 981。
#: 当 n 小于该值时，使用前 13 个素数 {2,3,5,...,41} 作见证即可给出**确定性**
#: 结论（已由 Sorenson & Webster 证明）。该上界约 3.3×10^24，完整覆盖
#: 64 位范围（2^64 ≈ 1.8×10^19），但不覆盖 128 位（2^128 ≈ 3.4×10^38），
#: 128 位以上退化为概率性判定。
#:
#: 注意：**上界与见证集个数必须成对匹配，不可拆开使用**。前 12 个素数
#: {2,...,37} 的确定性上界只到 3 186 658 578 340 311 511 674 671（≈3.19×10^23）；
#: 前 13 个素数 {2,...,41} 才对应本上界。若去掉 41 而保留本上界，
#: 区间 [3.19×10^23, 3.32×10^24) 内存在能骗过这 12 个基的强伪素数，
#: 会把合数误判为素数。
DETERMINISTIC_MR_BOUND = 3317044064679887385961981

#: 确定性见证集，必须与 DETERMINISTIC_MR_BOUND 成对使用（13 个素数，末位为 41）。
SMALL_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)

#: 朴素连续乘法允许的最大指数。朴素法复杂度为 O(e)，指数过大将长时间占用
#: CPU。该阈值用于防止误用导致的假死，超出即抛出 ValueError。
MAX_NAIVE_EXPONENT = 10_000_000


# =====================================================================
# 随机源：精确复刻 java.util.Random
# =====================================================================


class JavaRandom:
    """java.util.Random 的精确复刻（48 位线性同余发生器，LCG）。

    算法与常量与 JDK 完全一致：

        seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)

    提供 ``next_bytes(n)``，其字节序与 Java ``Random.nextBytes(byte[])``
    相同（每个 32 位输出按小端拆成 4 字节），因此
    ``big_int(bits)`` 与 Java ``new BigInteger(bits, rnd)`` 逐位等价。

    这是本模块保持「与 Java 版测试向量完全一致」的关键：同样的种子
    ``JavaRandom(2025)`` 在 Python 下生成的 RSA 密钥，与
    ``new Random(2025)`` 在 Java 下生成的完全相同。

    :param seed: 整数种子。固定种子即可复现整条随机序列。
    """

    __slots__ = ("_seed",)

    MULTIPLIER = 0x5DEECE66D
    ADDEND = 0xB
    MASK = (1 << 48) - 1

    def __init__(self, seed):
        if seed is None:
            raise ValueError("随机种子不能为 None")
        if not isinstance(seed, int):
            raise TypeError(f"随机种子必须是整数，收到 {type(seed).__name__}")
        self._seed = (seed ^ self.MULTIPLIER) & self.MASK

    def _next(self, bits):
        """Java Random.next(int bits)。"""
        self._seed = (self._seed * self.MULTIPLIER + self.ADDEND) & self.MASK
        return self._seed >> (48 - bits)

    def next_int(self):
        """Java Random.nextInt()：返回有符号 32 位整数。"""
        v = self._next(32)
        return v - (1 << 32) if v >= (1 << 31) else v

    def next_bytes(self, n):
        """Java Random.nextBytes(byte[])：生成 n 字节，小端填充。"""
        if n < 0:
            raise ValueError("字节数不能为负")
        out = bytearray(n)
        i = 0
        while i < n:
            r = self.next_int()
            k = min(n - i, 4)
            while k > 0:
                out[i] = r & 0xFF
                i += 1
                r >>= 8
                k -= 1
        return bytes(out)

    def big_int(self, bits):
        """等价于 ``new BigInteger(bits, rnd)``：返回 [0, 2^bits) 的随机整数。

        字节为大端序，并掩掉最高字节中超出 bits 的多余高位。
        """
        if bits < 0:
            raise ValueError("位长不能为负")
        num_bytes = (bits + 7) // 8
        b = bytearray(self.next_bytes(num_bytes)) if num_bytes > 0 else bytearray()
        if num_bytes > 0:
            excess = 8 * num_bytes - bits
            b[0] &= (1 << (8 - excess)) - 1
        return int.from_bytes(bytes(b), "big")

    def __repr__(self):
        return f"JavaRandom(seed=…, state=0x{self._seed:012X})"


def _random_big_int(bits, rnd):
    """从随机源取 [0, 2^bits) 的整数。

    优先使用 ``rnd.big_int``（JavaRandom 提供）；否则回退到
    ``getrandbits``，便于传入自定义随机源。
    """
    if hasattr(rnd, "big_int"):
        return rnd.big_int(bits)
    return rnd.getrandbits(bits)


# =====================================================================
# 五、参数校验工具
# =====================================================================


def _require_positive_modulus(m):
    """校验模数为正整数。"""
    if m is None:
        raise ValueError("模数不能为 None")
    if m <= 0:
        raise ValueError(f"模数必须为正整数，收到 {m}")


def _trunc_div(a, b):
    """Java 的 ``/`` 语义：向零截断除法。

    Python 的 ``//`` 对负数向下取整，与 Java 不同；扩展欧几里得中会
    出现负余数，故此处显式复刻 Java 行为，保证与既有实现逐值一致。
    """
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


# =====================================================================
# 一、模运算基础
# =====================================================================


def mod(a, m):
    """规范化取模：返回 ``a mod m`` 的非负代表元，结果恒在 ``[0, m)``。

    与 Python 内置 ``%`` 的结果一致，但显式声明了「模数必须为正」的
    前置条件：``mod(-1, 7) == 6``。密码学中必须使用非负代表元，
    否则负数会破坏后续模乘的正确性。

    复杂度：时间 O(n²) 位运算，空间 O(n)。

    :param a: 被模数，可为负
    :param m: 模数，必须 > 0
    :raises ValueError: m 为 None 或 m <= 0
    """
    _require_positive_modulus(m)
    return a % m


def mod_add(a, b, m):
    """模加：``(a + b) mod m``，结果为 ``[0, m)`` 内的非负代表元。

    复杂度：时间 O(n)，空间 O(n)。
    """
    _require_positive_modulus(m)
    return (a + b) % m


def mod_sub(a, b, m):
    """模减：``(a - b) mod m``，结果为 ``[0, m)`` 内的非负代表元。

    复杂度：时间 O(n)，空间 O(n)。
    """
    _require_positive_modulus(m)
    return (a - b) % m


def mod_mul(a, b, m):
    """模乘：``(a × b) mod m``，结果为 ``[0, m)`` 内的非负代表元。

    复杂度：时间 O(n²)，空间 O(n)。
    """
    _require_positive_modulus(m)
    return (a * b) % m


# =====================================================================
# 二、快速幂（模幂）
# =====================================================================


def mod_pow(base, exp, m):
    """快速幂（模幂）：计算 ``base^exp mod m``，采用重复平方乘。

    原理：把指数 exp 写成二进制 ``exp = Σ b_i·2^i``，则

        base^exp = Π (base^(2^i))   对所有 b_i = 1 的 i

    顺序扫描 exp 的每一位：为 1 时把当前平方积乘入结果，每轮把底数
    自乘一次。因此只需 O(log₂ exp) 次模乘，而非 O(exp) 次。

    边界与约定：

    ============  ==============  ==================================
    输入          返回            说明
    ============  ==============  ==================================
    exp = 0       1 mod m         约定 a⁰ = 1（含 a = 0，即 0⁰ = 1）
    m = 1         0               模 1 下唯一剩余类即 0
    base = 0     0               正常（exp > 0 时）
    base < 0      [0, m) 内结果    底数先规范化
    exp < 0       base⁻¹^|exp|    需 base 与 m 互素，否则抛异常
    m <= 0        抛异常          模数必须为正
    ============  ==============  ==================================

    复杂度：时间 O(log₂|exp| × M(n))，空间 O(n)，迭代实现无递归栈。

    :param base: 底数，可为负
    :param exp: 指数，可为负（要求 base 与 m 互素）
    :param m: 模数，必须 > 0
    :raises ValueError: m <= 0
    :raises ArithmeticError: exp < 0 且 base 在模 m 下不可逆
    """
    _require_positive_modulus(m)

    # 模 1：所有整数同余于 0，无需计算
    if m == 1:
        return ZERO

    # 负指数：先求逆元，再按正指数计算
    if exp < 0:
        base_inv = mod_inverse(base, m)
        return mod_pow(base_inv, -exp, m)

    # 重复平方乘
    result = ONE
    b = base % m            # 底数规范化到 [0, m)
    e = exp
    while e > 0:
        if e & 1:           # 当前最低位为 1
            result = (result * b) % m
        b = (b * b) % m     # 底数自乘，对应位权 2^i
        e >>= 1             # 指数右移一位
    return result


def mod_pow_naive(base, exp, m):
    """朴素连续乘法求模幂：重复 exp 次模乘，**仅用于性能对比**。

    复杂度：时间 O(exp)，空间 O(n)。与 :func:`mod_pow` 的 O(log exp)
    形成对照，是「为什么必须用快速幂」的实测证据来源。

    :raises ValueError: 指数为负或超过 MAX_NAIVE_EXPONENT
    """
    _require_positive_modulus(m)
    if exp < 0:
        raise ValueError("朴素实现不支持负指数，请用 mod_pow")
    if exp > MAX_NAIVE_EXPONENT:
        raise ValueError(
            f"朴素实现指数上限为 {MAX_NAIVE_EXPONENT}（O(e) 复杂度），"
            f"收到 {exp}；实际计算请用 mod_pow"
        )
    if m == 1:
        return ZERO

    result = ONE
    b = base % m
    e = exp
    while e > 0:            # 逐次相乘，而非按位平方
        result = (result * b) % m
        e -= 1
    return result


def bit_length(x):
    """返回 x 的比特长度（忽略符号），即表示 ``|x|`` 所需的二进制位数。

    例：``bit_length(0) == 0``、``bit_length(1) == 1``、``bit_length(255) == 8``。

    复杂度：时间 O(1)，空间 O(1)。
    """
    if x is None:
        raise ValueError("x 不能为 None")
    return abs(x).bit_length()


# =====================================================================
# 三、最大公约数与模逆
# =====================================================================


def gcd(a, b):
    """欧几里得算法求最大公约数，结果恒为非负。

    边界：``gcd(a, 0) == |a|``；``gcd(0, 0) == 0``；负数先取绝对值。

    复杂度：时间 O(log min(|a|,|b|))（Lamé 定理：最坏情形为相邻斐波那契数），
    空间 O(n)，迭代实现。
    """
    if a is None or b is None:
        raise ValueError("参数不能为 None")
    x = abs(a)
    y = abs(b)
    while y != 0:
        x, y = y, x % y
    return x


def ext_gcd(a, b):
    """扩展欧几里得算法，返回 ``(g, x, y)`` 使 ``a·x + b·y = g = gcd(a, b)``。

    迭代实现（递归在大数下可能栈溢出）。返回值保证 ``g >= 0``。

    复杂度：与 :func:`gcd` 同阶。
    """
    if a is None or b is None:
        raise ValueError("参数不能为 None")

    old_r, r = a, b
    old_s, s = ONE, ZERO       # a 的系数
    old_t, t = ZERO, ONE       # b 的系数

    while r != 0:
        q = _trunc_div(old_r, r)     # 与 Java 的 divide 同为向零截断
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    # 若 gcd 为负（a、b 同为负时可能出现），整体取反保持 g >= 0
    if old_r < 0:
        old_r, old_s, old_t = -old_r, -old_s, -old_t

    return old_r, old_s, old_t


def mod_inverse(a, m):
    """模逆：求 a 在模 m 下的乘法逆元，即满足 ``a·x ≡ 1 (mod m)`` 的 x ∈ [0, m)。

    存在性：当且仅当 ``gcd(a, m) == 1``。约定 ``m == 1`` 时逆元为 0。

    复杂度：时间 O(log min(|a|, m))，空间 O(n)。

    :raises ValueError: m <= 0
    :raises ArithmeticError: gcd(a, m) != 1，逆元不存在
    """
    _require_positive_modulus(m)
    if m == 1:
        return ZERO
    g, x, _ = ext_gcd(a, m)
    if g != ONE:
        raise ArithmeticError(f"模逆不存在：{a} 与 {m} 不互素（gcd = {g}）")
    return x % m


# =====================================================================
# 四、素性检测与素数生成
# =====================================================================


def _is_composite_witness(a, d, s, n, n_minus_one):
    """Miller-Rabin 单轮：a 是否能证明 n 为合数。"""
    x = mod_pow(a, d, n)
    if x == ONE or x == n_minus_one:
        return False                       # 本轮无法证伪
    for _ in range(1, s):
        x = (x * x) % n
        if x == n_minus_one:
            return False                   # 命中 -1，本轮无法证伪
    return True                            # 所有平方均未命中，n 为合数


def random_in_range(lo, hi, rnd):
    """在闭区间 ``[lo, hi]`` 内均匀随机取一个整数。

    采用**拒绝采样**：生成 ``bit_length(hi - lo + 1)`` 位的随机数，
    落在区间外则重抽，直到命中再平移。这样避免取模归约引入的模偏差。

    复杂度：时间 O(n) 期望（拒绝率 < 50%），空间 O(n)。

    :raises ValueError: 参数为 None 或 lo > hi
    """
    if lo is None or hi is None or rnd is None:
        raise ValueError("参数不能为 None")
    if lo > hi:
        raise ValueError(f"下界不能大于上界：{lo} > {hi}")
    span = hi - lo + 1                     # 区间内整数个数
    bits = span.bit_length()
    while True:
        r = _random_big_int(bits, rnd)
        if r < span:                       # 落在区间外则重抽
            return r + lo


def is_probable_prime(n, witnesses, rnd):
    """Miller-Rabin 素性检测。

    原理：把 n-1 写成 ``n-1 = 2^s·d``（d 为奇数）。对见证 a，若 n 为素数则
    ``a^d ≡ 1 (mod n)`` 或存在 ``0 <= r < s`` 使 ``a^(2^r·d) ≡ -1 (mod n)``。
    见证破坏该性质即可断定 n 为合数（合数一定被检出，无假阴性）；素数可能
    被误判为合数，但概率不超过 ``4^-k``（k 为轮数），故称「概率素性」。

    可复现性设计：当 ``n < DETERMINISTIC_MR_BOUND`` 时，改用固定的 13 个
    素数作见证，此时结论是**确定性**的——同一输入永远得到同一结果，不受
    随机源影响。因此 64 位及以下（含本课程 RSA 所用的 64/128 位中的 64 位）
    的判定完全可复现。n 超过该上界时，使用传入的随机源抽取 witnesses 个
    见证，结论为概率性，误判率 ``<= 4^-witnesses``。

    边界：``n <= 1`` → False；``n == 2`` 或 ``3`` → True；n 为偶数 → False。

    :param n: 待检测整数
    :param witnesses: 随机见证轮数；n 小于确定性上界时被忽略
    :param rnd: 随机源，传 ``JavaRandom(seed)`` 可固定种子复现
    :raises ValueError: n 为 None，或 n >= 确定性上界但 witnesses < 1 / rnd 为 None
    """
    if n is None:
        raise ValueError("n 不能为 None")
    if n < TWO:
        return False                       # 0、1 及负数
    if n == TWO or n == 3:
        return True
    if n % 2 == 0:
        return False                       # 偶数（2 已排除）

    # 分解 n-1 = 2^s · d
    d = n - 1
    s = (d & -d).bit_length() - 1          # d 中因子 2 的个数
    d >>= s

    n_minus_one = n - 1

    if n < DETERMINISTIC_MR_BOUND:
        # 确定性分支：固定见证集，不消耗随机源
        for w in SMALL_WITNESSES:
            if w >= n_minus_one:
                continue                   # 见证须落在 [2, n-2]
            if _is_composite_witness(w, d, s, n, n_minus_one):
                return False
        return True

    # 概率分支：随机见证
    if witnesses < 1:
        raise ValueError("n 超出确定性上界时，witnesses 必须 >= 1")
    if rnd is None:
        raise ValueError("n 超出确定性上界时，rnd 不能为 None")
    for _ in range(witnesses):
        a = random_in_range(TWO, n - TWO, rnd)
        if _is_composite_witness(a, d, s, n, n_minus_one):
            return False
    return True


def random_prime(bit_length, rnd):
    """生成恰好 ``bit_length`` 位的随机素数。

    候选由 ``big_int(bit_length) | 2^(bit_length-1) | 1`` 构造，分别保证
    「位长达标」与「为奇数」（直接排除一半候选）。

    注意：生成的素数必为奇数，故 ``bit_length == 2`` 只会得到 3，不会得到 2。

    :param bit_length: 目标位长，至少为 2
    :param rnd: 随机源
    :raises ValueError: rnd 为 None，或 bit_length < 2
    """
    if rnd is None:
        raise ValueError("随机源不能为 None")
    if bit_length < 2:
        raise ValueError(f"位长至少为 2，收到 {bit_length}")

    max_attempts = 1_000_000               # 防御性上限，正常远不会触及
    for _ in range(max_attempts):
        candidate = (
            _random_big_int(bit_length, rnd)
            | (1 << (bit_length - 1))      # 保证达到目标位长
            | 1                            # 保证为奇数
        )
        if is_probable_prime(candidate, 40, rnd):
            return candidate
    raise RuntimeError(f"生成 {bit_length} 位素数失败，已尝试 {max_attempts} 次")


# =====================================================================
# 六、直接运行：自检 + 边界 + 性能实测
# =====================================================================

_passed = 0
_failed = 0


def _brief(s):
    """过长数字截断显示，便于阅读。"""
    s = str(s)
    if len(s) <= 42:
        return s
    return s[:20] + f"…({len(s)}位)…" + s[-12:]


def check(label, actual, expected):
    """断言实际值等于期望值。"""
    global _passed, _failed
    a, e = str(actual), str(expected)
    if a == e:
        _passed += 1
        print(f"  [通过] {label:<52} = {_brief(a)}")
    else:
        _failed += 1
        print(f"  [失败] {label:<52} = {_brief(a)}")
        print(f"         {'':<52} 期望 {_brief(e)}")


def check_true(label, actual):
    """断言布尔结果为真。"""
    check(label, actual, True)


def check_throws(label, exc_type, action):
    """断定期望抛出指定异常（用于非法输入用例）。"""
    global _passed, _failed
    try:
        action()
        _failed += 1
        print(f"  [失败] {label:<52} 未抛出异常（期望 {exc_type.__name__}）")
    except BaseException as exc:            # noqa: BLE001 - 需覆盖所有异常类型
        if isinstance(exc, exc_type):
            _passed += 1
            print(f"  [通过] {label:<52} 抛出 {exc_type.__name__}")
        else:
            _failed += 1
            print(f"  [失败] {label:<52} 抛出 {type(exc).__name__}（期望 {exc_type.__name__}）")


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


def _check_bezout(a, b):
    """校验扩展欧几里得返回的三元组满足 Bézout 恒等式。"""
    global _passed, _failed
    g, x, y = ext_gcd(a, b)
    lhs = a * x + b * y
    if lhs == g and g >= 0:
        _passed += 1
        print(f"  [通过] {'ext_gcd(' + str(a) + ', ' + str(b) + ') 且 a·x+b·y=g':<52} "
              f"g={g}, x={x}, y={y}")
    else:
        _failed += 1
        print(f"  [失败] ext_gcd({a}, {b}): a·x+b·y={lhs} 但 g={g}")


def section1_known_vectors():
    _banner("【一】已知向量自检（期望值为独立实现 / Python 内置 pow 交叉核对所得）")

    print("  1.1 快速幂 mod_pow —— 与教科书/公开向量对照")
    check("mod_pow(4, 13, 497)", mod_pow(4, 13, 497), 445)
    check("mod_pow(65, 17, 3233)     [RSA 样例·加密]", mod_pow(65, 17, 3233), 2790)
    check("mod_pow(2790, 2753, 3233) [RSA 样例·解密]", mod_pow(2790, 2753, 3233), 65)
    check("mod_pow(2, 10, 1000)", mod_pow(2, 10, 1000), 24)
    check("mod_pow(3, 100, 1000000007)", mod_pow(3, 100, 1000000007), 886041711)
    check("mod_pow(2, 644, 645)", mod_pow(2, 644, 645), ONE)

    print()
    print("  1.2 超长输入 —— 指数规模远超朴素法可承受范围")
    exp64 = TWO ** 64
    mod64 = 18446744073709551557          # 已知 64 位素数
    check("mod_pow(2, 2^64, 2^64-59)   指数 65 位", mod_pow(2, exp64, mod64),
          1152921504606846976)
    exp100 = 10 ** 30
    mod128 = 340282366920938463463374607431768211297
    check("mod_pow(3, 10^30, 大模数)    指数 100 位", mod_pow(3, exp100, mod128),
          108836149400431396005421433468511712176)

    print()
    print("  1.3 快速幂与朴素法结果一致（交叉校验）")
    ok = True
    for e in range(0, 41):
        fast = mod_pow(7, e, 1000000007)
        slow = mod_pow_naive(7, e, 1000000007)
        if fast != slow:
            ok = False
            check(f"mod_pow vs mod_pow_naive @ e={e}", fast, slow)
    check_true("mod_pow 与 mod_pow_naive 在 e=0..40 全部一致", ok)

    print()
    print("  1.4 扩展欧几里得 —— 同时校验 a·x + b·y = gcd(a,b)")
    for a, b in [(1071, 462), (12, 8), (240, 46), (17, 3120), (3, 11),
                 (0, 5), (1, 1), (-1071, 462)]:
        _check_bezout(a, b)

    print()
    print("  1.5 模逆 —— 校验 a·a⁻¹ ≡ 1 (mod m)")
    check("mod_inverse(3, 11)", mod_inverse(3, 11), 4)
    check("mod_inverse(17, 3120)      [RSA 样例·私钥 d]", mod_inverse(17, 3120), 2753)
    check("mod_inverse(38, 97)", mod_inverse(38, 97), 23)
    check("mod_inverse(7, 26)", mod_inverse(7, 26), 15)
    check("mod_inverse(65537, 大素数)", mod_inverse(65537, DETERMINISTIC_MR_BOUND),
          3030876447277502728741952)

    print()
    print("  1.6 Miller-Rabin —— 素数判为真")
    for p in (2, 3, 5, 7, 13, 7919, 104729, 2147483647, 2305843009213693951):
        check_true(f"is_probable_prime({p})", is_probable_prime(p, 40, None))
    check_true("is_probable_prime(2^127-1 梅森素数)",
               is_probable_prime(170141183460469231731687303715884105727, 40,
                                 JavaRandom(2026)))

    print()
    print("  1.7 Miller-Rabin —— 合数与伪素数必须判为假")
    print("       （561/1105/1729 为卡迈克尔数，341/2047 为费马伪素数，")
    print("        只用费马小定理会被它们骗过，Miller-Rabin 不会）")
    for c in (0, 1, 4, 9, 15, 21, 25, 100, 341, 561, 1105, 1729, 2047):
        check_true(f"is_probable_prime({c}) = false",
                   not is_probable_prime(c, 40, None))
    check_true("is_probable_prime(1000000007 × 1000000009) = false",
               not is_probable_prime(1000000016000000063, 40, None))

    print()
    print("  1.8 随机素数生成 —— 固定种子可复现")
    p1 = random_prime(32, JavaRandom(42))
    p2 = random_prime(32, JavaRandom(42))
    check("种子 42 两次生成的 32 位素数相同", p1, p2)
    check_true("该素数确为素数", is_probable_prime(p1, 40, None))
    check("该素数位长为 32", bit_length(p1), 32)
    print(f"         种子 42 / 32 位 -> p = {p1}")
    q1 = random_prime(64, JavaRandom(2026))
    print(f"         种子 2026 / 64 位 -> p = {q1}")
    check("该 64 位素数位长为 64", bit_length(q1), 64)
    check_true("该 64 位素数确为素数", is_probable_prime(q1, 40, None))

    print()
    print("  1.9 模运算基础")
    check("mod(-1, 7)   负数的非负代表元", mod(-1, 7), 6)
    check("mod_add(9, 5, 7)", mod_add(9, 5, 7), 0)
    check("mod_sub(3, 5, 7)", mod_sub(3, 5, 7), 5)
    check("mod_mul(6, 6, 7)", mod_mul(6, 6, 7), 1)
    check("gcd(1071, 462)", gcd(1071, 462), 21)
    check("gcd(0, 0)", gcd(0, 0), 0)
    check("gcd(-12, 8)", gcd(-12, 8), 4)


def section2_boundaries():
    _banner("【二】边界与非法输入 —— 明确预期行为")

    print("  2.1 指数为 0（约定 a⁰ = 1）")
    check("mod_pow(7, 0, 13)", mod_pow(7, 0, 13), ONE)
    check("mod_pow(0, 0, 13)   0⁰ 也约定为 1", mod_pow(0, 0, 13), ONE)
    check("mod_pow(123456789, 0, 1000000007)", mod_pow(123456789, 0, 1000000007), ONE)

    print()
    print("  2.2 模数为 1（唯一剩余类为 0）")
    check("mod_pow(5, 7, 1)", mod_pow(5, 7, 1), ZERO)
    check("mod_inverse(5, 1)   约定为 0", mod_inverse(5, 1), ZERO)

    print()
    print("  2.3 底数为 0 / 负数")
    check("mod_pow(0, 5, 13)", mod_pow(0, 5, 13), ZERO)
    check("mod_pow(-2, 3, 13)  底数规范化", mod_pow(-2, 3, 13), 5)
    check("mod_pow(-2, 4, 13)", mod_pow(-2, 4, 13), 3)

    print()
    print("  2.4 负指数（自动转为求逆后计算）")
    check("mod_pow(3, -1, 11)  ≡ mod_inverse(3, 11)", mod_pow(3, -1, 11), 4)
    check("mod_pow(2, -1, 7)", mod_pow(2, -1, 7), 4)
    check_throws("mod_pow(2, -1, 8)  不可逆应抛异常",
                 ArithmeticError, lambda: mod_pow(2, -1, 8))

    print()
    print("  2.5 非法输入 —— 明确拒绝而非静默出错")
    check_throws("mod_pow(2, 3, 0)   模数为 0", ValueError, lambda: mod_pow(2, 3, 0))
    check_throws("mod_pow(2, 3, -7)  模数为负", ValueError, lambda: mod_pow(2, 3, -7))
    check_throws("mod(5, 0)", ValueError, lambda: mod(5, 0))
    check_throws("mod_inverse(6, 9)  gcd=3 逆元不存在",
                 ArithmeticError, lambda: mod_inverse(6, 9))
    check_throws("mod_inverse(0, 7)  0 不可逆",
                 ArithmeticError, lambda: mod_inverse(0, 7))
    check_throws("mod_inverse(3, 0)  模数为 0",
                 ValueError, lambda: mod_inverse(3, 0))
    check_throws("random_prime(1, rnd) 位长不足",
                 ValueError, lambda: random_prime(1, JavaRandom(1)))
    check_throws("random_in_range(9, 2, rnd) 下界大于上界",
                 ValueError, lambda: random_in_range(9, 2, JavaRandom(1)))
    check_throws("mod_pow_naive(2, -1, 7) 朴素法不支持负指数",
                 ValueError, lambda: mod_pow_naive(2, -1, 7))
    check_throws("mod_pow_naive(2, 10^9, 7) 超出朴素法上限",
                 ValueError, lambda: mod_pow_naive(2, 10 ** 9, 7))

    print()
    print("  2.6 位长与区间工具")
    check("bit_length(0)", bit_length(0), 0)
    check("bit_length(1)", bit_length(1), 1)
    check("bit_length(255)", bit_length(255), 8)
    check("bit_length(256)", bit_length(256), 9)
    r = random_in_range(10, 20, JavaRandom(7))
    check_true(f"random_in_range(10, 20) 落在区间内: {r}", 10 <= r <= 20)


def section3_performance():
    _banner("【三】复杂度与性能实测")

    print("  3.1 复杂度对照（n 为模数位宽，M(n) 为 n 位模乘开销）")
    print(f"      {'算法':<22} {'时间复杂度':<26} 空间复杂度")
    print(f"      {'mod / mod_add / mod_sub':<22} {'O(n) ~ O(n²)':<26} O(n)")
    print(f"      {'mod_mul':<22} {'O(n²)':<26} O(n)")
    print(f"      {'mod_pow（快速幂）':<22} {'O(log e × M(n))':<26} O(n)")
    print(f"      {'mod_pow_naive（朴素）':<22} {'O(e × M(n))':<26} O(n)")
    print(f"      {'gcd / ext_gcd':<22} {'O(log min(|a|,|b|))':<26} O(n)")
    print(f"      {'mod_inverse':<22} {'O(log min(|a|,m))':<26} O(n)")
    print(f"      {'is_probable_prime(k 轮)':<22} {'O(k × log n × M(n))':<26} O(n)")
    print(f"      {'random_prime(b 位)':<22} {'O(b × log n × M(n)) 期望':<26} O(b) 位")

    print()
    print("  3.2 快速幂 vs 朴素连续乘法（同一个指数，64 位模数）")
    modulus = 18446744073709551557
    print(f"      模数 n = {modulus}（64 位）")
    print(f"      {'指数 e':<14} {'e 的位长':<10} {'快速幂':<16} {'朴素连续乘法':<16} 加速比")
    for e in (4096, 65536, 1048576):
        t_fast = _time_best_ns(200, lambda e=e: mod_pow(3, e, modulus))
        t_slow = _time_best_ns(3, lambda e=e: mod_pow_naive(3, e, modulus))
        ratio = f"{t_slow / max(1, t_fast):.0f}×"
        print(f"      {e:<14} {bit_length(e):<10} {_fmt_ns(t_fast):<16} "
              f"{_fmt_ns(t_slow):<16} {ratio}")
    print("      说明：指数每翻一倍，朴素法耗时翻倍；快速幂只多约一次模乘，")
    print("            耗时随 log(e) 线性增长而非随 e 线性增长。")

    print()
    print("  3.3 快速幂的实测耗时随指数位长增长（模数固定 64 位）")
    print(f"      {'指数位长':<14} {'快速幂耗时':<16} 相对上一档")
    prev = 0
    bits = 8
    while bits <= 4096:
        exp = (1 << bits) - 1             # 2^bits - 1
        t = _time_best_ns(200, lambda exp=exp: mod_pow(3, exp, modulus))
        ratio = "—" if prev == 0 else f"{t / prev:.2f}×"
        print(f"      {str(bits) + ' bits':<14} {_fmt_ns(t):<16} {ratio}")
        prev = t
        bits *= 4
    print("      说明：位长每次 ×4，耗时约增至 4 倍，验证 O(log e) 而非 O(e)。")

    print()
    print("  3.4 大整数模幂在 RSA 量级下的表现")
    print(f"      {'用例':<30} 耗时")
    n512 = random_prime(512, JavaRandom(2026))
    e65537 = 65537
    t512 = _time_best_ns(50, lambda: mod_pow(123456789, e65537, n512))
    print(f"      {'512 位模数，e = 65537':<30} {_fmt_ns(t512)}")
    n1024 = random_prime(1024, JavaRandom(2026))
    t1024 = _time_best_ns(50, lambda: mod_pow(123456789, e65537, n1024))
    print(f"      {'1024 位模数，e = 65537':<30} {_fmt_ns(t1024)}")
    print("      说明：位宽翻倍时模乘开销约增 4 倍（O(n²)），符合预期；")
    print("            但快速幂的迭代次数据 e 的位长而定，不随模数增长。")


def section4_security_boundary():
    _banner("【四】安全边界 —— 本模块为什么不能用于生产")

    print("  本模块定位为「算法原理演示」，它证明了数学正确，但不具备工程安全性：")
    print()
    print("  1) 未做常数时间实现，存在计时侧信道")
    print("     快速幂按指数二进制位分支（为 1 才做一次额外模乘），运算次数与")
    print("     内存访问模式随密钥位变化。攻击者可通过精确测量解密耗时，")
    print("     统计推断私钥 d 的比特分布（Kocher 1996）。")
    print("     生产做法：使用常数时间实现，或对输入做盲化（blinding）。")
    print()
    print("  2) 随机源不是密码学安全的")
    print("     random_prime 接收 JavaRandom（LCG），其输出可被观测后预测，")
    print("     用于生成密钥会使私钥可被推算。")
    print("     生产做法：改用 CSPRNG（os.urandom / secrets / SystemRandom）。")
    print("     本模块保留 LCG 是为了「固定种子即可复现」，这是教学取舍，")
    print("     代价就是牺牲了随机性质量。")
    print()
    print("  3) 小位宽模数可被分解")
    print("     64 位 RSA 模数用 Pollard ρ 或 ECM 在普通笔记本上数秒内即可分解；")
    print("     128 位也在可及范围内。分解出 p、q 后由 e 求 d 毫无障碍。")
    print("     生产做法：RSA 密钥长度至少 2048 位（NIST 建议 3072 位）。")
    print()
    print("  4) 本模块不含填充，不能直接加密数据")
    print("     这里实现的是「教科书式 RSA」的运算基础：直接 c = m^e mod n。")
    print("     无填充的 RSA 是确定性的（同一明文永远同一密文），存在")
    print("     选择明文攻击、低指数广播攻击与小消息攻击等已知脆弱性。")
    print("     生产做法：加密用 RSA-OAEP，签名用 RSA-PSS，绝不裸用模幂。")
    print()
    print("  5) Miller-Rabin 只是「概率素性」，且见证集有适用边界")
    print(f"     64 位及以下使用确定性见证集，结论可靠；超过 {_brief(DETERMINISTIC_MR_BOUND)} 后退化为概率判定，")
    print("     误判率 ≤ 4^(-轮数)，但轮数不足时仍可能放入合数。")
    print("     生产做法：用标准库的素性检测，并保留足够轮数。")
    print()
    print("  ── 结论 ──")
    print("  本模块可以回答「RSA 的运算为什么正确、代价是多少」，")
    print("  但不能承担任何真实数据的机密性。集成到业务系统时，")
    print("  加密与签名必须一律委托给经审计的标准密码库。")


def main(argv=None):
    """入口：自检 → 边界 → 性能 → 安全边界。"""
    _banner("密码学基础算法模块 · 自检与性能实测")

    section1_known_vectors()
    section2_boundaries()
    section3_performance()
    section4_security_boundary()

    _banner("小结")
    print(f"  断言通过 {_passed} 项，失败 {_failed} 项")
    print("  结论：全部用例通过，算法结果与已知向量一致。"
          if _failed == 0 else "  结论：存在失败用例，请检查实现。")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
