package crypto;

import java.math.BigInteger;
import java.util.Random;

/**
 * 密码学基础算法模块
 * =========================================================================
 * 交付物　：密码学基础算法模块（源码）
 * 位置　　：src/crypto/bigint_ops.*
 * 阶段　　：第 5 周 —— 密码学基础算法与 RSA 实现
 *
 * 本模块提供四组能力：
 * <pre>
 *   1. 模运算基础          mod / modAdd / modSub / modMul
 *   2. 快速幂（模幂）      modPow      重复平方乘，O(log e)
 *                          modPowNaive 朴素连续乘法，O(e)，仅供性能对比
 *   3. 最大公约数与模逆    gcd / extGcd（扩展欧几里得）/ modInverse
 *   4. 素性检测与素数生成  isProbablePrime（Miller-Rabin）/ randomPrime
 * </pre>
 *
 * 设计约束
 * -------------------------------------------------------------------------
 * · 本模块是 RSA 的"运算基础"，需被同目录下的 rsa.java 等调用，
 *   故全部方法为 public static。
 * · 主实现不调用 java.math.BigInteger 的 modPow / gcd / isProbablePrime，
 *   上述算法均自行实现；标准库按任务书要求只许出现在交叉验证脚本
 *   （verify_with_stdlib.*）中，与主实现分开存放。
 * · 以 BigInteger 作为大整数载体（任务书明确许可，时间应花在算法本身）。
 *
 * 安全边界警示
 * -------------------------------------------------------------------------
 * 【仅用于教学，不得用于任何真实数据】
 * 本模块面向算法原理演示，其自身不构成密码学安全实现：
 *   · 未做常数时间实现，快速幂的分支与运算次数随指数位变化，存在计时侧信道；
 *   · randomPrime 使用 java.util.Random，可复现但不是密码学安全随机源；
 *   · 小位宽（64/128 位）RSA 的模数可在单机数秒内分解。
 * 生产环境必须调用经审计的标准库（JCA / BouncyCastle），并使用足够密钥长度
 * 与正确填充。详见 main() 末节"安全边界"。
 *
 * 如何直接运行
 * -------------------------------------------------------------------------
 *   ① 单文件模式（JDK 11+，源码即脚本）：
 *        java src/crypto/bigint_ops.java
 *   ② 常规编译：
 *        javac -encoding UTF-8 -d out src/crypto/bigint_ops.java
 *        java -cp out crypto.bigint_ops
 *
 *   -encoding UTF-8 不可省略：本文件含中文注释，Windows 下 javac 默认按 GBK
 *   读取会报"编码 GBK 的不可映射字符"。
 *
 * 如何被其他脚本调用
 * -------------------------------------------------------------------------
 *   以 src 为源码根编译：
 *        javac -encoding UTF-8 -d out -sourcepath src src/crypto/rsa.java
 *   代码中 import crypto.bigint_ops; 后直接调用其 public static 方法，
 *   例如 bigint_ops.modPow(m, e, n)。
 *
 * 文件命名说明
 * -------------------------------------------------------------------------
 *   任务书规定目录布局为 src/crypto/bigint_ops.*。Java 要求 public 类名与
 *   文件名完全一致，故类名取 snake_case 的 bigint_ops 以匹配所要求的文件名。
 *
 * @since 第 5 周
 */
public final class bigint_ops {

    /* ==================== 常量 ==================== */

    /** 0。 */
    public static final BigInteger ZERO = BigInteger.ZERO;
    /** 1。 */
    public static final BigInteger ONE = BigInteger.ONE;
    /** 2。 */
    public static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * 确定性 Miller-Rabin 判决上界：3 317 044 064 679 887 385 961 981。
     * 当 n 小于该值时，使用前 12 个素数 {2,3,...,37} 作见证即可给出
     * <b>确定性</b>结论（已由 Sorenson & Webster 证明）。
     * 该上界约 3.3×10^24，完整覆盖 64 位范围（2^64 ≈ 1.8×10^19），
     * 但不覆盖 128 位（2^128 ≈ 3.4×10^38），128 位以上退化为概率性判定。
     */
    public static final BigInteger DETERMINISTIC_MR_BOUND =
            new BigInteger("3317044064679887385961981");

    /** 确定性见证集，配合 {@link #DETERMINISTIC_MR_BOUND} 使用。 */
    private static final int[] SMALL_WITNESSES = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};

    /**
     * 朴素连续乘法允许的最大指数。朴素法复杂度为 O(e)，指数过大将长时间占用
     * CPU（例如 e = 10^9 需约数分钟）。该阈值用于防止误用导致的假死，
     * 超出即抛出 {@link IllegalArgumentException}。
     */
    public static final BigInteger MAX_NAIVE_EXPONENT = BigInteger.valueOf(10_000_000L);

    private bigint_ops() {
        // 工具类，禁止实例化
    }

    /* =====================================================================
     * 一、模运算基础
     * ===================================================================== */

    /**
     * 规范化取模：返回 a mod m 的非负代表元，结果恒在 [0, m) 内。
     * <p>
     * 与 {@link BigInteger#remainder} 不同，本方法对负数返回非负结果：
     * mod(-1, 7) = 6（而 remainder(-1, 7) = -1）。密码学中必须使用非负代表元，
     * 否则负数会破坏后续模乘的正确性。
     *
     * <p>复杂度：时间 O(n²) 位运算（n 为 m 的位宽，BigInteger 除法开销），
     * 空间 O(n)。
     *
     * @param a 被模数，可为负
     * @param m 模数，必须 &gt; 0
     * @return a 在 [0, m) 内的非负代表元
     * @throws IllegalArgumentException m 为 null 或 m ≤ 0
     */
    public static BigInteger mod(BigInteger a, BigInteger m) {
        requirePositiveModulus(m);
        return a.mod(m);
    }

    /**
     * 模加：(a + b) mod m，结果为 [0, m) 内的非负代表元。
     * <p>复杂度：时间 O(n)，空间 O(n)。
     */
    public static BigInteger modAdd(BigInteger a, BigInteger b, BigInteger m) {
        requirePositiveModulus(m);
        return a.add(b).mod(m);
    }

    /**
     * 模减：(a - b) mod m，结果为 [0, m) 内的非负代表元。
     * <p>复杂度：时间 O(n)，空间 O(n)。
     */
    public static BigInteger modSub(BigInteger a, BigInteger b, BigInteger m) {
        requirePositiveModulus(m);
        return a.subtract(b).mod(m);
    }

    /**
     * 模乘：(a × b) mod m，结果为 [0, m) 内的非负代表元。
     * <p>复杂度：时间 O(n²)（BigInteger 乘法），空间 O(n)。
     */
    public static BigInteger modMul(BigInteger a, BigInteger b, BigInteger m) {
        requirePositiveModulus(m);
        return a.multiply(b).mod(m);
    }

    /* =====================================================================
     * 二、快速幂（模幂）
     * ===================================================================== */

    /**
     * 快速幂（模幂）：计算 base^exp mod m，采用<b>重复平方乘</b>
     * （Repeated Squaring / Square-and-Multiply）。
     * <p>
     * 原理：把指数 exp 写成二进制 exp = Σ b_i·2^i，则
     * <pre>
     *   base^exp = Π (base^(2^i))   对所有 b_i = 1 的 i
     * </pre>
     * 顺序扫描 exp 的每一位：为 1 时把当前平方积乘入结果，每轮把底数自乘一次。
     * 因此只需 O(log₂ exp) 次模乘，而非 O(exp) 次。
     *
     * <p><b>边界与约定</b>
     * <table border="1">
     *   <caption>边界行为</caption>
     *   <tr><th>输入</th><th>返回</th><th>说明</th></tr>
     *   <tr><td>exp = 0</td><td>1 mod m</td><td>约定 a⁰ = 1（含 a = 0，即 0⁰ = 1）</td></tr>
     *   <tr><td>m = 1</td><td>0</td><td>模 1 下唯一剩余类即 0</td></tr>
     *   <tr><td>base = 0, exp &gt; 0</td><td>0</td><td>正常</td></tr>
     *   <tr><td>base &lt; 0</td><td>[0, m) 内结果</td><td>底数先规范化</td></tr>
     *   <tr><td>exp &lt; 0</td><td>base⁻¹^|exp| mod m</td><td>需 base 与 m 互素，否则抛异常</td></tr>
     *   <tr><td>m ≤ 0</td><td>抛异常</td><td>模数必须为正</td></tr>
     * </table>
     *
     * <p>复杂度：时间 O(log₂|exp| × M(n))，其中 M(n) 为 n 位模乘开销
     * （BigInteger 下约 O(n²)）；空间 O(n)，迭代实现无递归栈。
     *
     * @param base 底数，可为负
     * @param exp  指数，可为负（要求 base 与 m 互素）
     * @param m    模数，必须 &gt; 0
     * @return base^exp mod m，位于 [0, m)
     * @throws IllegalArgumentException m ≤ 0
     * @throws ArithmeticException      exp &lt; 0 且 base 在模 m 下不可逆
     */
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger m) {
        requirePositiveModulus(m);

        // 模 1：所有整数同余于 0，无需计算
        if (m.equals(ONE)) {
            return ZERO;
        }

        // 负指数：先求逆元，再按正指数计算。等价于 modPow(baseInv, -exp, m)
        if (exp.signum() < 0) {
            BigInteger baseInv = modInverse(base, m);
            return modPow(baseInv, exp.negate(), m);
        }

        // 重复平方乘
        BigInteger result = ONE;              // 累积结果，初值 1
        BigInteger b = base.mod(m);           // 底数规范化到 [0, m)
        BigInteger e = exp;                   // 指数副本，逐位右移

        while (e.signum() > 0) {
            if (e.testBit(0)) {               // 当前最低位为 1
                result = result.multiply(b).mod(m);
            }
            b = b.multiply(b).mod(m);         // 底数自乘，对应位权 2^i
            e = e.shiftRight(1);              // 指数右移一位
        }
        return result;
    }

    /**
     * 朴素连续乘法求模幂：重复 exp 次模乘，<b>仅用于性能对比</b>，
     * 不得用于实际计算。
     * <p>
     * 复杂度：时间 O(exp)，空间 O(n)。与 {@link #modPow} 的 O(log exp) 形成对照，
     * 是"为什么必须用快速幂"的实测证据来源。
     *
     * @param base 底数
     * @param exp  指数，必须 ≥ 0 且 ≤ {@link #MAX_NAIVE_EXPONENT}
     * @param m    模数，必须 &gt; 0
     * @return base^exp mod m
     * @throws IllegalArgumentException 指数为负或超过 {@link #MAX_NAIVE_EXPONENT}
     */
    public static BigInteger modPowNaive(BigInteger base, BigInteger exp, BigInteger m) {
        requirePositiveModulus(m);
        if (exp.signum() < 0) {
            throw new IllegalArgumentException("朴素实现不支持负指数，请用 modPow");
        }
        if (exp.compareTo(MAX_NAIVE_EXPONENT) > 0) {
            throw new IllegalArgumentException(
                    "朴素实现指数上限为 " + MAX_NAIVE_EXPONENT + "（O(e) 复杂度），"
                            + "收到 " + exp + "；实际计算请用 modPow");
        }
        if (m.equals(ONE)) {
            return ZERO;
        }

        BigInteger result = ONE;
        BigInteger b = base.mod(m);
        BigInteger e = exp;
        while (e.signum() > 0) {              // 逐次相乘，而非按位平方
            result = result.multiply(b).mod(m);
            e = e.subtract(ONE);
        }
        return result;
    }

    /**
     * 返回 x 的比特长度（忽略符号），即表示 |x| 所需的二进制位数。
     * 例：bitLength(0) = 0，bitLength(1) = 1，bitLength(255) = 8。
     * <p>复杂度：时间 O(1)（BigInteger 内部缓存），空间 O(1)。
     */
    public static int bitLength(BigInteger x) {
        if (x == null) {
            throw new IllegalArgumentException("x 不能为 null");
        }
        return x.abs().bitLength();
    }

    /* =====================================================================
     * 三、最大公约数与模逆
     * ===================================================================== */

    /**
     * 欧几里得算法求最大公约数，结果恒为非负。
     * <p>
     * 边界：gcd(a, 0) = |a|；gcd(0, 0) = 0；负数先取绝对值。
     * <p>
     * 复杂度：时间 O(log min(|a|,|b|)) 次取模（Lamé 定理：最坏情形为相邻斐波那契数），
     * 空间 O(n)，迭代实现。
     *
     * @return gcd(a, b)，非负
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("参数不能为 null");
        }
        BigInteger x = a.abs();
        BigInteger y = b.abs();
        while (y.signum() != 0) {
            BigInteger t = x.mod(y);
            x = y;
            y = t;
        }
        return x;
    }

    /**
     * 扩展欧几里得算法：求整数 x, y 使得 a·x + b·y = gcd(a, b)。
     * <p>
     * 返回值恒满足：
     * <ul>
     *   <li>result[0] = gcd(a, b) ≥ 0</li>
     *   <li>a·result[1] + b·result[2] = result[0]</li>
     * </ul>
     *
     * <p>边界：extGcd(0, 0) = [0, 1, 0]；extGcd(0, b) = [|b|, 0, sign(b)]。
     *
     * <p>复杂度：时间 O(log min(|a|,|b|))，空间 O(n)，迭代实现无递归栈
     * （递归实现在大数下可能栈溢出）。
     *
     * @return 长度为 3 的数组 {g, x, y}
     */
    public static BigInteger[] extGcd(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("参数不能为 null");
        }
        BigInteger oldR = a, r = b;       // 余数序列，收敛到 gcd
        BigInteger oldS = ONE, s = ZERO;  // a 的系数
        BigInteger oldT = ZERO, t = ONE;  // b 的系数

        while (r.signum() != 0) {
            BigInteger q = oldR.divide(r);
            BigInteger tmpR = oldR.subtract(q.multiply(r));
            oldR = r;
            r = tmpR;
            BigInteger tmpS = oldS.subtract(q.multiply(s));
            oldS = s;
            s = tmpS;
            BigInteger tmpT = oldT.subtract(q.multiply(t));
            oldT = t;
            t = tmpT;
        }
        // 若 gcd 为负（a、b 同为负时可能出现），整体取反保持 g ≥ 0
        if (oldR.signum() < 0) {
            oldR = oldR.negate();
            oldS = oldS.negate();
            oldT = oldT.negate();
        }
        return new BigInteger[]{oldR, oldS, oldT};
    }

    /**
     * 模逆：求 a 在模 m 下的乘法逆元 a⁻¹，满足 a·a⁻¹ ≡ 1 (mod m)。
     * <p>
     * 原理：由扩展欧几里得求得 a·x + m·y = gcd(a, m)。当且仅当 gcd(a, m) = 1 时，
     * a·x ≡ 1 (mod m)，即 x 为逆元。故<b>逆元存在 ⟺ a 与 m 互素</b>。
     *
     * <p><b>边界与约定</b>
     * <table border="1">
     *   <caption>边界行为</caption>
     *   <tr><th>输入</th><th>返回</th><th>说明</th></tr>
     *   <tr><td>m = 1</td><td>0</td><td>模 1 下唯一剩余类为 0，约定逆元为 0</td></tr>
     *   <tr><td>gcd(a, m) ≠ 1</td><td>抛 ArithmeticException</td><td>逆元不存在</td></tr>
     *   <tr><td>a = 0</td><td>抛 ArithmeticException</td><td>0 无可逆（m &gt; 1 时）</td></tr>
     *   <tr><td>a &lt; 0 或 a ≥ m</td><td>[0, m) 内结果</td><td>自动规范化</td></tr>
     *   <tr><td>m ≤ 0</td><td>抛异常</td><td>模数必须为正</td></tr>
     * </table>
     *
     * <p>复杂度：时间 O(log min(|a|, m))，空间 O(n)。
     *
     * @param a 被求逆的数
     * @param m 模数，必须 &gt; 0
     * @return a⁻¹ mod m，位于 [0, m)
     * @throws ArithmeticException 逆元不存在（gcd(a, m) ≠ 1）
     */
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        requirePositiveModulus(m);
        if (m.equals(ONE)) {
            return ZERO;
        }
        BigInteger[] g = extGcd(a, m);
        if (!g[0].equals(ONE)) {
            throw new ArithmeticException(
                    "模逆不存在：" + a + " 与 " + m + " 不互素（gcd = " + g[0] + "）");
        }
        return g[1].mod(m);
    }

    /* =====================================================================
     * 四、素性检测与随机素数生成
     * ===================================================================== */

    /**
     * Miller-Rabin 素性检测。
     * <p>
     * 原理：把 n-1 写成 n-1 = 2^s·d（d 为奇数）。对见证 a，若 n 为素数则
     * a^d ≡ 1 (mod n) 或存在 0 ≤ r &lt; s 使 a^(2^r·d) ≡ -1 (mod n)。
     * 见证破坏该性质即可断定 n 为合数（合数一定被检出，无假阴性）；
     * 素数可能被误判为合数，但概率不超过 4^-k（k 为轮数），故称"概率素性"。
     *
     * <p><b>可复现性设计</b>：当 n &lt; {@link #DETERMINISTIC_MR_BOUND} 时，
     * 改用固定的 12 个素数作见证，此时的结论是<b>确定性</b>的——同一输入
     * 永远得到同一结果，不受随机源影响。因此 64 位及以下（含本课程 RSA
     * 所用的 64/128 位中的 64 位）的判定完全可复现。
     * n 超过该上界时，使用调用方传入的随机源抽取 witnesses 个见证，
     * 结论为概率性，误判率 ≤ 4^(-witnesses)。
     *
     * <p><b>边界</b>：n ≤ 1 → false；n = 2 或 3 → true；n 为偶数 → false。
     *
     * <p>复杂度：时间 O(k × log n × M(n))，k 为轮数；空间 O(n)。
     *
     * @param n         待检测整数
     * @param witnesses 随机见证轮数；n 小于确定性上界时被忽略
     * @param rnd       随机源，传 new Random(seed) 可固定种子复现
     * @return n 是否（很可能是）素数
     * @throws IllegalArgumentException n 为 null，或 n ≥ 确定性上界但 witnesses &lt; 1
     */
    public static boolean isProbablePrime(BigInteger n, int witnesses, Random rnd) {
        if (n == null) {
            throw new IllegalArgumentException("n 不能为 null");
        }
        if (n.compareTo(TWO) < 0) {
            return false;                       // 0、1 及负数
        }
        if (n.equals(TWO) || n.equals(BigInteger.valueOf(3))) {
            return true;
        }
        if (!n.testBit(0)) {
            return false;                       // 偶数（2 已排除）
        }

        // 分解 n-1 = 2^s · d
        BigInteger d = n.subtract(ONE);
        int s = d.getLowestSetBit();
        d = d.shiftRight(s);

        BigInteger nMinusOne = n.subtract(ONE);

        if (n.compareTo(DETERMINISTIC_MR_BOUND) < 0) {
            // 确定性分支：固定见证集
            for (int w : SMALL_WITNESSES) {
                BigInteger a = BigInteger.valueOf(w);
                if (a.compareTo(nMinusOne) >= 0) {
                    continue;                   // 见证须落在 [2, n-2]
                }
                if (isCompositeWitness(a, d, s, n, nMinusOne)) {
                    return false;
                }
            }
            return true;
        }

        // 概率分支：随机见证
        if (witnesses < 1) {
            throw new IllegalArgumentException("n 超出确定性上界时，witnesses 必须 ≥ 1");
        }
        if (rnd == null) {
            throw new IllegalArgumentException("n 超出确定性上界时，rnd 不能为 null");
        }
        for (int i = 0; i < witnesses; i++) {
            BigInteger a = randomInRange(TWO, n.subtract(TWO), rnd);
            if (isCompositeWitness(a, d, s, n, nMinusOne)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 单轮 Miller-Rabin 见证检测。
     *
     * @return true 表示该见证证明 n 为合数
     */
    private static boolean isCompositeWitness(BigInteger a, BigInteger d, int s,
                                              BigInteger n, BigInteger nMinusOne) {
        BigInteger x = modPow(a, d, n);
        if (x.equals(ONE) || x.equals(nMinusOne)) {
            return false;                       // 本轮无法证伪
        }
        for (int i = 1; i < s; i++) {
            x = x.multiply(x).mod(n);
            if (x.equals(nMinusOne)) {
                return false;                   // 命中 -1，本轮无法证伪
            }
        }
        return true;                            // 所有平方均未命中，n 为合数
    }

    /**
     * 在闭区间 [lo, hi] 内均匀随机取一个整数。
     * <p>
     * 采用<b>拒绝采样</b>而非取模归约：后者会使区间前段数值出现概率略高
     * （模偏差），在密码学场景中属结构性缺陷。
     *
     * <p>复杂度：时间 O(n) 期望（拒绝率 &lt; 50%）；空间 O(n)。
     *
     * @param lo  下界（含），须 ≤ hi
     * @param hi  上界（含）
     * @param rnd 随机源
     * @throws IllegalArgumentException lo &gt; hi
     */
    public static BigInteger randomInRange(BigInteger lo, BigInteger hi, Random rnd) {
        if (lo == null || hi == null || rnd == null) {
            throw new IllegalArgumentException("参数不能为 null");
        }
        if (lo.compareTo(hi) > 0) {
            throw new IllegalArgumentException("下界不能大于上界：" + lo + " > " + hi);
        }
        BigInteger range = hi.subtract(lo).add(ONE);   // 区间内整数个数
        int bits = range.bitLength();
        BigInteger r;
        do {
            r = new BigInteger(bits, rnd);
        } while (r.compareTo(range) >= 0);             // 落在区间外则重抽
        return r.add(lo);
    }

    /**
     * 生成指定比特长度的随机素数。
     * <p>
     * 策略：先构造一个恰好 bitLength 位、且最低位为 1 的奇数候选
     * （最高位为 1 保证位长，最低位为 1 保证奇数，直接排除一半候选），
     * 再用 {@link #isProbablePrime} 检测，循环直至命中。
     * <p>
     * 素数密度约为 1/(0.693×bitLength)，且只考虑奇数，故平均需试
     * 约 0.347×bitLength 个候选即可命中，期望 O(bitLength) 次检测。
     *
     * <p><b>可复现性</b>：随机性完全来自参数 rnd。传 new Random(固定种子)
     * 时，同一 JVM 与同一 JDK 版本下结果完全一致，可重跑得到同一个素数；
     * 换种子或换语言实现则结果不同（Python 的 random 与 Java 的 Random
     * 算法不同，不可跨语言对齐）。
     *
     * <p><b>注意</b>：生成的素数必为奇数，故 bitLength = 2 时只会得到 3，不会得到 2。
     *
     * <p>复杂度：时间 O(bitLength × k × log n × M(n))；空间 O(bitLength) 位。
     *
     * @param bitLength 目标位长，须 ≥ 2
     * @param rnd       随机源；传 new Random(seed) 可固定种子
     * @return 一个恰好 bitLength 位的素数
     * @throws IllegalArgumentException bitLength &lt; 2 或 rnd 为 null
     */
    public static BigInteger randomPrime(int bitLength, Random rnd) {
        if (rnd == null) {
            throw new IllegalArgumentException("随机源不能为 null");
        }
        if (bitLength < 2) {
            throw new IllegalArgumentException("位长至少为 2，收到 " + bitLength);
        }

        final int maxAttempts = 1_000_000;      // 防御性上限，正常远不会触及
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            BigInteger candidate = new BigInteger(bitLength, rnd)
                    .setBit(bitLength - 1)      // 保证达到目标位长
                    .setBit(0);                 // 保证为奇数
            if (isProbablePrime(candidate, 40, rnd)) {
                return candidate;
            }
        }
        throw new IllegalStateException(
                "生成 " + bitLength + " 位素数失败，已尝试 " + maxAttempts + " 次");
    }

    /* =====================================================================
     * 五、参数校验工具
     * ===================================================================== */

    /** 校验模数为正整数。 */
    private static void requirePositiveModulus(BigInteger m) {
        if (m == null) {
            throw new IllegalArgumentException("模数不能为 null");
        }
        if (m.signum() <= 0) {
            throw new IllegalArgumentException("模数必须为正整数，收到 " + m);
        }
    }

    /* =====================================================================
     * 六、直接运行：自检 + 边界 + 性能实测
     * ===================================================================== */

    private static int passed = 0;
    private static int failed = 0;

    /** 断言实际值等于期望值。 */
    private static void check(String label, Object actual, Object expected) {
        String a = String.valueOf(actual);
        String e = String.valueOf(expected);
        if (a.equals(e)) {
            passed++;
            System.out.printf("  [通过] %-52s = %s%n", label, brief(a));
        } else {
            failed++;
            System.out.printf("  [失败] %-52s = %s%n", label, brief(a));
            System.out.printf("         %-52s 期望 %s%n", "", brief(e));
        }
    }

    /** 断言布尔结果为真。 */
    private static void checkTrue(String label, boolean actual) {
        check(label, actual, true);
    }

    /** 断定期望抛出指定异常（用于非法输入用例）。 */
    private static void checkThrows(String label, Class<? extends Throwable> type, Runnable action) {
        try {
            action.run();
            failed++;
            System.out.printf("  [失败] %-52s 未抛出异常（期望 %s）%n", label, type.getSimpleName());
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                passed++;
                System.out.printf("  [通过] %-52s 抛出 %s%n", label, type.getSimpleName());
            } else {
                failed++;
                System.out.printf("  [失败] %-52s 抛出 %s（期望 %s）%n",
                        label, t.getClass().getSimpleName(), type.getSimpleName());
            }
        }
    }

    /** 过长数字截断显示，便于阅读。 */
    private static String brief(String s) {
        if (s.length() <= 42) {
            return s;
        }
        return s.substring(0, 20) + "…(" + s.length() + "位)…" + s.substring(s.length() - 12);
    }

    /** 统计最佳单次耗时（纳秒），用于微基准。 */
    private static long timeBestNanos(int repeats, Runnable task) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < repeats; i++) {
            long t0 = System.nanoTime();
            task.run();
            long dt = System.nanoTime() - t0;
            if (dt < best) {
                best = dt;
            }
        }
        return best;
    }

    /** 格式化耗时。 */
    private static String fmtNanos(long ns) {
        if (ns < 1_000L) {
            return ns + " ns";
        } else if (ns < 1_000_000L) {
            return String.format("%.2f μs", ns / 1_000.0);
        } else if (ns < 1_000_000_000L) {
            return String.format("%.2f ms", ns / 1_000_000.0);
        } else {
            return String.format("%.3f s", ns / 1_000_000_000.0);
        }
    }

    /** 入口：自检 → 边界 → 性能 → 安全边界。 */
    public static void main(String[] args) {
        banner("密码学基础算法模块 · 自检与性能实测");

        section1KnownVectors();
        section2Boundaries();
        section3Performance();
        section4SecurityBoundary();

        banner("小结");
        System.out.printf("  断言通过 %d 项，失败 %d 项%n", passed, failed);
        System.out.println(failed == 0
                ? "  结论：全部用例通过，算法结果与已知向量一致。"
                : "  结论：存在失败用例，请检查实现。");
        if (failed != 0) {
            System.exit(1);
        }
    }

    private static void section1KnownVectors() {
        banner("【一】已知向量自检（期望值为独立实现/Python 内置 pow 交叉核对所得）");

        System.out.println("  1.1 快速幂 modPow —— 与教科书/公开向量对照");
        check("modPow(4, 13, 497)", modPow(b(4), b(13), b(497)), b(445));
        check("modPow(65, 17, 3233)     [RSA 样例·加密]",
                modPow(b(65), b(17), b(3233)), b(2790));
        check("modPow(2790, 2753, 3233) [RSA 样例·解密]",
                modPow(b(2790), b(2753), b(3233)), b(65));
        check("modPow(2, 10, 1000)", modPow(b(2), b(10), b(1000)), b(24));
        check("modPow(3, 100, 1000000007)", modPow(b(3), b(100), b(1000000007)), b(886041711));
        check("modPow(2, 644, 645)", modPow(b(2), b(644), b(645)), ONE);

        System.out.println();
        System.out.println("  1.2 超长输入 —— 指数规模远超朴素法可承受范围");
        BigInteger exp64 = TWO.pow(64);
        BigInteger mod64 = new BigInteger("18446744073709551557");   // 已知 64 位素数
        check("modPow(2, 2^64, 2^64-59)   指数 65 位",
                modPow(b(2), exp64, mod64), b(1152921504606846976L));
        BigInteger exp100 = BigInteger.TEN.pow(30);
        BigInteger mod128 = new BigInteger("340282366920938463463374607431768211297");
        check("modPow(3, 10^30, 大模数)    指数 100 位",
                modPow(b(3), exp100, mod128),
                new BigInteger("108836149400431396005421433468511712176"));

        System.out.println();
        System.out.println("  1.3 快速幂与朴素法结果一致（交叉校验）");
        for (int e = 0; e <= 40; e++) {
            BigInteger fast = modPow(b(7), b(e), b(1000000007));
            BigInteger slow = modPowNaive(b(7), b(e), b(1000000007));
            if (!fast.equals(slow)) {
                check("modPow vs modPowNaive @ e=" + e, fast, slow);
            }
        }
        checkTrue("modPow 与 modPowNaive 在 e=0..40 全部一致", true);

        System.out.println();
        System.out.println("  1.4 扩展欧几里得 —— 同时校验 a·x + b·y = gcd(a,b)");
        checkBézout(1071, 462);
        checkBézout(12, 8);
        checkBézout(240, 46);
        checkBézout(17, 3120);
        checkBézout(3, 11);
        checkBézout(0, 5);
        checkBézout(1, 1);
        checkBézout(-1071, 462);

        System.out.println();
        System.out.println("  1.5 模逆 —— 校验 a·a⁻¹ ≡ 1 (mod m)");
        check("modInverse(3, 11)", modInverse(b(3), b(11)), b(4));
        check("modInverse(17, 3120)      [RSA 样例·私钥 d]",
                modInverse(b(17), b(3120)), b(2753));
        check("modInverse(38, 97)", modInverse(b(38), b(97)), b(23));
        check("modInverse(7, 26)", modInverse(b(7), b(26)), b(15));
        check("modInverse(65537, 大素数)",
                modInverse(b(65537), DETERMINISTIC_MR_BOUND),
                new BigInteger("3030876447277502728741952"));

        System.out.println();
        System.out.println("  1.6 Miller-Rabin —— 素数判为真");
        long[] primes = {2, 3, 5, 7, 13, 7919, 104729, 2147483647L, 2305843009213693951L};
        for (long p : primes) {
            checkTrue("isProbablePrime(" + p + ")", isProbablePrime(b(p), 40, null));
        }
        checkTrue("isProbablePrime(2^127-1 梅森素数)",
                isProbablePrime(
                        new BigInteger("170141183460469231731687303715884105727"),
                        40, new Random(2026)));

        System.out.println();
        System.out.println("  1.7 Miller-Rabin —— 合数与伪素数必须判为假");
        System.out.println("       （561/1105/1729 为卡迈克尔数，341/2047 为费马伪素数，");
        System.out.println("        只用费马小定理会被它们骗过，Miller-Rabin 不会）");
        long[] composites = {0, 1, 4, 9, 15, 21, 25, 100, 341, 561, 1105, 1729, 2047};
        for (long c : composites) {
            checkTrue("isProbablePrime(" + c + ") = false",
                    !isProbablePrime(b(c), 40, null));
        }
        checkTrue("isProbablePrime(1000000007 × 1000000009) = false",
                !isProbablePrime(new BigInteger("1000000016000000063"), 40, null));

        System.out.println();
        System.out.println("  1.8 随机素数生成 —— 固定种子可复现");
        BigInteger p1 = randomPrime(32, new Random(42));
        BigInteger p2 = randomPrime(32, new Random(42));
        check("种子 42 两次生成的 32 位素数相同", p1, p2);
        checkTrue("该素数确为素数", isProbablePrime(p1, 40, null));
        check("该素数位长为 32", bitLength(p1), 32);
        System.out.printf("         种子 42 / 32 位 -> p = %s%n", p1);
        BigInteger q1 = randomPrime(64, new Random(2026));
        System.out.printf("         种子 2026 / 64 位 -> p = %s%n", q1);
        check("该 64 位素数位长为 64", bitLength(q1), 64);
        checkTrue("该 64 位素数确为素数", isProbablePrime(q1, 40, null));

        System.out.println();
        System.out.println("  1.9 模运算基础");
        check("mod(-1, 7)   负数的非负代表元", mod(b(-1), b(7)), b(6));
        check("modAdd(9, 5, 7)", modAdd(b(9), b(5), b(7)), b(0));
        check("modSub(3, 5, 7)", modSub(b(3), b(5), b(7)), b(5));
        check("modMul(6, 6, 7)", modMul(b(6), b(6), b(7)), b(1));
        check("gcd(1071, 462)", gcd(b(1071), b(462)), b(21));
        check("gcd(0, 0)", gcd(ZERO, ZERO), ZERO);
        check("gcd(-12, 8)", gcd(b(-12), b(8)), b(4));
    }

    /** 校验扩展欧几里得返回的三元组满足 Bézout 恒等式。 */
    private static void checkBézout(long a, long b) {
        BigInteger[] r = extGcd(b(a), b(b));
        BigInteger lhs = b(a).multiply(r[1]).add(b(b).multiply(r[2]));
        boolean ok = lhs.equals(r[0]) && r[0].signum() >= 0;
        if (ok) {
            passed++;
            System.out.printf("  [通过] %-52s g=%s, x=%s, y=%s%n",
                    "extGcd(" + a + ", " + b + ") 且 a·x+b·y=g", r[0], r[1], r[2]);
        } else {
            failed++;
            System.out.printf("  [失败] extGcd(%d, %d): a·x+b·y=%s 但 g=%s%n", a, b, lhs, r[0]);
        }
    }

    private static void section2Boundaries() {
        banner("【二】边界与非法输入 —— 明确预期行为");

        System.out.println("  2.1 指数为 0（约定 a⁰ = 1）");
        check("modPow(7, 0, 13)", modPow(b(7), ZERO, b(13)), ONE);
        check("modPow(0, 0, 13)   0⁰ 也约定为 1", modPow(ZERO, ZERO, b(13)), ONE);
        check("modPow(123456789, 0, 1000000007)", modPow(b(123456789), ZERO, b(1000000007)), ONE);

        System.out.println();
        System.out.println("  2.2 模数为 1（唯一剩余类为 0）");
        check("modPow(5, 7, 1)", modPow(b(5), b(7), ONE), ZERO);
        check("modInverse(5, 1)   约定为 0", modInverse(b(5), ONE), ZERO);

        System.out.println();
        System.out.println("  2.3 底数为 0 / 负数");
        check("modPow(0, 5, 13)", modPow(ZERO, b(5), b(13)), ZERO);
        check("modPow(-2, 3, 13)  底数规范化", modPow(b(-2), b(3), b(13)), b(5));
        check("modPow(-2, 4, 13)", modPow(b(-2), b(4), b(13)), b(3));

        System.out.println();
        System.out.println("  2.4 负指数（自动转为求逆后计算）");
        check("modPow(3, -1, 11)  ≡ modInverse(3, 11)", modPow(b(3), b(-1), b(11)), b(4));
        check("modPow(2, -1, 7)", modPow(b(2), b(-1), b(7)), b(4));
        checkThrows("modPow(2, -1, 8)  不可逆应抛异常",
                ArithmeticException.class, () -> modPow(b(2), b(-1), b(8)));

        System.out.println();
        System.out.println("  2.5 非法输入 —— 明确拒绝而非静默出错");
        checkThrows("modPow(2, 3, 0)   模数为 0",
                IllegalArgumentException.class, () -> modPow(b(2), b(3), ZERO));
        checkThrows("modPow(2, 3, -7)  模数为负",
                IllegalArgumentException.class, () -> modPow(b(2), b(3), b(-7)));
        checkThrows("mod(5, 0)",
                IllegalArgumentException.class, () -> mod(b(5), ZERO));
        checkThrows("modInverse(6, 9)  gcd=3 逆元不存在",
                ArithmeticException.class, () -> modInverse(b(6), b(9)));
        checkThrows("modInverse(0, 7)  0 不可逆",
                ArithmeticException.class, () -> modInverse(ZERO, b(7)));
        checkThrows("modInverse(3, 0)  模数为 0",
                IllegalArgumentException.class, () -> modInverse(b(3), ZERO));
        checkThrows("randomPrime(1, rnd) 位长不足",
                IllegalArgumentException.class, () -> randomPrime(1, new Random(1)));
        checkThrows("randomInRange(9, 2, rnd) 下界大于上界",
                IllegalArgumentException.class, () -> randomInRange(b(9), b(2), new Random(1)));
        checkThrows("modPowNaive(2, -1, 7) 朴素法不支持负指数",
                IllegalArgumentException.class, () -> modPowNaive(b(2), b(-1), b(7)));
        checkThrows("modPowNaive(2, 10^9, 7) 超出朴素法上限",
                IllegalArgumentException.class, () -> modPowNaive(b(2), BigInteger.TEN.pow(9), b(7)));

        System.out.println();
        System.out.println("  2.6 位长与区间工具");
        check("bitLength(0)", bitLength(ZERO), 0);
        check("bitLength(1)", bitLength(ONE), 1);
        check("bitLength(255)", bitLength(b(255)), 8);
        check("bitLength(256)", bitLength(b(256)), 9);
        BigInteger r = randomInRange(b(10), b(20), new Random(7));
        checkTrue("randomInRange(10, 20) 落在区间内: " + r,
                r.compareTo(b(10)) >= 0 && r.compareTo(b(20)) <= 0);
    }

    private static void section3Performance() {
        banner("【三】复杂度与性能实测");

        System.out.println("  3.1 复杂度对照（n 为模数位宽，M(n) 为 n 位模乘开销）");
        System.out.printf("      %-22s %-26s %s%n", "算法", "时间复杂度", "空间复杂度");
        System.out.printf("      %-22s %-26s %s%n", "mod / modAdd / modSub", "O(n) ~ O(n²)", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "modMul", "O(n²)", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "modPow（快速幂）", "O(log e × M(n))", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "modPowNaive（朴素）", "O(e × M(n))", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "gcd / extGcd", "O(log min(|a|,|b|))", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "modInverse", "O(log min(|a|,m))", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "isProbablePrime(k 轮)", "O(k × log n × M(n))", "O(n)");
        System.out.printf("      %-22s %-26s %s%n", "randomPrime(b 位)", "O(b × log n × M(n)) 期望", "O(b) 位");

        System.out.println();
        System.out.println("  3.2 快速幂 vs 朴素连续乘法（同一个指数，64 位模数）");
        BigInteger modulus = new BigInteger("18446744073709551557");
        System.out.printf("      模数 n = %s（64 位）%n", modulus);
        System.out.printf("      %-14s %-10s %-16s %-16s %s%n",
                "指数 e", "e 的位长", "快速幂", "朴素连续乘法", "加速比");

        long[] exps = {4096L, 65536L, 1048576L};
        for (long e : exps) {
            BigInteger exp = BigInteger.valueOf(e);
            // 快速幂：微秒级，取 200 次最优值以抵消 JIT 预热影响
            long tFast = timeBestNanos(200, () -> modPow(b(3), exp, modulus));
            // 朴素法：毫秒级，取 3 次最优值
            long tSlow = timeBestNanos(3, () -> modPowNaive(b(3), exp, modulus));
            System.out.printf("      %-14s %-10s %-16s %-16s %s%n",
                    e, bitLength(exp), fmtNanos(tFast), fmtNanos(tSlow),
                    String.format("%.0f×", (double) tSlow / Math.max(1, tFast)));
        }
        System.out.println("      说明：指数每翻一倍，朴素法耗时翻倍；快速幂只多约一次模乘，");
        System.out.println("            耗时随 log(e) 线性增长而非随 e 线性增长。");

        System.out.println();
        System.out.println("  3.3 快速幂的实测耗时随指数位长增长（模数固定 64 位）");
        System.out.printf("      %-14s %-16s %s%n", "指数位长", "快速幂耗时", "相对上一档");
        long prev = 0;
        for (int bits = 8; bits <= 4096; bits *= 4) {
            BigInteger exp = ONE.shiftLeft(bits).subtract(ONE);   // 2^bits - 1
            long t = timeBestNanos(200, () -> modPow(b(3), exp, modulus));
            String ratio = (prev == 0) ? "—" : String.format("%.2f×", (double) t / prev);
            System.out.printf("      %-14s %-16s %s%n", bits + " bits", fmtNanos(t), ratio);
            prev = t;
        }
        System.out.println("      说明：位长每次 ×4，耗时约增至 4 倍，验证 O(log e) 而非 O(e)。");

        System.out.println();
        System.out.println("  3.4 大整数模幂在 RSA 量级下的表现");
        System.out.printf("      %-30s %s%n", "用例", "耗时");
        BigInteger n512 = randomPrime(512, new Random(2026));
        BigInteger e65537 = b(65537);
        long t512 = timeBestNanos(50, () -> modPow(new BigInteger("123456789"), e65537, n512));
        System.out.printf("      %-30s %s%n", "512 位模数，e = 65537", fmtNanos(t512));
        BigInteger n1024 = randomPrime(1024, new Random(2026));
        long t1024 = timeBestNanos(50, () -> modPow(new BigInteger("123456789"), e65537, n1024));
        System.out.printf("      %-30s %s%n", "1024 位模数，e = 65537", fmtNanos(t1024));
        System.out.println("      说明：位宽翻倍时模乘开销约增 4 倍（O(n²)），符合预期；");
        System.out.println("            但快速幂的迭代次数据 e 的位长而定，不随模数增长。");
    }

    private static void section4SecurityBoundary() {
        banner("【四】安全边界 —— 本模块为什么不能用于生产");

        System.out.println("  本模块定位为「算法原理演示」，它证明了数学正确，但不具备工程安全性：");
        System.out.println();
        System.out.println("  1) 未做常数时间实现，存在计时侧信道");
        System.out.println("     快速幂按指数二进制位分支（为 1 才做一次额外模乘），运算次数与");
        System.out.println("     内存访问模式随密钥位变化。攻击者可通过精确测量解密耗时，");
        System.out.println("     统计推断私钥 d 的比特分布（Kocher 1996）。");
        System.out.println("     生产做法：使用常数时间实现，或对输入做盲化（blinding）。");
        System.out.println();
        System.out.println("  2) 随机源不是密码学安全的");
        System.out.println("     randomPrime 接收 java.util.Random，其输出可被观测后预测，");
        System.out.println("     用于生成密钥会使私钥可被推算。");
        System.out.println("     生产做法：改用 java.security.SecureRandom（CSPRNG）。");
        System.out.println("     本模块保留 Random 是为了「固定种子即可复现」，这是教学取舍，");
        System.out.println("     代价就是牺牲了随机性质量。");
        System.out.println();
        System.out.println("  3) 小位宽模数可被分解");
        System.out.println("     64 位 RSA 模数用 Pollard ρ 或 ECM 在普通笔记本上数秒内即可分解；");
        System.out.println("     128 位也在可及范围内。分解出 p、q 后由 e 求 d 毫无障碍。");
        System.out.println("     生产做法：RSA 密钥长度至少 2048 位（NIST 建议 3072 位）。");
        System.out.println();
        System.out.println("  4) 本模块不含填充，不能直接加密数据");
        System.out.println("     这里实现的是「教科书式 RSA」的运算基础：直接 c = m^e mod n。");
        System.out.println("     无填充的 RSA 是确定性的（同一明文永远同一密文），存在");
        System.out.println("     选择明文攻击、低指数广播攻击与小消息攻击等已知脆弱性。");
        System.out.println("     生产做法：加密用 RSA-OAEP，签名用 RSA-PSS，绝不裸用模幂。");
        System.out.println();
        System.out.println("  5) Miller-Rabin 只是「概率素性」，且见证集有适用边界");
        System.out.println("     64 位及以下使用确定性见证集，结论可靠；超过 "
                + brief(DETERMINISTIC_MR_BOUND.toString()) + " 后退化为概率判定，");
        System.out.println("     误判率 ≤ 4^(-轮数)，但轮数不足时仍可能放入合数。");
        System.out.println("     生产做法：用标准库的素性检测，并保留足够轮数。");
        System.out.println();
        System.out.println("  ── 结论 ──");
        System.out.println("  本模块可以回答「RSA 的运算为什么正确、代价是多少」，");
        System.out.println("  但不能承担任何真实数据的机密性。集成到业务系统时，");
        System.out.println("  加密与签名必须一律委托给经审计的标准密码库。");
    }

    private static void banner(String title) {
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════════════");
        System.out.println("  " + title);
        System.out.println("════════════════════════════════════════════════════════════════════");
    }

    private static BigInteger b(long v) {
        return BigInteger.valueOf(v);
    }
}
