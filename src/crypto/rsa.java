package crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * 小位宽 RSA 实现（64 / 128 / 256 位）
 * =========================================================================
 * 交付物　：小位宽 RSA 实现（源码）
 * 位置　　：src/crypto/rsa.java
 * 阶段　　：第 5 周 —— 密码学基础算法与 RSA 实现
 *
 * 本模块实现「教科书式 RSA」（Textbook RSA）的完整流程：
 * <pre>
 *   1. 密钥生成   p, q, n = p·q, φ(n) = (p-1)(q-1), e, d = e⁻¹ mod φ(n)
 *   2. 加密       c = m^e mod n
 *   3. 解密       m = c^d mod n
 *   4. CRT 加速   m = m2 + q·(q⁻¹·(m1 - m2) mod p)，m1 = c^dp mod p, m2 = c^dq mod q
 *   5. 字符串/中文  按模数位宽分块，块首加 0x01 哨兵字节以保留前导 0
 * </pre>
 *
 * 依赖
 * -------------------------------------------------------------------------
 * 复用同目录的 {@link bigint_ops}（模幂 modPow、模逆 modInverse、
 * 素数生成 randomPrime 等）。主实现<b>不</b>调用 java.math.BigInteger 的
 * modPow / gcd / isProbablePrime，这些方法只允许出现在交叉验证脚本
 * （verify_with_stdlib.*）中。
 *
 * 可复现性
 * -------------------------------------------------------------------------
 * 所有随机性都来自调用方传入的 {@link Random}。传入 new Random(固定种子)
 * 即可得到完全相同的密钥与密文（同一 JDK 版本下）。模块的 main() 即按固定
 * 种子运行，其输出即为测试向量的"期望值"来源。
 *
 * 安全边界警示
 * -------------------------------------------------------------------------
 * 【仅用于教学，不得用于任何真实数据】
 * 本模块刻意实现小位宽 RSA，目的是<b>演示它为什么不安全</b>，而不是提供安全能力：
 *   · 64 位模数可在毫秒级被 Pollard ρ 分解（见 main() 第 7 节实测）；
 *   · 无填充的 RSA 是确定性的，存在选择明文攻击、乘法同态攻击；
 *   · 非常数时间实现，存在计时侧信道；
 *   · 密钥生成的随机源是 java.util.Random，非密码学安全。
 * 生产环境必须使用经审计的标准密码库（JCA / BouncyCastle），密钥长度 ≥ 2048 位，
 * 加密用 RSA-OAEP，签名用 RSA-PSS。
 *
 * 如何直接运行
 * -------------------------------------------------------------------------
 *   ① 单文件模式（JDK 11+，需同时编译同包的 bigint_ops）：
 *        javac -encoding UTF-8 -d out src/crypto/bigint_ops.java src/crypto/rsa.java
 *        java -cp out crypto.rsa
 *   ② 以 src 为源码根编译（供其他脚本调用）：
 *        javac -encoding UTF-8 -d out -sourcepath src src/crypto/rsa.java
 *
 *   -encoding UTF-8 不可省略：本文件含中文注释与中文测试用例，Windows 下
 *   javac 默认按 GBK 读取会报"编码 GBK 的不可映射字符"。
 *
 * 文件命名说明
 * -------------------------------------------------------------------------
 * 任务书规定目录布局为 src/crypto/rsa.*。Java 要求 public 类名与文件名一致，
 * 故类名取小写的 rsa 以匹配所要求的文件名。
 *
 * @since 第 5 周
 */
public final class rsa {

    /** 常用公开指数 65537 = 2^16 + 1，兼具安全性与运算效率。 */
    public static final BigInteger DEFAULT_E = BigInteger.valueOf(65537);

    /** 备选公开指数（Fermat 素数），当 65537 与 φ(n) 不互素时依次尝试。 */
    private static final int[] FALLBACK_EXPONENTS = {3, 5, 17, 257};

    /** 允许的最小 RSA 位宽。太小的模数无法承载分块，且失去演示意义。 */
    public static final int MIN_BITLENGTH = 32;

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private rsa() {
        // 工具类，禁止实例化
    }

    /* =====================================================================
     * 一、密钥对象
     * ===================================================================== */

    /**
     * RSA 公钥：模数 n 与公开指数 e。
     * {@code c = m^e mod n}。
     */
    public static final class PublicKey {
        /** 模数 n = p·q。 */
        public final BigInteger n;
        /** 公开指数 e。 */
        public final BigInteger e;
        /** 密钥位宽（n 的比特长度）。 */
        public final int bitLength;

        public PublicKey(BigInteger n, BigInteger e) {
            if (n == null || e == null) {
                throw new IllegalArgumentException("n / e 不能为 null");
            }
            if (n.signum() <= 0) {
                throw new IllegalArgumentException("模数 n 必须为正");
            }
            if (e.signum() <= 0) {
                throw new IllegalArgumentException("公开指数 e 必须为正");
            }
            this.n = n;
            this.e = e;
            this.bitLength = n.bitLength();
        }

        /** 每个明文分块可承载的字节数（见 {@link #blockSizeBytes}）。 */
        public int blockSizeBytes() {
            return rsa.blockSizeBytes(n);
        }

        @Override
        public String toString() {
            return "RSA公钥{ 位宽=" + bitLength + ",\n"
                    + "  n = " + n + "\n"
                    + "  e = " + e + " }";
        }
    }

    /**
     * RSA 私钥：模数 n 与私钥指数 d，并额外保存 CRT 加速所需的参数。
     * {@code m = c^d mod n}。
     */
    public static final class PrivateKey {
        /** 模数 n = p·q。 */
        public final BigInteger n;
        /** 公开指数 e（与 d 配对，便于还原公钥）。 */
        public final BigInteger e;
        /** 私钥指数 d = e⁻¹ mod φ(n)。 */
        public final BigInteger d;
        /** 素数因子 p。 */
        public final BigInteger p;
        /** 素数因子 q。 */
        public final BigInteger q;
        /** 私钥欧拉函数 φ(n) = (p-1)(q-1)。 */
        public final BigInteger phi;
        /** CRT 参数 dp = d mod (p-1)。 */
        public final BigInteger dp;
        /** CRT 参数 dq = d mod (q-1)。 */
        public final BigInteger dq;
        /** CRT 参数 qInv = q⁻¹ mod p。 */
        public final BigInteger qInv;

        public PrivateKey(BigInteger n, BigInteger e, BigInteger d,
                          BigInteger p, BigInteger q, BigInteger phi,
                          BigInteger dp, BigInteger dq, BigInteger qInv) {
            this.n = n;
            this.e = e;
            this.d = d;
            this.p = p;
            this.q = q;
            this.phi = phi;
            this.dp = dp;
            this.dq = dq;
            this.qInv = qInv;
        }

        /** 对应的公钥。 */
        public PublicKey publicKey() {
            return new PublicKey(n, e);
        }

        @Override
        public String toString() {
            return "RSA私钥{\n"
                    + "  n    = " + n + "\n"
                    + "  e    = " + e + "\n"
                    + "  d    = " + d + "\n"
                    + "  p    = " + p + "\n"
                    + "  q    = " + q + "\n"
                    + "  φ(n) = " + phi + "\n"
                    + "  dp   = " + dp + "\n"
                    + "  dq   = " + dq + "\n"
                    + "  qInv = " + qInv + " }";
        }
    }

    /** 一对 RSA 密钥。 */
    public static final class KeyPair {
        /** 公钥。 */
        public final PublicKey publicKey;
        /** 私钥。 */
        public final PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    /* =====================================================================
     * 二、密钥生成
     * ===================================================================== */

    /**
     * 生成指定位宽的 RSA 密钥对。
     * <p>
     * 步骤：
     * <ol>
     *   <li>取两个位宽约各半的随机素数 p、q（p ≠ q），由 {@link bigint_ops#randomPrime}
     *       生成，素性由 Miller-Rabin 判定；</li>
     *   <li>n = p·q，若 n 的位宽不等于目标位宽则重挑（p、q 最高位均为 1 时，
     *       n 可能是 bitLength 或 bitLength-1 位）；</li>
     *   <li>φ(n) = (p-1)(q-1)；</li>
     *   <li>选 e：优先 65537，若 gcd(e, φ(n)) ≠ 1 则依次尝试 3/5/17/257，
     *       再退化为从 3 起的奇数搜索；</li>
     *   <li>d = e⁻¹ mod φ(n)（扩展欧几里得）；</li>
     *   <li>计算 CRT 参数 dp、dq、qInv。</li>
     * </ol>
     *
     * <p><b>可复现性</b>：随机性完全来自参数 rnd。传 new Random(seed) 时，
     * 同一 JDK 版本下可重跑得到完全相同的密钥。
     *
     * <p>复杂度：时间由素数搜索主导，期望 O(bitLength × log n × M(n))；
     * 空间 O(bitLength) 位。
     *
     * @param bitLength 目标位宽，须 ≥ {@link #MIN_BITLENGTH}
     * @param rnd       随机源；传 new Random(seed) 可固定种子
     * @return 密钥对
     * @throws IllegalArgumentException bitLength 过小或 rnd 为 null
     */
    public static KeyPair generateKeyPair(int bitLength, Random rnd) {
        if (rnd == null) {
            throw new IllegalArgumentException("随机源不能为 null");
        }
        if (bitLength < MIN_BITLENGTH) {
            throw new IllegalArgumentException(
                    "位宽至少为 " + MIN_BITLENGTH + "，收到 " + bitLength);
        }

        int pBits = bitLength / 2;
        int qBits = bitLength - pBits;

        BigInteger p;
        BigInteger q;
        BigInteger n;
        do {
            p = bigint_ops.randomPrime(pBits, rnd);
            do {
                q = bigint_ops.randomPrime(qBits, rnd);
            } while (q.equals(p));               // 必须互异
            n = p.multiply(q);
        } while (n.bitLength() != bitLength);     // 保证模数达到目标位宽

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = choosePublicExponent(phi);
        BigInteger d = bigint_ops.modInverse(e, phi);

        // CRT 加速参数
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger dp = d.mod(pMinus1);
        BigInteger dq = d.mod(qMinus1);
        BigInteger qInv = bigint_ops.modInverse(q, p);

        return new KeyPair(
                new PublicKey(n, e),
                new PrivateKey(n, e, d, p, q, phi, dp, dq, qInv));
    }

    /**
     * 选择与 φ(n) 互素的公开指数 e。
     * 优先 65537（2^16+1，二进制仅两个 1，模幂运算快），
     * 否则尝试小 Fermat 素数，最后从 3 起搜索奇数。
     */
    private static BigInteger choosePublicExponent(BigInteger phi) {
        if (bigint_ops.gcd(DEFAULT_E, phi).equals(BigInteger.ONE)) {
            return DEFAULT_E;
        }
        for (int candidate : FALLBACK_EXPONENTS) {
            BigInteger e = BigInteger.valueOf(candidate);
            if (bigint_ops.gcd(e, phi).equals(BigInteger.ONE)) {
                return e;
            }
        }
        BigInteger e = THREE;
        while (!bigint_ops.gcd(e, phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }
        return e;
    }

    /* =====================================================================
     * 三、加密与解密（整型）
     * ===================================================================== */

    /**
     * 加密单个整数：c = m^e mod n。
     * <p>
     * <b>要求</b>：0 ≤ m &lt; n。明文是「一个剩余类代表的整数」，不是任意大数。
     *
     * <p>复杂度：时间 O(log e × M(n))，其中 M(n) 为 n 位模乘开销
     * （BigInteger 下约 O(n²)）；空间 O(n)。
     *
     * @param pub 公钥
     * @param m   明文整数，须落在 [0, n)
     * @return 密文整数 c
     * @throws IllegalArgumentException m 不在 [0, n) 内
     */
    public static BigInteger encrypt(PublicKey pub, BigInteger m) {
        requireInRange(m, pub.n, "明文 m");
        return bigint_ops.modPow(m, pub.e, pub.n);
    }

    /**
     * 解密单个整数：m = c^d mod n（直接法，不使用 CRT）。
     * <p>复杂度：时间 O(log d × M(n))；空间 O(n)。
     *
     * @param priv 私钥
     * @param c    密文整数，须落在 [0, n)
     * @return 明文整数 m
     * @throws IllegalArgumentException c 不在 [0, n) 内
     */
    public static BigInteger decrypt(PrivateKey priv, BigInteger c) {
        requireInRange(c, priv.n, "密文 c");
        return bigint_ops.modPow(c, priv.d, priv.n);
    }

    /**
     * 解密单个整数（CRT 加速）。
     * <p>
     * 原理（中国剩余定理）：设 m1 = c^dp mod p、m2 = c^dq mod q，则
     * <pre>
     *   h = q⁻¹·(m1 - m2) mod p
     *   m = m2 + h·q
     * </pre>
     * 因 dp、dq 各只有 d 的一半位长，两半模幂的总代价约为直接法的 1/4
     * （模乘 O(n²) 下），再叠加小模数运算的常数优势。
     *
     * <p>复杂度：时间约为直接法的 1/4；空间 O(n)。
     *
     * @param priv 私钥（须含 CRT 参数）
     * @param c    密文整数，须落在 [0, n)
     * @return 明文整数 m
     */
    public static BigInteger decryptCRT(PrivateKey priv, BigInteger c) {
        requireInRange(c, priv.n, "密文 c");
        BigInteger m1 = bigint_ops.modPow(c, priv.dp, priv.p);
        BigInteger m2 = bigint_ops.modPow(c, priv.dq, priv.q);
        BigInteger h = priv.qInv.multiply(m1.subtract(m2)).mod(priv.p);
        return m2.add(h.multiply(priv.q));
    }

    /* =====================================================================
     * 四、字符串 / 中文明文的分块加解密
     * ===================================================================== */

    /**
     * 计算在模数 n 下每个明文分块可承载的字节数。
     * <p>
     * 推导：块首插入 1 个 0x01 哨兵字节（用于解密时还原被 BigInteger
     * 吞掉的前导 0）。设 n 的位宽为 b，则能安全落入 [0, n) 的最大编码字节数
     * 为 floor((b-1)/8)，扣掉哨兵 1 字节后即为本值。
     *
     * <p>例：64 位模数 → 6 字节/块；128 位 → 14 字节/块；256 位 → 30 字节/块。
     */
    public static int blockSizeBytes(BigInteger n) {
        if (n == null) {
            throw new IllegalArgumentException("模数不能为 null");
        }
        int maxEncodedBytes = (n.bitLength() - 1) / 8;
        int blockBytes = maxEncodedBytes - 1;
        if (blockBytes < 1) {
            throw new IllegalArgumentException(
                    "模数过小（位宽 " + n.bitLength() + "），无法承载分块加密");
        }
        return blockBytes;
    }

    /**
     * 加密任意字节串，按模数位宽自动分块。
     * <p>编码：每个分块前加 1 字节 0x01 哨兵，再整体解释为非负 BigInteger。
     * 空输入返回长度为 0 的数组。
     *
     * @param pub  公钥
     * @param data 明文字节
     * @return 密文分块数组
     */
    public static BigInteger[] encryptBytes(PublicKey pub, byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("明文不能为 null");
        }
        if (data.length == 0) {
            return new BigInteger[0];
        }
        int bs = blockSizeBytes(pub.n);
        int count = (data.length + bs - 1) / bs;
        BigInteger[] out = new BigInteger[count];
        for (int i = 0; i < count; i++) {
            int off = i * bs;
            int len = Math.min(bs, data.length - off);
            byte[] block = new byte[len + 1];
            block[0] = 0x01;                       // 哨兵：保证前导 0 不丢失
            System.arraycopy(data, off, block, 1, len);
            out[i] = encrypt(pub, new BigInteger(1, block));
        }
        return out;
    }

    /**
     * 解密字节分块并还原为原始字节串。
     * <p>每个分块解密后校验首字节必须为哨兵 0x01，否则说明密文被篡改或密钥不匹配。
     *
     * @param priv   私钥
     * @param blocks {@link #encryptBytes} 产生的密文分块
     * @return 还原后的明文字节
     * @throws IllegalArgumentException 分块格式非法（哨兵缺失）
     */
    public static byte[] decryptBytes(PrivateKey priv, BigInteger[] blocks) {
        if (blocks == null) {
            throw new IllegalArgumentException("密文分块不能为 null");
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (BigInteger block : blocks) {
            BigInteger m = decrypt(priv, block);
            byte[] raw = m.toByteArray();
            if (raw.length < 1 || raw[0] != 0x01) {
                throw new IllegalArgumentException(
                        "密文分块格式非法：缺失哨兵字节（可能被篡改或密钥不匹配）");
            }
            bos.write(raw, 1, raw.length - 1);
        }
        return bos.toByteArray();
    }

    /** 加密字符串（UTF-8 编码），支持中文等多字节字符。 */
    public static BigInteger[] encryptString(PublicKey pub, String message) {
        if (message == null) {
            throw new IllegalArgumentException("明文不能为 null");
        }
        return encryptBytes(pub, message.getBytes(StandardCharsets.UTF_8));
    }

    /** 解密回字符串（UTF-8 解码）。 */
    public static String decryptString(PrivateKey priv, BigInteger[] blocks) {
        return new String(decryptBytes(priv, blocks), StandardCharsets.UTF_8);
    }

    /* =====================================================================
     * 五、工具方法
     * ===================================================================== */

    /** 校验 x 落在 [0, n) 内，否则抛出异常（"非法输入明确拒绝"）。 */
    private static void requireInRange(BigInteger x, BigInteger n, String label) {
        if (x == null) {
            throw new IllegalArgumentException(label + " 不能为 null");
        }
        if (x.signum() < 0 || x.compareTo(n) >= 0) {
            throw new IllegalArgumentException(
                    label + " 必须落在 [0, n) 内，n = " + n + "，收到 " + x);
        }
    }

    /** 密文分块数组转十六进制字符串，便于写入测试向量表。 */
    public static String hex(BigInteger[] blocks) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < blocks.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append("0x").append(blocks[i].toString(16));
        }
        return sb.append("]").toString();
    }

    /* =====================================================================
     * 六、直接运行：自检 + 边界 + 性能 + 安全边界
     * ===================================================================== */

    private static int passed = 0;
    private static int failed = 0;

    private static void check(String label, Object actual, Object expected) {
        String a = String.valueOf(actual);
        String e = String.valueOf(expected);
        if (a.equals(e)) {
            passed++;
            System.out.printf("  [通过] %-56s = %s%n", label, brief(a));
        } else {
            failed++;
            System.out.printf("  [失败] %-56s = %s%n", label, brief(a));
            System.out.printf("         %-56s 期望 %s%n", "", brief(e));
        }
    }

    private static void checkTrue(String label, boolean actual) {
        check(label, actual, true);
    }

    private static void checkThrows(String label,
                                    Class<? extends Throwable> type, Runnable action) {
        try {
            action.run();
            failed++;
            System.out.printf("  [失败] %-56s 未抛出异常（期望 %s）%n",
                    label, type.getSimpleName());
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                passed++;
                System.out.printf("  [通过] %-56s 抛出 %s%n", label, type.getSimpleName());
            } else {
                failed++;
                System.out.printf("  [失败] %-56s 抛出 %s（期望 %s）%n",
                        label, t.getClass().getSimpleName(), type.getSimpleName());
            }
        }
    }

    private static String brief(String s) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= 46) {
            return s;
        }
        return s.substring(0, 22) + "…(" + s.length() + "位)…" + s.substring(s.length() - 12);
    }

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

    private static BigInteger b(long v) {
        return BigInteger.valueOf(v);
    }

    /** 主入口。 */
    public static void main(String[] args) {
        banner("小位宽 RSA 实现 · 自检 / 边界 / 性能 / 安全边界");

        section1ClassicVector();
        section2DeterministicVectors();
        section3StringAndChinese();
        section4Boundaries();
        section5CrtVsDirect();
        section6SecurityBoundary();

        banner("小结");
        System.out.printf("  断言通过 %d 项，失败 %d 项%n", passed, failed);
        System.out.println(failed == 0
                ? "  结论：全部用例通过，加解密结果可复现且与已知向量一致。"
                : "  结论：存在失败用例，请检查实现。");
        if (failed != 0) {
            System.exit(1);
        }
    }

    /* ---------- 1. 公开教科书向量 ---------- */

    private static void section1ClassicVector() {
        banner("【一】已知公开向量自检（教科书经典参数，可被任何实现交叉核对）");
        System.out.println("  p=61, q=53, n=3233, φ(n)=3120, e=17, d=2753");
        BigInteger p = b(61), q = b(53);
        BigInteger n = p.multiply(q);                  // 3233
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = b(17);
        BigInteger d = bigint_ops.modInverse(e, phi);
        PublicKey pub = new PublicKey(n, e);
        PrivateKey priv = new PrivateKey(n, e, d, p, q, phi,
                d.mod(p.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)),
                bigint_ops.modInverse(q, p));

        check("φ(n) = (p-1)(q-1)", phi, b(3120));
        check("d = e⁻¹ mod φ(n)", d, b(2753));
        BigInteger c = encrypt(pub, b(65));
        check("加密 c = 65^17 mod 3233", c, b(2790));
        check("解密 m = 2790^2753 mod 3233", decrypt(priv, c), b(65));
        check("CRT 解密与直接解密一致", decryptCRT(priv, c), decrypt(priv, c));
        check("e·d ≡ 1 (mod φ(n))", e.multiply(d).mod(phi), BigInteger.ONE);
    }

    /* ---------- 2. 固定种子的确定性向量 ---------- */

    private static void section2DeterministicVectors() {
        banner("【二】固定种子可复现 —— 64 位与 128 位 RSA 往返");
        System.out.println("  同一 seed 重复生成两次，密钥与密文应完全一致。");

        // 64 位
        KeyPair k64a = generateKeyPair(64, new Random(2025));
        KeyPair k64b = generateKeyPair(64, new Random(2025));
        check("64 位：seed=2025 两次 n 相同", k64a.publicKey.n, k64b.publicKey.n);
        check("64 位：seed=2025 两次 e 相同", k64a.publicKey.e, k64b.publicKey.e);
        check("64 位：seed=2025 两次 d 相同", k64a.privateKey.d, k64b.privateKey.d);
        check("64 位：n 位宽", k64a.publicKey.bitLength, 64);
        System.out.println("    p    = " + k64a.privateKey.p);
        System.out.println("    q    = " + k64a.privateKey.q);
        System.out.println("    n    = " + k64a.publicKey.n);
        System.out.println("    φ(n) = " + k64a.privateKey.phi);
        System.out.println("    e    = " + k64a.publicKey.e);
        System.out.println("    d    = " + k64a.privateKey.d);

        BigInteger[] ms = {BigInteger.ZERO, BigInteger.ONE, b(2), b(42),
                k64a.publicKey.n.subtract(BigInteger.ONE)};
        System.out.println("    ── 单块确定性向量（64 位密钥，seed=2025）──");
        System.out.printf("    %-22s %-24s %s%n", "明文 m", "密文 c = m^e mod n", "解密回 m");
        for (BigInteger m : ms) {
            BigInteger c = encrypt(k64a.publicKey, m);
            BigInteger back = decrypt(k64a.privateKey, c);
            boolean ok = back.equals(m);
            if (ok) {
                passed++;
            } else {
                failed++;
            }
            System.out.printf("    %-22s %-24s %s   %s%n",
                    m, brief(c.toString()), brief(back.toString()), ok ? "✓" : "✗");
        }

        // 128 位
        KeyPair k128 = generateKeyPair(128, new Random(20250909));
        check("128 位：n 位宽", k128.publicKey.bitLength, 128);
        BigInteger[] s128 = encryptString(k128.publicKey, "Secure E-Commerce");
        check("128 位：字符串往返", decryptString(k128.privateKey, s128), "Secure E-Commerce");
        check("128 位：CRT 解密一致",
                decryptCRT(k128.privateKey, s128[0]), decrypt(k128.privateKey, s128[0]));
    }

    /* ---------- 3. 字符串与中文 ---------- */

    private static void section3StringAndChinese() {
        banner("【三】字符串与中文明文的加解密（UTF-8 分块）");

        KeyPair kp = generateKeyPair(64, new Random(2025));
        System.out.println("  使用 64 位密钥（seed=2025），每块可承载 "
                + kp.publicKey.blockSizeBytes() + " 字节明文。");

        String[] messages = {
                "",                                  // 空串
                "A",                                 // 单字节
                "Online BookStore",                  // 纯英文，跨块
                "在线书店",                            // 中文，1 块
                "安全电子商务系统——第5周RSA演示",         // 中文混合，跨块
        };
        for (String msg : messages) {
            BigInteger[] ct = encryptString(kp.publicKey, msg);
            String back = decryptString(kp.privateKey, ct);
            boolean ok = back.equals(msg);
            if (ok) {
                passed++;
            } else {
                failed++;
            }
            System.out.printf("  [%s] 明文=「%s」 UTF-8 %d 字节 → %d 块 → 还原「%s」%n",
                    ok ? "通过" : "失败", msg,
                    msg.getBytes(StandardCharsets.UTF_8).length, ct.length, back);
            if (ct.length > 0 && ct.length <= 3) {
                System.out.println("        密文块 = " + hex(ct));
            }
        }
    }

    /* ---------- 4. 边界与非法输入 ---------- */

    private static void section4Boundaries() {
        banner("【四】边界与非法输入 —— 明确预期行为");

        KeyPair kp = generateKeyPair(64, new Random(7));
        PublicKey pub = kp.publicKey;
        PrivateKey priv = kp.privateKey;
        BigInteger n = pub.n;

        System.out.println("  4.1 明文取值边界");
        check("m = 0 → c = 0", encrypt(pub, BigInteger.ZERO), BigInteger.ZERO);
        check("m = 1 → c = 1", encrypt(pub, BigInteger.ONE), BigInteger.ONE);
        check("m = n-1 往返", decrypt(priv, encrypt(pub, n.subtract(BigInteger.ONE))),
                n.subtract(BigInteger.ONE));
        check("c = 0 → m = 0", decrypt(priv, BigInteger.ZERO), BigInteger.ZERO);
        check("CRT: c = 0 → m = 0", decryptCRT(priv, BigInteger.ZERO), BigInteger.ZERO);

        System.out.println();
        System.out.println("  4.2 非法输入 —— 明确拒绝而非静默出错");
        checkThrows("encrypt(m = n) 明文越界",
                IllegalArgumentException.class, () -> encrypt(pub, n));
        checkThrows("encrypt(m = n+1) 明文越界",
                IllegalArgumentException.class, () -> encrypt(pub, n.add(BigInteger.ONE)));
        checkThrows("encrypt(m = -1) 明文为负",
                IllegalArgumentException.class, () -> encrypt(pub, b(-1)));
        checkThrows("decrypt(c = n) 密文越界",
                IllegalArgumentException.class, () -> decrypt(priv, n));
        checkThrows("decrypt(c = -5) 密文为负",
                IllegalArgumentException.class, () -> decrypt(priv, b(-5)));
        checkThrows("encryptString(null)",
                IllegalArgumentException.class, () -> encryptString(pub, null));
        checkThrows("generateKeyPair(16, rnd) 位宽过小",
                IllegalArgumentException.class, () -> generateKeyPair(16, new Random(1)));

        System.out.println();
        System.out.println("  4.3 篡改检测 —— 分块哨兵校验");
        BigInteger[] ct = encryptString(pub, "RSA");
        ct[0] = ct[0].add(BigInteger.ONE);         // 人为篡改一个密文块
        checkThrows("篡改密文块后解密应被拒绝",
                IllegalArgumentException.class, () -> decryptString(priv, ct));

        System.out.println();
        System.out.println("  4.4 空串与超长输入");
        check("空串 → 0 块", encryptString(pub, "").length, 0);
        check("空串往返", decryptString(priv, encryptString(pub, "")), "");
        StringBuilder longMsg = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            longMsg.append("超长输入测试-").append(i).append(';');
        }
        String lm = longMsg.toString();
        checkTrue("超长输入(" + lm.getBytes(StandardCharsets.UTF_8).length + "字节)往返一致",
                decryptString(priv, encryptString(pub, lm)).equals(lm));
    }

    /* ---------- 5. CRT 与直接解密性能对比 ---------- */

    private static void section5CrtVsDirect() {
        banner("【五】复杂度与性能实测");
        System.out.println("  直接解密 m = c^d mod n：指数 d 约 n 位，1 次全宽模幂。");
        System.out.println("  CRT 解密：dp、dq 各约 n/2 位，2 次半宽模幂 + 合并。");
        System.out.println("  理论上模乘 O(n²) 时，CRT 约为直接法的 1/4 耗时。");
        System.out.println();
        System.out.printf("  %-10s %-18s %-18s %s%n", "位宽", "直接解密", "CRT 解密", "加速比");

        int[] widths = {128, 256, 512, 1024};
        for (int w : widths) {
            KeyPair kp = generateKeyPair(w, new Random(1000 + w));
            BigInteger c = encrypt(kp.publicKey, b(123456789));
            long tDirect = timeBestNanos(50, () -> decrypt(kp.privateKey, c));
            long tCrt = timeBestNanos(50, () -> decryptCRT(kp.privateKey, c));
            long tEnc = timeBestNanos(50, () -> encrypt(kp.publicKey, b(123456789)));
            System.out.printf("  %-10s %-18s %-18s %s%n",
                    w + " 位", fmtNanos(tDirect), fmtNanos(tCrt),
                    String.format("%.2f×", (double) tDirect / Math.max(1, tCrt)));
            if (w == widths[0]) {
                System.out.printf("  %-10s 加密(e=%s)耗时 %s（e 位长远小于 d，故远快于解密）%n",
                        "", kp.publicKey.e, fmtNanos(tEnc));
            }
        }
        System.out.println();
        System.out.println("  说明：位宽每次 ×2，直接解密耗时约 ×4（模乘 O(n²)），");
        System.out.println("        CRT 通过把一次全宽模幂拆成两次半宽模幂，取得约 3~4 倍加速。");
    }

    /* ---------- 6. 安全边界 ---------- */

    private static void section6SecurityBoundary() {
        banner("【六】安全边界 —— 小位宽 RSA 为什么不能用于生产");

        System.out.println("  6.1 实测：64 位模数可在毫秒级被分解（Pollard ρ）");
        KeyPair kp = generateKeyPair(64, new Random(2025));
        BigInteger n = kp.publicKey.n;
        long t0 = System.nanoTime();
        BigInteger factor = pollardRho(n);
        long dt = System.nanoTime() - t0;
        System.out.println("      模数 n      = " + n);
        System.out.println("      分解得到     = " + factor);
        System.out.println("      真实素因子 p = " + kp.privateKey.p);
        System.out.println("      分解耗时     = " + fmtNanos(dt));
        check("分解结果确为 n 的因子", n.mod(factor), BigInteger.ZERO);
        System.out.println("      → 分解出 p、q 后，由公开的 e 求 d 毫无障碍，私钥即刻泄露。");

        System.out.println();
        System.out.println("  6.2 实测：无填充 RSA 是确定性的，且具有乘法同态性");
        BigInteger m1 = b(1234567);
        BigInteger m2 = b(7654321);
        BigInteger c1 = encrypt(kp.publicKey, m1);
        BigInteger c2 = encrypt(kp.publicKey, m2);
        BigInteger c11 = encrypt(kp.publicKey, m1);
        check("同一明文两次加密得到同一密文（确定性）", c11, c1);
        BigInteger cProd = c1.multiply(c2).mod(n);
        BigInteger cMul = encrypt(kp.publicKey, m1.multiply(m2).mod(n));
        check("E(m1)·E(m2) ≡ E(m1·m2) (mod n)（乘法同态）", cProd, cMul);
        System.out.println("      → 攻击者可对密文做乘法，无需私钥即可让明文翻倍；");
        System.out.println("        更狡猾地，可通过选择明文攻击逐位恢复消息。");

        System.out.println();
        System.out.println("  6.3 计时侧信道");
        System.out.println("      modPow 按指数二进制位分支（为 1 才多一次模乘），");
        System.out.println("      运算次数与内存访问随密钥位变化，可被计时推断私钥比特。");
        System.out.println("      生产做法：常数时间实现，或对密文做盲化（blinding）。");

        System.out.println();
        System.out.println("  6.4 随机源不满足密码学安全");
        System.out.println("      密钥生成用 java.util.Random，其序列可被预测；");
        System.out.println("      本模块保留它是为了「固定种子即可复现」的教学取舍。");
        System.out.println("      生产做法：改用 java.security.SecureRandom（CSPRNG）。");

        System.out.println();
        System.out.println("  ── 生产环境应当怎么做 ──");
        System.out.println("  ① 密钥长度：RSA ≥ 2048 位（NIST 建议 3072 位，长期数据更长）；");
        System.out.println("  ② 填充：加密用 RSA-OAEP，签名用 RSA-PSS，绝不裸用模幂；");
        System.out.println("  ③ 实现：委托给经审计的标准库（JDK JCA / BouncyCastle），");
        System.out.println("     不要自行实现密钥生成、填充与常数时间运算；");
        System.out.println("  ④ 随机数：一律使用 CSPRNG（SecureRandom / getrandom）。");
        System.out.println();
        System.out.println("  结论：本模块可以回答「RSA 加解密为什么正确、代价是多少」，");
        System.out.println("        但它的一切设计都为教学复现服务，不能承担任何真实数据的机密性。");
    }

    /**
     * Pollard ρ 分解算法（仅用于演示小位宽模数可被分解）。
     * <p>
     * 用固定的 {@link Random} 种子保证演示可复现。对 64 位模数通常毫秒级命中。
     *
     * @param n 待分解的合数
     * @return n 的一个非平凡因子
     */
    static BigInteger pollardRho(BigInteger n) {
        if (n.mod(BigInteger.TWO).signum() == 0) {
            return BigInteger.TWO;
        }
        if (n.mod(THREE).signum() == 0) {
            return THREE;
        }
        Random rnd = new Random(0xC0FFEEL);
        while (true) {
            BigInteger c = new BigInteger(n.bitLength(), rnd)
                    .mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            BigInteger x = new BigInteger(n.bitLength(), rnd)
                    .mod(n.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            BigInteger y = x;
            BigInteger d = BigInteger.ONE;
            while (d.equals(BigInteger.ONE)) {
                x = rhoStep(x, c, n);
                y = rhoStep(rhoStep(y, c, n), c, n);
                d = x.subtract(y).abs().gcd(n);
            }
            if (!d.equals(n)) {
                return d;                          // 非平凡因子
            }
            // d == n 说明本轮退化为平凡，换一组参数重试
        }
    }

    /** ρ 迭代函数 f(x) = x² + c (mod n)。 */
    private static BigInteger rhoStep(BigInteger x, BigInteger c, BigInteger n) {
        return x.multiply(x).add(c).mod(n);
    }

    private static void banner(String title) {
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════════════");
        System.out.println("  " + title);
        System.out.println("════════════════════════════════════════════════════════════════════");
    }
}
