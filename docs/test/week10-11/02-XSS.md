# 安全测试记录 · 二：XSS

| 项目 | 内容 |
| :--- | :--- |
| 测试编号 | SEC-W10-02 |
| 测试日期 | 2026-11-10 |
| 被测对象 | 注册/个人信息接口（`src/user/`）+ 四个页面（`web/`） |
| 测试环境 | 同上，另加 Node.js 22（只用于跑同前端共用的一份转义函数） |
| 测试工具 | `test/security/week10-11_security_tests.py`、`test/security/xss_render_check.js` |
| 回指威胁 | T-TM-05（入口参数注入）、T-ID-05（错误页回显） |
| 回指需求 | SR-19（输出不出现内部结构）。**注意**：SR-19 只覆盖"注入失败后不泄露库结构"，XSS 本身由本记录新增的输出转义控制覆盖，见 §5 |

## 1. 判定标准（任务书原文）

> 原文入库、输出转义。把带 `alert(1)` 的 script 标签存进昵称，页面必须显示成文本。
> 证据是页面源码里该标签以实体形式出现（库里存原文、页面显示实体），只看"没弹窗"不算。

所以这一组必须同时给出四份证据，缺一条都不算通过：

| 证据 | 观测点 | 本记录位置 |
| :--- | :--- | :--- |
| ① 原文入库 | `SELECT nickname FROM user_account` 得到完整载荷 | §3 X-01～X-03 的"实际"列 |
| ② 接口原样返回 | `GET /api/users/me` 的 JSON 里是未转义原文 | 同上 |
| ③ 页面渲染为实体 | 页面源码中为 `&lt;script&gt;`，不是 `<script>` | §2 渲染输出 |
| ④ 没有"只是没弹窗"的解释 | 页面无内联脚本 + CSP `script-src 'self'` | §2 CSP 检查、X-08 |

## 2. 控制点与证据

**唯一的转义点在 `web/js/render.js`。** 所有服务端数据都经过 `escapeHtml()` 才能进 DOM：

```js
var ESCAPE_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, function (ch) { return ESCAPE_MAP[ch]; });
}
```

为什么不用 `textContent` 一把梭：两种都安全，但 `textContent` 把证据藏进 DOM，验收时说不清
"到底转义了没有"。用 `innerHTML + 显式转义`，页面源码里能直接看到实体、可以截图复核。
代价是"每个插值点都必须转义"，所以把渲染函数收敛到一个文件，页面只调用 `renderProfile()`。

用页面**同一份** `render.js`（`require` 进去，不是复制一份）跑出来的渲染结果：

```text
输入载荷：<script>alert(1)</script>
渲染结果：<dt>昵称</dt><dd>&lt;script&gt;alert(1)&lt;/script&gt;</dd>
```

`node test/security/xss_render_check.js` 的 8 项断言全部通过：

```text
PASS  输出含实体 &lt;script&gt;
PASS  输出含实体 &lt;/script&gt;
PASS  输出不含未转义 <script
PASS  img onerror 载荷被转义
PASS  双引号被转义
PASS  单引号被转义
PASS  & 先被转义（不会二次转义出 &amp;lt;）
PASS  javascript: 里的冒号不构成链接（纯文本渲染）

共 8 项，全部通过。
```

**第二道防线：CSP。** 5 个页面全部带 `Content-Security-Policy` meta，`script-src 'self'`，
且没有任何内联 `<script>`（X-08 断言 5/5、内联 0 个）。即使某处漏了转义，注入的
`<script>` 也执行不了；但**主控制仍是转义**，CSP 只是兜底——这一点在结论里不混淆。

## 3. 测试结果

| 编号 | 入口 | 攻击串 | 预期 | 实际 | 判定 | 威胁 | 需求 |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| X-01 | 注册 → 个人信息 | `<script>alert(1)</script>` | 201；原文入库；JSON 原文返回 | 201；库里原文=是；JSON 原文=是 | 通过 | T-TM-05 | SR-19 |
| X-02 | 注册 → 个人信息 | `<img src=x onerror=alert(1)>` | 同上 | 201；库里原文=是；JSON 原文=是 | 通过 | T-TM-05 | SR-19 |
| X-03 | 注册 → 个人信息 | `"><svg onload=alert(1)>` | 同上 | 201；库里原文=是；JSON 原文=是 | 通过 | T-TM-05 | SR-19 |
| X-04 | `web/js/render.js` | `<script>alert(1)</script>` | 源码为 `&lt;script&gt;`，无未转义标签 | node 返回 0，8 项断言全过 | 通过 | T-TM-05 | SR-19 |
| X-05 | 注册（username） | `<script>x</script>` | 400（登录名白名单） | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| X-06 | 注册（nickname） | `<script>` + 40×A + `</script>` | 400（超 32 字符 → TOO_LONG） | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| X-07 | 注册（nickname） | `a\x00b` | 400（控制字符） | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| X-08 | `web/*.html` | — | 每页有 CSP；无内联脚本 | CSP 5/5；内联脚本 0 个 | 通过 | T-TM-05 | SR-19 |

## 4. 两个刻意为之的设计，答辩时会被问

**昵称为什么允许尖括号？** 因为"输入侧过滤 `<`"并不是 XSS 的正解：同样的载荷可以走属性
（`" onmouseover=`）、URL（`javascript:`）、SVG（`onload`），过滤尖括号只能挡住其中一小类，
还会把"输出转义做没做"这个验收点藏起来——库里存的是净化后的串，页面源码里自然看不到实体。
所以这里选择**原文入库、输出转义**，X-01～X-03 三种载荷覆盖了标签、属性、SVG 三类载体。

**昵称的长度与控制字符为什么拦？** 这两条不是 XSS 控制，是数据形状控制：超过 32 字符会撑坏
页面布局，控制字符（NUL、换行）会破坏日志单行结构、并在终端里伪造输出。它们在
`validation.py` `_check_nickname` 里，判定依据是"数据形状"，不是"防注入"。

## 5. 结论与遗留

- 结论：脚本载荷**原文入库、实体输出**，三类载体均被转义；页面无内联脚本且有 CSP 兜底。
- 遗留一：SR-19 的措辞只覆盖"注入失败后不泄露库结构"，**没有一条安全需求正面要求"输出转义"**。
  这是需求层的缺口，建议在 II 阶段补 `SR-21：所有回显到页面的用户数据必须经过统一转义点`，
  威胁编号沿用 T-TM-05（或新登记 T-TM-07 存储型 XSS）。本期不擅自改第 6-9 周的 SR 清单，
  只在本记录登记。
- 遗留二：`web/js/render.js` 是唯一转义点，新增页面必须调用 `renderProfile()` 一类的函数，
  不得自己拼 HTML。这条写进 `web/README.md` 的"改动须知"。
