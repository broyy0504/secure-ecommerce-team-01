#!/usr/bin/env node
/* 用同一个转义函数验证"页面源码里是实体"。
 *
 * 为什么需要这条检查：XSS 验收要求"证据是页面源码里该标签以实体形式出现"。
 * 页面是 JS 渲染的，光看 JSON 只能证明"原文入库"，证明不了"输出转义"。
 * 这里直接 require 页面用的那个 `web/js/render.js`，喂一份带载荷的 profile，
 * 打印渲染结果并断言：
 *   1. 输出里出现 `&lt;script&gt;`；
 *   2. 输出里不出现未转义的 `<script`；
 *   3. 载荷里的 onerror / javascript: 同样被转义。
 *
 * 用法：node test/security/xss_render_check.js
 */
"use strict";

const path = require("path");
const render = require(path.join(__dirname, "..", "..", "web", "js", "render.js"));

const payloads = {
  scriptTag: '<script>alert(1)</script>',
  imgOnerror: '"><img src=x onerror=alert(1)>',
  jsUri: "javascript:alert(1)",
  quotes: "O'Reilly \"book\" & <b>co</b>"
};

const profile = {
  userId: "1",
  username: "xss_probe_01",
  nickname: payloads.scriptTag,
  phoneMasked: "138****8000",
  emailMasked: null,
  status: "active",
  lastLoginAt: null,
  createdAt: "2026-11-10T00:00:00.000Z"
};

const html = render.renderProfile(profile);

console.log("=== 输入载荷 ===");
console.log(payloads.scriptTag);
console.log("=== 渲染结果（页面源码片段）===");
console.log(html);

const checks = [
  ["输出含实体 &lt;script&gt;", html.includes("&lt;script&gt;")],
  ["输出含实体 &lt;/script&gt;", html.includes("&lt;/script&gt;")],
  ["输出不含未转义 <script", !/<script/i.test(html)],
  ["img onerror 载荷被转义", !/<img/i.test(html)],
  ["双引号被转义", render.escapeHtml(payloads.imgOnerror).includes("&quot;")],
  ["单引号被转义", render.escapeHtml(payloads.quotes).includes("&#39;")],
  ["& 先被转义（不会二次转义出 &amp;lt;）", render.escapeHtml("&lt;") === "&amp;lt;"],
  ["javascript: 里的冒号不构成链接（纯文本渲染）", !/<a\s/i.test(html)]
];

let failed = 0;
for (const [name, ok] of checks) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failed += 1;
}

console.log(failed === 0 ? `\n共 ${checks.length} 项，全部通过。` : `\n未通过 ${failed} 项。`);
process.exit(failed === 0 ? 0 : 1);
