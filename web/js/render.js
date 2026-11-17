/* 页面渲染：所有服务端数据都必须经过 escapeHtml 才能进 DOM。
 *
 * 这是整个前端唯一的转义点，也是 XSS 验收的观测点：
 * 昵称里存 `<script>alert(1)</script>`，原文进库、原样出现在 JSON 里，
 * 但页面源码（DevTools → Elements）里必须是 `&lt;script&gt;`。
 *
 * 为什么不用 `textContent` 一把梭：这里用 innerHTML + 显式转义，是为了让
 * "转义到底做没做"在页面源码里可看、可截图、可复核；textContent 会把证据
 * 藏进 DOM 属性里，验收时反而说不清。两种都安全，这里选可观测的那种。
 *
 * 同时提供 CommonJS 导出：`test/security/xss_render_check.js` 用同一份代码
 * 跑一遍，保证"测的"与"页面用的"是同一个函数，不是两份复制品。
 */
(function (global) {
  "use strict";

  var ESCAPE_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  };

  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value).replace(/[&<>"']/g, function (ch) {
      return ESCAPE_MAP[ch];
    });
  }

  var STATUS_TEXT = {
    active: "正常",
    locked: "已锁定",
    disabled: "已停用"
  };

  /* 服务端给的是 UTC 的 ISO 串（2026-11-17T01:08:18.006Z），直接显示会和本地时间差 8 小时。
     这里按浏览器本地时区转成 "2026-11-17 09:08"，转不出来就原样返回。 */
  function fmtTime(value) {
    if (!value) {
      return value;
    }
    var d = new Date(value);
    if (isNaN(d.getTime())) {
      return value;
    }
    var pad = function (n) {
      return n < 10 ? "0" + n : String(n);
    };
    return (
      d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
    );
  }

  function cell(label, valueHtml) {
    return "<dt>" + escapeHtml(label) + "</dt><dd>" + valueHtml + "</dd>";
  }

  function text(value, fallback) {
    if (value === null || value === undefined || value === "") {
      return '<span class="muted">' + escapeHtml(fallback || "—") + "</span>";
    }
    return escapeHtml(value);
  }

  function renderProfile(profile) {
    var p = profile || {};
    var status = p.status || "";
    var statusHtml = status
      ? '<span class="tag">' + escapeHtml(STATUS_TEXT[status] || status) + "</span>"
      : text(null);

    return (
      cell("用户编号", text(p.userId)) +
      cell("登录名", text(p.username)) +
      cell("昵称", text(p.nickname, "（未设置）")) +
      cell("手机号", text(p.phoneMasked)) +
      cell("邮箱", text(p.emailMasked, "本期不采集")) +
      cell("账号状态", statusHtml) +
      cell("上次登录", text(fmtTime(p.lastLoginAt), "本次是首次登录")) +
      cell("注册时间", text(fmtTime(p.createdAt)))
    );
  }

  var api = {
    escapeHtml: escapeHtml,
    fmtTime: fmtTime,
    renderProfile: renderProfile,
    STATUS_TEXT: STATUS_TEXT
  };

  global.BS_RENDER = api;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
