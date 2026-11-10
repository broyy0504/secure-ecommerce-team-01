/* web/assets/api.js —— 四个页面共用的后端调用与错误呈现
 *
 * 三条设计口径（与本组《03-接口契约》《安全需求》对齐）：
 *
 * 1. 令牌只放 sessionStorage、只走 Authorization 请求头，不用 Cookie。
 *    请求头不会随表单/链接自动携带，因此本场景不存在浏览器自动带凭证的问题，
 *    CSRF 由设计规避（对应任务书 2.3 中「令牌走请求头」这一条）。
 *    不用 localStorage 是因为关闭标签页即失效，长期驻留的风险更小（任务书 2.2）。
 *    注意：这只是降低风险，不是安全边界 —— 边界在服务端验签与过期。
 *
 * 2. 这里不判权限。页面显示什么、跳不跳转都只算体验；
 *    能不能看某个人的信息，完全由服务端 /api/users/me 返回 200 还是 401 决定。
 *    所以本文件没有任何「是不是管理员」「该不该显示按钮」之类的判断。
 *
 * 3. 所有来自服务端的文本一律用 textContent 写入，页面上不出现 innerHTML 拼接。
 *    用户名里塞 <script> 也只会显示成文本（对应 XSS 用例）。
 */

(function (global) {
  "use strict";

  var TOKEN_KEY = "cipherbook.accessToken";

  /* ── 令牌存取（sessionStorage 可能被浏览器策略禁用，异常一律当"没有令牌"）── */

  function getToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY) || null;
    } catch (e) {
      return null;
    }
  }

  function setToken(token) {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch (e) {
      /* 存不进去也不影响这一次请求，只是刷新后会退到未登录 */
    }
  }

  function clearToken() {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch (e) {
      /* 忽略 */
    }
  }

  /* ── 请求 ── */

  function request(path, options) {
    options = options || {};
    var method = options.method || "GET";
    var headers = {};
    var init = { method: method, headers: headers, credentials: "omit" };

    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    if (options.auth !== false) {
      var token = getToken();
      if (token) headers["Authorization"] = "Bearer " + token;
    }

    return fetch(path, init).then(
      function (res) {
        /* 204 没有响应体（退出接口就是这样），不能去 parse */
        if (res.status === 204) {
          return { status: 204, ok: res.ok, data: null };
        }
        return res.text().then(function (text) {
          var data = null;
          try {
            data = text ? JSON.parse(text) : null;
          } catch (e) {
            data = null;
          }
          return { status: res.status, ok: res.ok, data: data };
        });
      },
      function () {
        /* fetch 本身失败 = 连不上，通常是后端没起，给一句能照着做的话 */
        throw new Error("连不上服务端。请确认后端已在仓库根目录启动：python -m src.user.server");
      }
    );
  }

  /* ── 把封闭错误码翻成看得懂的提示 ──
   * 服务端只回 code / message / traceId / details，且 details 不回显原值。
   * 字段级原因比整句更具体，所以优先用 details 拼一句；拼不出来再用服务端的 message。
   */

  var FIELD_LABEL = {
    username: "登录名",
    phone: "手机号",
    password: "口令",
    account: "账号",
    body: "请求内容"
  };

  var REASON_LABEL = {
    REQUIRED: "不能为空",
    TYPE_MISMATCH: "类型不对",
    TOO_SHORT: "太短",
    TOO_LONG: "太长",
    FORMAT_INVALID: "格式不正确",
    OUT_OF_RANGE: "超出允许范围",
    NOT_ALLOWED: "不被允许",
    DUPLICATE: "已存在"
  };

  function describeError(result) {
    var data = result.data || {};
    var detail = data.details && data.details[0];

    if (detail && FIELD_LABEL[detail.field] && REASON_LABEL[detail.reason]) {
      return FIELD_LABEL[detail.field] + REASON_LABEL[detail.reason];
    }
    if (data.message) return data.message;
    if (result.status === 0) return "网络请求失败";
    return "请求失败（HTTP " + result.status + "）";
  }

  /* ── 页面上的提示区 ── */

  function setText(el, text) {
    if (el) el.textContent = text == null ? "" : String(text);
  }

  function clearMsg(msgEl, metaEl) {
    setText(msgEl, "");
    setText(metaEl, "");
    if (msgEl) msgEl.className = "msg";
  }

  function showOk(msgEl, metaEl, text) {
    setText(msgEl, text);
    setText(metaEl, "");
    if (msgEl) msgEl.className = "msg ok";
  }

  /* 错误提示 + 错误码与追踪号（追踪号能和后端日志对上，方便排查） */
  function showError(msgEl, metaEl, result, fallback) {
    setText(msgEl, fallback || describeError(result));
    if (msgEl) msgEl.className = "msg err";

    var data = (result && result.data) || {};
    var bits = [];
    if (data.code) bits.push("错误码 " + data.code);
    if (data.traceId) bits.push("追踪号 " + data.traceId);
    setText(metaEl, bits.join(" · "));
  }

  /* ── 提交按钮的忙闲，防止连点发出两次请求 ── */

  function withBusy(button, task) {
    if (button) button.disabled = true;
    return task().then(
      function (v) {
        if (button) button.disabled = false;
        return v;
      },
      function (e) {
        if (button) button.disabled = false;
        throw e;
      }
    );
  }

  global.CipherBook = {
    getToken: getToken,
    setToken: setToken,
    clearToken: clearToken,
    request: request,
    describeError: describeError,
    setText: setText,
    clearMsg: clearMsg,
    showOk: showOk,
    showError: showError,
    withBusy: withBusy
  };
})(window);
