/* 前端唯一的后端调用出口。
 *
 * 三条约定：
 * 1. 令牌只放 sessionStorage，只在 Authorization 头里发。不用 Cookie、不进 URL——
 *    CSRF 在结构上就没有落脚点（详见 docs/test/week10-11/03-CSRF.md）。
 * 2. 前端**不做安全判断**：口令强度、账号是否存在、令牌是否有效，一律由后端说了算，
 *    这里只把后端的结论翻译成人话。改 DOM 隐藏按钮也不构成鉴权。
 * 3. 任何 401 都清掉本地令牌并回登录页：那是服务端撤销或过期的唯一可靠信号。
 */
(function (global) {
  "use strict";

  var API_BASE = "http://127.0.0.1:8000";
  var TOKEN_KEY = "bookstore.token";
  var HOME = "login.html";

  /* 错误码 → 人话。出现的码全部来自后端封闭集（src/user/errors.py）。 */
  var CODE_TEXT = {
    VALIDATION_ERROR: "请求参数不合法",
    PAYLOAD_TOO_LARGE: "请求体过大",
    AUTH_INVALID_CREDENTIALS: "账号或密码错误",
    AUTH_UNAUTHENTICATED: "登录状态无效，请重新登录",
    AUTH_TOKEN_EXPIRED: "登录已过期，请重新登录",
    AUTH_FORBIDDEN: "无权执行该操作",
    RESOURCE_NOT_FOUND: "资源不存在",
    USER_ALREADY_EXISTS: "该登录名或手机号已被使用",
    RATE_LIMITED: "请求过于频繁，请稍后再试",
    INTERNAL_ERROR: "服务暂时不可用，请稍后再试",
    NETWORK_ERROR: "连不上后端服务，请确认后端已在 8000 端口启动"
  };

  var FIELD_TEXT = {
    username: "登录名",
    phone: "手机号",
    password: "口令",
    nickname: "昵称",
    account: "账号",
    userId: "用户编号"
  };

  var REASON_TEXT = {
    REQUIRED: "必填",
    TYPE_MISMATCH: "类型不对",
    TOO_SHORT: "太短",
    TOO_LONG: "太长",
    FORMAT_INVALID: "格式不对",
    OUT_OF_RANGE: "超出范围",
    NOT_ALLOWED: "不允许出现",
    DUPLICATE: "重复"
  };

  function getToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch (e) {
      return null;
    }
  }

  function setToken(token) {
    sessionStorage.setItem(TOKEN_KEY, token);
  }

  function clearToken() {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch (e) {
      /* sessionStorage 被禁用时不影响主流程 */
    }
  }

  function describe(err) {
    var data = (err && err.data) || {};
    var base = CODE_TEXT[data.code] || data.message || "请求失败（HTTP " + (err && err.status) + "）";
    var detail = "";
    if (data.details && data.details.length) {
      var first = data.details[0];
      var field = FIELD_TEXT[first.field] || first.field;
      var reason = REASON_TEXT[first.reason] || first.reason;
      detail = "：" + field + reason;
    }
    return base + detail;
  }

  function request(method, path, options) {
    options = options || {};
    var headers = { Accept: "application/json" };
    var body;

    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }

    var token = options.auth === false ? null : getToken();
    if (token) {
      headers.Authorization = "Bearer " + token;
    }

    return fetch(API_BASE + path, {
      method: method,
      headers: headers,
      body: body,
      cache: "no-store",
      credentials: "omit"
    })
      .then(function (resp) {
        return resp.text().then(function (text) {
          var data = null;
          if (text) {
            try {
              data = JSON.parse(text);
            } catch (e) {
              data = null;
            }
          }
          if (!resp.ok) {
            var err = { status: resp.status, data: data || {} };
            /* 令牌失效/过期：清掉本地副本。是否失效由后端判定，前端只照办。 */
            if (
              resp.status === 401 &&
              (err.data.code === "AUTH_UNAUTHENTICATED" || err.data.code === "AUTH_TOKEN_EXPIRED")
            ) {
              clearToken();
            }
            throw err;
          }
          return data;
        });
      })
      .catch(function (err) {
        if (err && typeof err.status === "number") {
          throw err;
        }
        throw { status: 0, data: { code: "NETWORK_ERROR" } };
      });
  }

  global.BS = {
    API_BASE: API_BASE,
    HOME: HOME,
    getToken: getToken,
    setToken: setToken,
    clearToken: clearToken,
    describe: describe,
    register: function (payload) {
      return request("POST", "/api/users/register", { body: payload, auth: false });
    },
    login: function (account, password) {
      return request("POST", "/api/auth/login", {
        body: { account: account, password: password },
        auth: false
      });
    },
    logout: function () {
      return request("POST", "/api/auth/logout", { body: {}, redirectOn401: false });
    },
    verify: function () {
      return request("GET", "/api/auth/verify");
    },
    me: function () {
      return request("GET", "/api/users/me");
    },
    goLogin: function () {
      location.href = HOME;
    }
  };

  /* 供页面共用的小工具：提示条与"必须先登录"的门槛 */
  global.BSUI = {
    banner: function (el, kind, text, traceId) {
      el.className = "banner show " + kind;
      el.textContent = text;
      if (traceId) {
        var span = document.createElement("span");
        span.className = "trace";
        span.textContent = "追踪编号 " + traceId + "（排障时把它给后端）";
        el.appendChild(span);
      }
    },
    hide: function (el) {
      el.className = "banner";
      el.textContent = "";
    },
    requireToken: function () {
      if (!global.BS.getToken()) {
        location.href = global.BS.HOME;
        return false;
      }
      return true;
    },
    busy: function (button, text) {
      if (text) {
        button.dataset.idle = button.textContent;
        button.textContent = text;
        button.disabled = true;
      } else {
        button.textContent = button.dataset.idle || button.textContent;
        button.disabled = false;
      }
    }
  };
})(window);
