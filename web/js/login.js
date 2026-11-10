/* 登录页交互。
 *
 * 这里没有一条前端校验规则：不判长度、不判格式、不判账号是否存在。
 * 表单空着提交也会照发，由后端回 400 并把 `details` 说清楚——现场演示时
 * 一眼能看出"校验在服务端"。
 */
(function () {
  "use strict";

  var form = document.getElementById("login-form");
  var banner = document.getElementById("banner");
  var button = document.getElementById("submit");
  var account = document.getElementById("account");
  var password = document.getElementById("password");

  /* 从个人中心被踢回来时给个说明（令牌过期或已退出） */
  if (location.search.indexOf("expired=1") >= 0) {
    BSUI.banner(banner, "warn", "登录状态已失效，请重新登录。");
  } else if (location.search.indexOf("from=logout") >= 0) {
    BSUI.banner(banner, "ok", "已经退出登录，原令牌在服务端已撤销。");
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    BSUI.hide(banner);
    BSUI.busy(button, "登录中…");

    try {
      var data = await BS.login(account.value.trim(), password.value);
      BS.setToken(data.accessToken);
      location.href = "profile.html";
    } catch (err) {
      BSUI.banner(banner, "error", BS.describe(err), err.data && err.data.traceId);
      password.value = "";
      password.focus();
      BSUI.busy(button);
    }
  });
})();
