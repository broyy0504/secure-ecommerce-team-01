/* 注册页交互：注册成功后自动登录，直接进个人信息页。
 *
 * 同样不做前端校验——手机号格式、口令长度、登录名规则全部由后端判。
 * 这样现场演示"注册失败"时，看到的是后端真实返回的字段级原因，
 * 而不是前端自己编的一句提示。
 */
(function () {
  "use strict";

  var form = document.getElementById("register-form");
  var banner = document.getElementById("banner");
  var button = document.getElementById("submit");

  var fields = {
    username: document.getElementById("username"),
    phone: document.getElementById("phone"),
    password: document.getElementById("password"),
    nickname: document.getElementById("nickname")
  };

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    BSUI.hide(banner);
    BSUI.busy(button, "提交中…");

    var payload = {
      username: fields.username.value.trim(),
      phone: fields.phone.value.trim(),
      password: fields.password.value
    };

    var nickname = fields.nickname.value.trim();
    if (nickname) {
      payload.nickname = nickname;
    }

    try {
      await BS.register(payload);
    } catch (err) {
      BSUI.banner(banner, "error", BS.describe(err), err.data && err.data.traceId);
      BSUI.busy(button);
      return;
    }

    /* 注册已成功，接着用同一份口令登录；登录失败不影响账号已建好这件事 */
    BSUI.busy(button, "自动登录中…");
    try {
      var session = await BS.login(payload.username, payload.password);
      BS.setToken(session.accessToken);
      location.href = "profile.html";
    } catch (err) {
      BSUI.banner(
        banner,
        "warn",
        "账号已创建，但自动登录没成功：" + BS.describe(err) + "。请到登录页手动登录。"
      );
      BSUI.busy(button);
    }
  });
})();
