/* 个人信息页：拉一次 /api/users/me 与 /api/auth/verify，按转义规则渲染。
 *
 * 401 一律回登录页——"令牌还有没有效"由后端判定，前端只根据结论动作，
 * 不靠"本地有没有字符串"来判断登录状态。
 */
(function () {
  "use strict";

  if (!BSUI.requireToken()) {
    return;
  }

  var banner = document.getElementById("banner");
  var greeting = document.getElementById("greeting");
  var profileEl = document.getElementById("profile");
  var sessionEl = document.getElementById("session");
  var refresh = document.getElementById("refresh");
  var esc = BS_RENDER.escapeHtml;

  function sessionRows(session) {
    var minutes = Math.max(0, Math.round((session.expiresIn || 0) / 60));
    return (
      '<dt>用户编号</dt><dd>' + esc(session.userId) + "</dd>" +
      '<dt>签发时间</dt><dd>' + esc(session.issuedAt) + "</dd>" +
      '<dt>失效时间</dt><dd>' + esc(session.expiresAt) + "</dd>" +
      '<dt>剩余有效</dt><dd>约 ' + esc(minutes) + " 分钟</dd>"
    );
  }

  async function load() {
    BSUI.hide(banner);
    BSUI.busy(refresh, "读取中…");
    try {
      var results = await Promise.all([BS.me(), BS.verify()]);
      var profile = results[0];
      var session = results[1];

      profileEl.innerHTML = BS_RENDER.renderProfile(profile);
      sessionEl.innerHTML = sessionRows(session);
      greeting.textContent = "你好，" + (profile.nickname || profile.username);
    } catch (err) {
      if (err && err.status === 401) {
        location.href = "login.html?expired=1";
        return;
      }
      BSUI.banner(banner, "error", "读取失败：" + BS.describe(err), err.data && err.data.traceId);
      greeting.textContent = "读取失败";
    } finally {
      BSUI.busy(refresh);
    }
  }

  refresh.addEventListener("click", load);
  load();
})();
