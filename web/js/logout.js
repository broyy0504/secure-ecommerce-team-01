/* 退出页：先确认"当前是谁"，再由用户点一下撤销。
 *
 * 顺序是刻意的：先调 /api/auth/verify 确认令牌还有效，再撤销。这样现场能看到
 * "退出前有效 / 退出后 401"的对照，而不是点一下按钮就跳走、什么都没证明。
 */
(function () {
  "use strict";

  var banner = document.getElementById("banner");
  var who = document.getElementById("who");
  var sessionEl = document.getElementById("session");
  var confirmBtn = document.getElementById("confirm");
  var esc = BS_RENDER.escapeHtml;

  if (!BS.getToken()) {
    who.textContent = "当前没有登录会话";
    BSUI.banner(banner, "warn", "本地没有令牌，可能已经退出过，或者换了标签页。");
    sessionEl.innerHTML = "";
    confirmBtn.disabled = true;
    return;
  }

  function sessionRows(session) {
    return (
      '<dt>用户编号</dt><dd>' + esc(session.userId) + "</dd>" +
      '<dt>登录名</dt><dd>' + esc(session.username) + "</dd>" +
      '<dt>失效时间</dt><dd>' + esc(session.expiresAt) + "</dd>"
    );
  }

  async function identify() {
    try {
      var session = await BS.verify();
      who.textContent = "确认要退出吗，" + session.username + "？";
      sessionEl.innerHTML = sessionRows(session);
    } catch (err) {
      who.textContent = "当前登录状态已无效";
      BSUI.banner(banner, "warn", BS.describe(err) + "。点下面的按钮清掉本地副本，再回登录页。");
      confirmBtn.textContent = "清除本地登录状态";
      confirmBtn.dataset.noop = "1";
    }
  }

  confirmBtn.addEventListener("click", async function () {
    BSUI.hide(banner);

    if (confirmBtn.dataset.noop === "1") {
      BS.clearToken();
      location.href = "login.html?from=logout";
      return;
    }

    if (confirmBtn.dataset.noop === "2") {
      location.href = "login.html?from=logout";
      return;
    }

    BSUI.busy(confirmBtn, "退出中…");
    try {
      await BS.logout();
    } catch (err) {
      /* 401 也照样清本地：服务端已经认定这枚令牌无效，留着没有意义 */
      if (err.status !== 401) {
        BSUI.banner(banner, "error", "退出失败：" + BS.describe(err), err.data && err.data.traceId);
        BSUI.busy(confirmBtn);
        return;
      }
    }

    BS.clearToken();
    who.textContent = "已退出登录";
    sessionEl.innerHTML = '<dt>服务端</dt><dd>该令牌已标记撤销</dd>' +
      '<dt>本地</dt><dd>令牌副本已清除</dd>';
    BSUI.banner(banner, "ok", "退出成功。现在回登录页，或直接调 /api/users/me 验证旧令牌已 401。");
    confirmBtn.textContent = "返回登录页";
    confirmBtn.dataset.noop = "2";
    confirmBtn.disabled = false;
  });

  identify();
})();
