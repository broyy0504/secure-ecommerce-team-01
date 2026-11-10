# 前端（web/）

四个页面 + 一个跳转入口，原生 HTML/CSS/JS，无框架、无 CDN、无构建步骤。
与后端**并列放在同一个仓库**（任务书 2.2："前后端分离不等于两个仓库"）。

## 1. 页面

| 文件 | 做什么 | 调哪个接口 |
| :--- | :--- | :--- |
| `login.html` | 登录，成功存令牌并跳个人信息 | `POST /api/auth/login` |
| `register.html` | 注册，成功后自动登录 | `POST /api/users/register` → `POST /api/auth/login` |
| `profile.html` | 个人信息 + 当前会话有效期，可重新拉取 | `GET /api/users/me`、`GET /api/auth/verify` |
| `logout.html` | 先确认"当前是谁"，再撤销会话，显示退出后状态 | `GET /api/auth/verify` → `POST /api/auth/logout` |
| `index.html` | 跳到登录页（避免直接访问目录时看到文件列表） | — |

## 2. 怎么起

```bash
# 终端 1：后端（先建表）
python -m src.user.db init
python -m src.user.server          # http://127.0.0.1:8000

# 终端 2：前端，两种起法任选其一
python web/serve.py                # 推荐：http://127.0.0.1:8080/login.html
python -m http.server 5173 -d web  # 或：http://127.0.0.1:5173/login.html
```

浏览器打开 <http://127.0.0.1:8080/login.html>。演示顺序：注册 → 登录 → 个人信息 → 退出 → 回登录页。

`serve.py` 只监听 `127.0.0.1`，顺便把 `/api/` 转发到 `127.0.0.1:8000`；页面本身仍按
`http://127.0.0.1:8000` 直连，两种起法都能跑，因为这两个端口都在后端 CORS 白名单里。

> 直接双击 `login.html`（`file://`）不行：CSP 与 CORS 都以"同源/白名单"为前提，必须经 HTTP 打开。

换前端端口时，后端要同步放行：

```bash
AUTH_ALLOWED_ORIGINS="http://127.0.0.1:5500" python -m src.user.server
```

## 3. 三个刻意的选择

**令牌放 `sessionStorage`，不放 `localStorage`。** 关掉标签页即失效，减少"长期驻留"的暴露面。
但它**不是安全边界**——真正的边界是服务端验签与过期；前端做的任何判断都只是体验。

**不复刻安全判断。** 表单没有 `pattern`、没有"口令必须含大小写"这类前端规则，`novalidate` 直接放行。
空着提交、格式不对，都由后端返回 400 与字段级原因。这样现场演示"校验在服务端"一眼可见，
也不会出现"前端放过了、后端拒绝了"或反之的错位。

**不用 Cookie。** 令牌只走 `Authorization` 头，因此不存在"浏览器自动带凭据"，CSRF 失去前提
（详见 `docs/test/week10-11/03-CSRF.md`）。这条前提一旦改动，CSRF 必须重测。

## 4. 改动须知（三条，改之前先看）

1. **所有用户数据必须走 `BS_RENDER.renderProfile()` 或 `escapeHtml()`。** `web/js/render.js` 是
   整个前端**唯一**的转义点。新增页面不许自己拼 HTML 插值，否则 XSS 记录里的证据立刻失效。
2. **不许加内联 `<script>` 与内联 `style`。** 每个页面都带 CSP（`script-src 'self'`），内联会被浏览器拦掉，
   表现是"页面没反应"——看起来像 JS 写错了，实际是策略拦的。
3. **后端地址只在 `web/js/api.js` 的 `API_BASE` 一处。** 换端口改这一个常量，并同步后端
   `AUTH_ALLOWED_ORIGINS` 与页面 CSP 的 `connect-src`。

## 5. 出错时看到什么

| 现象 | 说明 | 怎么办 |
| :--- | :--- | :--- |
| "连不上后端服务" | 后端没起，或端口不是 8000 | 确认 `python -m src.user.server` 在跑 |
| 401 后自动回登录页 | 令牌过期或被撤销（服务端判定） | 重新登录，这是预期行为 |
| 注册返回"该登录名或手机号已被使用" | 409，正常业务冲突 | 换一个手机号/登录名 |
| 连续登录失败后一直"账号或密码错误" | 触发锁定（5 次 / 10 分钟），对外文案不变 | 换账号演示，或等 10 分钟 |
| 页面空白、控制台报 CSP | 加了内联脚本或非白名单域名 | 见 §4 第 2 条 |
