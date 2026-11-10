# 接口文档：OpenAPI 3.0 与导入说明

| 项目 | 内容 |
| :--- | :--- |
| 文件 | [`openapi.yaml`](./openapi.yaml)（OpenAPI 3.0.3，单文件，无外部 `$ref`） |
| 覆盖接口 | 注册、登录、退出、个人信息、鉴权校验（五个必做）+ `GET /api/users/{userId}`（越权验收辅助） |
| 与实现的关系 | 由 `src/user/server.py` 的路由、`validation.py` 的约束、`errors.py` 的封闭错误码逐条对齐；不是"设计稿"，是与代码同版 |
| 脱敏 | 文件中只有 `127.0.0.1` 与演示端口；示例里的手机号、登录名、令牌都是占位值，不含真实账号、密钥、证书 |

## 1. 三步导入，然后就能发请求

### 方式一：Swagger Editor（不装任何东西）

1. 浏览器打开 <https://editor.swagger.io>；
2. 菜单 **File → Import file**，选 `docs/api/openapi.yaml`；
3. 右侧 **Servers** 选 `http://127.0.0.1:8000`，先按 §2 起后端，再逐个 **Try it out**。

> 注意：`editor.swagger.io` 是 HTTPS 页面，部分浏览器会拦 HTTPS → HTTP 的请求
> （混合内容）。被拦时改用方式二，或直接用 §3 的 curl。

### 方式二：Apifox

1. 项目 → **导入数据** → **OpenAPI/Swagger** → 选本地文件 `docs/api/openapi.yaml`；
2. 导入后把环境变量 `baseUrl` 设为 `http://127.0.0.1:8000`；
3. 登录接口跑通后，把返回的 `accessToken` 填进环境的 `token` 变量，
   在「目录设置 → 认证」里选 `Bearer`，其余四个接口即可直接点通。

### 方式三：本地 Redoc 预览（只看文档，不发请求）

```bash
npx @redocly/cli preview-docs docs/api/openapi.yaml
```

## 2. 导入前先起服务（三个进程/命令）

```bash
python -m src.user.db init            # 空库建表，打印库文件路径
python -m src.user.server             # 后端 127.0.0.1:8000
python web/serve.py                   # 前端 127.0.0.1:8080（只在要演示页面时需要）
```

后端默认只接受来自 `127.0.0.1:8080` / `127.0.0.1:5173` / `localhost:5173` 的跨域请求；换端口起前端时：

```bash
AUTH_ALLOWED_ORIGINS="http://127.0.0.1:5500" python -m src.user.server
```

## 3. 五个接口的点通顺序（照这个顺序点，不会踩限流）

| 步骤 | 接口 | 要点 |
| :---: | :--- | :--- |
| 1 | `POST /api/users/register` | 手机号每次换一个；重复会 409（这是预期行为，不是失败） |
| 2 | `POST /api/auth/login` | 用步骤 1 的账号口令；响应里的 `accessToken` 复制出来 |
| 3 | `GET /api/users/me` | 在 **Authorize** 里填 `accessToken`（只填值，不填 `Bearer ` 前缀，Swagger UI 会自动加） |
| 4 | `GET /api/auth/verify` | 应返回 `valid: true` 与剩余秒数 |
| 5 | `POST /api/auth/logout` | 返回 204；再点一次步骤 3，应变成 401 —— 这就是"退出即撤销"的现场证明 |

限流：注册单 IP 10 次/小时、登录单 IP 30 次/15 分钟、单账号 10 次/15 分钟（只计失败）。
连续失败 5 次会锁 10 分钟，期间即使口令正确也返回同一个 401。反复点"错误口令"很容易触发，
现场演示时换账号即可。

## 4. 错误码与实现的一致性

`ErrorResponse.code` 的枚举就是 `src/user/errors.py` 的封闭集（14 条）。本期五个接口实际会用到的子集：

| 错误码 | HTTP | 对外文案 | 本模块会出现的接口 |
| :--- | :---: | :--- | :--- |
| `VALIDATION_ERROR` | 400 | 请求参数不合法 | 全部 |
| `PAYLOAD_TOO_LARGE` | 413 | 请求体过大 | 注册、登录 |
| `AUTH_INVALID_CREDENTIALS` | 401 | 账号或密码错误 | 登录 |
| `AUTH_UNAUTHENTICATED` | 401 | 登录状态无效，请重新登录 | 全部受保护接口 |
| `AUTH_TOKEN_EXPIRED` | 401 | 登录已过期，请重新登录 | 全部受保护接口 |
| `AUTH_FORBIDDEN` | 403 | 无权执行该操作 | 当前仅 CORS 预检拒绝时返回（角色分支留 II 阶段） |
| `RESOURCE_NOT_FOUND` | 404 | 资源不存在 | `GET /api/users/{userId}` |
| `USER_ALREADY_EXISTS` | 409 | 该登录名或手机号已被使用 | 注册 |
| `RATE_LIMITED` | 429 | 请求过于频繁，请稍后再试 | 注册、登录 |
| `INTERNAL_ERROR` | 500 | 服务暂时不可用，请稍后再试 | 全部 |

其余四个码（`ORDER_STOCK_INSUFFICIENT`、`IDEMPOTENCY_CONFLICT`、`PAY_AMOUNT_MISMATCH`、
`PAY_SIGNATURE_INVALID`）属项目 II，本期不会出现，但保留在枚举里以免 II 阶段再改契约。

**怎么核对"文档与实现一致"**：跑一遍 47 项安全测试，把每个响应实际返回的 `code` 与本文对照；
再跑 `test/test_user_flow.py` 的 75 项主流程断言（其中包含"错误码与状态码对应"的检查）。

## 5. 文件里刻意没写的东西

| 没写 | 原因 |
| :--- | :--- |
| 生产域名 / IP | 只写 `127.0.0.1`；部署地址由部署环境注入 |
| 数据库连接串 | 接口文档不需要；`AUTH_DB` 属运行配置 |
| 密钥、证书、令牌示例（真实） | 示例令牌是随机占位串，复制也无法使用 |
| 真实手机号、真实用户数据 | 示例统一用 `13800138000` 一类不可能真实收到的号段 |
