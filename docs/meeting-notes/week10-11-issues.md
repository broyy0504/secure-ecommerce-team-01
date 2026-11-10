# 第 10-11 周 Issue 拆分（8+2 条）

| 项目 | 内容 |
| :--- | :--- |
| 用途 | 任务书 §五要求"至少 6 个 Issue，按交付项拆，每名成员至少负责一个，条条有 assignee；挂在 Issue 上的提交要能对上" |
| 状态 | 本文件是**待创建清单**（标题、正文、assignee、标签、对应提交都已写好）。仓库里没有 GitHub 凭据，创建动作需在网页或带 token 的环境执行 |
| 拆分依据 | 五个交付项 + 一条回归 + 一条文档，每项可独立验收 |

> 创建方式：GitHub → Issues → New issue，标题直接复制下表"标题"列，正文复制对应小节。
> 创建后把 Issue 编号填进 §3 的映射表，并在对应提交说明里补 `refs #<编号>`。

## 1. 总览

| # | 标题 | Assignee | 标签 | 交付项 |
| :---: | :--- | :--- | :--- | :--- |
| 1 | 用户模块：令牌校验收敛为单一函数，覆盖全部受保护接口 | 王鹏宇 | `backend` `security` | 用户模块补齐 |
| 2 | 用户模块：个人信息查询与越权返回 404 | 王鹏宇 | `backend` `security` | 用户模块补齐 |
| 3 | 用户模块：退出即撤销，多设备会话并存 | 王鹏宇 | `backend` `security` | 用户模块补齐 |
| 4 | 用户模块：登录失败计数、锁定与限流 | 王鹏宇 | `backend` `security` | 用户模块补齐 |
| 5 | 前端：注册/登录/个人信息/退出四页面与错误提示 | 王陈俊 | `frontend` | 前端界面 |
| 6 | 安全测试记录：五类测试与实测表格 | 王鹏宇 | `security` `docs` | 安全测试记录 |
| 7 | 接口文档：OpenAPI 3.0 五接口与导入说明 | 方越 | `docs` | 接口文档 |
| 8 | 交接契约：用户表冻结、订单主键、商品与支付接口预留 | 张桐睿 | `docs` `handover` | 项目 II 交接契约 |
| 9 | 回归：169 + 75 + 47 + 8 四项脚本全绿，边界用例补齐 | 李陶然 | `test` | 质量要求 |
| 10 | README 第 10-11 周章节与 `week10-11-submission` 标签 | 王鹏宇 | `docs` | 提交与验收 |

> 覆盖检查：王鹏宇 1/2/3/4/6/10、王陈俊 5、方越 7、张桐睿 8、李陶然 9 —— 每名成员至少一条。

## 2. 正文（逐条复制）

### Issue 1 · 用户模块：令牌校验收敛为单一函数，覆盖全部受保护接口

**背景**：第 9 周的 `server.py` 在每个 handler 里各写一遍 `Authorization` 解析，四处重复，
新增接口时容易漏。

**要做**
- 新增 `src/user/auth.py`，提供唯一的 `require_auth(headers, trace_id, allow_revoked=False)`；
- 所有受保护路由（`/api/auth/logout`、`/api/users/me`、`/api/auth/verify`、`/api/users/{userId}`）
  第一行调用它，删除其它解析 `Authorization` 的代码；
- 401 的三种情形（没带、形状不对、查不到）对外同形；过期单列 `AUTH_TOKEN_EXPIRED`。

**验收**：`grep -c "Authorization" src/user/*.py` 只在 `auth.py` 与测试里出现；
`python test/test_user_flow.py` 第 5 组全过。

**对应提交**：`feat(user): 抽出唯一鉴权函数 require_auth`

---

### Issue 2 · 用户模块：个人信息查询与越权返回 404

**背景**：契约 §4.4 只定义了 `/api/users/me`，接口不接收用户标识，导致"越权返回 404"没有可测入口。

**要做**
- `GET /api/users/me` 返回 `{userId, username, nickname, phoneMasked, emailMasked, status, lastLoginAt, createdAt}`；
- 新增辅助接口 `GET /api/users/{userId}`：等于本人返回同一结构，否则 `404 RESOURCE_NOT_FOUND`，
  与"编号不存在"除 `traceId` 外逐字一致；
- 越权尝试写 `authz_denied` 审计。

**验收**：`test/security/week10-11_security_tests.py` 的 A-01～A-03 通过。

**对应提交**：`feat(user): 个人信息查询与越权 404`

---

### Issue 3 · 用户模块：退出即撤销，多设备会话并存

**要做**
- 退出写 `session_token.revoked_at`、`revoke_reason='logout'`，只撤销当前令牌对应会话；
- 幂等：同一令牌再退一次仍 204；已撤销令牌调退出不返回 401；
- 退出后原令牌访问任何受保护接口一律 401。

**验收**：`test/test_user_flow.py` 第 6 组（退出 204 / 旧令牌 401 / 再退 204 / 其它会话仍有效）。

**对应提交**：`feat(user): 退出即撤销与幂等`

---

### Issue 4 · 用户模块：登录失败计数、锁定与限流

**要做**
- 连续失败 5 次锁 10 分钟（`failed_login_count`、`locked_until`），锁定期间正确口令也返回同一个 401；
- 账号不存在时跑一次等时假校验（PBKDF2），避免耗时差枚举账号；
- 限流：登录单 IP 30/15min、单账号 10/15min（只计失败），注册单 IP 10/h；键必须是摘要。

**验收**：`test/test_user_flow.py` 第 8、9 组；`login_log` 里能查到 `ACCOUNT_LOCKED`。

**对应提交**：`feat(user): 失败计数、锁定与限流`

---

### Issue 5 · 前端：注册/登录/个人信息/退出四页面与错误提示

**要做**
- `web/` 四个页面 + `index.html` 跳转；令牌放 `sessionStorage`，只在 `Authorization` 头里发；
- 所有服务端数据经 `web/js/render.js` 的 `escapeHtml` 后进 DOM（唯一转义点）；
- 错误码翻译成人话（含字段与原因），页面不复刻任何安全判断；
- 每页带 CSP，且无内联脚本。

**验收**：浏览器走完注册→登录→个人信息→退出；`node test/security/xss_render_check.js` 8 项通过；
`test/security/week10-11_security_tests.py` 的 X-08（CSP 5/5、内联 0）通过。

**对应提交**：`feat(web): 四页面与统一转义`

---

### Issue 6 · 安全测试记录：五类测试与实测表格

**要做**
- `test/security/week10-11_security_tests.py`：五类共 47 项，真实 HTTP + 真实 SQLite；
- `docs/test/week10-11/`：每类一份，三列（攻击串/预期/实际）+ 威胁编号 + 需求编号；
- CSRF 如实记"由设计规避"并给出补登记建议（`T-SP-07` / `SR-21`）。

**验收**：脚本退出码 0；文档里每行都能回指编号。

**对应提交**：`test(security): 五类安全测试与记录`

---

### Issue 7 · 接口文档：OpenAPI 3.0 五接口与导入说明

**要做**
- `docs/api/openapi.yaml`（3.0.3）覆盖注册、登录、退出、个人信息、鉴权校验；
  每个接口写全输入约束、输出、错误码、鉴权；
- `docs/api/README.md`：Swagger Editor / Apifox 导入步骤 + 点通顺序 + 限流注意；
- 不写真实地址、密钥、账号。

**验收**：导入后五个接口都能发出请求；错误码与 `src/user/errors.py` 一致。

**对应提交**：`docs(api): OpenAPI 3.0 与导入说明`

---

### Issue 8 · 交接契约：用户表冻结、订单主键、商品与支付接口预留

**要做**
- `docs/handover/01`：用户表 15 列 + 7 项身份字段 + 会话/审计表 + 变更记录 + 已知局限；
- `docs/handover/02`：`order_id`（自增）与 `order_no`（20 字符）的名称、类型、生成规则、DDL；
- `docs/handover/03`：9 条预留路由签名，返回 501、不返回假数据；
- 明确"只能加字段，不能改名改类型"。

**验收**：别人只读这三份文件能写出订单表 DDL 与下单接口签名。

**对应提交**：`docs(handover): 冻结用户表与订单主键`

---

### Issue 9 · 回归：四项脚本全绿，边界用例补齐

**要做**
- 跑通 `test/test_input_validation.py`（169）、`test/test_user_flow.py`（75）、
  `test/security/week10-11_security_tests.py`（47）、`node test/security/xss_render_check.js`（8）；
- 修第 9 周遗留：`password_port` 调用了不存在的函数导致 169 项脚本 `AttributeError`（修正调用口径，
  **脚本本身不改**）；
- 补边界：空体、超大体积、重复 JSON 键、禁用字段、令牌形状、路径参数格式。

**验收**：四份输出均为"未通过 0 项"。

**对应提交**：`fix(user): 修正常量调用口径，四项脚本全绿`

---

### Issue 10 · README 第 10-11 周章节与标签

**要做**
- README 增"第 10-11 周"一节：怎么建库、起后端、起前端、怎么试、接口一览、测试摘要、交接索引；
- `.gitignore` 排除运行时库（`var/`、`auth.db`），把已入库的 `auth.db` 移出版本控制；
- 打标签 `week10-11-submission`（验收以该标签版本为准）。

**验收**：空库一条命令建表 → 起服务 → 浏览器走完主流程；标签指向的提交能复现。

**对应提交**：`docs: README 第 10-11 周章节与运行时库清理`

## 3. 提交 ↔ Issue 映射（创建后补编号）

| 提交（前缀） | Issue |
| :--- | :---: |
| `fix(user): 修正常量调用口径，四项脚本全绿` | #9 |
| `feat(user): 抽出唯一鉴权函数 require_auth` | #1 |
| `feat(user): 个人信息查询与越权 404` | #2 |
| `feat(user): 退出即撤销与幂等` | #3 |
| `feat(user): 失败计数、锁定与限流` | #4 |
| `feat(web): 四页面与统一转义` | #5 |
| `test(security): 五类安全测试与记录` | #6 |
| `docs(api): OpenAPI 3.0 与导入说明` | #7 |
| `docs(handover): 冻结用户表与订单主键` | #8 |
| `docs: README 第 10-11 周章节与运行时库清理` | #10 |

> 实际提交为一次合并提交（见 `git log`），Issue 里用 `refs #<编号>` 指回本文件即可；
> 若需"一条提交对一条 Issue"，按上表拆分提交即可，代码已按此分块。
