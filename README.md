# [项目名称：在线书店电商系统]

## 一、 本组电商场景

本组选择**在线书店电商场景**，专注于纸质书的零售交易，主要交易对象为实体书。
主要服务对象为普通读者、学生及藏书爱好者。

## 二、 项目 I 的功能范围

项目准备完成的核心功能范围包括：

* **用户模块**：注册登录、密码加密传输、个人中心
* **商品模块**：商品详情页、商品管理
* **交易模块**：购物车、订单支付、支付信息加密、订单处理

## 三、 系统角色清单

| 角色   | 类型     | 主要职责 | 允许执行的操作     | 数据访问范围   | 禁止执行的操作   |
| ---- | ------ | ---- | ----------- | -------- | --------- |
| 买家   | 内部业务角色 | 购买书籍 | 注册、登录、下单    | 本人资料和订单  | 修改商品      |
| 商户   | 内部业务角色 | 售卖书籍 | 商品维护、发货     | 本店商品和订单  | 修改其他商户商品  |
| 管理员  | 内部业务角色 | 管理平台 | 审核、封禁、审计    | 授权范围内的数据 | 无理由查看用户密码 |
| 支付机构 | 外部系统   | 处理支付 | 接收支付请求、返回结果 | 必要的支付数据  | 直接访问业务数据库 |

## 四、 小组成员及分工

* **张桐睿（组长）**：后端开发，负责整体架构搭建。
* **方越**：后端开发，负责用户模块、数据库。
* **王陈俊**：前端开发，负责前端框架搭建、登录注册界面。
* **王鹏宇**：后端开发，负责密码加密，登录鉴权。
* **李陶然**：后端开发，负责修bug。

## 五、 架构选型结论

**综合选型结论：本项目最终选定“前后端分离架构”。**

**选型依据：**
综合网上书店场景需求，对比单体架构、前后端分离架构和服务化架构后得出：

1. **成本与周期**：开发成本低于服务化方案，契合当前3~5人小团队规模，能够在项目规定时间内完成。
2. **团队匹配度**：前后端解耦后可并行开发、并行调试（按“两人前端、其余后端”分工），利于团队协作。
3. **可维护性与扩展能力**：相比单体架构，具备更好的可维护性与多端扩展能力（同一套后端API可同时服务PC端、后续小程序/移动端）。
4. **安全边界**：认证、鉴权、数据访问全部收敛在后端API，边界清晰，前端不直连数据库。

该架构有效平衡了开发效率与系统解耦需求，满足当前业务快速迭代要求，为后续架构平滑演进奠定基础。

## 六、 仓库目录说明

```text
secure-ecommerce-team-01/
├── README.md                                 # 项目说明文档
├── docs/                                     # 项目文档目录
│   ├── feasibility/架构方案对比与选型决策.pdf    # 可行性分析与架构选型文档
│   ├── roles/系统角色清单.md                   # 系统角色清单与权限定义
│   └── meeting-notes/ 第2周团队分工表.md        # 小组会议记录与进度跟踪
├── src/                                      # 源码目录
│   ├── frontend/                             # 前端项目源码 
│   └── backend/                              # 后端项目源码 
├── test/                                     # 测试用例与自动化测试脚本
└── .gitignore                                # Git 忽略文件配置
```

## 七、 当前完成情况

已建立仓库，完成初步方案调研与分工

## 八、 第 5 周：密码学基础算法与 RSA 实现

第 5 周成果独立成模块，位于 `src/crypto/`，不接入项目业务代码（第 7 周用户管理模块开发时再集成）。

| 成果 | 文件 | 状态 |
| :--- | :--- | :--- |
| 密码学基础算法模块（源码） | [`src/crypto/bigint_ops.py`](src/crypto/bigint_ops.py) | 已完成 |
| 小位宽 RSA 实现（源码） | [`src/crypto/rsa.py`](src/crypto/rsa.py) | 已完成 |
| 加盐哈希演示 | [`src/crypto/加盐哈希.py`](src/crypto/加盐哈希.py) | 已完成 |
| 标准库交叉验证（与主实现分开存放） | [`src/crypto/verify_with_stdlib.py`](src/crypto/verify_with_stdlib.py) | 已完成 |
| 测试向量表 | [`docs/crypto/week05/测试向量表.md`](docs/crypto/week05/测试向量表.md) | 已完成 |
| 算法说明 | [`docs/crypto/week05/算法说明.md`](docs/crypto/week05/算法说明.md) | 已完成 |

`bigint_ops.py` 提供四组能力：

1. **模运算基础** —— `mod` / `mod_add` / `mod_sub` / `mod_mul`，负数返回非负代表元；
2. **快速幂（模幂）** —— `mod_pow` 采用重复平方乘，复杂度 O(log e)；
3. **最大公约数与模逆** —— `gcd` / `ext_gcd`（扩展欧几里得）/ `mod_inverse`；
4. **素性检测与素数生成** —— `is_probable_prime`（Miller-Rabin）/ `random_prime`（固定种子可复现）。

运行方式（Python 3.9+，无第三方依赖；模块含自检与性能实测，直接运行即可看到结果）：

```bash
python src/crypto/bigint_ops.py
```

`rsa.py` 实现小位宽（64 / 128 / 256 位）**教科书式 RSA**：

1. **密钥生成** —— `generate_key_pair(bit_length, rnd)`，产出 p、q、n、φ(n)、e、d 及 CRT 参数；
2. **加密 / 解密** —— `encrypt`（`c = m^e mod n`）、`decrypt`（`m = c^d mod n`）；
3. **CRT 加速** —— `decrypt_crt`，约 3 倍提速（1024 位实测 2.78×）；
4. **字符串与中文** —— `encrypt_string` / `decrypt_string`，按模数位宽分块、块首加 `0x01` 哨兵，支持任意长度与中文字符串。

运行方式（会依次输出公开向量自检、固定种子确定性向量、中文用例、边界与非法输入、
CRT 性能对比、以及"小位宽为什么不能用于生产"的分解实测）：

```bash
python src/crypto/rsa.py
```

交叉验证（第二条路径，用标准库 `pow` / `math.gcd` 独立复算，共 128 项断言）：

```bash
python src/crypto/verify_with_stdlib.py
```

> **安全提示**：本模块为教学示例代码，**仅用于课程演示，不得用于任何真实数据**。
> 源码与运行输出中均说明了它的安全边界：非常数时间实现（存在计时侧信道）、
> 随机源非密码学安全、小位宽模数可被分解、未含填充不能直接加密数据。
> RSA 部分详细的原理、复杂度、性能与安全边界见
> [`docs/crypto/week05/算法说明.md`](docs/crypto/week05/算法说明.md)，
> 输入 → 期望输出用例见 [`docs/crypto/week05/测试向量表.md`](docs/crypto/week05/测试向量表.md)。

## 九、 第 6-9 周：安全设计与接口契约

第 6-9 周阶段一的「安全设计与接口契约」成果位于 `docs/design/`。威胁清单、攻击树与整改清单由组内另一成员负责，存放于 [`docs/threat-model/`](docs/threat-model/)，两者共同构成阶段一交付。威胁清单沿用本设计的 `T-<STRIDE>-<序号>` 编号，两套编号一一对应。

| 交付物 | 文件 | 状态 |
| :--- | :--- | :--- |
| 数据流与信任边界（注册 / 登录 / 下单三条流程） | [`docs/design/01-数据流与信任边界.md`](docs/design/01-数据流与信任边界.md) | 已完成 |
| 安全需求 SR-01～SR-20（每条含「怎样算通过」与源威胁编号） | [`docs/design/02-安全需求.md`](docs/design/02-安全需求.md) | 已完成 |
| 核心接口契约（7 个接口 × 输入约束 / 输出 / 错误码 / 鉴权） | [`docs/design/03-接口契约.md`](docs/design/03-接口契约.md) | 已完成 |
| 控制指认与整改输入（R-D-01～R-D-13） | [`docs/design/04-控制指认与整改输入.md`](docs/design/04-控制指认与整改输入.md) | 已完成 |

覆盖范围：3 类资产（用户凭证、会话令牌、订单与支付）、3 条流程、7 个核心接口、31 条威胁清单中与本设计建立对应关系的 22 条、20 条安全需求、14 个封闭错误码、13 条整改条目、5 条待裁决冲突。

契约自检脚本把「四要素齐全」「威胁全覆盖」「编号可追溯」变成可执行检查（Python 3.9+，无第三方依赖）：

```bash
python test/check_design_docs.py
```

> **边界声明**：`docs/design/` 声明的控制均为**设计规定**。`src/backend/`、`src/user/`、`db/` 尚未实现，因此除 `src/crypto/加盐哈希.py` 的口令派生算法外，没有控制已在代码中落地。凡声明「已做控制」的，均可在 [`04-控制指认与整改输入.md`](docs/design/04-控制指认与整改输入.md) §2 指到文件与位置；未落地的一律登记为 `R-D-xx` 整改条目。口令派生复用第 5 周 `src/crypto/加盐哈希.py`，不另写算法。
>
> `docs/design/02-安全需求.md` §2 登记**被安全需求引用**的 22 条威胁，用于让每条 SR 能指到威胁编号；§7 另列出威胁清单中未被 SR 覆盖的 9 条及其处置去向。完整的 STRIDE 清单与 DREAD 打分以 [`docs/threat-model/threat-list.md`](docs/threat-model/threat-list.md) 为准。

## 十、 第 6-9 周阶段二：用户模块——输入校验与说明

阶段二按交付项拆给不同成员。本节记录**「输入校验与说明」**这一条的成果，位于 `src/user/`；
建库脚本（`db/`）、注册登录业务与令牌签发由组内其他成员负责，本层只提供它们调用的校验与错误出口。

| 交付物 | 文件 | 状态 |
| :--- | :--- | :--- |
| 入口参数校验（注册 / 登录 / 退出 / 本人信息：类型、长度、格式、禁用字段） | [`src/user/validation.py`](src/user/validation.py) | 已完成 |
| 封闭错误码与统一错误结构 `{code, message, traceId, details?}` | [`src/user/errors.py`](src/user/errors.py) | 已完成 |
| 日志脱敏与异常收敛（不记口令、派生值、盐、密钥、堆栈） | [`src/user/logging_utils.py`](src/user/logging_utils.py) | 已完成 |
| 第 5 周密码学模块的调用口径（`hash_password` / `verify_password` / 四列拆分） | [`src/user/password_port.py`](src/user/password_port.py) | 已完成 |
| 说明：每个入口校验什么、调用第 5 周哪个函数、已知局限、复现步骤 | [`src/user/输入校验与说明.md`](src/user/输入校验与说明.md) | 已完成 |
| 可执行验收脚本（169 项检查） | [`test/test_input_validation.py`](test/test_input_validation.py) | 已完成 |

校验规则与 [`docs/design/03-接口契约.md`](docs/design/03-接口契约.md) §4.1—§4.4 逐条对齐：
用户名 `^[A-Za-z0-9_]{4,32}$`、手机号 `^1[3-9]\d{9}$`（去空格与连字符）、口令 8—64 字符且
UTF-8 ≤ 256 字节、请求体 4 KB / 2 KB 上限、`additionalProperties: false`、
`details` 只回字段名与 8 个原因枚举且不回显原值。

运行方式（Python 3.9+，无第三方依赖）：

```bash
python test/test_input_validation.py
```

```text
共 169 项，通过 169 项，未通过 0 项。
结果：输入校验、错误与日志脱敏、第 5 周密码学调用口径全部通过。
```

> **边界**：本层只判"请求是否合法"，不判"账号是否存在、令牌是否有效"；限流与锁定、
> 数据库唯一约束、鉴权中间件均不在本层（对应整改条目 R-D-01、R-D-06、R-D-03）。
> 已知局限 12 条见 [`src/user/输入校验与说明.md`](src/user/输入校验与说明.md) §6。

## 十一、第 10-11 周：用户模块可演示原型与 II 阶段交接

第 9 周交的注册与登录是这两周的地基。本周只做一件事：把用户模块做成**能现场演示的原型**
（浏览器里走完注册、登录、个人信息、退出），并把项目 II 接手要用的材料备齐。
商品、购物车、下单、支付、证书认证属项目 II，本期**只留契约、不实现**。

### 11.1 交付物

| 交付项 | 在哪 | 状态 |
| :--- | :--- | :--- |
| 用户模块补齐（个人信息、登录态鉴权、退出即撤销，令牌校验收敛成一个函数） | [`src/user/`](src/user/)：`auth.py`、`auth_service.py`、`server.py` | 已完成 |
| 前端界面（注册、登录、个人信息、退出四个页面） | [`web/`](web/)，说明见 [`web/README.md`](web/README.md) | 已完成 |
| 安全测试记录（注入、XSS、CSRF、会话劫持、越权） | [`docs/test/week10-11/`](docs/test/week10-11/) | 已完成，47 项全过 |
| 接口文档（OpenAPI 3.0，五个接口） | [`docs/api/openapi.yaml`](docs/api/openapi.yaml)，导入说明见 [`docs/api/README.md`](docs/api/README.md) | 已完成 |
| 项目 II 交接契约（用户表冻结、订单主键、商品与支付接口预留） | [`docs/handover/`](docs/handover/) | 已完成 |
| 主流程验收脚本（75 项） | [`test/test_user_flow.py`](test/test_user_flow.py) | 已完成 |

### 11.2 怎么建库、怎么起、怎么试

**建库（空库一条命令）**

```bash
python -m src.user.db init          # 建表，打印库文件路径（默认 var/auth.db）
python -m src.user.db init --drop   # 本地重置（删表重建）
```

库文件默认落在 `var/auth.db`，`var/` 已在 `.gitignore`——**运行时生成的库不进仓库**。
换路径用环境变量 `AUTH_DB=/tmp/demo.db`。

**起后端**

```bash
python -m src.user.server           # http://127.0.0.1:8000
```

启动时会打印库路径、CORS 白名单、限流是否开启。`GET /health` 可探活。

**起前端**（前后端分离，两个进程，两种起法任选其一）

```bash
python web/serve.py                 # 推荐：http://127.0.0.1:8080/login.html
python -m http.server 5173 -d web   # 或：http://127.0.0.1:5173/login.html
```

两种都在 CORS 白名单里（`127.0.0.1:8080`、`127.0.0.1:5173`、`localhost:5173`），不用改配置。
`web/serve.py` 只监听 `127.0.0.1`，并把 `/api/` 转发到 `127.0.0.1:8000`——加这层转发是为了让浏览器
只看到一个来源；页面里仍按 `http://127.0.0.1:8000` 直连，两条路都通。

换到白名单外的端口时要同步放行：`AUTH_ALLOWED_ORIGINS="http://127.0.0.1:5500" python -m src.user.server`。

**不要直接双击 html 文件打开**：`file://` 下拿不到 `/api`，页面只会提示连不上服务端。

**怎么试**

```bash
python test/test_user_flow.py                    # 主流程 75 项：建表→注册→登录→鉴权→退出→越权→锁定→限流
python test/test_input_validation.py             # 第 9 周输入校验 169 项（未改动，全过）
python test/security/week10-11_security_tests.py # 五类安全测试 47 项，输出即 docs 里的表格
node test/security/xss_render_check.js           # XSS"页面源码为实体"8 项（用页面同一份转义函数）
```

浏览器里：注册 →（自动登录）→ 个人信息 → 退出登录 → 确认退出 → 回登录页。
中途不需要手工插数据、不需要改配置。

### 11.2.1 前端三条口径

- **令牌放 `sessionStorage`、只走 `Authorization` 请求头、不用 Cookie。** 请求头不会随表单或链接
  自动携带，CSRF 在本场景由设计规避；不用 `localStorage` 是因为关掉标签页即失效，长期驻留风险更小。
  这只是降低风险，不是安全边界——边界在服务端的验签与过期。
- **页面不判权限。** 个人信息页能不能看，由服务端返回 200 还是 401 决定；前端没有"是不是管理员"
  "该不该显示按钮"之类的判断，也没有靠隐藏入口实现鉴权。两次口令一致性之类的检查只算体验。
- **所有来自服务端的文本先转义再写入页面。** 全站唯一转义点是
  [`web/js/render.js`](web/js/render.js) 的 `escapeHtml()`（`& < > " '` 五个字符实体化），
  各页面只调它、不各写一份。选择显式转义而不是 `textContent`，是因为验收要求"XSS 处置要在页面
  源码里看得见"——`textContent` 不产生可截图的证据。兜底是响应头 CSP `script-src 'self'`。

> `web/` 在本周被两名成员并行写过：合并时以本分支的四个页面与 `web/js/` 为准（它们有端到端走查与
> XSS 证据），`web/serve.py` 取自另一版；被取代的 `web/assets/api.js`、`web/assets/style.css`
> 已删除，避免仓库里留两套前端。

### 11.3 接口一览

| 方法与路径 | 说明 | 鉴权 |
| :--- | :--- | :--- |
| `POST /api/users/register` | 注册（`username` / `phone` / `password` / 可选 `nickname`） | 公开 + 限流 |
| `POST /api/auth/login` | 登录，返回 `accessToken`（2 小时） | 公开 + 限流 |
| `POST /api/auth/logout` | 退出，服务端撤销当前会话，幂等返回 204 | Bearer |
| `GET /api/users/me` | 个人信息，身份只从令牌解析 | Bearer |
| `GET /api/auth/verify` | 鉴权校验，返回剩余有效期 | Bearer |
| `GET /api/users/{userId}` | 越权验收辅助接口：非本人一律 404 | Bearer |
| 其余 9 条（商品/购物车/下单/订单/支付/证书） | 路由已存在，返回 `501 NOT_IMPLEMENTED`，不返回假数据 | — |

鉴权只有一个出口：`src/user/auth.py` 的 `require_auth()`，所有受保护路由的第一行都是它。

### 11.4 安全测试结论（摘要）

| 类别 | 项数 | 结果 | 一句话 |
| :--- | :---: | :---: | :--- |
| SQL 注入 | 15 | 全过 | 白名单 + 参数化；12 个响应体里表名/SQL/栈命中 0 |
| XSS | 8 | 全过 | 原文入库、实体输出；标签/属性/SVG 三类载荷均转义，页面无内联脚本 + CSP 兜底 |
| CSRF | 5 | 全过 | **由设计规避**：无 Cookie、令牌只在自定义头、CORS 白名单 |
| 会话劫持 | 9 | 全过 | 改一字节 / 拼身份 / 退出重放 三枪全拒；库里只存摘要 |
| 越权 | 10 | 全过 | 越权 404 且与"不存在"同形；身份字段一律 400 |

三处判定按任务书口径写死：有效的记"通过"，靠架构消除前提的记"**由设计规避**"（附前提与失效条件），
需求文档没提的记"**未登记**"。CSRF 属于第三种——威胁清单 31 条与 SR 20 条里都没有它，
已在 [`docs/test/week10-11/03-CSRF.md`](docs/test/week10-11/03-CSRF.md) §3 给出补登记建议
（`T-SP-07` / `SR-21`）交 II 阶段。

### 11.5 给项目 II 的交接

| 文件 | 冻结了什么 |
| :--- | :--- |
| [`01-用户表与身份字段冻结清单.md`](docs/handover/01-用户表与身份字段冻结清单.md) | 用户表 15 列、7 项身份字段、会话与登录审计两张表、6 条变更记录、已知局限 |
| [`02-订单主键定义.md`](docs/handover/02-订单主键定义.md) | `order_id`（自增主键）+ `order_no`（20 字符对外编号）的名称、类型、生成规则、DDL |
| [`03-商品与支付接口预留.md`](docs/handover/03-商品与支付接口预留.md) | 9 条预留路由的签名、返回、错误码、禁用字段、事务要求 |

规则一句话：**只能加字段，不能改名、改类型、改含义**。要改就写变更记录并同步三处
（`db/schema.sql`、`src/user/db.py`、`openapi.yaml`），否则 II 会接手两份不一样的表。

### 11.6 本周边界与已知局限

- 不实现商品、购物车、下单、支付、证书认证；不接第三方登录、不做短信真实下发。这五类字段
  **没有**提前塞进用户表（`03` §4 列了原因）。
- `phone_hash` 是无密钥 SHA-256：只防明文落库，不防枚举反推；II 阶段换 HMAC 或加密列。
- 限流计数在进程内存：多实例部署会各算各的，需要换共享存储。
- 角色表（`app_role` / `user_role_relation`）本期不建，角色固定为 `buyer`；"角色不允许 → 403"
  这条分支要等 II 阶段接角色表才能验收。
- CSRF 的规避依赖"不用 Cookie"，一旦引入 Cookie 会话必须重测。

### 11.7 目录（本周新增部分）

```text
src/user/
├── auth.py            # 唯一鉴权函数 require_auth()
├── auth_service.py    # 注册/登录/退出/个人信息/鉴权校验的业务与落库
├── ratelimit.py       # 登录与注册的滑动窗口限流
├── tokens.py          # 令牌签发、摘要、形状校验
├── timeutil.py        # ISO-8601 UTC 时间口径
├── db.py              # SQLite 建表（口径对齐 db/schema.sql）
└── validation.py      # 入口校验（第 9 周交付，本周接进服务）
web/                   # 四个页面 + 共享 JS/CSS（见 web/README.md）
docs/test/week10-11/   # 五类安全测试记录
docs/api/              # OpenAPI 3.0 与导入说明
docs/handover/         # II 阶段交接契约
test/test_user_flow.py # 主流程验收 75 项
test/security/         # 安全测试脚本与夹具
```
