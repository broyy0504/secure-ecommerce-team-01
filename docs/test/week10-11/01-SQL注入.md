# 安全测试记录 · 一：SQL 注入

| 项目 | 内容 |
| :--- | :--- |
| 测试编号 | SEC-W10-01 |
| 测试日期 | 2026-11-10 |
| 被测对象 | 用户模块后端 `src/user/`（标签 `week10-11-submission` 对应提交） |
| 测试环境 | Windows 11 · Python 3.13.14 · SQLite 3（`var/auth.db`）· 单进程 127.0.0.1，前后端分离起法 |
| 测试工具 | `test/security/week10-11_security_tests.py`（真实 HTTP，不 mock） |
| 回指威胁 | T-TM-05（入口参数注入改写 `user_account`）、T-ID-05（报错回显库结构） |
| 回指需求 | SR-19（错误响应只含封闭集，不出现表名/SQL/栈）；注入本身的控制见 R-D-02（参数化查询） |

## 1. 要证明什么

任务书对这一项的要求是："测参数化有没有生效，不是报错文案好不好看"。

所以判定标准不是"页面有没有报错"，而是三条：

1. 攻击串**没有改变数据库状态**（没有多读出全表、没有删掉表、没有多出一个账号）；
2. 攻击串**没有进入 SQL 拼接**——任何一个响应体里都找不到表名、SQL 关键字、异常类型、调用栈；
3. 拦下它的应当是**白名单/类型校验**或**参数化查询**，而不是"恰好没报错"。

## 2. 控制点在哪

| 控制 | 位置 | 说明 |
| :--- | :--- | :--- |
| 登录名/手机号白名单 | `src/user/validation.py` `USERNAME_RE`、`PHONE_RE` | 引号、分号、空格、`--`、`%` 一律 `400 VALIDATION_ERROR`，根本到不了 SQL |
| 参数化查询 | `src/user/auth_service.py`、`src/user/auth.py` | 所有语句都是 `?` 占位；没有任何 f-string / `%` / `+` 拼进 SQL |
| 精确匹配而非 LIKE | `auth_service.py` `WHERE username = ?` | `_` 与 `%` 不具通配语义（I-06 就是这条的对照测试） |
| 路径参数只收数字 | `validation.py` `validate_user_path` | `1 OR 1=1` 直接 400，不落到查询 |
| 错误出口封闭 | `errors.py`、`server.py` `_handle_exception` | 未预期异常只回 `INTERNAL_ERROR` + `traceId`，不记栈、不回显异常消息 |

## 3. 测试结果

> 表由脚本真打出来后贴入，未手工修改"实际"列。复现命令：
> `python test/security/week10-11_security_tests.py`

| 编号 | 入口 | 攻击串 | 预期 | 实际 | 判定 | 威胁 | 需求 |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| I-01 | POST /api/auth/login（account） | `' OR '1'='1` | 登录名含引号与空格，白名单应拦下 → 400 VALIDATION_ERROR | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-02 | POST /api/auth/login（account） | `admin'--` | 注释符截断，应拦下 → 400 VALIDATION_ERROR | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-03 | POST /api/auth/login（account） | `' OR 1=1 --` | 永真条件，应拦下 → 400 VALIDATION_ERROR | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-04 | POST /api/auth/login（account） | `reader_01' --` | 已知账号 + 注释符，应拦下 → 400 VALIDATION_ERROR | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-05 | POST /api/auth/login（account） | `%` | LIKE 通配符（单字符，长度不足）→ 400 | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-06 | POST /api/auth/login（account） | `____` | LIKE 下划线通配符（4 个 `_`，恰与已存在的 4 字符账号 `abcd` 同形）→ 401 | 401 AUTH_INVALID_CREDENTIALS | 通过 | T-TM-05 | SR-19 |
| I-07 | POST /api/auth/login（account） | `1;DROP TABLE user_account;--` | 堆叠语句，应拦下 → 400 | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-08 | POST /api/auth/login（account） | `reader_01\x00`（末尾 NUL） | NUL 截断 → 400 | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-09 | POST /api/auth/login（password） | `' OR '1'='1` | 长度合法，**能走到口令派生比较那一步** → 401 | 401 AUTH_INVALID_CREDENTIALS | 通过 | T-TM-05 | SR-19 |
| I-10 | POST /api/users/register（username） | `' OR 1=1 --` | 400，且不落库 | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-11 | POST /api/users/register（nickname） | `'; DROP TABLE user_account;--` | 201；原文入库；`user_account` 表仍存在 | 201；库里为原文；表存在 | 通过 | T-TM-05 | SR-19 |
| I-12 | GET /api/users/{userId} | `1 OR 1=1` | 400（1—19 位数字） | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-13 | GET /api/users/{userId} | `1'` | 400（1—19 位数字） | 400 VALIDATION_ERROR | 通过 | T-TM-05 | SR-19 |
| I-14 | 以上 12 个响应体 | — | 不含表名、SQL 关键字、异常类型、栈 | 命中 0 | 通过 | T-ID-05 | SR-19 |
| I-15 | 直接查库 | — | 账号数 = 3（未被注入删除或读出） | users=3 | 通过 | T-TM-05 | SR-19 |

## 4. 三条值得在演示时讲的

**I-06 是这一组里最有说服力的一条。** 库里注册了 `abcd`，登录名传 `____`。如果查询写成
`WHERE username LIKE ?`，`____` 会命中 `abcd` 并进入口令比较；实际返回的是
`401 AUTH_INVALID_CREDENTIALS`，说明走的是等值匹配，`_` 没有通配语义。

**I-09 证明的不是"拦住了"，而是"拦不住也没事"。** 口令位置允许任意字符（`' OR '1'='1` 能通过长度
校验），它真的进入了口令派生与常数时间比较环节，最后仍然 401——因为口令从来不是拼进 SQL 的，
而是当作 PBKDF2 的输入。

**I-11 是最容易被误判的一条。** 昵称允许任意字符（XSS 的处置是"原文入库、输出转义"），
所以 `'; DROP TABLE user_account;--` 会被**成功存进库里**，注册接口还会把它回显在响应里。
表没被删，是因为整串走的是 `?` 占位参数，而不是语句片段。也正因为响应回显了这个昵称，
I-14 的"响应体泄露统计"把它排除在外——否则会把"业务回显"误算成"泄露表名"。

## 5. 结论与遗留

- 结论：注入类攻击**全部被拒绝或无效**，库状态未变，响应体未泄露库结构；参数化查询与白名单生效。
- 遗留：`app_role` / `user_role_relation` 两张表本期未落 SQLite，涉及角色的查询在 II 阶段接入时
  必须沿用同样的占位参数写法；这一点写进 `docs/handover/01-用户表与身份字段冻结清单.md` §6。
