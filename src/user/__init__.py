#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户模块。

第 6-9 周只交了「输入校验与说明」这一层；第 10-11 周把它接进真实服务，
补齐了个人信息、登录态鉴权、退出即撤销，并统一了建表口径。现在的分层：

| 文件 | 作用 |
| :--- | :--- |
| `validation.py` | 入口的类型/长度/格式/禁用字段校验，与契约逐条对齐 |
| `errors.py` | 14 个封闭错误码与统一错误结构 `{code, message, traceId, details?}` |
| `logging_utils.py` | 日志脱敏、异常收敛（不记口令/派生值/盐/密钥/堆栈）、追踪编号 |
| `password_port.py` | 第 5 周 `src/crypto/加盐哈希.py` 的调用口径（只做加载与切分） |
| `password.py` | 四列拆分、口令校验、等时假校验（防账号枚举的耗时差） |
| `tokens.py` | 令牌签发（32 字节随机）、SHA-256 摘要、形状校验 |
| `auth.py` | **唯一**鉴权函数 `require_auth()`，所有受保护接口都调它 |
| `auth_service.py` | 注册/登录/退出/个人信息/鉴权校验的业务与落库 |
| `ratelimit.py` | 登录与注册的滑动窗口限流（键必须是摘要，不存明文） |
| `timeutil.py` | ISO-8601 UTC 时间口径（与 MySQL `DATETIME(3)` 同义） |
| `db.py` | SQLite 建表，列名与约束对齐 `db/schema.sql` |
| `server.py` | HTTP 路由、CORS 白名单、错误收敛、II 阶段预留路由（501） |

表结构与字段口径的唯一来源是 `docs/handover/01-用户表与身份字段冻结清单.md`；
接口契约见 `docs/api/openapi.yaml`；五类安全测试见 `docs/test/week10-11/`。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

from .errors import ApiError, ERROR_CODES, RESPONSE_KEYS, new_trace_id
from .logging_utils import get_logger, handle_unexpected, log_event, redact_text
from .validation import (
    BODY_LIMITS,
    LoginInput,
    RegisterInput,
    Secret,
    validate_login,
    validate_logout,
    validate_me,
    validate_register,
    validate_user_path,
    validate_verify,
)

__all__ = [
    "ApiError",
    "BODY_LIMITS",
    "ERROR_CODES",
    "LoginInput",
    "RESPONSE_KEYS",
    "RegisterInput",
    "Secret",
    "get_logger",
    "handle_unexpected",
    "log_event",
    "new_trace_id",
    "redact_text",
    "validate_login",
    "validate_logout",
    "validate_me",
    "validate_register",
    "validate_user_path",
    "validate_verify",
]
