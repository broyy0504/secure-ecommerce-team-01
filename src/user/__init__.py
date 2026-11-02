#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户模块（第 6-9 周阶段二）。

本包当前只包含「输入校验与说明」这一条交付线：

| 文件 | 作用 |
| :--- | :--- |
| `validation.py` | 四个入口的类型、长度、格式校验，以及与契约对齐的请求体结构检查 |
| `errors.py` | 14 个封闭错误码与统一错误结构 `{code, message, traceId, details?}` |
| `logging_utils.py` | 日志脱敏、异常收敛（不记口令/派生值/盐/密钥/堆栈）、追踪编号 |
| `password_port.py` | 第 5 周 `src/crypto/加盐哈希.py` 的调用口径（只做加载与切分） |
| `输入校验与说明.md` | 说明：每个入口校验什么、调用第 5 周哪个函数、已知局限 |

**不在本包内**：建库脚本（`db/schema.sql`）、注册/登录业务与令牌签发、
数据访问层——由组内其他成员负责，本包只提供它们要调用的校验与错误出口。

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
]
