#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户模块的统一错误结构与封闭错误码。

对齐 `docs/design/03-接口契约.md` §2：

1. 对外只允许出现本文件登记的错误码，状态码与文案逐字固定，不得按场景改写；
2. 响应体最多四个字段 `code` / `message` / `traceId` / `details`；
3. `details` 的 `field` 只能是请求字段名（且在白名单内），`reason` 只能取 8 个枚举值；
4. 任何异常都不得把异常消息、SQL、表名、堆栈带进响应。

本文件只负责"能对用户说什么"，不负责判断对错；判断在 `validation.py`。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import re
import secrets
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# 封闭错误码集（14 条，与 DES-03 §2 逐行一致）
# ---------------------------------------------------------------------------

ERROR_CODES: Dict[str, Tuple[int, str]] = {
    "VALIDATION_ERROR": (400, "请求参数不合法"),
    "PAYLOAD_TOO_LARGE": (413, "请求体过大"),
    "AUTH_INVALID_CREDENTIALS": (401, "账号或密码错误"),
    "AUTH_UNAUTHENTICATED": (401, "登录状态无效，请重新登录"),
    "AUTH_TOKEN_EXPIRED": (401, "登录已过期，请重新登录"),
    "AUTH_FORBIDDEN": (403, "无权执行该操作"),
    "RESOURCE_NOT_FOUND": (404, "资源不存在"),
    "USER_ALREADY_EXISTS": (409, "该登录名或手机号已被使用"),
    "ORDER_STOCK_INSUFFICIENT": (409, "所选图书库存不足"),
    "IDEMPOTENCY_CONFLICT": (409, "重复提交内容不一致"),
    "PAY_AMOUNT_MISMATCH": (409, "支付金额与订单不一致"),
    "PAY_SIGNATURE_INVALID": (401, "支付回调验签失败"),
    "RATE_LIMITED": (429, "请求过于频繁，请稍后再试"),
    "INTERNAL_ERROR": (500, "服务暂时不可用，请稍后再试"),
}

# `details.reason` 的封闭枚举，多一个都会被契约判为不合规
REASONS = frozenset(
    {
        "REQUIRED",
        "TYPE_MISMATCH",
        "TOO_SHORT",
        "TOO_LONG",
        "FORMAT_INVALID",
        "OUT_OF_RANGE",
        "NOT_ALLOWED",
        "DUPLICATE",
    }
)

# `details.field` 的字符形状限制：只允许 ASCII 标识符。
# 限制形状是为了防止把攻击者构造的任意串（含引号、换行、中文、SQL 片段）
# 原样回显到响应与前端页面里。
FIELD_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")

# 响应体允许出现的键，多一个都不行
RESPONSE_KEYS = ("code", "message", "traceId", "details")


def new_trace_id() -> str:
    """生成追踪编号（16 位十六进制），与审计日志共用同一个值。"""
    return secrets.token_hex(8)


def _check_detail(detail: Mapping[str, str]) -> Dict[str, str]:
    """校验并规范化一条 detail：字段名合法、原因在枚举内、只保留两个键。"""
    if set(detail) != {"field", "reason"}:
        raise ValueError("detail 只允许 field 与 reason 两个键")

    field = detail["field"]
    reason = detail["reason"]

    if not isinstance(field, str) or not FIELD_NAME_RE.match(field):
        raise ValueError(f"detail.field 不是合法标识符: {field!r}")
    if reason not in REASONS:
        raise ValueError(f"detail.reason 不在封闭枚举内: {reason!r}")

    return {"field": field, "reason": reason}


class ApiError(Exception):
    """带封闭错误码的业务异常。

    刻意只承载"对外可说的话"（错误码 + 字段级原因）。原始输入值、异常消息、
    内部对象一律不挂在这个异常上——异常会出现在最不该出现的地方（日志、
    调试面板、错误上报），少挂一样就少一处泄露面。
    """

    def __init__(
        self,
        code: str,
        details: Optional[Iterable[Mapping[str, str]]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        if code not in ERROR_CODES:
            # 拼错错误码属于编码错误，不是业务错误：直接抛，不让它变成对外响应
            raise ValueError(f"未登记的错误码: {code!r}")

        self.code = code
        self.status, self.message = ERROR_CODES[code]
        # 与写入日志的编号保持一致，响应与日志才能对上（SR-19 验收要求）
        self.trace_id: Optional[str] = trace_id
        self.details: Tuple[Dict[str, str], ...] = tuple(
            _check_detail(d) for d in (details or ())
        )
        # 异常自身的 str() 也只有固定文案，避免被 logging 顺手记下来
        super().__init__(self.message)

    def to_response(self, trace_id: Optional[str] = None) -> Dict[str, object]:
        """转成对外响应体：只含契约允许的字段。"""
        body: Dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "traceId": trace_id or self.trace_id or new_trace_id(),
        }
        if self.details:
            body["details"] = [dict(d) for d in self.details]
        return body


def validation_error(
    field: Optional[str] = None,
    reason: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> ApiError:
    """构造 400：有具体字段就带 detail，没有就只给固定文案。"""
    details: List[Dict[str, str]] = []
    if field is not None and reason is not None:
        details.append({"field": field, "reason": reason})
    return ApiError("VALIDATION_ERROR", details, trace_id)


def payload_too_large(trace_id: Optional[str] = None) -> ApiError:
    """构造 413。"""
    return ApiError("PAYLOAD_TOO_LARGE", None, trace_id)


def internal_error_response(trace_id: Optional[str] = None) -> Dict[str, object]:
    """构造 500 响应：只有 code 与 traceId，连 message 也只取固定文案。"""
    return ApiError("INTERNAL_ERROR").to_response(trace_id)


def http_status(code: str) -> int:
    """按错误码取 HTTP 状态，供 Web 框架的异常处理器使用。"""
    if code not in ERROR_CODES:
        raise ValueError(f"未登记的错误码: {code!r}")
    return ERROR_CODES[code][0]


def assert_closed_response(body: Mapping[str, object]) -> None:
    """自检用：确认响应体没有越界的键（测试与验收脚本会调用它）。"""
    extra = set(body) - set(RESPONSE_KEYS)
    if extra:
        raise AssertionError(f"响应体出现契约外字段: {sorted(extra)}")


__all__ = [
    "ApiError",
    "ERROR_CODES",
    "REASONS",
    "RESPONSE_KEYS",
    "assert_closed_response",
    "http_status",
    "internal_error_response",
    "new_trace_id",
    "payload_too_large",
    "validation_error",
]
