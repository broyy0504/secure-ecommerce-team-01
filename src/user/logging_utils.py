#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""日志脱敏与异常收敛。

对应交付要求："错误与日志不出现口令、派生值、密钥、栈信息"。

三条规定写在这里，业务代码不需要各自记得：

1. **值级脱敏**：口令进入 `Secret` 时自动登记到脱敏表，之后任何一条日志里
   出现这个字符串都会被替换成 `<redacted>`——即使有人直接
   `logger.info("pwd=%s", pwd)` 也漏不出去。
2. **键级脱敏**：`password` / `token` / `salt` / `derived` 一类键名，值一律不输出。
3. **异常收敛**：未预期异常只记**异常类型**与处理阶段，不记异常消息（异常消息
   常带着 SQL、字段值、文件路径），不记堆栈；对外只回 `INTERNAL_ERROR` + `traceId`。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import json
import logging
import re
from collections import OrderedDict
from typing import Dict, Iterable, List, Mapping, Optional

# 键名命中这些词的字段，值一律不落日志（大小写不敏感，按包含关系匹配）
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "salt",
    "derived",
    "hash",
    "signature",
    "api_key",
    "apikey",
    "private_key",
    "credential",
)

REDACTED = "<redacted>"

# 已登记的真实敏感值，最长 512 条，超出按先进先出淘汰，避免测试里无限增长
_SECRET_REGISTRY: "OrderedDict[str, None]" = OrderedDict()
_SECRET_REGISTRY_LIMIT = 512

# 派生值存储串：pbkdf2_sha256$600000$<salt>$<hash>
_STORED_HASH_RE = re.compile(r"pbkdf2_sha256\$\d+\$[^\s$\"',}]+\$[^\s$\"',}]+")

# Authorization 头
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]+")

# key=value / "key": "value" 形式，只针对敏感键名
_KV_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|access_?token|refresh_?token|token|secret|"
    r"salt|derived|password_?hash|signature|api_?key|private_?key"
    r")\b(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,&}]+)"
)


def register_secret(value: str) -> None:
    """登记一个不得出现在日志里的值（口令、令牌、密钥都适用）。"""
    if not isinstance(value, str) or len(value) < 4:
        # 太短的值全局替换会误伤正常文本
        return
    _SECRET_REGISTRY[value] = None
    _SECRET_REGISTRY.move_to_end(value)
    while len(_SECRET_REGISTRY) > _SECRET_REGISTRY_LIMIT:
        _SECRET_REGISTRY.popitem(last=False)


def clear_secret_registry() -> None:
    """清空登记表（测试用；生产不需要调用）。"""
    _SECRET_REGISTRY.clear()


def is_sensitive_key(key: str) -> bool:
    """键名是否属于"值不可记录"的一类。"""
    lowered = str(key).lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact_text(text: str) -> str:
    """对一段文本做值级 + 形状级脱敏。"""
    if not text:
        return text

    out = str(text)

    # 1) 已登记的真实值：先替换，避免被后面的正则截断
    if _SECRET_REGISTRY:
        for secret_value in sorted(_SECRET_REGISTRY, key=len, reverse=True):
            if secret_value in out:
                out = out.replace(secret_value, REDACTED)

    # 2) 派生值存储串（口令的盐与派生值都在里面）
    out = _STORED_HASH_RE.sub(REDACTED, out)

    # 3) Bearer 令牌
    out = _BEARER_RE.sub("Bearer " + REDACTED, out)

    # 4) 敏感键名后面跟的值
    out = _KV_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)

    return out


class RedactingFilter(logging.Filter):
    """挂在 logger 上的兜底过滤器：任何日志记录都会被清洗一遍。"""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            raw = record.getMessage()
        except Exception:  # 格式化失败也不能让日志本身炸掉
            raw = str(record.msg)

        cleaned = redact_text(raw)
        # 直接把 msg 换成清洗后的成品，args 置空，避免下游再格式化一次
        record.msg = cleaned
        record.args = ()
        if not hasattr(record, "trace_id"):
            record.trace_id = "-"
        return True


class _SafeFormatter(logging.Formatter):
    """没带 traceId 的记录也能正常格式化。"""

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "trace_id"):
            record.trace_id = "-"
        return super().format(record)


def get_logger(name: str = "bookstore.user") -> logging.Logger:
    """取一个已装好脱敏过滤器的 logger。"""
    logger = logging.getLogger(name)

    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            _SafeFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s traceId=%(trace_id)s %(message)s"
            )
        )
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    return logger


def _format_value(value: object) -> str:
    """键值对里的值：字符串原样，其余交给 json，保证单行。"""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(type(value).__name__)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    trace_id: Optional[str] = None,
    **fields: object,
) -> str:
    """按 `event=... key=value ...` 记一条结构化日志，返回最终落盘的文本。

    敏感键名的值直接换成 `<redacted>`，字符串值再过一遍 `redact_text`。
    """
    # traceId 由 Formatter 统一打在前缀上（见 get_logger），正文里不重复
    parts: List[str] = [f"event={event}"]

    for key, value in fields.items():
        if value is None:
            continue
        if is_sensitive_key(key):
            parts.append(f"{key}={REDACTED}")
            continue
        text = _format_value(value)
        parts.append(f"{key}={redact_text(text)}")

    line = " ".join(parts)
    logger.info(line, extra={"trace_id": trace_id or "-"})
    return line


def handle_unexpected(
    exc: BaseException,
    *,
    stage: str,
    trace_id: str,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, object]:
    """把未预期异常收敛成对外 500，并留下可追的日志。

    - 日志只记 `exc_type`，不记 `str(exc)`：异常消息里常见 SQL 片段、
      字段值、文件路径，正是 SR-19 禁止出现的东西。
    - 不记堆栈：交付要求"日志不出现栈信息"。定位靠 `stage` + `traceId`。
    - 对外只回 `{code, message, traceId}`。
    """
    from .errors import internal_error_response  # 延迟导入，避免循环依赖

    logger = logger or get_logger()
    log_event(
        logger,
        "unexpected_error",
        trace_id=trace_id,
        stage=stage,
        exc_type=type(exc).__name__,
    )
    return internal_error_response(trace_id)


# ---------------------------------------------------------------------------
# 审计/展示用的脱敏函数（不是"加密"，只是少露几位）
# ---------------------------------------------------------------------------


def mask_phone(phone: str) -> str:
    """138****8000。输入不合法时退化为全掩码，绝不原样返回。"""
    digits = re.sub(r"\D", "", str(phone or ""))
    if len(digits) < 7:
        return "***"
    return f"{digits[:3]}****{digits[-4:]}"


def mask_email(email: str) -> str:
    """ab***@example.com。"""
    text = str(email or "")
    if "@" not in text:
        return "***"
    local, _, domain = text.partition("@")
    if not local or not domain:
        return "***"
    keep = local[:2] if len(local) > 2 else local[:1]
    return f"{keep}***@{domain}"


def mask_account(account: str) -> str:
    """登录名保留首 2 位，其余打码；像手机号的走手机号规则。"""
    text = str(account or "")
    if re.fullmatch(r"[\d\s\-]{7,}", text):
        return mask_phone(text)
    if len(text) <= 2:
        return text[:1] + "***"
    return f"{text[:2]}***{text[-1:]}"


def summarize_fields(names: Iterable[str]) -> str:
    """把字段名列表压成一行，用于审计"哪些禁用字段被提交了"。"""
    return ",".join(sorted({str(n) for n in names})) or "-"


__all__ = [
    "REDACTED",
    "RedactingFilter",
    "clear_secret_registry",
    "get_logger",
    "handle_unexpected",
    "is_sensitive_key",
    "log_event",
    "mask_account",
    "mask_email",
    "mask_phone",
    "redact_text",
    "register_secret",
    "summarize_fields",
]
