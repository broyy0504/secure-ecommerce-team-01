#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""入口参数校验：类型、长度、格式。

覆盖本阶段四个入口（对齐 `docs/design/03-接口契约.md` §4.1—§4.4）：

| 入口 | 函数 | 契约 |
| :--- | :--- | :--- |
| 注册 | `validate_register` | §4.1 API-USER-001 |
| 登录 | `validate_login` | §4.2 API-AUTH-001 |
| 退出 | `validate_logout` | §4.3 API-AUTH-002 |
| 本人信息 | `validate_me` | §4.4 API-USER-002 |

三条实现原则：

1. **先看结构，再看字段**：Content-Type、体积、JSON 形状、禁用字段、未知字段
   先处理——这些是"请求本身不合规"，与字段值无关，失败得快也更安全。
2. **不回显原值**：`details` 只带契约里写死的字段名与 8 个原因枚举；未知字段名
   由调用方（攻击者）决定，因此一律不进 `details`、不进日志。
3. **口令一旦进来就包成 `Secret`**：`repr`/`str`/格式化都不吐明文，并自动登记到
   日志脱敏表（见 `logging_utils.register_secret`）。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import ApiError, FIELD_NAME_RE, new_trace_id, validation_error
from .logging_utils import (
    REDACTED,
    get_logger,
    log_event,
    register_secret,
)

# ---------------------------------------------------------------------------
# 契约常量（改这里等于改契约，必须同步 DES-03）
# ---------------------------------------------------------------------------

USERNAME_MIN, USERNAME_MAX = 4, 32
PASSWORD_MIN, PASSWORD_MAX = 8, 64
PASSWORD_MAX_BYTES = 256
ACCOUNT_MIN, ACCOUNT_MAX = 4, 64

# 请求体上限（字节），按接口分别设定
BODY_LIMITS: Dict[str, int] = {
    "register": 4 * 1024,
    "login": 2 * 1024,
    "logout": 1 * 1024,
    "me": 0,
}

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{4,32}\Z")
PHONE_RE = re.compile(r"1[3-9]\d{9}\Z")
PHONE_SEPARATORS_RE = re.compile(r"[ \-]")

ALLOWED_REGISTER = frozenset({"username", "phone", "password"})
ALLOWED_LOGIN = frozenset({"account", "password"})

# 契约里逐字列出的禁用字段：名字是常量，不是用户自由构造的，可以回给调用方
FORBIDDEN_REGISTER: Tuple[str, ...] = (
    "userId",
    "role",
    "status",
    "iterations",
    "salt",
    "passwordHash",
    "passwordDerived",
)
FORBIDDEN_LOGIN: Tuple[str, ...] = (
    "role",
    "userId",
    "iterations",
    "salt",
    "rememberMe",
)

RawBody = Union[bytes, str, Mapping[str, Any], None]


# ---------------------------------------------------------------------------
# 口令容器
# ---------------------------------------------------------------------------


class Secret:
    """口令的包装：任何"顺手打印"都不会漏明文。

    `register_secret` 会把值登记到日志脱敏表，所以即使有人把 `reveal()`
    的结果拼进日志，过滤器仍会把它替换成 `<redacted>`。
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Secret 只接受 str")
        self._value = value
        register_secret(value)

    def reveal(self) -> str:
        """取出明文，只允许传给哈希/验证函数，不得写日志、不得进响应。"""
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, spec: str) -> str:
        return REDACTED

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self._value == other._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))


# ---------------------------------------------------------------------------
# 校验结果
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegisterInput:
    """注册入口的已校验输入。字段顺序即落库顺序。"""

    username: str
    phone: str  # 已去空格与连字符
    password: Secret

    def __repr__(self) -> str:
        return f"RegisterInput(username={self.username!r}, phone={self.phone!r}, password=<redacted>)"


@dataclass(frozen=True)
class LoginInput:
    """登录入口的已校验输入。"""

    account: str  # 已归一化（去首尾空白；手机号去分隔符）
    password: Secret
    account_kind: str  # "username" | "phone"


# ---------------------------------------------------------------------------
# 结构层：Content-Type / 体积 / JSON 形状
# ---------------------------------------------------------------------------


class _DuplicateKeys(Exception):
    """JSON 里出现重复键。重复键在解析器之间取值不一致，是绕过校验的常用手法。"""


def _pairs_hook(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKeys(key)
        seen.add(key)
    return dict(pairs)


def _is_json_content_type(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json"


def _coerce_bytes(raw_body: RawBody) -> bytes:
    """把入参统一成字节；字节长度才是体积上限的判据。"""
    if raw_body is None:
        return b""
    if isinstance(raw_body, bytes):
        return raw_body
    if isinstance(raw_body, str):
        return raw_body.encode("utf-8")
    if isinstance(raw_body, Mapping):
        # 框架已经反序列化过的情况：按紧凑 JSON 重新量一次体积
        return json.dumps(raw_body, ensure_ascii=False).encode("utf-8")
    raise TypeError("请求体只接受 bytes / str / 映射对象")


def _decode_object(
    raw_body: RawBody,
    *,
    limit: int,
    content_type: Optional[str],
    stage: str,
    trace_id: str,
) -> Dict[str, Any]:
    """体积 → 编码 → JSON → 形状。任何一步不过都抛 ApiError。"""
    if not _is_json_content_type(content_type):
        # 不确定的媒体类型不猜，直接 400；details 不带，避免回显头里的内容
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="CONTENT_TYPE")
        raise validation_error(trace_id=trace_id)

    raw = _coerce_bytes(raw_body)
    if len(raw) > limit:
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="BODY_TOO_LARGE", body_bytes=len(raw),
                  limit_bytes=limit)
        raise ApiError("PAYLOAD_TOO_LARGE", None, trace_id)

    if not raw.strip():
        # 空体不是 `{}`：四个入口都要求至少是一个 JSON 对象
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="EMPTY_BODY")
        raise validation_error(trace_id=trace_id)

    try:
        text = raw.decode("utf-8")  # 严格解码，不接受替换字符
    except UnicodeDecodeError:
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="BAD_ENCODING")
        raise validation_error(trace_id=trace_id)

    try:
        obj = json.loads(text, object_pairs_hook=_pairs_hook)
    except _DuplicateKeys:
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="DUPLICATE_JSON_KEY")
        raise validation_error(trace_id=trace_id)
    except json.JSONDecodeError:
        # 不回传解析器的行列信息：那等于把内部解析细节告诉调用方
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="BAD_JSON")
        raise validation_error(trace_id=trace_id)

    if not isinstance(obj, dict):
        log_event(get_logger(), "validation_failed", trace_id=trace_id,
                  stage=stage, reason="NOT_AN_OBJECT")
        raise validation_error(trace_id=trace_id)

    return obj


def _reject_forbidden(
    body: Mapping[str, Any],
    forbidden: Sequence[str],
    *,
    stage: str,
    trace_id: str,
) -> None:
    """契约逐字列出的禁用字段：出现即 400，并在审计里记下是哪些。"""
    hit = [name for name in forbidden if name in body]
    if not hit:
        return

    log_event(
        get_logger(),
        "forbidden_field_rejected",
        trace_id=trace_id,
        stage=stage,
        fields=",".join(hit),  # 常量名单，可以记
        count=len(hit),
    )
    raise ApiError(
        "VALIDATION_ERROR",
        [{"field": name, "reason": "NOT_ALLOWED"} for name in hit],
        trace_id,
    )


def _reject_unknown(
    body: Mapping[str, Any],
    allowed: frozenset,
    *,
    stage: str,
    trace_id: str,
) -> None:
    """契约要求 additionalProperties: false。

    未知字段名由调用方决定，可能是 `' OR 1=1--`、换行、超长串，
    所以只记个数，既不进 details 也不进日志原文。
    """
    unknown = [key for key in body if not isinstance(key, str) or key not in allowed]
    if not unknown:
        return

    log_event(
        get_logger(),
        "unknown_field_rejected",
        trace_id=trace_id,
        stage=stage,
        count=len(unknown),
    )
    raise validation_error(trace_id=trace_id)


# ---------------------------------------------------------------------------
# 字段层
# ---------------------------------------------------------------------------


class _Issues:
    """收集字段级问题，一次返回全部，避免调用方逐个试错。"""

    def __init__(self, limit: int = 16) -> None:
        self._items: List[Dict[str, str]] = []
        self._limit = limit

    def add(self, field: str, reason: str) -> None:
        if len(self._items) < self._limit:
            self._items.append({"field": field, "reason": reason})

    def __len__(self) -> int:
        return len(self._items)

    def raise_if_any(self, *, stage: str, trace_id: str) -> None:
        if not self._items:
            return
        log_event(
            get_logger(),
            "validation_failed",
            trace_id=trace_id,
            stage=stage,
            fields=",".join(f'{i["field"]}:{i["reason"]}' for i in self._items),
            count=len(self._items),
        )
        raise ApiError("VALIDATION_ERROR", self._items, trace_id)


def _require_text(body: Mapping[str, Any], field: str, issues: _Issues) -> Optional[str]:
    """必填 + 字符串类型。不 trim——长度按契约要求的时机算。"""
    if field not in body:
        issues.add(field, "REQUIRED")
        return None
    value = body[field]
    if not isinstance(value, str):
        # 含 true/false/数字/数组/对象；bool 不是 str，也会落到这里
        issues.add(field, "TYPE_MISMATCH")
        return None
    return value


def _check_username(body: Mapping[str, Any], issues: _Issues) -> Optional[str]:
    raw = _require_text(body, "username", issues)
    if raw is None:
        return None

    name = raw.strip()  # 契约：去首尾空白后 4—32 字符
    if len(name) < USERNAME_MIN:
        issues.add("username", "TOO_SHORT")
        return None
    if len(name) > USERNAME_MAX:
        issues.add("username", "TOO_LONG")
        return None
    if not USERNAME_RE.match(name):
        # 内部空白、中文、特殊字符、控制字符都在这里拦下
        issues.add("username", "FORMAT_INVALID")
        return None
    return name


def _normalize_phone(raw: str) -> str:
    """只去空格与连字符，与契约一致；`+86` 前缀不处理（见说明文档"已知局限"）。"""
    return PHONE_SEPARATORS_RE.sub("", raw)


def _check_phone(body: Mapping[str, Any], issues: _Issues) -> Optional[str]:
    raw = _require_text(body, "phone", issues)
    if raw is None:
        return None

    phone = _normalize_phone(raw).strip()
    if not PHONE_RE.match(phone):
        issues.add("phone", "FORMAT_INVALID")
        return None
    return phone


def _check_password_register(
    body: Mapping[str, Any],
    issues: _Issues,
    *,
    username: Optional[str],
    phone: Optional[str],
) -> Optional[Secret]:
    """注册口令：长度 + 字节上限 + 不得全同字符 + 不得等于账号/手机号。"""
    raw = _require_text(body, "password", issues)
    if raw is None:
        return None

    length = len(raw)
    if length < PASSWORD_MIN:
        issues.add("password", "TOO_SHORT")
        return None
    if length > PASSWORD_MAX:
        issues.add("password", "TOO_LONG")
        return None
    # 字符数与字节数两条线都要过：64 个汉字是 192 字节，还在限内；
    # 而 200 个 emoji 字符数没超，字节数已经爆了
    if len(raw.encode("utf-8")) > PASSWORD_MAX_BYTES:
        issues.add("password", "TOO_LONG")
        return None
    if len(set(raw)) == 1:
        issues.add("password", "FORMAT_INVALID")  # 全为同一字符
        return None

    lowered = raw.lower()
    if username and lowered == username.lower():
        issues.add("password", "FORMAT_INVALID")
        return None
    if phone and _normalize_phone(raw) == phone:
        issues.add("password", "FORMAT_INVALID")
        return None

    return Secret(raw)


def _check_password_login(body: Mapping[str, Any], issues: _Issues) -> Optional[Secret]:
    """登录口令：只校验长度。

    登录阶段不做强度判断——强度是注册时把关的；登录时多做一次强度拒绝，
    会把"格式不符"变成 400，反而给攻击者多一个区分信号。
    """
    raw = _require_text(body, "password", issues)
    if raw is None:
        return None

    if len(raw) < PASSWORD_MIN:
        issues.add("password", "TOO_SHORT")
        return None
    if len(raw) > PASSWORD_MAX:
        issues.add("password", "TOO_LONG")
        return None
    return Secret(raw)


def _check_account(body: Mapping[str, Any], issues: _Issues) -> Tuple[Optional[str], str]:
    """登录账号：登录名格式或手机号格式二选一，并归一化。"""
    raw = _require_text(body, "account", issues)
    if raw is None:
        return None, ""

    account = raw.strip()
    if len(account) < ACCOUNT_MIN:
        issues.add("account", "TOO_SHORT")
        return None, ""
    if len(account) > ACCOUNT_MAX:
        issues.add("account", "TOO_LONG")
        return None, ""

    phone = _normalize_phone(account)
    if PHONE_RE.match(phone):
        return phone, "phone"
    if USERNAME_RE.match(account):
        return account, "username"

    issues.add("account", "FORMAT_INVALID")
    return None, ""


# ---------------------------------------------------------------------------
# 四个入口
# ---------------------------------------------------------------------------


def validate_register(
    raw_body: RawBody,
    *,
    content_type: Optional[str] = "application/json",
    trace_id: Optional[str] = None,
) -> RegisterInput:
    """注册入口校验。通过则返回已归一化的输入，不通过抛 `ApiError`。"""
    tid = trace_id or new_trace_id()
    body = _decode_object(
        raw_body,
        limit=BODY_LIMITS["register"],
        content_type=content_type,
        stage="register",
        trace_id=tid,
    )
    _reject_forbidden(body, FORBIDDEN_REGISTER, stage="register", trace_id=tid)
    _reject_unknown(body, ALLOWED_REGISTER, stage="register", trace_id=tid)

    issues = _Issues()
    username = _check_username(body, issues)
    phone = _check_phone(body, issues)
    password = _check_password_register(
        body, issues, username=username, phone=phone
    )
    issues.raise_if_any(stage="register", trace_id=tid)

    assert username is not None and phone is not None and password is not None
    return RegisterInput(username=username, phone=phone, password=password)


def validate_login(
    raw_body: RawBody,
    *,
    content_type: Optional[str] = "application/json",
    trace_id: Optional[str] = None,
) -> LoginInput:
    """登录入口校验。"""
    tid = trace_id or new_trace_id()
    body = _decode_object(
        raw_body,
        limit=BODY_LIMITS["login"],
        content_type=content_type,
        stage="login",
        trace_id=tid,
    )
    _reject_forbidden(body, FORBIDDEN_LOGIN, stage="login", trace_id=tid)
    _reject_unknown(body, ALLOWED_LOGIN, stage="login", trace_id=tid)

    issues = _Issues()
    account, kind = _check_account(body, issues)
    password = _check_password_login(body, issues)
    issues.raise_if_any(stage="login", trace_id=tid)

    assert account is not None and password is not None
    return LoginInput(account=account, password=password, account_kind=kind)


def validate_logout(
    raw_body: RawBody = None,
    *,
    content_type: Optional[str] = "application/json",
    trace_id: Optional[str] = None,
) -> None:
    """退出入口校验：允许无体或空对象 `{}`，出现任何字段即 400。

    撤销哪个会话由请求头里的令牌决定，所以这里不接受 `token` / `userId`
    一类参数——多传参数本身就是探测行为。
    """
    tid = trace_id or new_trace_id()
    raw = _coerce_bytes(raw_body)

    if not raw.strip():
        return

    body = _decode_object(
        raw,
        limit=BODY_LIMITS["logout"],
        content_type=content_type,
        stage="logout",
        trace_id=tid,
    )
    if body:
        # 字段名由调用方决定，只记个数
        log_event(
            get_logger(),
            "validation_failed",
            trace_id=tid,
            stage="logout",
            reason="BODY_FIELD_NOT_ALLOWED",
            count=len(body),
        )
        raise validation_error(trace_id=trace_id)


def validate_me(
    raw_body: RawBody = None,
    *,
    query: Optional[Mapping[str, Any]] = None,
    content_type: Optional[str] = "application/json",
    trace_id: Optional[str] = None,
) -> List[str]:
    """本人信息入口校验：不接受请求体，查询参数忽略并记审计。

    返回"被忽略的查询参数名"（已过滤成安全标识符），供调用方写审计。
    该接口的语义是"令牌对应的人"，多传参数只是探测行为，不改变结果。
    """
    tid = trace_id or new_trace_id()

    # 该接口不接受请求体：有体就 400，不需要再解析内容
    if _coerce_bytes(raw_body).strip():
        log_event(
            get_logger(),
            "validation_failed",
            trace_id=tid,
            stage="me",
            reason="BODY_NOT_ALLOWED",
        )
        raise validation_error(trace_id=tid)

    ignored: List[str] = []
    for name in (query or {}):
        if isinstance(name, str) and FIELD_NAME_RE.match(name):
            ignored.append(name)
    if ignored:
        # 只记个数与安全标识符，不记参数值
        log_event(
            get_logger(),
            "ignored_query_param",
            trace_id=tid,
            stage="me",
            count=len(ignored),
            names=",".join(ignored[:8]),
        )
    return ignored


__all__ = [
    "BODY_LIMITS",
    "LoginInput",
    "RegisterInput",
    "Secret",
    "validate_login",
    "validate_logout",
    "validate_me",
    "validate_register",
]
