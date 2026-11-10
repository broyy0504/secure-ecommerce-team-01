#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""时间口径：全项目统一用 ISO-8601 UTC 字符串。

为什么不用 Unix 秒：
- 接口契约（DES-03 §4.1/§4.2）的输出本来就是 `2026-10-20T01:02:03.456Z`，
  库里存同一种表示，序列化时不需要二次转换，也就没有"库里的时间和接口里的
  时间差 8 小时"这类现场事故；
- 固定格式（毫秒三位 + 字面量 Z）下字典序等于时间序，`ORDER BY created_at`
  与窗口比较都能直接用字符串比较。

MySQL 侧对应 `DATETIME(3)`，逻辑含义相同，物理类型不同——这一点写进
`docs/handover/01-用户表与身份字段冻结清单.md` §4，避免 II 阶段误以为两边是两套时间。
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

UTC = _dt.timezone.utc
_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def now() -> _dt.datetime:
    """当前 UTC 时间（秒以下截到毫秒，与库里的字符串精度一致）。"""
    current = _dt.datetime.now(tz=UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


def now_iso() -> str:
    """当前时间，`2026-11-10T00:53:11.123Z` 形式。"""
    return to_iso(now())


def to_iso(value: _dt.datetime) -> str:
    """datetime → 固定格式字符串（毫秒三位 + 字面量 Z）；naive 时间按 UTC 处理。"""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return "%s.%03dZ" % (value.strftime("%Y-%m-%dT%H:%M:%S"), value.microsecond // 1000)


def iso_after(seconds: int) -> str:
    """从现在起 `seconds` 秒之后的时间戳。"""
    return to_iso(_dt.datetime.now(tz=UTC) + _dt.timedelta(seconds=seconds))


def parse_iso(text: Optional[str]) -> Optional[_dt.datetime]:
    """字符串 → datetime；解析不了返回 None（调用方按"无效"处理，不抛异常）。"""
    if not text:
        return None
    try:
        return _dt.datetime.strptime(text, _FMT).replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def is_past(text: Optional[str]) -> bool:
    """给定时间是否早于现在（解析失败按"已过期"处理，宁可拒绝）。"""
    parsed = parse_iso(text)
    if parsed is None:
        return True
    return parsed <= _dt.datetime.now(tz=UTC)


def seconds_until(text: Optional[str]) -> int:
    """距离给定时间还有多少秒；已过去或解析失败返回 0。"""
    parsed = parse_iso(text)
    if parsed is None:
        return 0
    delta = (parsed - _dt.datetime.now(tz=UTC)).total_seconds()
    return max(0, int(delta))


__all__ = [
    "UTC",
    "iso_after",
    "is_past",
    "now",
    "now_iso",
    "parse_iso",
    "seconds_until",
    "to_iso",
]
