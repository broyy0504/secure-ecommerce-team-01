#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""请求频率限制（SR-20 / R-D-06）。

三个维度：

| 维度 | 默认阈值 | 依据 |
| :--- | :--- | :--- |
| 登录 · 来源地址 | 30 次 / 15 分钟 | DES-03 §4.2 |
| 登录 · 账号 | 10 次 / 15 分钟（只计失败） | DES-03 §4.2，配合 SR-05 的锁定 |
| 注册 · 来源地址 | 10 次 / 1 小时 | DES-03 §4.1 |

两条实现约束：

1. **键必须是哈希**。SR-03 明确"限流与缓存使用的键必须是账号或地址的哈希，不得是
   明文"——本模块接收的是调用方算好的摘要，不做明文穿透，也不把键写进日志。
2. **只防"刷"，不防"错"**。限流命中返回 `429 RATE_LIMITED`，与"账号是否存在"
   "口令对不对"完全无关，不构成额外的账号枚举信号。

计数放在进程内存里：这是单进程课堂演示的合理边界，多实例部署要换成 Redis 一类的
共享计数——写进 `docs/handover/01-用户表与身份字段冻结清单.md` §6 已知局限，
不在代码里假装它能跨进程。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from .errors import ApiError, new_trace_id

# (limit, window_seconds)
LIMITS: Dict[str, Tuple[int, int]] = {
    "login_ip": (30, 900),
    "login_account": (10, 900),
    "register_ip": (10, 3600),
}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw.isdigit():
        return default
    return int(raw)


def _limit_for(scope: str) -> Tuple[int, int]:
    """取阈值；环境变量可临时放松，供自动化测试互不干扰。"""
    default_limit, default_window = LIMITS[scope]
    return (
        _env_int(f"AUTH_RL_{scope.upper()}_LIMIT", default_limit),
        _env_int(f"AUTH_RL_{scope.upper()}_WINDOW", default_window),
    )


def enabled() -> bool:
    return os.environ.get("AUTH_RL_ENABLED", "1").strip() not in ("0", "off", "false")


class RateLimiter:
    """滑动窗口计数器：每个键存最近 window 秒内的命中时刻。"""

    def __init__(self) -> None:
        self._hits: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = threading.Lock()

    # -- 内部 ---------------------------------------------------------------
    def _prune(self, key: Tuple[str, str], window: int, now: float) -> Deque[float]:
        bucket = self._hits.setdefault(key, deque())
        edge = now - window
        while bucket and bucket[0] <= edge:
            bucket.popleft()
        return bucket

    def _gc(self, now: float) -> None:
        """键太多时清掉整桶过期的，避免长跑进程内存只涨不落。"""
        if len(self._hits) < 4096:
            return
        for key in [k for k, v in self._hits.items() if not v]:
            self._hits.pop(key, None)

    # -- 对外 ---------------------------------------------------------------
    def hit(
        self,
        scope: str,
        subject_digest: str,
        *,
        trace_id: Optional[str] = None,
        cost: int = 1,
    ) -> int:
        """记一次命中；超阈值抛 `429`。返回当前窗口内的次数。"""
        if not enabled():
            return 0

        limit, window = _limit_for(scope)
        key = (scope, subject_digest)
        now = time.monotonic()

        with self._lock:
            bucket = self._prune(key, window, now)
            bucket.extend([now] * max(1, cost))
            count = len(bucket)
            self._gc(now)

        if count > limit:
            raise ApiError("RATE_LIMITED", None, trace_id or new_trace_id())
        return count

    def peek(self, scope: str, subject_digest: str) -> int:
        """只读当前窗口内的次数（测试与演示用）。"""
        limit, window = _limit_for(scope)
        with self._lock:
            return len(self._prune((scope, subject_digest), window, time.monotonic()))

    def reset(self, scope: Optional[str] = None, subject_digest: Optional[str] = None) -> None:
        """清计数器。测试用；上线不需要调用。"""
        with self._lock:
            if scope is None:
                self._hits.clear()
                return
            for key in [k for k in self._hits if k[0] == scope]:
                if subject_digest is None or key[1] == subject_digest:
                    self._hits.pop(key, None)


LIMITER = RateLimiter()


__all__ = ["LIMITER", "LIMITS", "RateLimiter", "enabled"]
