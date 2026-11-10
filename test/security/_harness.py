#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试夹具：起一个临时库 + 临时端口的服务实例，供各测试脚本共用。

设计目标只有一个：**测出来的东西就是现场会跑的东西**。所以这里不模拟、不 mock，
直接 import `src.user.server.create_server`，用真实的 HTTP 打真实的 SQLite 文件。

- 每次 `Api()` 都换一个新库（`tempfile.mkdtemp()`），互不污染；
- 端口用 0，由系统分配，五个类别可以连着跑；
- 服务跑在后台线程里，`stop()` 之后删库。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.user.server import create_server  # noqa: E402


@dataclass
class Resp:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    data: Optional[object] = None
    elapsed: float = 0.0

    @property
    def code(self) -> Optional[str]:
        return self.data.get("code") if isinstance(self.data, dict) else None

    @property
    def message(self) -> Optional[str]:
        return self.data.get("message") if isinstance(self.data, dict) else None

    def __repr__(self) -> str:
        return f"Resp(status={self.status}, code={self.code!r})"


class Api:
    """一个独立的服务实例。用 with 语句保证退出时收干净。"""

    def __init__(self, *, rate_limit: bool = True) -> None:
        self.dir = tempfile.mkdtemp(prefix="bookstore-test-")
        self.db_path = os.path.join(self.dir, "auth.db")
        self._saved_env = {k: os.environ.get(k) for k in ("AUTH_DB", "AUTH_RL_ENABLED")}
        os.environ["AUTH_DB"] = self.db_path
        os.environ["AUTH_RL_ENABLED"] = "1" if rate_limit else "0"
        self._httpd = None
        self._thread: Optional[threading.Thread] = None
        self.base_url = ""

    # -- 生命周期 -----------------------------------------------------------
    def start(self) -> "Api":
        from src.user import db, ratelimit

        db.init_db(drop=True)
        ratelimit.LIMITER.reset()
        self._httpd = create_server("127.0.0.1", 0)
        host, port = self._httpd.server_address[:2]
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self._wait_ready()
        return self

    def _wait_ready(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", int(self.base_url.rsplit(":", 1)[1])), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError("服务没起来")

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> "Api":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- 请求 ---------------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        *,
        body: object = None,
        raw_body: Optional[bytes] = None,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        origin: Optional[str] = None,
        content_type: str = "application/json",
    ) -> Resp:
        payload = raw_body
        hdrs = {"Accept": "application/json"}
        if payload is None and body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        if payload is not None:
            hdrs["Content-Type"] = content_type
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        if origin:
            hdrs["Origin"] = origin
        hdrs.update(headers or {})

        req = urllib.request.Request(
            self.base_url + path, data=payload, headers=hdrs, method=method
        )
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return Resp(
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=raw,
                    data=_maybe_json(raw),
                    elapsed=time.time() - started,
                )
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", "replace")
            return Resp(
                status=err.code,
                headers={k.lower(): v for k, v in (err.headers or {}).items()},
                body=raw,
                data=_maybe_json(raw),
                elapsed=time.time() - started,
            )

    # -- 便捷动作 -----------------------------------------------------------
    def register(self, username: str, phone: str, password: str, nickname: Optional[str] = None) -> Resp:
        body = {"username": username, "phone": phone, "password": password}
        if nickname is not None:
            body["nickname"] = nickname
        return self.request("POST", "/api/users/register", body=body)

    def login(self, account: str, password: str) -> Resp:
        return self.request("POST", "/api/auth/login", body={"account": account, "password": password})

    def token_of(self, account: str, password: str) -> str:
        resp = self.login(account, password)
        assert resp.status == 200, f"登录失败: {resp.status} {resp.body}"
        return resp.data["accessToken"]

    def me(self, token: Optional[str]) -> Resp:
        return self.request("GET", "/api/users/me", token=token)


def _maybe_json(raw: str):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def sql(db_path: str, statement: str, params: tuple = ()) -> list:
    """直接查库，用于"库里存的是不是原文"这类断言。"""
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(statement, params).fetchall()]
    finally:
        conn.close()


class CaptureLogs:
    """抓一段应用日志，用来断言"审计里确实记下了这次尝试"。

    越权、鉴权失败这类事件对外必须同形，能证明它发生过的只有日志与审计表，
    所以这里直接把 `bookstore.user` 的记录收下来。
    """

    def __init__(self) -> None:
        import logging

        self.records: list[str] = []
        self._logger = logging.getLogger("bookstore.user")
        self._handler = logging.Handler()
        self._handler.emit = lambda record: self.records.append(record.getMessage())  # type: ignore[method-assign]

    def __enter__(self) -> "CaptureLogs":
        self._logger.addHandler(self._handler)
        return self

    def __exit__(self, *exc) -> None:
        self._logger.removeHandler(self._handler)

    @property
    def text(self) -> str:
        return "\n".join(self.records)

    def has(self, needle: str) -> bool:
        return any(needle in line for line in self.records)


__all__ = ["Api", "CaptureLogs", "Resp", "sql"]
