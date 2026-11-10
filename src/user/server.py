#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户模块的 HTTP 服务（标准库 http.server，零第三方依赖）。

只为课堂演示：`python -m src.user.server` 就能起，不需要装框架。分层很清楚：

```text
server.py          路由、请求体读取、CORS、响应头、异常 → 错误响应
  ├─ validation.py 入口校验（类型/长度/格式/禁用字段）
  ├─ auth.py       受保护接口统一的鉴权函数
  └─ auth_service.py 注册/登录/退出/个人信息/鉴权校验的业务与落库
```

三条硬规矩：

1. **受保护路由的第一行必须是 `require_auth()`**，没有第二处解析 Authorization 的代码。
2. **对外错误只来自 `errors.py` 的封闭集**，异常一律经 `handle_unexpected()` 收敛，
   响应里不出现异常类型、SQL、表名、堆栈。
3. **令牌只走请求头**，不进 URL、不进 Cookie；因此所有响应都带 `Cache-Control: no-store`。

CORS 白名单只放前端开发的几个源（8080 / 5173）。不做 `*`：`*` 配 `Authorization` 头等于
把"任何站点都能拿着用户令牌发请求"写进配置，测 CSRF 时会直接判不通过。

II 阶段的路由在这里**先占位、后实现**：只返回 `501 NOT_IMPLEMENTED`，不返回假数据
（DES-03 §4.5—§4.7 的契约已在 `docs/handover/03-商品与支付接口预留.md` 定稿）。

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

# 允许 `python src/user/server.py` 与 `python -m src.user.server` 两种起法
if __package__ in (None, ""):
    _ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)

from src.user import auth_service, ratelimit  # noqa: E402
from src.user.auth import require_auth  # noqa: E402
from src.user.db import init_db  # noqa: E402
from src.user.errors import ApiError, new_trace_id  # noqa: E402
from src.user.logging_utils import get_logger, handle_unexpected, log_event  # noqa: E402
from src.user.validation import (  # noqa: E402
    validate_login,
    validate_logout,
    validate_me,
    validate_register,
    validate_user_path,
    validate_verify,
)

HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
PORT = int(os.environ.get("AUTH_PORT", "8000"))

# 前端开发源的默认白名单；换端口时用 AUTH_ALLOWED_ORIGINS 覆盖（逗号分隔）
# 8080 是 web/serve.py 的默认端口，5173 是 python -m http.server 的常用端口，两条路都留着
DEFAULT_ORIGINS = (
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)

# 单次读取的上限：超过它连读都不读，直接 413 + 关连接，避免用一个 100MB 的体打满内存
MAX_READ_BYTES = 64 * 1024

USER_PATH_RE = re.compile(r"/api/users/([^/]+)\Z")

# 项目 II 范围：路由先存在，明确返回未实现（任务书 2.5："不能返回假数据"）
STUB_ROUTES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("GET", re.compile(r"/api/books\Z")),
    ("GET", re.compile(r"/api/books/[^/]+\Z")),
    ("GET", re.compile(r"/api/cart\Z")),
    ("POST", re.compile(r"/api/cart/items\Z")),
    ("DELETE", re.compile(r"/api/cart/items/[^/]+\Z")),
    ("POST", re.compile(r"/api/orders\Z")),
    ("GET", re.compile(r"/api/orders/[^/]+\Z")),
    ("POST", re.compile(r"/api/payments/callback\Z")),
    ("POST", re.compile(r"/api/auth/cert/verify\Z")),
)


def allowed_origins() -> Tuple[str, ...]:
    """环境变量覆盖默认白名单；没设就用 DEFAULT_ORIGINS 这一组。"""
    raw = os.environ.get("AUTH_ALLOWED_ORIGINS")
    if not raw:
        return DEFAULT_ORIGINS
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class AuthHandler(BaseHTTPRequestHandler):
    server_version = "bookstore-user/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- 响应 ---------------------------------------------------------------
    def _cors_headers(self) -> Dict[str, str]:
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return {}
        if origin not in allowed_origins():
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
            "Access-Control-Max-Age": "600",
            "Vary": "Origin",
        }

    def _base_headers(self) -> Dict[str, str]:
        headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        }
        headers.update(self._cors_headers())
        return headers

    def _send(self, status: int, body: Optional[bytes], content_type: str, extra: Optional[Dict[str, str]] = None) -> None:
        payload = body or b""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in self._base_headers().items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _json(self, status: int, payload: object, extra: Optional[Dict[str, str]] = None) -> None:
        self._send(status, _json_bytes(payload), "application/json; charset=utf-8", extra)

    def _empty(self, status: int = 204) -> None:
        self.send_response(status)
        for key, value in self._base_headers().items():
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- 请求体 -------------------------------------------------------------
    def _raw_body(self, trace_id: str, limit: int = MAX_READ_BYTES) -> bytes:
        if (self.headers.get("Transfer-Encoding") or "").lower().find("chunked") >= 0:
            # 分块传输我们不解，直接拒：不猜边界就不会被边界绕过
            raise ApiError("VALIDATION_ERROR", None, trace_id)

        raw_length = (self.headers.get("Content-Length") or "0").strip()
        if not raw_length.isdigit():
            raise ApiError("VALIDATION_ERROR", None, trace_id)

        length = int(raw_length)
        if length == 0:
            return b""
        if length > limit:
            # 不读、不解析，直接 413 并断开，免得攻击者用一个超大体积拖住线程
            self.close_connection = True
            raise ApiError("PAYLOAD_TOO_LARGE", None, trace_id)
        return self.rfile.read(length)

    # -- 异常 ---------------------------------------------------------------
    def _handle_exception(self, exc: BaseException, trace_id: str, stage: str) -> None:
        if isinstance(exc, ApiError):
            log_event(
                get_logger(),
                "request_failed",
                trace_id=trace_id,
                stage=stage,
                code=exc.code,
                status=exc.status,
            )
            self._json(exc.status, exc.to_response(trace_id))
            return

        # 未预期异常：日志只留异常类型与阶段，对外只有 INTERNAL_ERROR
        self._json(500, handle_unexpected(exc, stage=stage, trace_id=trace_id))

    # -- 路由 ---------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        origin = (self.headers.get("Origin") or "").strip()
        trace_id = new_trace_id()
        if origin not in allowed_origins():
            # 非白名单源的预检：不回任何 ACAO 头，等于告诉浏览器"不许带凭据来"
            log_event(get_logger(), "cors_preflight_denied", trace_id=trace_id)
            self._json(403, ApiError("AUTH_FORBIDDEN", None, trace_id).to_response(trace_id))
            return
        self._empty(204)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        trace_id = new_trace_id()
        path, _, raw_query = self.path.partition("?")
        path = urllib.parse.unquote(path)
        query = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
        stage = f"{method} {path}"
        try:
            self._route(method, path, query, trace_id)
        except ApiError as exc:
            self._handle_exception(exc, trace_id, stage)
        except Exception as exc:  # noqa: BLE001 —— 最外层兜底，绝不让异常穿出去
            self._handle_exception(exc, trace_id, stage)

    def _route(self, method: str, path: str, query: Dict[str, list], trace_id: str) -> None:
        # ---- 公开接口 ----
        if method == "POST" and path == "/api/users/register":
            body = self._raw_body(trace_id)
            data = validate_register(
                body,
                content_type=self.headers.get("Content-Type"),
                trace_id=trace_id,
            )
            result = auth_service.register(data, trace_id=trace_id)
            self._json(201, result)
            return

        if method == "POST" and path == "/api/auth/login":
            body = self._raw_body(trace_id)
            data = validate_login(
                body,
                content_type=self.headers.get("Content-Type"),
                trace_id=trace_id,
            )
            result = auth_service.login(
                data, client_ip=self.client_address[0], trace_id=trace_id
            )
            self._json(200, result)
            return

        if method == "GET" and path == "/health":
            self._json(200, {"ok": True, "service": "bookstore-user"})
            return

        if method == "GET" and path == "/":
            self._json(
                200,
                {
                    "service": "bookstore-user",
                    "api": [
                        "POST /api/users/register",
                        "POST /api/auth/login",
                        "POST /api/auth/logout",
                        "GET /api/users/me",
                        "GET /api/auth/verify",
                    ],
                    "web": "前端在 http://127.0.0.1:8080/login.html（或 5173）",
                    "docs": "docs/api/openapi.yaml",
                },
            )
            return

        # ---- 受保护接口：第一行统一过 require_auth ----
        if method == "POST" and path == "/api/auth/logout":
            # 允许"已撤销"通过：再退一次仍是 204（DES-03 §4.3）
            ctx = require_auth(self.headers, trace_id, allow_revoked=True)
            body = self._raw_body(trace_id)
            validate_logout(
                body,
                content_type=self.headers.get("Content-Type"),
                trace_id=trace_id,
            )
            auth_service.logout(ctx, trace_id=trace_id)
            self._empty(204)
            return

        if method == "GET" and path == "/api/users/me":
            ctx = require_auth(self.headers, trace_id)
            validate_me(None, query=query, trace_id=trace_id)
            self._json(200, auth_service.get_profile(ctx, target_user_id=None, trace_id=trace_id))
            return

        if method == "GET" and path == "/api/auth/verify":
            ctx = require_auth(self.headers, trace_id)
            validate_verify(None, query=query, trace_id=trace_id)
            self._json(200, auth_service.verify_payload(ctx))
            return

        matched = USER_PATH_RE.match(path)
        if method == "GET" and matched and matched.group(1) != "me":
            ctx = require_auth(self.headers, trace_id)
            target_id = validate_user_path(matched.group(1), trace_id=trace_id)
            self._json(
                200,
                auth_service.get_profile(ctx, target_user_id=target_id, trace_id=trace_id),
            )
            return

        # ---- 项目 II 预留：明确未实现 ----
        for stub_method, pattern in STUB_ROUTES:
            if method == stub_method and pattern.match(path):
                log_event(
                    get_logger(), "not_implemented", trace_id=trace_id, route=path
                )
                self._json(
                    501,
                    {
                        "code": "NOT_IMPLEMENTED",
                        "message": "该接口属项目 II 范围，本期未实现",
                        "traceId": trace_id,
                    },
                )
                return

        raise ApiError("RESOURCE_NOT_FOUND", None, trace_id)

    # -- 访问日志 -----------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:
        """访问日志走统一 logger（带脱敏）。URL 里不含令牌，所以路径可以照记。"""
        log_event(get_logger(), "http", detail=fmt % args)


def create_server(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    """建服务实例（测试脚本用它起临时实例，不占用 8000）。"""
    httpd = ThreadingHTTPServer((host, port), AuthHandler)
    httpd.daemon_threads = True
    return httpd


def run() -> None:
    path = init_db()
    ratelimit.enabled()  # 触发一次配置读取，日志里能看到限流是否生效
    httpd = create_server()
    host, port = httpd.server_address[:2]
    print("=" * 62)
    print(f"用户模块服务已启动: http://{host}:{port}")
    print(f"库文件: {path}")
    print(f"CORS 白名单: {', '.join(allowed_origins())}")
    print(f"限流: {'开启' if ratelimit.enabled() else '关闭'}")
    print("健康检查: GET /health")
    print("=" * 62)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run()
