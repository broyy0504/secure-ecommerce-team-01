#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""web/serve.py —— 前端页面的本地服务，顺便把 /api/ 转给后端。

为什么需要一个转发：
    浏览器把「不同端口」当作不同来源。后端跑在 127.0.0.1:8000、页面在 :8080，
    前端直接 fetch 后端就会被同源策略拦下，而后端只实现了 GET/POST，
    没有应答 OPTIONS 预检，也没有 Access-Control-Allow-* 头。
    在前端这一侧加一层转发，浏览器看到的就始终是同一个来源，
    既不用去改别人负责的服务端代码，也不用为了跨域放开一堆响应头。

两个进程仍然分开起，前端只依赖 HTTP 接口，不 import 任何后端模块。

用法（在仓库根目录执行）：
    python -m src.user.server        # 终端 1：后端，127.0.0.1:8000
    python web/serve.py              # 终端 2：前端，http://127.0.0.1:8080

只监听 127.0.0.1，不对外网开放。仅用于教学演示，不得用于任何真实数据。
"""

from __future__ import annotations

import argparse
import http.client
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

WEB_DIR = os.path.dirname(os.path.abspath(__file__))

# 只放行这几个扩展名；其余一律 404，避免把任意文件当静态资源读出去
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
}

# 首页指向登录页，四个页面之间靠顶栏互相跳
DEFAULT_PAGE = "/login.html"

NOT_FOUND_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>404</title></head>
<body style="font-family:'Microsoft YaHei',sans-serif;padding:48px;color:#1c2024">
<h1 style="font-size:18px">页面不存在</h1>
<p style="color:#5b6470">可用页面：/login.html /register.html /profile.html /logout.html</p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "CipherBookWeb/1.0"
    backend_host = "127.0.0.1"
    backend_port = 8000

    # ── 工具 ──────────────────────────────────────────────────────────

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    # ── 静态页面 ──────────────────────────────────────────────────────

    def _serve_static(self, url_path: str) -> None:
        if url_path in ("/", ""):
            url_path = DEFAULT_PAGE

        rel = unquote(url_path).lstrip("/")
        target = os.path.realpath(os.path.join(WEB_DIR, rel))

        # 目录穿越：解析后必须仍在 web/ 里面
        if not (target == WEB_DIR or target.startswith(WEB_DIR + os.sep)):
            self._send_text(403, "禁止访问")
            return

        ext = os.path.splitext(target)[1].lower()
        if ext not in CONTENT_TYPES or not os.path.isfile(target):
            self._send(404, NOT_FOUND_PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return

        with open(target, "rb") as fh:
            body = fh.read()
        self._send(200, body, CONTENT_TYPES[ext])

    # ── 转发到后端 ────────────────────────────────────────────────────

    def _proxy(self, method: str, full_path: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else None

        # 只转这几样：Authorization 是令牌，Content-Type 决定后端怎么解析请求体
        headers = {}
        for name in ("Content-Type", "Authorization", "Accept"):
            value = self.headers.get(name)
            if value:
                headers[name] = value

        conn = http.client.HTTPConnection(self.backend_host, self.backend_port, timeout=30)
        try:
            conn.request(method, full_path, body=body, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
            status = resp.status
            content_type = resp.getheader("Content-Type") or "application/json; charset=utf-8"
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            hint = (
                "后端没有响应（%s）。\n"
                "请先在仓库根目录的另一个终端启动：python -m src.user.server\n" % exc
            )
            self._send_text(502, hint)
            return
        finally:
            conn.close()

        # 204 按规范不带响应体，后端虽然也回了 "{}"，这里不再往下传
        if status == 204:
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        self._send(status, payload, content_type)

    # ── 路由 ──────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") or parsed.path == "/health":
            self._proxy("GET", self.path)
        else:
            self._serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._proxy("POST", self.path)
        else:
            self._send_text(404, "接口不存在")

    def log_message(self, fmt: str, *args) -> None:
        sys.stdout.write("  %s  %s\n" % (self.log_date_time_string(), fmt % args))


def main() -> int:
    parser = argparse.ArgumentParser(description="CipherBook 前端页面服务")
    parser.add_argument("--port", type=int, default=8080, help="前端端口，默认 8080")
    parser.add_argument("--backend-port", type=int, default=8000, help="后端端口，默认 8000")
    args = parser.parse_args()

    Handler.backend_port = args.backend_port
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)

    print("=" * 54)
    print("前端已启动： http://127.0.0.1:%d/login.html" % args.port)
    print("后端转发到： http://127.0.0.1:%d" % args.backend_port)
    print("停止：Ctrl+C")
    print("=" * 54)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
