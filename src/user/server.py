# src/user/server.py
import sys
import os
import json
import uuid

# 核心：动态将项目根目录加入 sys.path，彻底解决找不到模块的问题
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, '..', '..'))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from src.user.auth_service import register, login, logout, verify_token_and_get_user, AuthException
from src.user.db import init_db

class AuthHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store") # SR-11
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _handle_exception(self, e):
        trace_id = uuid.uuid4().hex[:16]
        if isinstance(e, AuthException):
            resp = {"code": e.code, "message": e.message, "traceId": trace_id}
            if e.details: resp["details"] = [e.details]
            self._send_json(e.http_status, resp)
        else:
            print(f"[-] 内部错误: {e}") # 终端打印错误方便排查
            self._send_json(500, {"code": "INTERNAL_ERROR", "message": "服务暂时不可用，请稍后再试", "traceId": trace_id})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 4096: 
            raise AuthException(413, "PAYLOAD_TOO_LARGE", "请求体过大")
        return json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

    def do_POST(self):
        try:
            if self.path == "/api/users/register":
                data = self._read_json()
                self._send_json(201, register(data))
            elif self.path == "/api/auth/login":
                data = self._read_json()
                self._send_json(200, login(data))
            elif self.path == "/api/auth/logout":
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    raise AuthException(401, "AUTH_UNAUTHENTICATED", "登录状态无效，请重新登录")
                logout(auth[7:].strip())
                self._send_json(204, {})
            else:
                raise AuthException(404, "RESOURCE_NOT_FOUND", "资源不存在")
        except Exception as e:
            self._handle_exception(e)

    def do_GET(self):
        try:
            if self.path == "/api/users/me":
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    raise AuthException(401, "AUTH_UNAUTHENTICATED", "登录状态无效，请重新登录")
                user_info = verify_token_and_get_user(auth[7:].strip())
                self._send_json(200, user_info)
            elif self.path == "/health":
                self._send_json(200, {"ok": True})
            else:
                raise AuthException(404, "RESOURCE_NOT_FOUND", "资源不存在")
        except Exception as e:
            self._handle_exception(e)

def run():
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), AuthHandler)
    print("==================================================")
    print("Server running at http://127.0.0.1:8000")
    print("==================================================")
    server.serve_forever()

if __name__ == "__main__":
    run()