import time
import datetime
from .db import get_conn
from .password import create_password_fields, check_password, dummy_check
from .tokens import generate_token, hash_token


class AuthException(Exception):
    def __init__(self, http_status, code, message, details=None):
        self.http_status = http_status
        self.code = code
        self.message = message
        self.details = details


# API-USER-001 注册
def register(data: dict):
    # 1. 严格白名单校验
    allowed = {"username", "phone", "password"}
    if not set(data.keys()).issubset(allowed) or not allowed.issubset(data.keys()):
        raise AuthException(400, "VALIDATION_ERROR", "请求参数不合法", {"field": "body", "reason": "NOT_ALLOWED"})

    username, phone, password = data["username"], data["phone"], data["password"]
    phone_masked = phone[:3] + "****" + phone[-4:]

    # 2. 密码派生 (慢哈希)
    fields = create_password_fields(password)

    conn = get_conn()
    try:
        # 3. 唯一性校验 (409)
        if conn.execute("SELECT 1 FROM users WHERE username=? OR phone=?", (username, phone)).fetchone():
            raise AuthException(409, "USER_ALREADY_EXISTS", "该登录名或手机号已被使用")

        # 4. 写入四列 (SR-01)
        now = datetime.datetime.utcnow().isoformat() + "Z"
        cur = conn.execute(
            """INSERT INTO users (username, phone, phone_masked, password_algo, 
               password_iterations, password_salt, password_derived, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, phone, phone_masked, fields["algo"], fields["iterations"],
             fields["salt"], fields["derived"], now)
        )
        conn.commit()
        return {"userId": str(cur.lastrowid), "username": username, "phoneMasked": phone_masked, "status": "active",
                "createdAt": now}
    finally:
        conn.close()


# API-AUTH-001 登录
def login(data: dict) -> dict:
    account, password = data.get("account", ""), data.get("password", "")
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=? OR phone=?", (account, account)).fetchone()

        # SR-04: 账号不存在时走等时假校验
        if not row:
            dummy_check(password)
            raise AuthException(401, "AUTH_INVALID_CREDENTIALS", "账号或密码错误")

        # 账号被锁定或停用，统一报错，不透出状态
        if row["status"] != "active":
            raise AuthException(401, "AUTH_INVALID_CREDENTIALS", "账号或密码错误")

        # 口令校验
        if not check_password(password, row):
            raise AuthException(401, "AUTH_INVALID_CREDENTIALS", "账号或密码错误")

        # SR-06: 生成 Token 并记录摘要
        raw_token, token_hash, expires_at = generate_token()
        conn.execute("INSERT INTO session_token (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                     (token_hash, row["id"], expires_at))
        conn.commit()

        return {
            "accessToken": raw_token,
            "tokenType": "Bearer",
            "expiresIn": 7200,
            "user": {"userId": str(row["id"]), "username": row["username"], "role": "buyer"}
        }
    finally:
        conn.close()


# API-AUTH-002 退出 (幂等)
def logout(raw_token: str):
    conn = get_conn()
    try:
        token_hash = hash_token(raw_token)
        # SR-08: 标记撤销，但不强求原 Token 必须有效（幂等）
        conn.execute(
            "UPDATE session_token SET revoked_at=?, revoke_reason='logout' WHERE token_hash=? AND revoked_at IS NULL",
            (int(time.time()), token_hash))
        conn.commit()
    finally:
        conn.close()


# API-USER-002 鉴权中间件
def verify_token_and_get_user(raw_token: str) -> dict:
    conn = get_conn()
    try:
        token_hash = hash_token(raw_token)
        # 查 token 库，校验是否过期、是否被撤销
        row = conn.execute("SELECT * FROM session_token WHERE token_hash=?", (token_hash,)).fetchone()
        if not row:
            raise AuthException(401, "AUTH_UNAUTHENTICATED", "登录状态无效，请重新登录")
        if row["revoked_at"] is not None:
            raise AuthException(401, "AUTH_UNAUTHENTICATED", "登录状态无效，请重新登录")
        if row["expires_at"] < int(time.time()):
            raise AuthException(401, "AUTH_TOKEN_EXPIRED", "登录已过期，请重新登录")

        user = conn.execute("SELECT id, username, phone_masked, status, created_at FROM users WHERE id=?",
                            (row["user_id"],)).fetchone()
        return {
            "userId": str(user["id"]),
            "username": user["username"],
            "phoneMasked": user["phone_masked"],
            "status": user["status"],
            "createdAt": user["created_at"]
        }
    finally:
        conn.close()