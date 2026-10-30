import secrets
import hashlib
import time

TOKEN_TTL = 7200 # 2小时 (SR-09)

def generate_token() -> tuple[str, str, int]:
    """返回 (明文token, 摘要, 过期时间戳)"""
    raw_token = secrets.token_urlsafe(32) # 至少128位 (SR-06)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = int(time.time()) + TOKEN_TTL
    return raw_token, token_hash, expires_at

def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()