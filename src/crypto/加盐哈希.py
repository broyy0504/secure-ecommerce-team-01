import hashlib
import hmac
import secrets
import base64

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# 根据 SR-02，迭代 600000 次，16字节盐，32字节派生
def generate_pbkdf2_derived(password: str, iterations: int = 600000) -> dict:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return {
        "algo": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": _b64e(salt),
        "derived": _b64e(dk)
    }

def verify_pbkdf2_derived(password: str, algo: str, iterations: int, salt_b64: str, hash_b64: str) -> bool:
    if algo != "pbkdf2_sha256":
        return False
    salt = _b64d(salt_b64)
    expected = _b64d(hash_b64)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
    return hmac.compare_digest(actual, expected)