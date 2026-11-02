from src.crypto.加盐哈希 import generate_pbkdf2_derived, verify_pbkdf2_derived

# 用于等时失败的假数据（SR-04）
DUMMY_DATA = generate_pbkdf2_derived("dummy_password_for_timing")

def create_password_fields(password: str) -> dict:
    return generate_pbkdf2_derived(password)

def check_password(password: str, user_row: dict) -> bool:
    return verify_pbkdf2_derived(
        password,
        user_row["password_algo"],
        user_row["password_iterations"],
        user_row["password_salt"],
        user_row["password_derived"]
    )

def dummy_check(password: str):
    """账号不存在时消耗同等时间，防时间侧信道"""
    verify_pbkdf2_derived(
        password,
        DUMMY_DATA["algo"],
        DUMMY_DATA["iterations"],
        DUMMY_DATA["salt"],
        DUMMY_DATA["derived"]
    )