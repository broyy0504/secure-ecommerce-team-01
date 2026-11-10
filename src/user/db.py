#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""建库与连接（SQLite 可运行版）。

口径：表名、列名、含义以 `db/schema.sql`（MySQL 5.7 基线，第 6 周冻结）为准，
本文件只把它落成 SQLite 能跑的等价结构，供现场演示"空库一条命令建表"。

与 MySQL 基线的差异只有三处，逐条记在
`docs/handover/01-用户表与身份字段冻结清单.md` §4，不在这里私自改口径：

| 项 | MySQL 基线 | 本文件 | 原因 |
| :--- | :--- | :--- | :--- |
| 手机号 | `phone_ciphertext` + `phone_hash` | `phone_hash` + `phone_masked` | 本期不引入密钥管理；系统不需要读回完整手机号，只做唯一约束与脱敏展示 |
| 时间 | `DATETIME(3)` | ISO-8601 UTC 文本 | 与接口输出同一种表示，见 `timeutil.py` |
| 自增主键类型 | `BIGINT UNSIGNED` | `INTEGER` | SQLite 的 `INTEGER PRIMARY KEY` 即 rowid 别名 |

运行时不生成在仓库里：默认落在 `<repo>/var/auth.db`，`var/` 已在 `.gitignore`。
用 `AUTH_DB` 环境变量可指到别处（测试脚本就是这么做的）。

用法：

    python -m src.user.db init          # 建表（幂等），打印实际路径
    python -m src.user.db init --drop   # 删表重建，仅用于本地重置

仅用于教学，不得用于任何真实数据。
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "var" / "auth.db"


def db_path() -> Path:
    """当前生效的库文件路径（`AUTH_DB` 优先，其次 `var/auth.db`）。"""
    raw = os.environ.get("AUTH_DB", "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_DB_PATH


def get_conn() -> sqlite3.Connection:
    """开一条连接。每次请求各开一条，交给线程独立的 sqlite 连接。"""
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS user_account (
    user_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    NOT NULL UNIQUE,
    password_algo       TEXT    NOT NULL,
    password_iterations INTEGER NOT NULL,
    password_salt       TEXT    NOT NULL,
    password_derived    TEXT    NOT NULL,
    phone_hash          TEXT    NOT NULL UNIQUE,
    phone_masked        TEXT    NOT NULL,
    nickname            TEXT,
    status              TEXT    NOT NULL DEFAULT 'active',
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    last_login_at       TEXT,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    CHECK (status IN ('active', 'locked', 'disabled')),
    CHECK (failed_login_count >= 0),
    CHECK (length(password_salt) = 22),
    CHECK (length(password_derived) = 43),
    CHECK (password_algo = 'pbkdf2_sha256'),
    CHECK (password_iterations >= 600000)
);

CREATE INDEX IF NOT EXISTS idx_user_account_status ON user_account (status);
CREATE INDEX IF NOT EXISTS idx_user_account_created_at ON user_account (created_at);

CREATE TABLE IF NOT EXISTS session_token (
    session_token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL,
    token_hash       TEXT    NOT NULL UNIQUE,
    issued_at        TEXT    NOT NULL,
    expires_at       TEXT    NOT NULL,
    revoked_at       TEXT,
    revoke_reason    TEXT,
    client_ip        TEXT,
    user_agent       TEXT,
    FOREIGN KEY (user_id) REFERENCES user_account (user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_token_user_state
    ON session_token (user_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS login_log (
    login_log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER,
    account_ref_hash TEXT,
    account_masked   TEXT,
    result           TEXT    NOT NULL,
    failure_code     TEXT,
    client_ip        TEXT,
    trace_id         TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    CHECK (result IN ('success', 'failure', 'locked', 'blocked')),
    FOREIGN KEY (user_id) REFERENCES user_account (user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_login_log_account_time ON login_log (account_ref_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_login_log_result_time ON login_log (result, created_at);
"""

DROP = """
DROP TABLE IF EXISTS login_log;
DROP TABLE IF EXISTS session_token;
DROP TABLE IF EXISTS user_account;
"""


def init_db(*, drop: bool = False, verbose: bool = False) -> Path:
    """建表（幂等）。`drop=True` 先删后建，仅用于本地重置与测试。"""
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0)
    try:
        # WAL：演示时前端轮询与命令行查库会并发读，默认的 rollback journal 容易撞锁
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(DROP if drop else "")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()

    if verbose:
        print(f"[db] 已建表: {path}")
    return path


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] != "init":
        print(__doc__)
        return 2

    drop = "--drop" in argv[2:]
    path = init_db(drop=drop, verbose=True)
    if drop:
        print("[db] 已按要求先删表（--drop）")

    conn = sqlite3.connect(path)
    try:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
    finally:
        conn.close()

    print(f"[db] 表: {', '.join(names)}")
    print("[db] 下一步: python -m src.user.server")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
