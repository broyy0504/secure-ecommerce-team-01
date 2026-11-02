import sqlite3
import os

DB_PATH = os.environ.get("AUTH_DB", "auth.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        phone_masked TEXT NOT NULL,
        password_algo TEXT NOT NULL,
        password_iterations INTEGER NOT NULL,
        password_salt TEXT NOT NULL,
        password_derived TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS session_token (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER DEFAULT NULL,
        revoke_reason TEXT DEFAULT NULL
    );
    """)
    conn.commit()
    conn.close()