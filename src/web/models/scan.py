"""Web 服务数据库模型 —— 项目管理 + 扫描记录。

使用 SQLite（与现有 feedback_db.py 分离，独立数据库文件）。
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = "/workspace/web/web.db"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


def get_db() -> sqlite3.Connection:
    """获取数据库连接（自动建表）。"""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """初始化数据库表（幂等）。"""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'upload',
            source_path TEXT NOT NULL DEFAULT '',
            git_url     TEXT DEFAULT '',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id      INTEGER NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            standard        TEXT DEFAULT '',
            offline         INTEGER DEFAULT 1,
            total_findings  INTEGER DEFAULT 0,
            report_dir      TEXT DEFAULT '',
            started_at      TEXT DEFAULT '',
            finished_at     TEXT DEFAULT '',
            error_message   TEXT DEFAULT '',
            FOREIGN KEY (project_id) REFERENCES projects(id)
        );

        CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
    """)
    conn.commit()
    conn.close()
