"""SQLite 存储：用户 / UGC 帖 / 反应。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id INTEGER NOT NULL UNIQUE,
  login TEXT NOT NULL,
  avatar_url TEXT,
  name TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  body_md TEXT NOT NULL,
  description TEXT,
  github_url TEXT,
  full_name TEXT,
  scene TEXT,
  scene_l2 TEXT,
  scene_label TEXT,
  scene_l2_label TEXT,
  cover_url TEXT,
  status TEXT NOT NULL DEFAULT 'published',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_posts_status_created
  ON posts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS reactions (
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, post_id, kind),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(post_id) REFERENCES posts(id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_session(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_user(
    conn: sqlite3.Connection,
    *,
    github_id: int,
    login: str,
    avatar_url: str = "",
    name: str = "",
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM users WHERE github_id = ?", (github_id,),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE users SET login=?, avatar_url=?, name=? WHERE id=?",
            (login, avatar_url, name, row["id"]),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
    else:
        cur = conn.execute(
            "INSERT INTO users (github_id, login, avatar_url, name, created_at) VALUES (?,?,?,?,?)",
            (github_id, login, avatar_url, name, _now()),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def get_user(conn: sqlite3.Connection, user_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_post(conn: sqlite3.Connection, author_id: int, data: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    cur = conn.execute(
        """
        INSERT INTO posts (
          author_id, title, body_md, description, github_url, full_name,
          scene, scene_l2, scene_label, scene_l2_label, cover_url,
          status, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            author_id,
            data["title"],
            data["body_md"],
            data.get("description") or "",
            data.get("github_url") or "",
            data.get("full_name") or "",
            data.get("scene") or "other",
            data.get("scene_l2") or "",
            data.get("scene_label") or "其他",
            data.get("scene_l2_label") or "",
            data.get("cover_url") or "",
            data.get("status") or "published",
            now,
            now,
        ),
    )
    return get_post(conn, int(cur.lastrowid))  # type: ignore[return-value]


def get_post(conn: sqlite3.Connection, post_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute(
        """
        SELECT p.*, u.login AS author_login, u.avatar_url AS author_avatar
        FROM posts p JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
        """,
        (post_id,),
    ).fetchone()
    return dict(row) if row else None


def list_published_posts(conn: sqlite3.Connection, *, limit: int = 50, offset: int = 0) -> list[dict]:
    rows = conn.execute(
        """
        SELECT p.*, u.login AS author_login, u.avatar_url AS author_avatar
        FROM posts p JOIN users u ON u.id = p.author_id
        WHERE p.status = 'published'
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def list_user_posts(conn: sqlite3.Connection, user_id: int, *, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        """
        SELECT p.*, u.login AS author_login, u.avatar_url AS author_avatar
        FROM posts p JOIN users u ON u.id = p.author_id
        WHERE p.author_id = ?
        ORDER BY p.created_at DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def set_reaction(
    conn: sqlite3.Connection, *, user_id: int, post_id: int, kind: str, on: bool,
) -> None:
    if on:
        conn.execute(
            """
            INSERT OR IGNORE INTO reactions (user_id, post_id, kind, created_at)
            VALUES (?,?,?,?)
            """,
            (user_id, post_id, kind, _now()),
        )
    else:
        conn.execute(
            "DELETE FROM reactions WHERE user_id=? AND post_id=? AND kind=?",
            (user_id, post_id, kind),
        )


def user_public(u: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": u["id"],
        "login": u["login"],
        "avatar_url": u.get("avatar_url") or "",
        "name": u.get("name") or "",
    }
