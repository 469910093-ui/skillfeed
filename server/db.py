"""SQLite 存储：用户 / UGC 帖 / 反应。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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

-- 匿名设备。公众号登录还没做完，现阶段「二次进入的用户」只能靠这个识别。
-- merged_into 而不是删行：并档后客户端可能还用旧 device_id 上报一段时间，
-- 读路径统一顺链解析，保证幂等可重放。
CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  user_id     INTEGER,
  merged_into TEXT,
  ua_hash     TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  item_key TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  position INTEGER,
  position_band INTEGER,
  dwell_ms INTEGER,
  scene TEXT, scene_l2 TEXT, owner TEXT, language TEXT, source TEXT, scope TEXT,
  ts TEXT NOT NULL,
  client_ts TEXT NOT NULL DEFAULT '',
  UNIQUE(device_id, session_id, item_key, action, client_ts)
);

CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device_id, ts DESC);

CREATE TABLE IF NOT EXISTS item_stats (
  item_key TEXT NOT NULL,
  position_band INTEGER NOT NULL,
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (item_key, position_band)
);

CREATE TABLE IF NOT EXISTS device_affinity (
  device_id TEXT NOT NULL,
  dim TEXT NOT NULL,
  key TEXT NOT NULL,
  weight REAL NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, dim, key)
);

CREATE TABLE IF NOT EXISTS device_focus (
  device_id TEXT NOT NULL,
  dim TEXT NOT NULL,
  key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (device_id, dim, key)
);

CREATE TABLE IF NOT EXISTS device_suppress (
  device_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  key TEXT NOT NULL,
  weight REAL NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (device_id, scope, key)
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


# —— 设备与埋点 ——

def touch_device(conn: sqlite3.Connection, device_id: str, *, ua_hash: str = "") -> bool:
    """返回 True 表示这是首次见到该设备。

    设备凭据只在首次注册时下发一次，所以调用方需要知道「是不是新的」。
    """
    now = _now()
    before = conn.total_changes
    conn.execute(
        """
        INSERT OR IGNORE INTO devices (device_id, first_seen, last_seen, ua_hash)
        VALUES (?,?,?,?)
        """,
        (device_id, now, now, ua_hash),
    )
    created = conn.total_changes > before
    if not created:
        conn.execute(
            "UPDATE devices SET last_seen=? WHERE device_id=?", (now, device_id),
        )
    return created


def resolve_device(conn: sqlite3.Connection, device_id: str, *, max_hops: int = 8) -> str:
    """顺 merged_into 链找到主设备。链有环或过长就地停下，不死循环。"""
    seen = {device_id}
    cur = device_id
    for _ in range(max_hops):
        row = conn.execute(
            "SELECT merged_into FROM devices WHERE device_id=?", (cur,),
        ).fetchone()
        nxt = (row["merged_into"] if row else None) or ""
        if not nxt or nxt in seen:
            return cur
        seen.add(nxt)
        cur = nxt
    return cur


_EVENT_COLS = (
    "device_id", "session_id", "item_key", "action", "position", "position_band",
    "dwell_ms", "scene", "scene_l2", "owner", "language", "source", "scope",
    "ts", "client_ts",
)


_TEXT_COLS = frozenset({"device_id", "session_id", "item_key", "action", "ts", "client_ts"})


def insert_events(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """批量写事件，返回真正入库的那些。

    逐行插而不是 executemany：CTR 统计只能给「真的写进去了」的行加数，
    executemany 拿不到逐行的 OR IGNORE 结果，重试上报就会把点击数刷高。
    """
    sql = (
        f"INSERT OR IGNORE INTO events ({','.join(_EVENT_COLS)}) "
        f"VALUES ({','.join('?' * len(_EVENT_COLS))})"
    )
    accepted: list[dict[str, Any]] = []
    for r in rows:
        params = tuple(
            (r.get(c) or "") if c in _TEXT_COLS else r.get(c)
            for c in _EVENT_COLS
        )
        before = conn.total_changes
        conn.execute(sql, params)
        if conn.total_changes > before:
            accepted.append(r)
    return accepted


def bump_item_stats(
    conn: sqlite3.Connection,
    *,
    item_key: str,
    position_band: int,
    impressions: int = 0,
    clicks: int = 0,
) -> None:
    now = _now()
    conn.execute(
        """
        INSERT INTO item_stats (item_key, position_band, impressions, clicks, first_seen_at, updated_at)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(item_key, position_band) DO UPDATE SET
          impressions = impressions + excluded.impressions,
          clicks = clicks + excluded.clicks,
          updated_at = excluded.updated_at
        """,
        (item_key, position_band, impressions, clicks, now, now),
    )


def load_item_stats(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        "SELECT item_key, position_band, impressions, clicks, first_seen_at FROM item_stats",
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        bucket = out.setdefault(r["item_key"], {
            "impressions": {}, "clicks": {}, "first_seen_at": r["first_seen_at"],
        })
        bucket["impressions"][int(r["position_band"])] = int(r["impressions"])
        bucket["clicks"][int(r["position_band"])] = int(r["clicks"])
        if r["first_seen_at"] and (
            not bucket["first_seen_at"] or r["first_seen_at"] < bucket["first_seen_at"]
        ):
            bucket["first_seen_at"] = r["first_seen_at"]
    return out


def load_device_events(
    conn: sqlite3.Connection, device_id: str, *, limit: int = 2000,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE device_id=? ORDER BY ts DESC LIMIT ?",
        (device_id, limit),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def load_device_affinity(conn: sqlite3.Connection, device_id: str) -> dict[str, dict[str, tuple]]:
    rows = conn.execute(
        "SELECT dim, key, weight, updated_at FROM device_affinity WHERE device_id=?",
        (device_id,),
    ).fetchall()
    out: dict[str, dict[str, tuple]] = {}
    for r in rows:
        out.setdefault(r["dim"], {})[r["key"]] = (float(r["weight"]), r["updated_at"])
    return out


def save_device_affinity(
    conn: sqlite3.Connection, device_id: str, affinity: dict[str, dict[str, tuple]],
) -> None:
    for dim, bucket in (affinity or {}).items():
        for key, row in bucket.items():
            weight, updated = row if isinstance(row, (tuple, list)) else (row, _now())
            conn.execute(
                """
                INSERT INTO device_affinity (device_id, dim, key, weight, updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(device_id, dim, key) DO UPDATE SET
                  weight = excluded.weight, updated_at = excluded.updated_at
                """,
                (device_id, dim, key, float(weight), str(updated or _now())),
            )


def load_device_focus(conn: sqlite3.Connection, device_id: str) -> list[tuple[str, str]]:
    rows = conn.execute(
        "SELECT dim, key FROM device_focus WHERE device_id=?", (device_id,),
    ).fetchall()
    return [(r["dim"], r["key"]) for r in rows]


def set_device_focus(
    conn: sqlite3.Connection, device_id: str, focus: list[tuple[str, str]],
) -> None:
    """全量覆盖：前端上报的是当前完整关注集，不是增量 diff。"""
    conn.execute("DELETE FROM device_focus WHERE device_id=?", (device_id,))
    now = _now()
    for dim, key in focus or []:
        if dim and key:
            conn.execute(
                "INSERT OR IGNORE INTO device_focus (device_id, dim, key, created_at) VALUES (?,?,?,?)",
                (device_id, str(dim)[:20], str(key)[:80], now),
            )


def load_device_suppress(conn: sqlite3.Connection, device_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT scope, key, weight, created_at, expires_at FROM device_suppress WHERE device_id=?",
        (device_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def upsert_suppress(conn: sqlite3.Connection, device_id: str, row: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO device_suppress (device_id, scope, key, weight, created_at, expires_at)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(device_id, scope, key) DO UPDATE SET
          weight = MAX(weight, excluded.weight),
          created_at = excluded.created_at,
          expires_at = excluded.expires_at
        """,
        (
            device_id, row["scope"], row["key"], float(row.get("weight") or 0),
            row.get("created_at") or _now(), row.get("expires_at") or _now(),
        ),
    )


def ingest_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """摄入侧的持久化事实：总量、最后一条时间、按动作分布、设备数。

    这三个量必须来自库而不是进程计数器——进程重启会把计数器清零，
    而「自 7 月 27 日起零新增」这种事恰恰要跨重启才看得出来。
    """
    row = conn.execute(
        "SELECT COUNT(*) AS n, MAX(ts) AS last_ts FROM events",
    ).fetchone()
    by_action = {
        r["action"]: int(r["n"])
        for r in conn.execute(
            "SELECT action, COUNT(*) AS n FROM events GROUP BY action",
        ).fetchall()
    }
    stats = conn.execute(
        "SELECT COALESCE(SUM(impressions),0) AS imp, COALESCE(SUM(clicks),0) AS clk "
        "FROM item_stats",
    ).fetchone()
    devices = conn.execute("SELECT COUNT(*) AS n FROM devices").fetchone()
    return {
        "events_total": int(row["n"] or 0),
        "last_event_at": row["last_ts"],
        "events_by_action": by_action,
        "impressions_total": int(stats["imp"] or 0),
        "clicks_total": int(stats["clk"] or 0),
        "devices_total": int(devices["n"] or 0),
    }


def load_device_reactions(
    conn: sqlite3.Connection,
    device_id: str,
    *,
    actions: tuple[str, ...] = ("useful", "save", "open_github"),
    limit: int = 500,
) -> list[dict[str, Any]]:
    """设备自己的正向动作流水，供「我的」面板回看。

    按 (action, item_key) 去重取最早那次：用户关心的是「我赞过这个」，
    不是「我赞过它 3 次」；取最早那次才能按收藏时间排序。
    """
    if not actions:
        return []
    placeholders = ",".join("?" * len(actions))
    rows = conn.execute(
        f"""
        SELECT action, item_key, scene, scene_l2, owner, language, source,
               MIN(ts) AS ts
        FROM events
        WHERE device_id = ? AND item_key != '' AND action IN ({placeholders})
        GROUP BY action, item_key
        ORDER BY ts DESC
        LIMIT ?
        """,
        (device_id, *actions, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def item_stats_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """扁平导出全站曝光/点击。只有聚合量，没有任何设备维度信息。"""
    rows = conn.execute(
        "SELECT item_key, position_band, impressions, clicks, first_seen_at "
        "FROM item_stats ORDER BY item_key, position_band",
    ).fetchall()
    return [dict(r) for r in rows]


def prune_events(conn: sqlite3.Connection, *, days: int = 30) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    return cur.rowcount or 0
