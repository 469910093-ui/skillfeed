"""SQLite 存储：用户 / UGC 帖 / 反应。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

# users 的 DDL 单独抽出来：迁移时要用同一份 DDL 建一张临时表再搬数据，
# 抄两份必然漂移（一份加了列另一份没加，只有老库会炸，本地测不出来）。
#
# github_id 现在可空——主站 V1 是微信登录，GitHub 降为可选绑定。
# 三个身份列（github_id / wechat_openid / phone）都可空，唯一性靠下面的
# **部分唯一索引**保证：普通 UNIQUE 会把「一堆空串」判成重复，而 ALTER TABLE
# ADD COLUMN 给老行填的是 NULL、新写入代码稍不注意就会填 ''，两种都得排除。
USERS_DDL = """
CREATE TABLE IF NOT EXISTS {name} (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id INTEGER,
  wechat_openid TEXT,
  unionid TEXT,
  phone TEXT,
  login TEXT NOT NULL,
  nickname TEXT,
  avatar_url TEXT,
  name TEXT,
  plan TEXT DEFAULT 'free',
  plan_until TEXT,
  created_at TEXT NOT NULL
);
"""

# users 的列顺序即迁移时的搬运列表，新增身份列要同步加进来
USERS_COLUMNS: tuple[tuple[str, str], ...] = (
    ("id", "INTEGER"),
    ("github_id", "INTEGER"),
    ("wechat_openid", "TEXT"),
    ("unionid", "TEXT"),
    ("phone", "TEXT"),
    ("login", "TEXT"),
    ("nickname", "TEXT"),
    ("avatar_url", "TEXT"),
    ("name", "TEXT"),
    ("plan", "TEXT DEFAULT 'free'"),
    ("plan_until", "TEXT"),
    ("created_at", "TEXT"),
)

# 这几条索引不能进 SCHEMA：老库执行 SCHEMA 时 users 还没有 wechat_openid 列，
# `CREATE INDEX ... ON users(wechat_openid)` 会直接报 no such column。
# 必须等 _migrate_users 把列补齐之后再建，见 init_db 的调用顺序。
USER_INDEXES = (
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github ON users(github_id) "
        "WHERE github_id IS NOT NULL"
    ),
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_wechat ON users(wechat_openid) "
        "WHERE wechat_openid IS NOT NULL AND wechat_openid <> ''"
    ),
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_unionid ON users(unionid) "
        "WHERE unionid IS NOT NULL AND unionid <> ''"
    ),
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) "
        "WHERE phone IS NOT NULL AND phone <> ''"
    ),
)

SCHEMA = USERS_DDL.format(name="users") + """

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

CREATE TABLE IF NOT EXISTS moderation_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER,
  action TEXT NOT NULL,
  post_id INTEGER,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

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
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

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

-- 短信验证码。存的是 HMAC 摘要而不是明文：这张表被读出来（备份泄露、
-- 误加日志、SQL 注入读表）时，明文码等于「任何人可以登录任何手机号」。
-- 一个手机号同时只有一个在途验证码（PRIMARY KEY 覆盖），重发即覆盖旧码；
-- attempts 是**服务端**的失败计数，验证成功即删行 —— 单次有效靠删行保证，
-- 不靠客户端自觉。
CREATE TABLE IF NOT EXISTS sms_codes (
  phone       TEXT PRIMARY KEY,
  code_hash   TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0
);

-- 免费用户当天解锁过的发现条目。订阅用户不写这张表。
CREATE TABLE IF NOT EXISTS feed_unlocks (
  user_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  item_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, day, item_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_feed_unlocks_user_day
  ON feed_unlocks(user_id, day);

-- 订阅订单。开通只信 status=paid 这一跳（回调验签之后），创建订单本身不发权益。
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  out_trade_no TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  sku TEXT NOT NULL,
  amount_fen INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY',
  status TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'wechat',
  provider_txn_id TEXT,
  paid_at TEXT,
  plan_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_orders_user_created
  ON orders(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS site_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
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


def _table_columns(conn: sqlite3.Connection, table: str) -> dict[str, sqlite3.Row]:
    return {r["name"]: r for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _rebuild_users(conn: sqlite3.Connection) -> None:
    """把 users 换成新 DDL（唯一目的：摘掉 github_id 的 NOT NULL）。

    SQLite 没有 ALTER COLUMN，只能建新表 → 搬数据 → 换名字。两个 PRAGMA 是必须的：

    - `foreign_keys=OFF`：posts.author_id / reactions.user_id 都指向 users。
      开着外键去 DROP TABLE users，子表那些行会被当成违约处理。
    - `legacy_alter_table=ON`：SQLite ≥3.25 的 RENAME 会顺手改写其它表里对旧名字的
      引用。这里 users 已经被 drop 了，posts 的 FK 正指着一个不存在的表名，
      新行为会在 rename 时报「no such table: main.users」。开 legacy 就是纯改名，
      posts 里写的还是 `users`，rename 完那个名字又存在了，引用自动接回去。

    id 是显式搬过去的（不是重新自增），所以既有 posts.author_id 仍然指得对。
    """
    old = _table_columns(conn, "users")
    keep = [c for c, _ in USERS_COLUMNS if c in old]
    cols = ",".join(keep)
    conn.commit()  # PRAGMA 在事务里是空操作，先把隐式事务关掉
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("PRAGMA legacy_alter_table = ON")
    try:
        conn.execute("BEGIN")
        conn.execute(USERS_DDL.format(name="users_rebuild"))
        conn.execute(f"INSERT INTO users_rebuild ({cols}) SELECT {cols} FROM users")
        conn.execute("DROP TABLE users")
        conn.execute("ALTER TABLE users_rebuild RENAME TO users")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA legacy_alter_table = OFF")
        conn.execute("PRAGMA foreign_keys = ON")


def _migrate_users(conn: sqlite3.Connection) -> None:
    """把老库的 users 抬到新形状。对新库是纯 no-op。

    只加列不删列：老库里可能有本 schema 不认识的列（另一支改的），
    删掉等于把别人的数据丢了。
    """
    cols = _table_columns(conn, "users")
    if not cols:
        return
    for name, decl in USERS_COLUMNS:
        if name not in cols:
            # ADD COLUMN 填的是 NULL 而不是 ''，正好落在部分唯一索引的排除区内
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")
    # 老库是 `github_id INTEGER NOT NULL UNIQUE`，微信用户没有 github_id，
    # 不摘掉这条约束就一行都插不进去
    if cols["github_id"]["notnull"]:
        conn.commit()
        _rebuild_users(conn)


_POST_EXTRA_COLS: tuple[tuple[str, str], ...] = (
    ("skill_path", "TEXT"),
    ("public_id", "TEXT"),
    ("reject_reason", "TEXT"),
    ("featured", "INTEGER NOT NULL DEFAULT 0"),
    ("github_meta", "TEXT"),
    ("reviewed_at", "TEXT"),
    ("reviewed_by", "INTEGER"),
)

_USER_GOV_COLS: tuple[tuple[str, str], ...] = (
    ("role", "TEXT NOT NULL DEFAULT 'creator'"),
    ("status", "TEXT NOT NULL DEFAULT 'active'"),
    ("trust_level", "TEXT NOT NULL DEFAULT 'new'"),
    ("approved_count", "INTEGER NOT NULL DEFAULT 0"),
)


def _migrate_posts(conn: sqlite3.Connection) -> None:
    post_cols = _table_columns(conn, "posts")
    if post_cols:
        for name, decl in _POST_EXTRA_COLS:
            if name not in post_cols:
                conn.execute(f"ALTER TABLE posts ADD COLUMN {name} {decl}")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_posts_public_id "
            "ON posts(public_id) WHERE public_id IS NOT NULL AND public_id <> ''"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_posts_coord "
            "ON posts(full_name, skill_path) "
            "WHERE full_name IS NOT NULL AND full_name <> '' "
            "AND skill_path IS NOT NULL AND skill_path <> ''"
        )
    user_cols = _table_columns(conn, "users")
    if user_cols:
        for name, decl in _USER_GOV_COLS:
            if name not in user_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {name} {decl}")


def init_db(db_path: Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate_users(conn)
        _migrate_posts(conn)
        for stmt in USER_INDEXES:
            conn.execute(stmt)
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


def _synthetic_login(prefix: str, secret_ish: str) -> str:
    """给没有 GitHub 用户名的登录方式派生一个稳定、不可反推的展示 ID。

    openid / 手机号都不能直接当 login：login 会随 UGC 帖以 `author_login` 出现在
    公开 Feed 里。手机号泄露不用解释；openid 虽然是按应用隔离的假名，
    但它是那个人在本站的登录凭据标识，没有任何理由公开。

    取 blake2b 前 6 字节：稳定（同一 openid 永远同一个 login）、
    不可反推、48 bit 空间对本站规模足够。
    """
    digest = hashlib.blake2b(secret_ish.encode("utf-8"), digest_size=6).hexdigest()
    return f"{prefix}-{digest}"


class IdentityBound(ValueError):
    """这把钥匙已经挂在另一个 users.id 上，不能偷绑。"""


def attach_wechat(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    openid: str,
    unionid: str = "",
    nickname: str = "",
    avatar_url: str = "",
) -> dict[str, Any]:
    """把微信绑到已有户口。已占用则 IdentityBound。"""
    openid = (openid or "").strip()
    if not openid:
        raise ValueError("openid is required")
    unionid = (unionid or "").strip()
    taken = None
    if unionid:
        taken = conn.execute("SELECT * FROM users WHERE unionid=?", (unionid,)).fetchone()
    if taken is None:
        taken = conn.execute(
            "SELECT * FROM users WHERE wechat_openid=?", (openid,),
        ).fetchone()
    if taken and int(taken["id"]) != int(user_id):
        raise IdentityBound("wechat already bound")
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise ValueError("user not found")
    nickname = (nickname or "")[:64] or (row["nickname"] or "")
    avatar_url = (avatar_url or "")[:512] or (row["avatar_url"] or "")
    conn.execute(
        """
        UPDATE users SET wechat_openid=?,
               unionid=COALESCE(NULLIF(?, ''), unionid),
               nickname=?, avatar_url=?
        WHERE id=?
        """,
        (openid, unionid, nickname, avatar_url, user_id),
    )
    return dict(conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def attach_phone(conn: sqlite3.Connection, user_id: int, *, phone: str) -> dict[str, Any]:
    phone = (phone or "").strip()
    if not phone:
        raise ValueError("phone is required")
    taken = conn.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    if taken and int(taken["id"]) != int(user_id):
        raise IdentityBound("phone already bound")
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise ValueError("user not found")
    conn.execute("UPDATE users SET phone=? WHERE id=?", (phone, user_id))
    return dict(conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def attach_github(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    github_id: int,
    login: str,
    avatar_url: str = "",
    name: str = "",
) -> dict[str, Any]:
    taken = conn.execute("SELECT * FROM users WHERE github_id=?", (github_id,)).fetchone()
    if taken and int(taken["id"]) != int(user_id):
        raise IdentityBound("github already bound")
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise ValueError("user not found")
    conn.execute(
        "UPDATE users SET github_id=?, login=?, avatar_url=?, name=? WHERE id=?",
        (github_id, login, avatar_url or (row["avatar_url"] or ""), name or (row["name"] or ""), user_id),
    )
    return dict(conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def list_user_reactions(conn: sqlite3.Connection, user_id: int, *, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT r.kind, r.created_at, p.public_id, p.full_name, p.title, p.github_url
        FROM reactions r
        JOIN posts p ON p.id = r.post_id
        WHERE r.user_id=?
        ORDER BY r.created_at DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def export_account(conn: sqlite3.Connection, user_id: int) -> dict[str, Any]:
    user = get_user(conn, user_id)
    if not user:
        raise ValueError("user not found")
    posts = []
    for p in list_user_posts(conn, user_id, limit=200):
        posts.append({
            "id": p.get("id"),
            "title": p.get("title") or "",
            "description": p.get("description") or "",
            "github_url": p.get("github_url") or "",
            "full_name": p.get("full_name") or "",
            "skill_path": p.get("skill_path") or "",
            "public_id": p.get("public_id") or "",
            "status": p.get("status") or "",
            "created_at": p.get("created_at") or "",
        })
    return {
        "exported_at": _now(),
        "user": user_public(user),
        "posts": posts,
        "reactions": list_user_reactions(conn, user_id),
        "note": "github_url 是作品外链；仓本身仍在 GitHub。这是 SkillFeeder 户口账本。",
    }


def upsert_user(
    conn: sqlite3.Connection,
    *,
    github_id: int,
    login: str,
    avatar_url: str = "",
    name: str = "",
) -> dict[str, Any]:
    """GitHub 身份的 upsert。V1 里 GitHub 已降为可选绑定，但路径保留。"""
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


def upsert_wechat_user(
    conn: sqlite3.Connection,
    *,
    openid: str,
    unionid: str = "",
    nickname: str = "",
    avatar_url: str = "",
) -> dict[str, Any]:
    """微信网页授权身份的 upsert。

    优先按 unionid 认人：同一主体下服务号 / 小程序 / 开放平台的 openid 各不相同，
    只认 openid 的话以后接第二个入口就会给同一个人开第二个账号。
    unionid 拿不到（未绑开放平台）时退回 openid。
    """
    openid = (openid or "").strip()
    if not openid:
        raise ValueError("openid is required")
    unionid = (unionid or "").strip()
    row = None
    if unionid:
        row = conn.execute(
            "SELECT * FROM users WHERE unionid = ?", (unionid,),
        ).fetchone()
    if row is None:
        row = conn.execute(
            "SELECT * FROM users WHERE wechat_openid = ?", (openid,),
        ).fetchone()
    nickname = (nickname or "")[:64]
    avatar_url = (avatar_url or "")[:512]
    if row:
        conn.execute(
            """
            UPDATE users SET wechat_openid=?, unionid=COALESCE(NULLIF(?, ''), unionid),
                   nickname=?, avatar_url=? WHERE id=?
            """,
            (openid, unionid, nickname, avatar_url or (row["avatar_url"] or ""), row["id"]),
        )
        return dict(conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone())
    cur = conn.execute(
        """
        INSERT INTO users (wechat_openid, unionid, login, nickname, avatar_url, name, created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            openid,
            unionid or None,
            _synthetic_login("wx", unionid or openid),
            nickname,
            avatar_url,
            nickname,
            _now(),
        ),
    )
    return dict(conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())


def upsert_phone_user(conn: sqlite3.Connection, *, phone: str) -> dict[str, Any]:
    """手机号兜底身份的 upsert。手机号只入库，不进 login、不进任何公开字段。"""
    phone = (phone or "").strip()
    if not phone:
        raise ValueError("phone is required")
    row = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
    if row:
        return dict(row)
    cur = conn.execute(
        "INSERT INTO users (phone, login, nickname, created_at) VALUES (?,?,?,?)",
        (phone, _synthetic_login("u", phone), "", _now()),
    )
    return dict(conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())


def get_user(conn: sqlite3.Connection, user_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_post(conn: sqlite3.Connection, author_id: int, data: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    meta = data.get("github_meta") or {}
    if isinstance(meta, dict):
        meta_s = json.dumps(meta, ensure_ascii=False)
    else:
        meta_s = str(meta or "")
    cur = conn.execute(
        """
        INSERT INTO posts (
          author_id, title, body_md, description, github_url, full_name,
          skill_path, public_id, github_meta,
          scene, scene_l2, scene_label, scene_l2_label, cover_url,
          status, featured, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            author_id,
            data["title"],
            "",
            data.get("description") or "",
            data.get("github_url") or "",
            data.get("full_name") or "",
            data.get("skill_path") or "SKILL.md",
            data.get("public_id") or "",
            meta_s,
            data.get("scene") or "other",
            data.get("scene_l2") or "",
            data.get("scene_label") or "其他",
            data.get("scene_l2_label") or "",
            data.get("cover_url") or "",
            data.get("status") or "pending",
            1 if data.get("featured") else 0,
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
        WHERE p.status IN ('published', 'approved')
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


def count_posts_today(conn: sqlite3.Connection, author_id: int) -> int:
    day = _now()[:10]
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM posts WHERE author_id=? AND created_at >= ?",
        (author_id, day),
    ).fetchone()
    return int(row["n"] or 0)


def find_live_card(conn: sqlite3.Connection, slug: str) -> Optional[dict[str, Any]]:
    """用仓库名或 public_id 找已上架的卡，给 /p/{slug} 短链用。"""
    key = (slug or "").strip()
    if not key or "/" in key or "\\" in key or len(key) > 120:
        return None
    row = conn.execute(
        """
        SELECT * FROM posts
        WHERE status IN ('approved', 'published')
          AND (
            public_id = ?
            OR full_name = ?
            OR full_name LIKE ?
            OR public_id LIKE ?
          )
        ORDER BY updated_at DESC
        LIMIT 1
        """,
        (key, key, "%/" + key, "%/" + key + "::%"),
    ).fetchone()
    return dict(row) if row else None


def find_post_by_coord(
    conn: sqlite3.Connection, full_name: str, skill_path: str,
) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM posts WHERE full_name=? AND skill_path=?",
        (full_name, skill_path),
    ).fetchone()
    return dict(row) if row else None


def list_moderation_queue(
    conn: sqlite3.Connection, *, status: str = "pending", limit: int = 100,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT p.*, u.login AS author_login, u.avatar_url AS author_avatar,
               u.trust_level, u.approved_count, u.status AS author_status
        FROM posts p JOIN users u ON u.id = p.author_id
        WHERE p.status = ?
        ORDER BY p.created_at ASC
        LIMIT ?
        """,
        (status, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def moderate_post(
    conn: sqlite3.Connection,
    post_id: int,
    *,
    action: str,
    actor_id: int,
    note: str = "",
) -> dict[str, Any]:
    post = get_post(conn, post_id)
    if not post:
        raise ValueError("投稿不存在")
    now = _now()
    featured = int(post.get("featured") or 0)
    status = post["status"]
    reject_reason = post.get("reject_reason") or ""
    if action == "approve":
        status = "approved"
        reject_reason = ""
        if post["status"] != "approved":
            conn.execute(
                "UPDATE users SET approved_count = approved_count + 1, "
                "trust_level = CASE WHEN approved_count + 1 >= 3 AND trust_level = 'new' "
                "THEN 'trusted' ELSE trust_level END WHERE id=?",
                (post["author_id"],),
            )
    elif action == "reject":
        if len((note or "").strip()) < 2:
            raise ValueError("拒绝必须填写原因")
        status = "rejected"
        reject_reason = note.strip()
        featured = 0
    elif action == "hide":
        status = "hidden"
        featured = 0
    elif action == "feature":
        if status not in ("approved", "published"):
            raise ValueError("只有已上架的条目能精选")
        status = "approved"
        featured = 1
    elif action == "ban":
        status = "banned"
        featured = 0
    else:
        raise ValueError("未知动作")
    conn.execute(
        """
        UPDATE posts SET status=?, featured=?, reject_reason=?,
               reviewed_at=?, reviewed_by=?, updated_at=? WHERE id=?
        """,
        (status, featured, reject_reason, now, actor_id, now, post_id),
    )
    conn.execute(
        "INSERT INTO moderation_events (actor_id, action, post_id, note, created_at) "
        "VALUES (?,?,?,?,?)",
        (actor_id, action, post_id, note or "", now),
    )
    out = get_post(conn, post_id)
    if out is None:
        raise ValueError("投稿不存在")
    return out


def set_user_banned(conn: sqlite3.Connection, user_id: int, banned: bool) -> None:
    conn.execute(
        "UPDATE users SET status=? WHERE id=?",
        ("banned" if banned else "active", user_id),
    )


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


def mask_phone(phone: str) -> str:
    """`13812345678` → `138****5678`。给「我的账户」显示用。

    返回掩码而不是原号：这个字段会进 /auth/me 的响应，也就是会进浏览器、
    可能进前端日志。用户需要认出「我是用哪个号登的」，不需要看到完整号码。
    """
    p = (phone or "").strip()
    if len(p) < 7:
        return "*" * len(p)
    return f"{p[:3]}****{p[-4:]}"


def user_public(u: dict[str, Any]) -> dict[str, Any]:
    """能安全交给前端的用户字段。

    白名单而不是黑名单：`SELECT *` 出来的行里有 phone、wechat_openid、unionid，
    哪天有人往 users 加一列凭据，黑名单写法会默认把它发出去。
    """
    nickname = (u.get("nickname") or "").strip()
    name = (u.get("name") or "").strip()
    return {
        "id": u["id"],
        "login": u["login"],
        "avatar_url": u.get("avatar_url") or "",
        "name": name,
        "nickname": nickname,
        # 前端拿这个直接渲染，不用自己排优先级
        "display_name": nickname or name or u["login"],
        "phone_masked": mask_phone(u.get("phone") or ""),
        # 「用什么登进来的」：给「我的账户」tab 显示绑定状态用
        "providers": [
            k for k, v in (
                ("wechat", u.get("wechat_openid")),
                ("phone", u.get("phone")),
                ("github", u.get("github_id")),
            ) if v
        ],
        "plan": (u.get("plan") or "free") or "free",
        "plan_until": u.get("plan_until") or "",
        "subscriber": _user_is_subscriber(u),
        "trust_level": u.get("trust_level") or "new",
        "approved_count": int(u.get("approved_count") or 0),
    }


def _user_is_subscriber(u: dict[str, Any]) -> bool:
    # 延迟导入：entitlement 不依赖 db，这边可以读它的判定，避免两套过期规则。
    from server.entitlement import is_subscriber
    return is_subscriber(u)


def set_user_plan(
    conn: sqlite3.Connection,
    user_id: int,
    plan: str,
    plan_until: Optional[str] = None,
) -> None:
    conn.execute(
        "UPDATE users SET plan=?, plan_until=? WHERE id=?",
        (plan, plan_until, user_id),
    )


def insert_order(conn: sqlite3.Connection, row: dict[str, Any]) -> dict[str, Any]:
    cur = conn.execute(
        """
        INSERT INTO orders (
          out_trade_no, user_id, sku, amount_fen, currency, status, provider,
          provider_txn_id, paid_at, plan_until, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            row["out_trade_no"],
            int(row["user_id"]),
            row["sku"],
            int(row["amount_fen"]),
            row.get("currency") or "CNY",
            row.get("status") or "pending",
            row.get("provider") or "wechat",
            row.get("provider_txn_id"),
            row.get("paid_at"),
            row.get("plan_until"),
            row["created_at"],
            row["updated_at"],
        ),
    )
    return get_order(conn, int(cur.lastrowid))  # type: ignore[return-value]


def get_order(conn: sqlite3.Connection, order_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    return dict(row) if row else None


def get_order_by_trade_no(
    conn: sqlite3.Connection, out_trade_no: str,
) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM orders WHERE out_trade_no=?", (out_trade_no,),
    ).fetchone()
    return dict(row) if row else None


def list_orders_for_user(
    conn: sqlite3.Connection, user_id: int, *, limit: int = 20,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT ?",
        (int(user_id), max(1, min(100, int(limit)))),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_order_paid(
    conn: sqlite3.Connection,
    order_id: int,
    *,
    provider_txn_id: str,
    paid_at: str,
    plan_until: Optional[str],
) -> dict[str, Any]:
    now = _now()
    conn.execute(
        """
        UPDATE orders SET status='paid', provider_txn_id=?, paid_at=?,
               plan_until=?, updated_at=? WHERE id=?
        """,
        (provider_txn_id, paid_at, plan_until, now, order_id),
    )
    return get_order(conn, order_id)  # type: ignore[return-value]


# —— 短信验证码 ——

def put_sms_code(
    conn: sqlite3.Connection, *, phone: str, code_hash: str, ttl_s: int,
) -> None:
    """写入/覆盖某手机号的在途验证码。重发即作废旧码。"""
    now = datetime.now(timezone.utc)
    conn.execute(
        """
        INSERT INTO sms_codes (phone, code_hash, created_at, expires_at, attempts)
        VALUES (?,?,?,?,0)
        ON CONFLICT(phone) DO UPDATE SET
          code_hash = excluded.code_hash,
          created_at = excluded.created_at,
          expires_at = excluded.expires_at,
          attempts = 0
        """,
        (
            phone,
            code_hash,
            now.isoformat(),
            (now + timedelta(seconds=max(1, int(ttl_s)))).isoformat(),
        ),
    )


def get_sms_code(conn: sqlite3.Connection, phone: str) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM sms_codes WHERE phone=?", (phone,)).fetchone()
    return dict(row) if row else None


def bump_sms_attempt(conn: sqlite3.Connection, phone: str) -> int:
    """失败计数 +1，返回新值。计数在服务端，客户端改不了。"""
    conn.execute("UPDATE sms_codes SET attempts = attempts + 1 WHERE phone=?", (phone,))
    row = conn.execute("SELECT attempts FROM sms_codes WHERE phone=?", (phone,)).fetchone()
    return int(row["attempts"]) if row else 0


def drop_sms_code(conn: sqlite3.Connection, phone: str) -> None:
    """删行即作废。验证成功、尝试超限、过期都走这里 —— 单次有效靠它保证。"""
    conn.execute("DELETE FROM sms_codes WHERE phone=?", (phone,))


def prune_sms_codes(conn: sqlite3.Connection) -> int:
    cur = conn.execute("DELETE FROM sms_codes WHERE expires_at < ?", (_now(),))
    return cur.rowcount or 0


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


def link_device_user(conn: sqlite3.Connection, device_id: str, user_id: int) -> None:
    if not device_id or not user_id:
        return
    conn.execute(
        "UPDATE devices SET user_id=? WHERE device_id=? AND (user_id IS NULL OR user_id=?)",
        (int(user_id), device_id, int(user_id)),
    )


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


def load_user_reactions(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    actions: tuple[str, ...] = ("useful", "save", "open_github"),
    limit: int = 500,
) -> list[dict[str, Any]]:
    """账号自己的正向动作流水，供「我的」面板跨设备回看。

    和 :func:`load_device_reactions` 的区别：这里按 ``user_id`` 聚合该账号下
    **所有**设备（含已 ``merged_into`` 主设备的从设备）的动作——登录后并档，
    旧设备上点过的赞/收藏仍要能在新设备上看到。按 ``(action, item_key)``
    去重取最早那次，和设备版口径一致。
    """
    if not actions:
        return []
    placeholders = ",".join("?" * len(actions))
    rows = conn.execute(
        f"""
        SELECT action, item_key, scene, scene_l2, owner, language, source,
               MIN(ts) AS ts
        FROM events
        WHERE device_id IN (SELECT device_id FROM devices WHERE user_id = ?)
          AND item_key != ''
          AND action IN ({placeholders})
        GROUP BY action, item_key
        ORDER BY ts DESC
        LIMIT ?
        """,
        (int(user_id), *actions, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def user_saved_full_names(
    conn: sqlite3.Connection, user_id: int, *, limit: int = 1000
) -> list[str]:
    """账号收藏过的 ``item_key``（= 卡片 full_name）数组，按收藏时间倒序、去重。

    给前端「我的 → 查看收藏」做跨设备一致列表：列表和计数都从这里出，
    不会再出现「计数读云端、列表读本机」两边对不上。
    """
    rows = conn.execute(
        """
        SELECT item_key, MIN(ts) AS ts
        FROM events
        WHERE device_id IN (SELECT device_id FROM devices WHERE user_id = ?)
          AND action = 'save'
          AND item_key != ''
        GROUP BY item_key
        ORDER BY ts DESC
        LIMIT ?
        """,
        (int(user_id), limit),
    ).fetchall()
    return [str(r["item_key"]) for r in rows if r["item_key"]]


def user_liked_full_names(
    conn: sqlite3.Connection, user_id: int, *, limit: int = 1000
) -> list[str]:
    """账号赞过的 ``item_key`` 数组，口径同 :func:`user_saved_full_names`。"""
    rows = conn.execute(
        """
        SELECT item_key, MIN(ts) AS ts
        FROM events
        WHERE device_id IN (SELECT device_id FROM devices WHERE user_id = ?)
          AND action = 'useful'
          AND item_key != ''
        GROUP BY item_key
        ORDER BY ts DESC
        LIMIT ?
        """,
        (int(user_id), limit),
    ).fetchall()
    return [str(r["item_key"]) for r in rows if r["item_key"]]


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


SITE_SETTING_DEFAULTS: dict[str, str] = {
    "slogan": "每刷一下，就快人一步",
    "search_placeholder": "短关键词更好，如：去AI味 / 剪视频",
    "logo_url": "",
    "review_webhook": "",
}
PUBLIC_SITE_KEYS: tuple[str, ...] = ("slogan", "search_placeholder", "logo_url")


def get_site_setting(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM site_settings WHERE key=?", (key,)).fetchone()
    if row and row["value"] is not None:
        return str(row["value"])
    return SITE_SETTING_DEFAULTS.get(key, "")


def set_site_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    if key not in SITE_SETTING_DEFAULTS:
        raise ValueError(f"unknown site setting: {key}")
    conn.execute(
        """
        INSERT INTO site_settings(key, value, updated_at) VALUES(?,?,?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """,
        (key, value, _now()),
    )


def list_site_settings(conn: sqlite3.Connection, *, public_only: bool = False) -> dict[str, str]:
    keys = PUBLIC_SITE_KEYS if public_only else tuple(SITE_SETTING_DEFAULTS)
    out = {k: SITE_SETTING_DEFAULTS[k] for k in keys}
    rows = conn.execute(
        f"SELECT key, value FROM site_settings WHERE key IN ({','.join('?' * len(keys))})",
        keys,
    ).fetchall()
    for row in rows:
        out[row["key"]] = str(row["value"] or "")
    return out


def op_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    def count(sql: str, *args: Any) -> int:
        row = conn.execute(sql, args).fetchone()
        return int((row["n"] if row else 0) or 0)

    pending = list_moderation_queue(conn, status="pending", limit=20)
    day = _now()[:10]
    return {
        "users": count("SELECT COUNT(*) AS n FROM users"),
        "posts_total": count("SELECT COUNT(*) AS n FROM posts"),
        "posts_pending": count("SELECT COUNT(*) AS n FROM posts WHERE status='pending'"),
        "posts_published": count(
            "SELECT COUNT(*) AS n FROM posts WHERE status IN ('published','approved')"
        ),
        "posts_rejected": count("SELECT COUNT(*) AS n FROM posts WHERE status='rejected'"),
        "events_today": count("SELECT COUNT(*) AS n FROM events WHERE ts >= ?", day),
        "sessions_today": count(
            "SELECT COUNT(DISTINCT session_id) AS n FROM events WHERE ts >= ?", day,
        ),
        "pending": pending,
    }


JOURNEY_NOISE = frozenset({"impression", "dwell"})


def journey_kpis(conn: sqlite3.Connection, *, hours: int = 24) -> dict[str, Any]:
    hours = max(1, min(24 * 30, int(hours)))
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).isoformat()
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    def count(sql: str, *args: Any) -> int:
        row = conn.execute(sql, args).fetchone()
        return int((row["n"] if row else 0) or 0)

    actions = [
        {"action": r["action"], "n": int(r["n"] or 0)}
        for r in conn.execute(
            """
            SELECT action, COUNT(*) AS n FROM events
            WHERE ts >= ? AND action NOT IN ('impression', 'dwell')
            GROUP BY action ORDER BY n DESC LIMIT 12
            """,
            (cutoff,),
        )
    ]
    return {
        "hours": hours,
        "events": count(
            "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND action NOT IN ('impression','dwell')",
            cutoff,
        ),
        "sessions": count(
            "SELECT COUNT(DISTINCT session_id) AS n FROM events WHERE ts >= ?", cutoff,
        ),
        "devices_7d": count(
            "SELECT COUNT(DISTINCT device_id) AS n FROM events WHERE ts >= ?", week,
        ),
        "actions": actions,
    }


def list_journey_sessions(
    conn: sqlite3.Connection, *, hours: int = 72, limit: int = 40,
) -> list[dict[str, Any]]:
    hours = max(1, min(24 * 30, int(hours)))
    limit = max(1, min(200, int(limit)))
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).isoformat()
    heads = conn.execute(
        """
        SELECT session_id, MIN(ts) AS started, MAX(ts) AS ended,
               COUNT(*) AS steps, device_id
        FROM events
        WHERE ts >= ? AND action NOT IN ('impression', 'dwell')
        GROUP BY session_id
        ORDER BY ended DESC
        LIMIT ?
        """,
        (cutoff, limit),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for head in heads:
        sid = head["session_id"]
        steps = [
            dict(r)
            for r in conn.execute(
                """
                SELECT e.ts, e.action, e.item_key, e.source, e.owner, e.device_id,
                       u.login AS user_login
                FROM events e
                LEFT JOIN devices d ON d.device_id = e.device_id
                LEFT JOIN users u ON u.id = d.user_id
                WHERE e.session_id=? AND e.action NOT IN ('impression', 'dwell')
                ORDER BY e.ts ASC
                LIMIT 80
                """,
                (sid,),
            )
        ]
        path = " → ".join(
            _journey_step_label(s["action"], s.get("item_key") or "")
            for s in steps
        )
        out.append({
            "session_id": sid,
            "device_id": head["device_id"],
            "user_login": next((s.get("user_login") for s in steps if s.get("user_login")), ""),
            "started": head["started"],
            "ended": head["ended"],
            "steps": int(head["steps"] or 0),
            "path": path,
            "events": steps,
        })
    return out


def list_journey_rows(
    conn: sqlite3.Connection, *, hours: int = 72, limit: int = 2000,
) -> list[dict[str, Any]]:
    hours = max(1, min(24 * 30, int(hours)))
    limit = max(1, min(10000, int(limit)))
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).isoformat()
    rows = conn.execute(
        """
        SELECT e.ts, e.session_id, e.device_id, e.action, e.item_key, e.source,
               e.owner, u.login AS user_login
        FROM events e
        LEFT JOIN devices d ON d.device_id = e.device_id
        LEFT JOIN users u ON u.id = d.user_id
        WHERE e.ts >= ? AND e.action NOT IN ('impression', 'dwell')
        ORDER BY e.ts DESC
        LIMIT ?
        """,
        (cutoff, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _journey_step_label(action: str, item_key: str) -> str:
    labels = {
        "session_start": "进入",
        "view_tab": "开" + (item_key or "页"),
        "search": "搜" + (item_key[:16] if item_key else ""),
        "open_card": "看卡",
        "close_card": "关卡",
        "open_github": "GitHub",
        "useful": "赞",
        "save": "藏",
        "bad": "不感兴趣",
        "login_click": "去登录",
        "publish_view": "看发布",
        "publish_submit": "投稿",
        "follow": "关注",
        "unfollow": "取关",
        "coach": "引导",
        "expand_detail": "展开",
    }
    return labels.get(action, action)
