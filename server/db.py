"""SQLite 存储：用户 / UGC 帖 / 反应。"""

from __future__ import annotations

import hashlib
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


def init_db(db_path: Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate_users(conn)
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
    }


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
