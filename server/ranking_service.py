"""把 SQLite 里的事件/画像喂给 ranking.py 的纯函数核心。

分层原则：ranking.py 不认识数据库，db.py 不认识排序，本模块是唯一的胶水。
这样打分逻辑可以脱库单测，换存储也只动这一个文件。
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import feedback as feedback_mod
import ranking
import ranking_profile
from server import attribution, db

# 事件里允许落库的动作。session_start 也存，它是北极星指标的分母
ALLOWED_ACTIONS = frozenset({
    "session_start", "impression", "dwell", "open_github", "useful", "save",
    "expand_detail", "not_interested", "focus_set", "bad", "wrong_scene",
    # 运营看的操作路径，不进 CTR / 亲和度
    "view_tab", "search", "open_card", "close_card",
    "login_click", "publish_view", "publish_submit",
    "follow", "unfollow", "coach",
})

JOURNEY_ACTIONS = frozenset({
    "view_tab", "search", "open_card", "close_card",
    "login_click", "publish_view", "publish_submit",
    "follow", "unfollow", "coach",
})

# 必须带 item_key 才有意义的动作。session_start / focus_set 是会话级和设备级的，
# 它们没有 item_key 是正常的，不能一并卡掉
ITEM_SCOPED_ACTIONS = ALLOWED_ACTIONS - {"session_start", "focus_set"} - JOURNEY_ACTIONS


def _now() -> datetime:
    return datetime.now(timezone.utc)


def filter_signature(**parts: Any) -> str:
    raw = "|".join(f"{k}={parts.get(k) or ''}" for k in sorted(parts))
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()


# —— 事件入库 ——

def normalize_events(
    device_id: str,
    session_id: str,
    events: list[dict],
    *,
    config: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """返回 (可入库的行, 按原因分类的丢弃计数)。

    第二个返回值不是可选的装饰：这条链路上一次出问题时，前端往一个不存在的
    端点写了一个多月没人察觉。丢弃必须能报数，否则「合法地丢」和「坏了在丢」
    在外部看起来一模一样。
    """
    cfg = ranking.resolve_config(config)
    bands = list(cfg["ctr"]["position_bands"])
    now = now or _now()
    ignore_below = float(cfg["dwell"]["ignore_below_ms"])
    out: list[dict[str, Any]] = []
    rejected: dict[str, int] = {}

    def _reject(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1

    for raw in events or []:
        if not isinstance(raw, dict):
            _reject("not_a_dict")
            continue
        action = (raw.get("action") or "").strip()
        action = feedback_mod.ACTION_ALIASES.get(action, action)
        if action not in ALLOWED_ACTIONS:
            _reject("unknown_action")
            continue
        item_key = (raw.get("item_key") or raw.get("full_name") or "").strip()
        # 条目级动作没带 item_key 就是废数据：CTR 归不到条目、画像归不到维度。
        # 之前这种行照样入库，前端漏传字段在服务端完全看不出来
        if not item_key and action in ITEM_SCOPED_ACTIONS:
            _reject("missing_item_key")
            continue
        dwell = raw.get("dwell_ms")
        try:
            dwell = int(dwell) if dwell is not None else None
        except (TypeError, ValueError):
            dwell = None
        # 甩屏整条丢弃：卡片可能都没渲染完，既不是曝光也不是判断
        if action in ("impression", "dwell") and dwell is not None and dwell < ignore_below:
            _reject("fling")
            continue
        try:
            position = int(raw.get("position")) if raw.get("position") is not None else None
        except (TypeError, ValueError):
            position = None
        band = raw.get("position_band")
        try:
            band = int(band) if band is not None else (
                ranking.position_band(position, bands) if position is not None else None
            )
        except (TypeError, ValueError):
            band = None
        attr = (
            attribution.sanitize_attr(raw)
            if action == "session_start"
            else {
                "channel": "", "referrer": "", "landing": "",
                "utm_source": "", "utm_medium": "", "utm_campaign": "",
            }
        )
        row = {
            "device_id": device_id,
            "session_id": session_id,
            "item_key": item_key,
            "action": action,
            "position": position,
            "position_band": band,
            "dwell_ms": dwell,
            "scene": (raw.get("scene") or "")[:40],
            "scene_l2": (raw.get("scene_l2") or "")[:40],
            "owner": (raw.get("owner") or "")[:80],
            "language": (raw.get("language") or "")[:40],
            "source": (raw.get("source") or attr.get("channel") or "")[:40],
            "scope": (
                ranking_profile.normalize_scope(raw.get("scope"))
                if action == "not_interested" else None
            ),
            **attr,
            "ts": now.isoformat(),
            "client_ts": (str(raw.get("client_ts") or ""))[:40],
            "_focus": raw.get("focus") if action == "focus_set" else None,
        }
        out.append(row)
    return out, rejected


def ingest_events(
    conn: sqlite3.Connection,
    device_id: str,
    session_id: str,
    events: list[dict],
    *,
    config: Optional[dict] = None,
    ua_hash: str = "",
    now: Optional[datetime] = None,
    session_state: Optional["SessionOrderCache"] = None,
) -> dict[str, Any]:
    cfg = ranking.resolve_config(config)
    now = now or _now()
    db.touch_device(conn, device_id, ua_hash=ua_hash)
    target = db.resolve_device(conn, device_id)

    rows, rejected = normalize_events(device_id, session_id, events, config=cfg, now=now)
    focus_payloads = [r.pop("_focus") for r in rows]
    accepted = db.insert_events(conn, rows)
    accepted_ids = {id(r) for r in accepted}
    by_action: dict[str, int] = {}

    for row, focus in zip(rows, focus_payloads):
        if id(row) not in accepted_ids:
            continue
        action = row["action"]
        by_action[action] = by_action.get(action, 0) + 1
        if action == "session_start":
            db.set_device_attribution_if_empty(conn, device_id, row)
        if action == "impression" and row["item_key"]:
            db.bump_item_stats(
                conn, item_key=row["item_key"],
                position_band=int(row["position_band"] or 0), impressions=1,
            )
        elif action == "open_github" and row["item_key"]:
            db.bump_item_stats(
                conn, item_key=row["item_key"],
                position_band=int(row["position_band"] or 0), clicks=1,
            )
        elif action == "focus_set":
            pairs = []
            if isinstance(focus, list):
                for f in focus[:20]:
                    if isinstance(f, dict) and f.get("dim") and f.get("key"):
                        pairs.append((str(f["dim"]), str(f["key"])))
            db.set_device_focus(conn, target, pairs)
        elif action == "not_interested":
            scope = row["scope"] or "item"
            spec = cfg["suppress"].get(scope) or [0.2, 7, 0.02]
            key = {
                "item": row["item_key"],
                "owner": row["owner"],
                "scene_l2": row["scene_l2"],
                "scene": row["scene"],
            }.get(scope) or ""
            if key:
                db.upsert_suppress(conn, target, {
                    "scope": scope,
                    "key": key,
                    "weight": float(spec[0]),
                    "created_at": now.isoformat(),
                    # 存活到衰减到地板以下为止，过期行直接不参与打分
                    "expires_at": (now + timedelta(days=float(spec[1]) * 4)).isoformat(),
                })
            if session_state is not None:
                session_state.note_not_interested(
                    device_id, session_id, row, config=cfg,
                )

    return {
        "accepted": len(accepted),
        "deduped": max(0, len(rows) - len(accepted)),
        "rejected": rejected,
        "by_action": by_action,
    }


# —— 画像与统计 ——

def load_item_stats(conn: sqlite3.Connection) -> dict[str, ranking.ItemStats]:
    out: dict[str, ranking.ItemStats] = {}
    for key, row in db.load_item_stats(conn).items():
        out[key] = ranking.ItemStats(
            impressions=dict(row["impressions"]),
            clicks=dict(row["clicks"]),
            first_seen_at=row.get("first_seen_at"),
        )
    return out


def load_profile(
    conn: sqlite3.Connection,
    device_id: str,
    *,
    config: Optional[dict] = None,
    item_lookup: Optional[dict[str, dict]] = None,
    now: Optional[datetime] = None,
    extra_suppress: Optional[list[dict]] = None,
) -> Optional[ranking.DeviceProfile]:
    if not device_id:
        return None
    target = db.resolve_device(conn, device_id)
    events = db.load_device_events(conn, target)
    if target != device_id:
        events += db.load_device_events(conn, device_id)
    return ranking_profile.build_profile(
        target,
        events,
        base_affinity=db.load_device_affinity(conn, target),
        # extra_suppress 是会话级回声（见 SessionOrderCache.note_not_interested），
        # 只在本次请求里生效，不会被 claim 并档带走
        suppress=db.load_device_suppress(conn, target) + list(extra_suppress or []),
        focus=db.load_device_focus(conn, target),
        item_lookup=item_lookup,
        config=config,
        now=now,
    )


def claim_device(conn: sqlite3.Connection, device_id: str, user_id: int) -> dict[str, Any]:
    """登录后并档。幂等：重复调用不会重复相加。"""
    db.touch_device(conn, device_id)
    row = conn.execute(
        "SELECT device_id FROM devices WHERE user_id=? AND merged_into IS NULL LIMIT 1",
        (user_id,),
    ).fetchone()
    primary = row["device_id"] if row else ""

    if not primary or primary == device_id:
        conn.execute(
            "UPDATE devices SET user_id=?, merged_into=NULL WHERE device_id=?",
            (user_id, device_id),
        )
        return {"ok": True, "primary": device_id, "merged": False}

    current = db.resolve_device(conn, device_id)
    if current == primary:
        return {"ok": True, "primary": primary, "merged": True}

    merged_aff = ranking_profile.merge_affinity(
        db.load_device_affinity(conn, primary),
        db.load_device_affinity(conn, device_id),
    )
    merged_focus = ranking_profile.merge_focus(
        db.load_device_focus(conn, primary),
        db.load_device_focus(conn, device_id),
    )
    merged_sup = ranking_profile.merge_suppress(
        db.load_device_suppress(conn, primary),
        db.load_device_suppress(conn, device_id),
    )
    db.save_device_affinity(conn, primary, merged_aff)
    db.set_device_focus(conn, primary, merged_focus)
    for s in merged_sup:
        db.upsert_suppress(conn, primary, s)
    conn.execute(
        "UPDATE devices SET merged_into=?, user_id=? WHERE device_id=?",
        (primary, user_id, device_id),
    )
    return {"ok": True, "primary": primary, "merged": True}


# —— 会话内顺序固化 ——

def session_scope(device_id: str, session_id: str) -> str:
    return f"{device_id}|{session_id}"


def cache_key(device_id: str, session_id: str, signature: str) -> str:
    return f"{session_scope(device_id, session_id)}|{signature}"


class SessionOrderCache:
    """同一会话内顺序不变：用户刷新/翻页不会找不到刚看过的卡。

    但「顺序不变」和「不感兴趣要当场生效」是直接冲突的两个需求。这里的解法是
    **只冻结已经送出去的那一段**：

    - `mark_served()` 记录本会话每个筛选条件下已经交付到第几条（offset+limit 的高水位）
    - 收到 not_interested 时 `note_not_interested()` 把缓存顺序截断到高水位，
      高水位之前的原样保留（用户已经看过的卡不会移位），之后的下次请求重新排

    结果是：已看过的部分绝对稳定，还没看到的部分立刻按新的负反馈重排。
    这个规则完全靠服务端自己知道的信息（它交付过哪些位置）实现，
    不依赖前端上报滚动位置。
    """

    def __init__(self, ttl_s: float = 1800.0, max_entries: int = 5000) -> None:
        self.ttl_s = float(ttl_s)
        self.max_entries = int(max_entries)
        self._data: dict[str, tuple[float, list[str], int]] = {}
        # 会话级负反馈回声：(scope, key) -> weight。刻意不落库，见 note_not_interested
        self._echo: dict[str, tuple[float, dict[tuple[str, str], float]]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, *, now: Optional[float] = None) -> Optional[list[str]]:
        now = time.monotonic() if now is None else now
        with self._lock:
            row = self._data.get(key)
            if not row:
                return None
            expires, order, _served = row
            if expires <= now:
                self._data.pop(key, None)
                return None
            return list(order)

    def put(self, key: str, order: list[str], *, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._data) >= self.max_entries:
                for k in [k for k, (exp, _o, _s) in self._data.items() if exp <= now]:
                    self._data.pop(k, None)
            if len(self._data) >= self.max_entries:
                self._data.clear()
            served = self._data.get(key, (0.0, [], 0))[2]
            self._data[key] = (now + self.ttl_s, list(order), served)

    def mark_served(self, key: str, upto: int, *, now: Optional[float] = None) -> None:
        """记录这个筛选条件下已经交付到第几条（高水位，只增不减）。"""
        now = time.monotonic() if now is None else now
        with self._lock:
            row = self._data.get(key)
            if not row:
                return
            expires, order, served = row
            self._data[key] = (expires, order, max(served, int(upto)))

    def served_upto(self, key: str) -> int:
        with self._lock:
            row = self._data.get(key)
            return row[2] if row else 0

    def note_not_interested(
        self,
        device_id: str,
        session_id: str,
        row: dict[str, Any],
        *,
        config: Optional[dict] = None,
        now: Optional[float] = None,
    ) -> None:
        """让「不感兴趣」在当前会话就有感。

        持久化那一层（device_suppress）刻意只压用户显式选的那个粒度，因为压错了
        用户既看不见也撤不掉。但只压这一条的话，用户接着往下滑同类内容照样出现，
        这个按钮就成了空头承诺。

        所以在**会话内存**里再加一层更宽的软压制（scene_l2 + owner）：
        - 只活到会话过期，不写库、不跨会话、不进并档，猜错的代价上限是半小时
        - 探索位无视行业级压制（见 ranking.exploration_candidates），
          所以即使压错也留着解封通道
        - **不做一级行业**：那一层占库存三分之一，杀伤半径太大，必须由用户显式选

        这是对 ranking-engine-design §4.1「服务端绝不自行放大作用域」的一处
        有意放宽，放宽的只是**会话内**这一段；持久层的规则原样不动。
        """
        cfg = ranking.resolve_config(config)
        echo_cfg = cfg["session"].get("echo") or {}
        if not echo_cfg.get("enabled", True):
            return
        cap = float(echo_cfg.get("max", 0.35))
        pairs = [
            ("scene_l2", (row.get("scene_l2") or "").strip(),
             float(echo_cfg.get("scene_l2", 0.12))),
            ("owner", (row.get("owner") or "").strip(),
             float(echo_cfg.get("owner", 0.10))),
        ]
        scope = row.get("scope") or "item"
        if scope == "scene":
            return  # 用户已经选了最宽的一级，不需要再放大
        if scope == "scene_l2":
            pairs = [p for p in pairs if p[0] != "scene_l2"]

        now = time.monotonic() if now is None else now
        skey = session_scope(device_id, session_id)
        with self._lock:
            expires, bucket = self._echo.get(skey, (now + self.ttl_s, {}))
            if expires <= now:
                expires, bucket = now + self.ttl_s, {}
            for dim, key, weight in pairs:
                if not key or weight <= 0:
                    continue
                # 同一会话里反复点同一类会累加，但封顶——连点十次也不该等于永久拉黑
                bucket[(dim, key)] = min(cap, bucket.get((dim, key), 0.0) + weight)
            self._echo[skey] = (expires, bucket)

            # 截断到高水位：已送出的部分冻结，未送出的部分下次请求重排
            prefix = f"{skey}|"
            for k in [k for k in self._data if k.startswith(prefix)]:
                exp, order, served = self._data[k]
                self._data[k] = (exp, list(order[:served]), served)

    def session_echo(
        self,
        device_id: str,
        session_id: str,
        *,
        now: Optional[float] = None,
        wall_now: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """转成 ranking.negative_penalty 认识的 suppress 行。"""
        now = time.monotonic() if now is None else now
        wall = wall_now or _now()
        with self._lock:
            entry = self._echo.get(session_scope(device_id, session_id))
            if not entry:
                return []
            expires, bucket = entry
            if expires <= now:
                self._echo.pop(session_scope(device_id, session_id), None)
                return []
            items = list(bucket.items())
        # created_at 取当下：回声不该随会话变老而衰减，它本来就只活半小时
        return [
            {
                "scope": dim,
                "key": key,
                "weight": weight,
                "created_at": wall.isoformat(),
                "expires_at": (wall + timedelta(seconds=self.ttl_s)).isoformat(),
                "session_echo": True,
            }
            for (dim, key), weight in items
        ]

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._echo.clear()


def apply_cached_order(items: list[dict], order: list[str]) -> list[dict]:
    """按缓存顺序还原。缓存里没有的（本轮新增的条目）追加到末尾，不丢。"""
    pos = {key: i for i, key in enumerate(order)}
    tail = len(order)
    return sorted(
        items,
        key=lambda it: pos.get(it.get("id") or it.get("full_name") or "", tail),
    )
