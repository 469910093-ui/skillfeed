"""匿名设备画像：事件流 → ranking.DeviceProfile，以及登录后的并档合并。

衰减在构建时按每条事件各自的年龄算（精确），而不是给整个维度存一个
updated_at 再统一衰减（近似）。代价是每次要遍历近期事件，收益是
「上周点了 10 次 + 今天点了 1 次」不会被当成「今天点了 11 次」。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

import ranking

# 单维度权重上限。并档会把两份画像相加，不封顶的话老设备能把新设备完全压死
MAX_AFFINITY = 6.0

POSITIVE_ACTIONS = frozenset({"open_github", "useful", "save", "expand_detail"})
# 构成画像置信度的事件。曝光不算：看到卡片不等于表达了偏好
MEANINGFUL_ACTIONS = POSITIVE_ACTIONS | {"dwell_long", "skip_fast", "not_interested"}

VALID_SCOPES = ("item", "owner", "scene_l2", "scene")


def normalize_scope(value: Any) -> str:
    """scope 缺失/非法时降级为 item——最保守的粒度。

    前端埋点那一轮上线前，not_interested 可能不带 scope。宁可只压这一条，
    也不能替用户猜「他讨厌整个行业」：作用域给宽了会永久杀死品类，
    而 item 级压制的代价只是少推一条。
    """
    s = (str(value or "").strip() or "item").lower()
    return s if s in VALID_SCOPES else "item"


def _dims(row: dict) -> list[tuple[str, str]]:
    return [
        ("scene", (row.get("scene") or "").strip()),
        ("scene_l2", (row.get("scene_l2") or "").strip()),
        ("owner", (row.get("owner") or "").strip()),
        ("language", (row.get("language") or "").strip()),
    ]


def _event_key(row: dict) -> str:
    return (row.get("item_key") or row.get("full_name") or "").strip()


def classify_dwell(row: dict, cfg: dict, opened: set[str]) -> Optional[str]:
    """把 dwell_ms 折成 dwell_long / skip_fast / None。阈值判定放服务端，
    这样调阈值不用发前端版本。"""
    ms = row.get("dwell_ms")
    if not isinstance(ms, (int, float)):
        return None
    d = cfg["dwell"]
    if ms < float(d["ignore_below_ms"]):
        return None  # 甩屏，不是判断
    if ms >= float(d["long_ms"]):
        return "dwell_long"
    if ms < float(d["skip_fast_ms"]):
        # 已经打开过 GitHub 的条目再快速划走不算负信号：已经转化过了
        return None if _event_key(row) in opened else "skip_fast"
    return None


def build_profile(
    device_id: str,
    events: Iterable[dict],
    *,
    base_affinity: Optional[dict[str, dict[str, tuple[float, Any]]]] = None,
    focus: Optional[list[tuple[str, str]]] = None,
    suppress: Optional[list[dict]] = None,
    item_lookup: Optional[dict[str, dict]] = None,
    config: Optional[dict] = None,
    now: Optional[datetime] = None,
    liked_limit: int = 20,
    liked_days: float = 30.0,
) -> ranking.DeviceProfile:
    cfg = config if config and "event_weights" in config else ranking.resolve_config(config)
    now = now or datetime.now(timezone.utc)
    rows = [r for r in events if isinstance(r, dict)]
    rows.sort(key=lambda r: str(r.get("ts") or r.get("client_ts") or ""))

    opened = {_event_key(r) for r in rows if (r.get("action") or "") == "open_github"}
    ew = cfg["event_weights"]
    half = cfg["profile"]["half_life_days"]

    affinity: dict[str, dict[str, float]] = {}
    fatigue: dict[str, tuple[int, Any]] = {}
    derived_suppress: list[dict] = []
    positive_any: set[str] = set()
    liked: list[dict] = []
    meaningful = 0

    def _add(dim: str, key: str, amount: float, age: Optional[float]) -> None:
        if not key or not amount:
            return
        eff = ranking.decay(amount, age, float(half.get(dim, 14)))
        if abs(eff) < 1e-4:
            return
        bucket = affinity.setdefault(dim, {})
        bucket[key] = bucket.get(key, 0.0) + eff

    for row in rows:
        action = (row.get("action") or "").strip()
        ts = row.get("ts") or row.get("client_ts")
        age = ranking.days_since(ts, now)
        key = _event_key(row)

        if action == "dwell":
            action = classify_dwell(row, cfg, opened) or ""
            if not action:
                continue

        if action == "not_interested":
            scope = normalize_scope(row.get("scope"))
            spec = cfg["suppress"].get(scope) or [0.2, 7, 0.02]
            target = {
                "item": key,
                "owner": (row.get("owner") or "").strip(),
                "scene_l2": (row.get("scene_l2") or "").strip(),
                "scene": (row.get("scene") or "").strip(),
            }[scope]
            if target:
                created = ranking.parse_ts(ts) or now
                derived_suppress.append({
                    "scope": scope,
                    "key": target,
                    "weight": float(spec[0]),
                    "created_at": created.isoformat(),
                    "expires_at": (created + timedelta(days=float(spec[1]) * 4)).isoformat(),
                })
            meaningful += 1
            continue

        if action == "impression":
            if key and key not in positive_any:
                count, last = fatigue.get(key, (0, ts))
                newer = last if (last and str(last) > str(ts or "")) else ts
                fatigue[key] = (count + 1, newer)
                for dim, val in _dims(row):
                    _add(dim, val, float(ew["impression_no_action"]), age)
            continue

        weight = ew.get(action)
        if weight is None:
            continue
        meaningful += 1 if action in MEANINGFUL_ACTIONS else 0
        for dim, val in _dims(row):
            _add(dim, val, float(weight), age)
        if key:
            _add("item", key, float(weight), age)
        if action in POSITIVE_ACTIONS:
            positive_any.add(key)
            fatigue.pop(key, None)  # 已经产生正反馈，之前的无动作曝光不再算疲劳
            if age is not None and age <= liked_days:
                hydrated = (item_lookup or {}).get(key)
                liked.append(hydrated or {
                    "id": key,
                    "full_name": key.split("::")[0],
                    "scene": row.get("scene") or "",
                    "scene_l2": row.get("scene_l2") or "",
                    "owner": row.get("owner") or "",
                    "language": row.get("language") or "",
                })

    merged_aff: dict[str, dict[str, tuple[float, Any]]] = {}
    for dim, bucket in affinity.items():
        merged_aff[dim] = {
            k: (max(-MAX_AFFINITY, min(MAX_AFFINITY, v)), now)
            for k, v in bucket.items()
        }
    if base_affinity:
        for dim, bucket in base_affinity.items():
            dst = merged_aff.setdefault(dim, {})
            hl = float(half.get(dim, 14))
            for k, row in bucket.items():
                w, ts = row if isinstance(row, (tuple, list)) else (row, now)
                aged = ranking.decay(float(w), ranking.days_since(ts, now), hl)
                prev = dst.get(k, (0.0, now))[0]
                dst[k] = (max(-MAX_AFFINITY, min(MAX_AFFINITY, prev + aged)), now)

    return ranking.DeviceProfile(
        device_id=device_id,
        affinity=merged_aff,
        focus=list(focus or []),
        suppress=list(suppress or []) + derived_suppress,
        fatigue=fatigue,
        opened_items=opened,
        liked_items=liked[-liked_limit:],
        events=meaningful,
    )


# —— 登录后并档 ——

def merge_affinity(
    primary: dict[str, dict[str, tuple[float, Any]]],
    secondary: dict[str, dict[str, tuple[float, Any]]],
) -> dict[str, dict[str, tuple[float, Any]]]:
    """weight 相加后封顶，updated_at 取较晚的一侧。"""
    out: dict[str, dict[str, tuple[float, Any]]] = {
        dim: dict(bucket) for dim, bucket in (primary or {}).items()
    }
    for dim, bucket in (secondary or {}).items():
        dst = out.setdefault(dim, {})
        for key, row in bucket.items():
            w2, t2 = row if isinstance(row, (tuple, list)) else (row, None)
            w1, t1 = dst.get(key, (0.0, None))
            total = max(-MAX_AFFINITY, min(MAX_AFFINITY, float(w1) + float(w2)))
            newer = t1 if (t1 and str(t1) >= str(t2 or "")) else t2
            dst[key] = (total, newer)
    return out


def merge_focus(
    primary: list[tuple[str, str]],
    secondary: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []
    for row in list(primary or []) + list(secondary or []):
        pair = (row[0], row[1]) if isinstance(row, (tuple, list)) else (row.get("dim"), row.get("key"))
        if pair not in seen and all(pair):
            seen.append(pair)
    return seen


def merge_suppress(primary: list[dict], secondary: list[dict]) -> list[dict]:
    """同 (scope,key) 取较晚的 expires_at 与较大的 weight——压制不因并档被削弱。"""
    out: dict[tuple[str, str], dict] = {}
    for row in list(primary or []) + list(secondary or []):
        scope = normalize_scope(row.get("scope"))
        key = (row.get("key") or "").strip()
        if not key:
            continue
        prev = out.get((scope, key))
        if prev is None:
            out[(scope, key)] = dict(row, scope=scope)
            continue
        merged = dict(prev)
        if str(row.get("expires_at") or "") > str(prev.get("expires_at") or ""):
            merged["expires_at"] = row.get("expires_at")
            merged["created_at"] = row.get("created_at")
        merged["weight"] = max(float(prev.get("weight") or 0), float(row.get("weight") or 0))
        out[(scope, key)] = merged
    return list(out.values())
