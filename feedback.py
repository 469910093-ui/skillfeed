"""用户反馈与埋点事件落盘 feedback.jsonl。

本机单用户版和线上多用户版共用同一套 action 命名和字段，这样
impressions.py / ranking_profile.py 的聚合逻辑只写一份。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import ranking_profile

# 显式态度
ATTITUDE_ACTIONS = frozenset({
    "useful",
    "bad",
    "opened_github",
    "wrong_scene",
    "skip",
    "save",
})

# 行为埋点（排序引擎的 CTR / 疲劳 / 亲和度靠它们）
BEHAVIOR_ACTIONS = frozenset({
    "session_start",
    "impression",
    "dwell",
    "open_github",
    "expand_detail",
    "not_interested",
    "focus_set",
})

VALID_ACTIONS = ATTITUDE_ACTIONS | BEHAVIOR_ACTIONS

# 必须带 item_key（或 full_name）才有意义的动作。session_start 是会话级、
# focus_set 是设备级，它们没有条目是正常的
ITEM_SCOPED_ACTIONS = VALID_ACTIONS - {"session_start", "focus_set"}

# 旧前端发的是 opened_github，排序引擎内部统一用 open_github。
# 只在读取时归一，落盘保持原样：feedback.jsonl 是追加式历史文件，
# 改写盘名字会让同一个动作在文件里前后两副面孔，统计口径直接断裂。
ACTION_ALIASES = {"opened_github": "open_github"}


def feedback_path(data_dir: Path) -> Path:
    return data_dir / "feedback.jsonl"


def _int_or_none(value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
    """把一条上报整成落盘行。不做校验，校验在 append_feedback。"""
    action = (payload.get("action") or "").strip()
    item_key = (payload.get("item_key") or payload.get("full_name") or "").strip()
    # item_key 形如 owner/repo::skills/x/SKILL.md；前端只回传 item_key 时把 full_name 还原出来，
    # 否则 rank.load_feedback_affinity 这类按 full_name 聚合的老逻辑会整段丢数
    full_name = (payload.get("full_name") or "").strip() or item_key.split("::")[0]
    row: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "item_key": item_key,
        "full_name": full_name,
        "source": payload.get("source") or "",
        "scene": payload.get("scene") or "",
        "scene_l2": payload.get("scene_l2") or "",
        "owner": payload.get("owner") or "",
        "language": payload.get("language") or "",
        "device_id": (payload.get("device_id") or "").strip(),
        "session_id": (payload.get("session_id") or "").strip(),
        "position": _int_or_none(payload.get("position")),
        "position_band": _int_or_none(payload.get("position_band")),
        "dwell_ms": _int_or_none(payload.get("dwell_ms")),
        "client_ts": (payload.get("client_ts") or "").strip(),
        "suggested_scene": payload.get("suggested_scene") or "",
        "note": (payload.get("note") or "")[:500],
        "from_corpus": bool(payload.get("from_corpus")),
    }
    if action == "not_interested":
        row["scope"] = ranking_profile.normalize_scope(payload.get("scope"))
    if action == "focus_set":
        focus = payload.get("focus")
        rows = []
        if isinstance(focus, list):
            for f in focus[:20]:
                if isinstance(f, dict) and f.get("dim") and f.get("key"):
                    rows.append({"dim": str(f["dim"])[:20], "key": str(f["key"])[:80]})
        row["focus"] = rows
    return row


def append_feedback(data_dir: Path, payload: dict[str, Any]) -> dict:
    raw_action = (payload.get("action") or "").strip()
    if raw_action not in VALID_ACTIONS:
        return {"ok": False, "error": f"invalid action; want one of {sorted(VALID_ACTIONS)}"}
    row = normalize_event(payload)
    path = feedback_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return {"ok": True, "row": row}


def append_many(data_dir: Path, payloads: list[dict[str, Any]]) -> dict:
    """批量落盘。单条非法只跳过该条，不整批失败——埋点不该因为一条脏数据全丢。

    丢弃必须**按原因**报数（`rejected_by_reason`）。这条链路上一次出问题时
    整整一个多月没人发现，就是因为「合法地丢」和「坏了在丢」从外面看一模一样。
    """
    accepted = 0
    by_reason: dict[str, int] = {}
    by_action: dict[str, int] = {}
    path = feedback_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    def _reject(reason: str) -> None:
        by_reason[reason] = by_reason.get(reason, 0) + 1

    with path.open("a", encoding="utf-8") as f:
        for payload in payloads or []:
            if not isinstance(payload, dict):
                _reject("not_a_dict")
                continue
            raw_action = (payload.get("action") or "").strip()
            if raw_action not in VALID_ACTIONS:
                _reject("unknown_action")
                continue
            row = normalize_event(payload)
            if not row["item_key"] and raw_action in ITEM_SCOPED_ACTIONS:
                _reject("missing_item_key")
                continue
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            accepted += 1
            action = ACTION_ALIASES.get(raw_action, raw_action)
            by_action[action] = by_action.get(action, 0) + 1
    return {
        "ok": True,
        "accepted": accepted,
        "rejected": sum(by_reason.values()),
        "rejected_by_reason": by_reason,
        "accepted_by_action": by_action,
    }


def load_events(data_dir: Path, *, device_id: str = "", limit: int = 5000) -> list[dict]:
    path = feedback_path(data_dir)
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows: list[dict] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if device_id and (obj.get("device_id") or "") != device_id:
            continue
        obj["action"] = ACTION_ALIASES.get(obj.get("action") or "", obj.get("action") or "")
        if not obj.get("item_key"):
            obj["item_key"] = obj.get("full_name") or ""
        rows.append(obj)
    return rows


def ingest_health(
    data_dir: Path,
    *,
    stale_after_s: float = 86400.0,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """本机版的摄入健康：最后一条是什么时候、隔了多久、算不算断了。

    这是那个「7 月 27 日之后零新增、一个多月没人发现」的直接对策。
    人不会每天去 tail 一个 jsonl，但 `skillfeed.py feedback` 里多一行
    `stale: true` 是看得见的。
    """
    now = now or datetime.now(timezone.utc)
    path = feedback_path(data_dir)
    total = 0
    by_action: dict[str, int] = {}
    last_ts: Optional[str] = None
    if path.exists():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return {"ok": False, "error": "cannot read feedback.jsonl"}
        for line in lines:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            total += 1
            action = obj.get("action") or "?"
            by_action[ACTION_ALIASES.get(action, action)] = (
                by_action.get(ACTION_ALIASES.get(action, action), 0) + 1
            )
            ts = obj.get("ts")
            if ts and (last_ts is None or str(ts) > last_ts):
                last_ts = str(ts)

    age: Optional[float] = None
    if last_ts:
        try:
            dt = datetime.fromisoformat(str(last_ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = max(0.0, (now - dt).total_seconds())
        except ValueError:
            age = None
    return {
        "ok": True,
        "path": str(path),
        "total": total,
        "by_action": by_action,
        "last_event_at": last_ts,
        "last_event_age_s": round(age, 1) if age is not None else None,
        # 一条都没有 ≠ 很久没有：前者是没开张，后者是链路断了，别混成一个告警
        "stale": bool(age is not None and age > float(stale_after_s)),
        "empty": total == 0,
    }


def summarize(data_dir: Path, limit: int = 50) -> dict:
    path = feedback_path(data_dir)
    if not path.exists():
        return {"ok": True, "total": 0, "by_action": {}, "recent": []}
    by: dict[str, int] = {}
    recent: list[dict] = []
    total = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"ok": False, "error": "cannot read feedback.jsonl"}
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        a = obj.get("action") or "?"
        by[a] = by.get(a, 0) + 1
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            recent.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(recent) >= limit:
            break
    return {"ok": True, "total": total, "by_action": by, "recent": recent}
