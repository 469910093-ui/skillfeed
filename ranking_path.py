"""路径判断层：不改 G/P/F/N，只在近邻同分里做二次键，并给出 path + 置信度。

依据：小红书笔记 https://xhslink.cn/o/8fvgNlMau1U
（「Jev让我觉得千人千面的网站要来了」）——推荐系统是百万物料召回；
这里学的是「从少数路径里选一条 + 冲突时给答案和概率 + sticky，不换品牌壳」。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

import ranking

PATHS = ("default", "reliable", "task", "publisher")


@dataclass
class PathDecision:
    path: str = "default"
    confidence: float = 0.0
    conflict: bool = False
    reasons: list[str] = field(default_factory=list)

    def as_public(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "confidence": round(float(self.confidence), 3),
            "conflict": bool(self.conflict),
        }


def _cfg(config: Optional[dict] = None) -> dict[str, Any]:
    resolved = ranking.resolve_config(config)
    return resolved.get("path_judgment") or {}


def judge_feed_path(
    profile: Optional[ranking.DeviceProfile] = None,
    *,
    query: str = "",
    scene_filter: str = "",
    device_id: str = "",
    extras: Optional[dict[str, Any]] = None,
    config: Optional[dict] = None,
) -> PathDecision:
    """用手写信号投票。冲突时降置信度并 sticky 回 default，不发明优先级树。"""
    pj = _cfg(config)
    extras = extras or {}
    votes: dict[str, float] = {p: 0.0 for p in PATHS}
    reasons: list[str] = []

    q = (query or "").strip()
    if q:
        votes["task"] += 2.0
        reasons.append("query→task")
    if (scene_filter or "").strip():
        votes["task"] += 1.0
        reasons.append("scene_filter→task")

    events = int(getattr(profile, "events", 0) or 0) if profile else 0
    suppress_n = len(getattr(profile, "suppress", None) or []) if profile else 0
    has_focus = bool(getattr(profile, "has_focus", False)) if profile else False
    opened_n = len(getattr(profile, "opened_items", None) or []) if profile else 0

    if events < 4:
        votes["reliable"] += 1.4
        reasons.append("cold→reliable")
    if suppress_n >= 2:
        votes["reliable"] += 1.2
        reasons.append("rejects→reliable")
    if not has_focus and events >= 1:
        votes["reliable"] += 0.4

    recent = [str(a) for a in (extras.get("recent_actions") or [])]
    if any(a in {"publish_view", "publish_submit", "login_click"} for a in recent):
        votes["publisher"] += 2.2
        reasons.append("publish_journey→publisher")
    if extras.get("view_tab") == "publish":
        votes["publisher"] += 1.5
        reasons.append("publish_tab→publisher")

    if events >= 12 and not q and not has_focus:
        votes["default"] += 1.0
        reasons.append("browse→default")
    if opened_n >= 3 and not q:
        votes["default"] += 0.6

    ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
    top_path, top_s = ranked[0]
    second_s = ranked[1][1]
    conflict = top_s >= 1.6 and second_s >= 1.6 and (top_s - second_s) < 0.8
    if top_s <= 0:
        top_path, top_s = "default", 0.0
    conf = min(1.0, top_s / 3.2)
    if conflict:
        conf *= 0.45
        reasons.append("signal_conflict")

    decision = PathDecision(path=top_path, confidence=conf, conflict=conflict, reasons=reasons)
    return _sticky(decision, device_id or (getattr(profile, "device_id", "") if profile else ""), pj)


def _sticky(decision: PathDecision, device_id: str, pj: dict[str, Any]) -> PathDecision:
    """同一个人不因噪声在路径之间跳。冲突或低置信度锁在 default。"""
    min_conf = float(pj.get("min_confidence") or 0.55)
    if decision.conflict or decision.confidence < min_conf:
        if device_id:
            digest = hashlib.blake2b(device_id.encode("utf-8"), digest_size=4).digest()
            # sticky 只在 default/reliable 两档里选，避免无标注时乱切 publisher
            locked = "reliable" if digest[0] % 2 else "default"
        else:
            locked = "default"
        if decision.path != locked:
            decision.reasons.append(f"sticky→{locked}")
        decision.path = locked
        decision.confidence = min(decision.confidence, min_conf - 0.01)
    return decision


def apply_path_tiebreak(
    items: list[dict],
    decision: PathDecision,
    config: Optional[dict] = None,
) -> list[dict]:
    """只重排 personal_score 落在 epsilon 内的近邻，不改分数本身。"""
    pj = _cfg(config)
    if not items:
        return items
    if not pj.get("enabled", True):
        return items
    if decision.path == "default" or decision.confidence < float(pj.get("min_confidence") or 0.55):
        return items
    eps = float(pj.get("tie_epsilon") or 0.03)
    out: list[dict] = []
    i = 0
    n = len(items)
    while i < n:
        base = float(items[i].get("personal_score") or 0)
        j = i + 1
        while j < n and abs(base - float(items[j].get("personal_score") or 0)) <= eps:
            j += 1
        chunk = items[i:j]
        if len(chunk) > 1:
            chunk = sorted(chunk, key=lambda it: _secondary(it, decision.path), reverse=True)
        out.extend(chunk)
        i = j
    return out


def _secondary(item: dict[str, Any], path: str) -> tuple:
    stars = int(item.get("stars") or 0)
    rel = float(item.get("_relevance") or 0)
    src = str(item.get("source") or "")
    ugc = 1 if src in {"ugc", "user"} else 0
    skillish = 1 if (item.get("skill_path") or item.get("skill_url")) else 0
    if path == "reliable":
        return (stars, skillish, rel)
    if path == "task":
        return (rel, stars)
    if path == "publisher":
        return (ugc, -stars // 50, rel)
    return (0, 0, 0)
