"""发现流全量免费。

2026-09-16 定案：不再按天切条，获客基本盘不设墙。订阅 / 激活码仍可记录
在用户档案上，留给其他变现，但 **不裁剪 Feed**。
`quota` 载荷继续返回（登录用户 `unlimited=True`），方便前端与旧客户端
读字段，不再表示「今天还能看几条」。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import sqlite3

# 保留常量以免旧调用方 ImportError；值不再参与切片。
FREE_DAILY_LIMIT = 0
CN_TZ = timezone(timedelta(hours=8))
SUBSCRIBER_PLANS = frozenset({"subscriber", "unlimited", "pro"})


def today_cn(now: Optional[datetime] = None) -> str:
    """配额按东八区自然日切。"""
    stamp = now or datetime.now(CN_TZ)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=CN_TZ)
    return stamp.astimezone(CN_TZ).date().isoformat()


def item_key(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("full_name") or "").strip()


def parse_plan_until(raw: str) -> Optional[datetime]:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        exp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp


def is_subscriber(user: Optional[dict[str, Any]], *, now: Optional[datetime] = None) -> bool:
    if not user:
        return False
    plan = str(user.get("plan") or "free").strip().lower()
    if plan not in SUBSCRIBER_PLANS:
        return False
    until = str(user.get("plan_until") or "").strip()
    if not until:
        return True
    exp = parse_plan_until(until)
    if exp is None:
        return False
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp <= exp


def next_plan_until(
    user: Optional[dict[str, Any]],
    days: int,
    *,
    now: Optional[datetime] = None,
) -> Optional[str]:
    """从现有未过期订阅往后顺延；days<=0 表示终身（plan_until 为空）。"""
    if int(days) <= 0:
        return None
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    base = stamp
    if user and is_subscriber(user, now=stamp):
        exp = parse_plan_until(str(user.get("plan_until") or ""))
        if exp is not None and exp > base:
            base = exp
    return (base + timedelta(days=int(days))).isoformat()


def _quota_payload(
    *,
    plan: str,
    limit: Optional[int],
    used: int,
    remaining: Optional[int],
    day: str,
    unlimited: bool,
) -> dict[str, Any]:
    return {
        "plan": plan,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "day": day,
        "unlimited": unlimited,
    }


def quota_status(
    conn: sqlite3.Connection,
    user: Optional[dict[str, Any]],
    *,
    limit: int = FREE_DAILY_LIMIT,
    now: Optional[datetime] = None,
) -> Optional[dict[str, Any]]:
    if not user:
        return None
    day = today_cn(now)
    plan = "subscriber" if is_subscriber(user, now=now) else "free"
    return _quota_payload(
        plan=plan, limit=None, used=0, remaining=None,
        day=day, unlimited=True,
    )


def apply_daily_quota(
    conn: sqlite3.Connection,
    user: Optional[dict[str, Any]],
    items: list[dict[str, Any]],
    *,
    limit: int = FREE_DAILY_LIMIT,
    claim: bool = True,
    now: Optional[datetime] = None,
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    """全量返回，不再按天切条。claim 保留签名兼容旧调用，无副作用。"""
    del claim, limit  # 获客定案：Feed 不再消耗每日额度
    return list(items), quota_status(conn, user, now=now)
