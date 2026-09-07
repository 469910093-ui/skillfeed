"""埋点摄入的进程内计数器。

存在的理由是一个具体事故：feedback.jsonl 从 7 月 27 日起零新增，
这件事一个多月没人发现——因为写入失败是静默的，唯一的发现方式是人工打开
文件数行数。所以摄入侧必须自己报数：收了多少、去重多少、**按原因**拒了多少、
最后一条成功写入是什么时候。

进程内、不落库：这些是运维指标不是业务数据，重启归零可以接受。需要跨重启
的那两个量（累计事件数、最后一条事件时间）直接查 SQLite 得到，比再建一套
持久化计数便宜，也不会和真实数据对不上。
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Optional

# 拒绝原因的封闭枚举。加新原因就加进这里，别用裸字符串——
# 监控面板按 key 画图，拼错一个字母等于凭空多出一条永远为 0 的曲线。
REASONS = (
    "not_a_dict",        # 数组元素不是对象
    "unknown_action",    # action 不在契约里
    "missing_item_key",  # 条目级动作却没带 item_key，画像和 CTR 都用不上
    "fling",             # dwell 低于阈值，卡片可能都没渲染完
    "ratelimited",       # 超限静默丢弃（仍返回 200，见 ranking-engine-design §13）
    "truncated",         # 单请求超过 MAX_EVENTS_PER_REQUEST 的部分
    "legacy_payload",    # 老 /api/feedback 契约，字段不足以喂排序引擎
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IngestMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = _now_iso()
        self.requests = 0
        self.accepted = 0
        self.deduped = 0
        self.rejected: dict[str, int] = {r: 0 for r in REASONS}
        self.by_action: dict[str, int] = {}
        self.last_accepted_at: Optional[str] = None
        self.last_request_at: Optional[str] = None

    def record(
        self,
        *,
        accepted: int = 0,
        deduped: int = 0,
        rejected: Optional[dict[str, int]] = None,
        by_action: Optional[dict[str, int]] = None,
    ) -> None:
        with self._lock:
            self.requests += 1
            self.last_request_at = _now_iso()
            self.accepted += int(accepted)
            self.deduped += int(deduped)
            for reason, n in (rejected or {}).items():
                if not n:
                    continue
                # 未知原因也计，但归到 unknown_action 之外的单独桶里暴露出来，
                # 不要静默吞掉——静默吞掉正是这套计数器要修的那个毛病
                self.rejected[reason] = self.rejected.get(reason, 0) + int(n)
            for action, n in (by_action or {}).items():
                if n:
                    self.by_action[action] = self.by_action.get(action, 0) + int(n)
            if accepted:
                self.last_accepted_at = self.last_request_at

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            total_rejected = sum(self.rejected.values())
            return {
                "started_at": self.started_at,
                "requests": self.requests,
                "accepted": self.accepted,
                "deduped": self.deduped,
                "rejected_total": total_rejected,
                "rejected_by_reason": {k: v for k, v in self.rejected.items() if v},
                "accepted_by_action": dict(self.by_action),
                "last_accepted_at": self.last_accepted_at,
                "last_request_at": self.last_request_at,
            }

    def reset(self) -> None:
        with self._lock:
            self.requests = 0
            self.accepted = 0
            self.deduped = 0
            self.rejected = {r: 0 for r in REASONS}
            self.by_action = {}
            self.last_accepted_at = None
            self.last_request_at = None


def staleness(last_event_ts: Optional[str], *, now: Optional[datetime] = None) -> Optional[float]:
    """距最后一条事件的秒数。没有任何事件时返回 None（区别于「很久没有」）。"""
    if not last_event_ts:
        return None
    now = now or datetime.now(timezone.utc)
    text = str(last_event_ts).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds())
