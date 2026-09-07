"""埋点接口限流：进程内滑动窗口。

为什么必须有：排序规则第 1 条依赖「本站用户点得最多的 skills」，也就是 CTR
直接决定首页顺序。一个匿名可写、无限流的 /api/events 等于把首页排序的写权限
公开——刷几百次曝光+点击就能把任意条目顶上去。

超限走静默丢弃（依然返回 200）：给刷的人返回 429 等于告诉他限流阈值在哪，
反而方便试探。正常用户永远碰不到这个阈值，所以静默不会伤到体验。

进程内计数器够用：单实例部署、限流只需要挡住脚本级别的刷量。
多实例部署时每个实例各算各的，实际阈值放大 N 倍，仍在可接受范围；
真要精确再换 Redis。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional

# 键太多时的上限，防止被随机 device_id 撑爆内存
MAX_KEYS = 20000


class SlidingWindow:
    def __init__(self, window_s: float = 300.0, max_keys: int = MAX_KEYS) -> None:
        self.window_s = float(window_s)
        self.max_keys = int(max_keys)
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        dq = self._hits.get(key)
        if dq is None:
            dq = deque()
            self._hits[key] = dq
        cutoff = now - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        return dq

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_s
        dead = [k for k, dq in self._hits.items() if not dq or dq[-1] < cutoff]
        for k in dead:
            self._hits.pop(k, None)
        if len(self._hits) > self.max_keys:
            # 还超就按最后活跃时间砍掉一半，宁可漏放也不要 OOM
            rows = sorted(self._hits.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            for k, _ in rows[: len(rows) // 2]:
                self._hits.pop(k, None)

    def check(self, key: str, limit: int, cost: int = 1, *, now: Optional[float] = None) -> int:
        """返回本次允许通过的数量（0 ~ cost）。超限部分静默丢弃。"""
        if not key or limit <= 0:
            return cost
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) > self.max_keys:
                self._evict(now)
            dq = self._prune(key, now)
            room = max(0, limit - len(dq))
            take = min(cost, room)
            for _ in range(take):
                dq.append(now)
            return take

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class EventLimiter:
    """按 IP 和设备各限一道。两者都过才算通过，取更严的那个。"""

    def __init__(self, config: Optional[dict] = None) -> None:
        cfg = (config or {}).get("ratelimit") or {}
        self.window_s = float(cfg.get("window_s", 300))
        self.max_ip = int(cfg.get("max_events_per_ip", 600))
        self.max_device = int(cfg.get("max_events_per_device", 400))
        self._window = SlidingWindow(self.window_s)

    def allow(self, *, ip: str, device_id: str, count: int) -> int:
        if count <= 0:
            return 0
        take = self._window.check(f"ip:{ip}", self.max_ip, count)
        if take <= 0:
            return 0
        return self._window.check(f"dev:{device_id}", self.max_device, take)

    def reset(self) -> None:
        self._window.reset()
