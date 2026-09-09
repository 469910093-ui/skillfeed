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


class SmsLimiter:
    """短信发送 / 验证的防刷，复用上面那个滑动窗口。

    短信和埋点不是同一类风险，所以单独一个类而不是往 EventLimiter 上挂参数：

    - 埋点超限**静默丢弃**（不告诉刷的人阈值在哪）；短信超限必须**明确报错**，
      否则用户点了「获取验证码」什么都没发生，会一直点。
    - 埋点是「排序被污染」，短信是「真金白银 + 别人手机被轰炸」，
      阈值要严一个量级。

    三道桶，任一超限即拒：

    1. `phone:` 同一个手机号的发送次数 —— 挡短信轰炸（拿别人号码当靶子）。
    2. `ip:` 同一来源的发送次数 —— 挡「换手机号绕过第 1 道」的批量烧钱。
    3. `verify:` 同一来源的校验次数 —— 挡跨手机号的验证码爆破。单个验证码的
       尝试次数上限在 DB 里（见 db.bump_sms_attempt），那道挡的是「同一个码猜 6 位」，
       这道挡的是「换手机号换码不停试」，两道都需要。
    """

    def __init__(
        self,
        *,
        window_s: float = 3600.0,
        max_per_phone: int = 5,
        max_per_ip: int = 20,
        max_verify_per_ip: int = 30,
    ) -> None:
        self.window_s = float(window_s)
        self.max_per_phone = int(max_per_phone)
        self.max_per_ip = int(max_per_ip)
        self.max_verify_per_ip = int(max_verify_per_ip)
        self._window = SlidingWindow(self.window_s)

    def allow_send(self, *, phone: str, ip: str) -> str:
        """返回空串表示放行，否则返回被拒的原因（用于给前端的提示文案）。

        先判手机号后判 IP：手机号那道被拒时不应该消耗 IP 配额，
        否则一个被反复轰炸的号码会把同一出口 NAT 后面所有正常用户一起限死。
        """
        if self._window.check(f"sms:phone:{phone}", self.max_per_phone) <= 0:
            return "phone"
        if self._window.check(f"sms:ip:{ip}", self.max_per_ip) <= 0:
            return "ip"
        return ""

    def allow_verify(self, *, ip: str) -> bool:
        return self._window.check(f"sms:verify:{ip}", self.max_verify_per_ip) > 0

    def reset(self) -> None:
        self._window.reset()


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
