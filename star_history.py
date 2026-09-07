"""star 快照与增速计算。

为什么这里自己解析数据目录（架构上的取舍，不是设计品味问题）：
本该由调用方（skillfeed.py 的 refresh/build）把 data_dir 注入 feed_pack.pack_feed()
再传进来，那样依赖是显式的。写这版时 skillfeed.py 正被另一个 agent 并发修改，
跨 agent 协调两处调用点的代价高于这点架构收益，所以改成本模块自解析
SKILLFEED_HOME / ~/.skill-feed（与 server/config.data_home() 同一套逻辑）。
所有对外函数都保留 data_dir 参数可显式覆盖，单测走显式路径。
以后重构的人若要改回注入式，改 observe()/load_snapshot() 的默认值即可。

为什么需要这个模块：feed.json 里 stars_today 只有 trending 源才有（实测 388 条
里仅 2 条非 0），纯 star 存量又会让 feed 每天一模一样，所以增速必须自己攒。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

STATE_DIR = "rank_state"
SNAPSHOT_NAME = "stars_history.json"

# 每个仓库最多保留的观测点；再多对增速没帮助，只会让文件变大
MAX_POINTS = 8
# 算增速时回看的最长窗口，超出的观测点视为过期
LOOKBACK_DAYS = 14.0


def data_home(explicit: Optional[Path] = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    env = (os.environ.get("SKILLFEED_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".skill-feed"


def snapshot_path(data_dir: Optional[Path] = None) -> Path:
    return data_home(data_dir) / STATE_DIR / SNAPSHOT_NAME


def _load_raw(path: Path) -> dict[str, list[list[Any]]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def daily_gain(points: list[list[Any]], now: datetime) -> Optional[float]:
    """用窗口内最早与最新两个观测点算日均增速。少于 2 点返回 None。"""
    rows: list[tuple[datetime, float]] = []
    for p in points:
        if not isinstance(p, (list, tuple)) or len(p) < 2:
            continue
        ts = _parse_ts(p[0])
        if ts is None:
            continue
        try:
            rows.append((ts, float(p[1])))
        except (TypeError, ValueError):
            continue
    rows.sort(key=lambda x: x[0])
    rows = [r for r in rows if (now - r[0]).total_seconds() / 86400.0 <= LOOKBACK_DAYS]
    if len(rows) < 2:
        return None
    (t0, s0), (t1, s1) = rows[0], rows[-1]
    span = (t1 - t0).total_seconds() / 86400.0
    if span < 0.5:
        return None
    return max(0.0, (s1 - s0) / span)


def load_snapshot(data_dir: Optional[Path] = None, *, now: Optional[datetime] = None) -> dict[str, dict]:
    """返回 {full_name: {"daily_gain": float, "points": n}}，无数据的仓库不出现。"""
    now = now or datetime.now(timezone.utc)
    raw = _load_raw(snapshot_path(data_dir))
    out: dict[str, dict] = {}
    for fn, points in raw.items():
        if not isinstance(points, list):
            continue
        g = daily_gain(points, now)
        if g is None:
            continue
        out[fn] = {"daily_gain": round(g, 4), "points": len(points)}
    return out


def observe(
    items: list[dict],
    *,
    data_dir: Optional[Path] = None,
    now: Optional[datetime] = None,
) -> dict[str, dict]:
    """记一次观测并返回最新增速表。同一天重复跑只更新当天的点，不重复累加。"""
    now = now or datetime.now(timezone.utc)
    today = now.date().isoformat()
    path = snapshot_path(data_dir)
    raw = _load_raw(path)

    # 快照按 full_name 存，monorepo 拆出的 20 条子 skill 带的是同一个仓库星数。
    # 先去重再写：不去重的话同一个 key 会被反复覆盖 20 次，结果一样但白做 19 次。
    # 存储层面本来就不会膨胀（同 key 覆盖），这里只是省掉无谓的重复计算。
    observed: dict[str, int] = {}
    for it in items:
        fn = (it.get("full_name") or "").strip()
        stars = it.get("stars")
        if not fn or not isinstance(stars, (int, float)) or stars <= 0:
            continue
        observed[fn] = max(observed.get(fn, 0), int(stars))

    for fn, stars in observed.items():
        points = [p for p in raw.get(fn, []) if isinstance(p, (list, tuple)) and len(p) >= 2]
        points = [list(p) for p in points if str(p[0])[:10] != today]
        points.append([now.isoformat(), stars])
        raw[fn] = points[-MAX_POINTS:]

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    except OSError:
        # 快照写不进去不该拖垮整个 build，增速退化成置信度 0 的兜底
        pass
    return load_snapshot(data_dir, now=now)


def first_seen_map(
    items: list[dict],
    *,
    data_dir: Optional[Path] = None,
    now: Optional[datetime] = None,
) -> dict[str, str]:
    """首次观测时间，用于新条目保护期和新鲜度衰减。"""
    now = now or datetime.now(timezone.utc)
    raw = _load_raw(snapshot_path(data_dir))
    out: dict[str, str] = {}
    for it in items:
        fn = (it.get("full_name") or "").strip()
        if not fn:
            continue
        points = raw.get(fn) or []
        stamps = [str(p[0]) for p in points if isinstance(p, (list, tuple)) and p]
        out[fn] = min(stamps) if stamps else now.isoformat()
    return out
