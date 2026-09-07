"""曝光/点击统计聚合：把事件流折成 ranking.ItemStats。

本机版事件在 feedback.jsonl，线上版在 SQLite events 表，两边字段命名一致，
所以聚合逻辑只写一份，靠 rows 迭代器解耦存储。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

import ranking

# 计入 CTR 分子的动作。刻意只认 open_github：它是北极星行为，
# useful/save 是态度不是转化，混进 CTR 会让「顺手点赞」污染排序主信号。
CLICK_ACTIONS = frozenset({"open_github"})


def aggregate(
    rows: Iterable[dict],
    *,
    config: Optional[dict] = None,
) -> dict[str, ranking.ItemStats]:
    cfg = config if config and "ctr" in config else ranking.resolve_config(config)
    bands = list(cfg["ctr"]["position_bands"])
    ignore_below = float(cfg["dwell"]["ignore_below_ms"])
    out: dict[str, ranking.ItemStats] = {}

    for row in rows:
        key = (row.get("item_key") or row.get("full_name") or "").strip()
        if not key:
            continue
        action = (row.get("action") or "").strip()
        if action not in ("impression", *CLICK_ACTIONS):
            continue
        # 甩屏不算曝光：卡片可能都没渲染完，计进分母会稀释所有条目的 CTR
        dwell = row.get("dwell_ms")
        if action == "impression" and isinstance(dwell, (int, float)) and dwell < ignore_below:
            continue
        try:
            pos = int(row.get("position") if row.get("position") is not None else 0)
        except (TypeError, ValueError):
            pos = 0
        band_raw = row.get("position_band")
        try:
            band = int(band_raw) if band_raw is not None else ranking.position_band(pos, bands)
        except (TypeError, ValueError):
            band = ranking.position_band(pos, bands)

        st = out.get(key)
        if st is None:
            st = ranking.ItemStats()
            out[key] = st
        if action == "impression":
            st.impressions[band] = st.impressions.get(band, 0) + 1
        else:
            st.clicks[band] = st.clicks.get(band, 0) + 1
        ts = row.get("ts") or row.get("client_ts")
        if ts and (st.first_seen_at is None or str(ts) < st.first_seen_at):
            st.first_seen_at = str(ts)
    return out


def read_jsonl(path: Path, *, limit: int = 20000) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
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
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def from_feedback_file(
    data_dir: Path,
    *,
    config: Optional[dict] = None,
    limit: int = 20000,
) -> dict[str, ranking.ItemStats]:
    rows = read_jsonl(Path(data_dir) / "feedback.jsonl", limit=limit)
    return aggregate(rows, config=config)


# —— 站内热度的第二、第三个来源 ——
#
# 排序规则第 1 条要求「star 降序 × 本站点击最多的 skills 交叉」。GitHub Pages 上
# 那份 feed.html 是纯静态的，没有服务端，运行期个性化无从谈起——但「站内热度」
# 是**全站聚合量**，完全可以在 build 期算好烧进 feed.json。
#
# 问题是真实流量落在服务端的 SQLite 里，而 build 可能跑在别的机器上。所以支持
# 三个来源并集：本机 feedback.jsonl、同机 server.db、以及从线上导出的
# item_stats.json 快照（`GET /api/stats/items` 的产物）。缺哪个都不影响构建。

STATS_EXPORT_NAME = "item_stats.json"
SERVER_DB_NAME = "server.db"


def merge(*sources: dict[str, ranking.ItemStats]) -> dict[str, ranking.ItemStats]:
    """按 (item_key, band) 相加。同一批流量不要喂两次，这里不做去重。"""
    out: dict[str, ranking.ItemStats] = {}
    for src in sources:
        for key, st in (src or {}).items():
            dst = out.get(key)
            if dst is None:
                dst = ranking.ItemStats(first_seen_at=st.first_seen_at)
                out[key] = dst
            for b, v in st.impressions.items():
                dst.impressions[b] = dst.impressions.get(b, 0) + v
            for b, v in st.clicks.items():
                dst.clicks[b] = dst.clicks.get(b, 0) + v
            if st.first_seen_at and (
                dst.first_seen_at is None or st.first_seen_at < dst.first_seen_at
            ):
                dst.first_seen_at = st.first_seen_at
    return out


def from_stats_rows(rows: Iterable[dict]) -> dict[str, ranking.ItemStats]:
    """从扁平的 (item_key, position_band, impressions, clicks) 行还原。"""
    out: dict[str, ranking.ItemStats] = {}
    for row in rows or []:
        key = str(row.get("item_key") or "").strip()
        if not key:
            continue
        try:
            band = int(row.get("position_band") or 0)
        except (TypeError, ValueError):
            band = 0
        st = out.setdefault(key, ranking.ItemStats())
        try:
            st.impressions[band] = st.impressions.get(band, 0) + int(row.get("impressions") or 0)
            st.clicks[band] = st.clicks.get(band, 0) + int(row.get("clicks") or 0)
        except (TypeError, ValueError):
            continue
        seen = row.get("first_seen_at")
        if seen and (st.first_seen_at is None or str(seen) < st.first_seen_at):
            st.first_seen_at = str(seen)
    return out


def from_stats_export(path: Path) -> dict[str, ranking.ItemStats]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rows = data.get("items") if isinstance(data, dict) else data
    return from_stats_rows(rows if isinstance(rows, list) else [])


def from_sqlite(db_path: Path) -> dict[str, ranking.ItemStats]:
    """直读 server.db 的 item_stats。

    刻意用裸 sqlite3 而不是 import server.db：build 链路不该被迫装上 FastAPI，
    而且这里只读一张纯聚合表，没有任何设备维度信息。
    """
    p = Path(db_path)
    if not p.exists():
        return {}
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    except sqlite3.Error:
        return {}
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT item_key, position_band, impressions, clicks, first_seen_at "
            "FROM item_stats",
        ).fetchall()
    except sqlite3.Error:
        # 表还没建（服务端从没跑过）是正常情况，不是错误
        return {}
    finally:
        conn.close()
    return from_stats_rows([dict(r) for r in rows])


def load_stats(
    data_dir: Path,
    *,
    config: Optional[dict] = None,
    limit: int = 20000,
) -> dict[str, ranking.ItemStats]:
    """build 期用的站内热度：本机 jsonl + 同机 server.db + 线上导出快照。"""
    home = Path(data_dir)
    return merge(
        from_feedback_file(home, config=config, limit=limit),
        from_sqlite(home / SERVER_DB_NAME),
        from_stats_export(home / STATS_EXPORT_NAME),
    )


def stats_rows(stats: dict[str, ranking.ItemStats]) -> list[dict[str, Any]]:
    """展开成可写库/可导出的扁平行。"""
    out: list[dict[str, Any]] = []
    for key, st in stats.items():
        bands = set(st.impressions) | set(st.clicks)
        for b in sorted(bands):
            out.append({
                "item_key": key,
                "position_band": b,
                "impressions": st.impressions.get(b, 0),
                "clicks": st.clicks.get(b, 0),
            })
    return out
