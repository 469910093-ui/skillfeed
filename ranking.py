"""信息流排序打分核心。

纯函数：零 IO、零网络、零 DB。所有时间相关计算都要求调用方传 now，
这样单测可以冻结时间，不用 sleep 也不用 mock 系统时钟。

设计文档见 docs/ranking-engine-design.md。核心是一个连续加权的打分函数，
不是三种互斥模式——权重随画像置信度平滑变化，回访用户和有显式关注的用户
走的是同一条代码路径，两项相加而不是互相覆盖。

依赖方向：ranking → rank / scene，单向。rank.py 不得反向 import 本模块，
否则循环依赖。
"""

from __future__ import annotations

import hashlib
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import rank as rank_mod
import scene as scene_mod

# 默认值必须在代码侧齐备：config_defaults.json 缺字段时不能崩
DEFAULTS: dict[str, Any] = {
    "weights": {
        "global": 1.00,
        "global_min": 0.55,
        "personal_max": 0.30,
        "focus": 0.15,
        "fatigue": 0.25,
        "personal_scale": 2.0,
        "lookalike": 0.5,
    },
    "global_parts": {
        "ctr": 0.34,
        "velocity": 0.28,
        "stock": 0.14,
        "freshness": 0.12,
        "completeness": 0.12,
    },
    "ctr": {
        "prior_alpha": 20.0,
        "z": 1.96,
        "position_bands": [5, 15, 40],
    },
    "profile": {
        "confidence_events": 12,
        "half_life_days": {
            "scene": 21,
            "scene_l2": 14,
            "owner": 14,
            "language": 30,
            "item": 90,
        },
    },
    # 点赞与收藏是两个信号，不是一个。收藏 ≈ 0.9 贴着 open_github，点赞压到 0.45：
    #   - 收藏是「我以后要用这个」，它是一次延迟的打开，指向未来的行动
    #   - 点赞是「这个不错」，零成本、可用双击手势误触发，且量级天然大得多
    # 让廉价动作拿高权重，等于让「顺手点」的音量盖过「真的要用」，
    # 把最强的意图信号稀释掉。差距做到 2 倍是刻意的，不是微调。
    "event_weights": {
        "open_github": 1.0,
        "save": 0.9,
        "useful": 0.45,
        "dwell_long": 0.35,
        "expand_detail": 0.3,
        "impression_no_action": -0.05,
        "skip_fast": -0.15,
        "not_interested": -1.0,
    },
    "dwell": {
        "skip_fast_ms": 1500,
        "ignore_below_ms": 200,
        "long_ms": 8000,
    },
    # scope -> [初始惩罚, 半衰期天数, 惩罚地板]；衰减到地板以下直接归零，让压制干净过期
    "suppress": {
        "item": [1.00, 60, 0.02],
        "owner": [0.45, 30, 0.05],
        "scene_l2": [0.30, 14, 0.03],
        "scene": [0.20, 7, 0.02],
    },
    "fatigue": {
        "half_life_days": 3,
        "hard_block_impressions": 6,
        "hard_block_days": 7,
        "scale": 3.0,
    },
    "diversity": {
        "window": 20,
        "max_consecutive_scene": 2,
        "max_owner_per_window": 3,
        "max_l2_per_10": 3,
        "max_focus_per_window": 8,
        "search_max_consecutive_scene": 4,
    },
    "exploration": {
        "ratio": 0.15,
        "slots": [5, 12, 17],
        "min_new_per_window": 1,
    },
    "new_item": {
        "grace_days": 3,
        "min_impressions": 200,
    },
    "star": {
        # 同仓 n 条子 skill 共享一份 star 证据，每条的证据强度按 n^-exponent 衰减。
        # 0.5（开方）是「完全继承(0)」和「均分(1)」之间的折中
        "share_exponent": 0.5,
        # 全库都没有 star 数据时的兜底中性值
        "neutral_fallback": 0.5,
    },
    "session": {
        "order_ttl_s": 1800,
        "jitter_amp": 0.02,
        # 「不感兴趣」的会话内回声：比持久压制宽、但只活到会话结束。
        # 见 server/ranking_service.SessionOrderCache.note_not_interested
        "echo": {
            "enabled": True,
            "scene_l2": 0.12,
            "owner": 0.10,
            "max": 0.35,
        },
    },
    # 摄入健康：超过 stale_after_s 没有新事件就判定链路可能断了。
    # 默认 1 天——正常站点每天都该有事件，而上次那个 bug 藏了一个多月
    "ingest": {
        "stale_after_s": 86400,
    },
    "search": {
        "personal_scale": 0.35,
        "focus_scale": 0.30,
        "relevance_bucket": 0.1,
        "min_relevance": 0.02,
    },
    "ratelimit": {
        "window_s": 300,
        "max_events_per_ip": 600,
        "max_events_per_device": 400,
    },
}


def resolve_config(cfg: Optional[dict] = None) -> dict[str, Any]:
    """把用户配置深合并到默认值上。缺字段走默认，不抛异常。"""

    def _merge(base: dict, over: Any) -> dict:
        out = dict(base)
        if not isinstance(over, dict):
            return out
        for k, v in over.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = _merge(out[k], v)
            elif v is not None:
                out[k] = v
        return out

    section = (cfg or {}).get("ranking") if isinstance(cfg, dict) else None
    if section is None and isinstance(cfg, dict) and "global_parts" in cfg:
        section = cfg  # 允许直接传 ranking 段本身
    return _merge(DEFAULTS, section or {})


# —— 基础数学 ——

def squash(x: float) -> float:
    """把无界正数压到 [0,1)，1.0 → 0.5。"""
    if x <= 0:
        return 0.0
    return x / (1.0 + x)


def wilson_lower(k: float, n: float, z: float = 1.96) -> float:
    """二项比例的 Wilson 95% 下界。k 可为小数（先验平滑后的等效成功数）。"""
    if n <= 0:
        return 0.0
    p = min(max(k / n, 0.0), 1.0)
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, (center - margin) / denom)


def parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_since(ts: Any, now: datetime) -> Optional[float]:
    dt = parse_ts(ts)
    if dt is None:
        return None
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def decay(weight: float, age_days: Optional[float], half_life_days: float) -> float:
    if age_days is None or half_life_days <= 0:
        return weight
    return weight * (0.5 ** (age_days / half_life_days))


def position_band(position: int, bands: list[int]) -> int:
    """位置分档。bands=[5,15,40] → 0:<5, 1:5-14, 2:15-39, 3:>=40。"""
    for i, edge in enumerate(bands):
        if position < edge:
            return i
    return len(bands)


# —— 统计输入 ——

@dataclass
class ItemStats:
    """单条目的分档曝光/点击。点击 = open_github（北极星行为）。"""

    impressions: dict[int, int] = field(default_factory=dict)
    clicks: dict[int, int] = field(default_factory=dict)
    first_seen_at: Optional[str] = None

    @property
    def total_impressions(self) -> int:
        return sum(self.impressions.values())

    @property
    def total_clicks(self) -> int:
        return sum(self.clicks.values())


@dataclass
class GlobalStats:
    """全站汇总，用于位置去偏和场景先验。"""

    ctr_overall: float = 0.0
    ctr_by_band: dict[int, float] = field(default_factory=dict)
    scene_l2_ctr: dict[str, float] = field(default_factory=dict)

    def band_ctr(self, band: int) -> float:
        v = self.ctr_by_band.get(band)
        return v if v and v > 0 else self.ctr_overall

    def prior_for(self, item: dict) -> float:
        key = item.get("scene_l2") or item.get("scene") or ""
        v = self.scene_l2_ctr.get(key)
        return v if v and v > 0 else self.ctr_overall


def build_global_stats(all_stats: dict[str, ItemStats], items: list[dict]) -> GlobalStats:
    """从逐条目统计聚出全站 CTR 与分档 CTR。"""
    imp_by_band: dict[int, int] = {}
    clk_by_band: dict[int, int] = {}
    for st in all_stats.values():
        for b, v in st.impressions.items():
            imp_by_band[b] = imp_by_band.get(b, 0) + v
        for b, v in st.clicks.items():
            clk_by_band[b] = clk_by_band.get(b, 0) + v
    total_imp = sum(imp_by_band.values())
    total_clk = sum(clk_by_band.values())
    overall = (total_clk / total_imp) if total_imp else 0.0
    by_band = {
        b: (clk_by_band.get(b, 0) / v)
        for b, v in imp_by_band.items() if v > 0
    }
    l2_imp: dict[str, int] = {}
    l2_clk: dict[str, int] = {}
    by_key = {(it.get("id") or it.get("full_name") or ""): it for it in items}
    for key, st in all_stats.items():
        it = by_key.get(key)
        if not it:
            continue
        l2 = it.get("scene_l2") or it.get("scene") or ""
        l2_imp[l2] = l2_imp.get(l2, 0) + st.total_impressions
        l2_clk[l2] = l2_clk.get(l2, 0) + st.total_clicks
    scene_ctr = {k: (l2_clk.get(k, 0) / v) for k, v in l2_imp.items() if v > 0}
    return GlobalStats(ctr_overall=overall, ctr_by_band=by_band, scene_l2_ctr=scene_ctr)


# —— G：全局质量分 ——

def ctr_ratio(item: dict, stats: Optional[ItemStats], gstats: GlobalStats, cfg: dict) -> float:
    """位置去偏后的「相对期望点击率」，1.0 = 与全站平均持平。

    两层保护叠在一起，缺一不可：
    - COEC：用位置分档的期望点击当分母，消掉「排得高所以点得多」的回路
    - Wilson 下界 + 场景先验：低曝光时把比值拽回平均，防「3 曝光 2 点击」冲榜
    再按置信度往中性 1.0 混合，避免 0 曝光(中性) 到 1 曝光(骤降) 之间出现悬崖，
    否则「从没被展示过」反而成了优势。
    """
    ctr_overall = gstats.ctr_overall
    if not stats or ctr_overall <= 0:
        return 1.0
    expected = sum(
        imp * gstats.band_ctr(b) for b, imp in stats.impressions.items()
    )
    if expected <= 0:
        return 1.0
    alpha = float(cfg["ctr"]["prior_alpha"])
    prior = gstats.prior_for(item)
    n_equiv = expected / ctr_overall
    k_equiv = float(stats.total_clicks)
    n = n_equiv + alpha
    k = k_equiv + alpha * prior
    p_lb = wilson_lower(k, n, float(cfg["ctr"]["z"]))
    ratio_lb = p_lb / ctr_overall
    conf = n_equiv / (n_equiv + alpha)
    return 1.0 * (1 - conf) + ratio_lb * conf


def velocity_parts(item: dict, snapshot: Optional[dict] = None) -> tuple[float, float]:
    """返回 (日均新增 star, 置信度)。三级降级见设计文档 2.2。"""
    today = item.get("stars_today")
    if isinstance(today, (int, float)) and today > 0:
        return float(today), 1.0
    # build 期已经算过就直接复用：线上 server 没有 star 快照文件，只有 feed.json
    baked = item.get("star_velocity")
    if isinstance(baked, (int, float)) and baked > 0:
        return float(baked), 0.85
    snap = (snapshot or {}).get(item.get("full_name") or "")
    if isinstance(snap, dict):
        gain = snap.get("daily_gain")
        if isinstance(gain, (int, float)):
            return max(0.0, float(gain)), 0.85
    stars = item.get("stars")
    age = item.get("_age_days")
    if isinstance(stars, (int, float)) and stars > 0 and isinstance(age, (int, float)) and age >= 1:
        return float(stars) / float(age), 0.4
    return 0.0, 0.0


def raw_stock(item: dict) -> Optional[float]:
    stars = item.get("stars")
    if not isinstance(stars, (int, float)) or stars <= 0:
        return None
    return min(1.0, math.log10(1 + float(stars)) / 5.0)


def annotate_repo_share(items: list[dict], *, config: Optional[dict] = None) -> list[dict]:
    """标注 star 证据强度，修掉 monorepo 子 skill 继承母仓库星数的问题。

    一个仓库拆出 20 条子 skill 时，这 20 条会带着**同一个** star 数进 feed
    （实测 388 条里 76.8% 的 star 值与别的卡重复，单仓最多拆 20 条）。
    star 是仓库级信号，不是单条 skill 的成绩：anthropics/skills 的 17 万星
    印在每个子 skill 上，等于给它们凭空发通行证。而且 log10 曲线在万星以上
    已经饱和，实测有 star 条目的 stock 中位数高达 0.93、p25 也有 0.73，
    这一项几乎失去了区分度。

    处理方式是**按证据强度向中性值收缩**，而不是直接打折到 0：
      share = n^-0.5          n=1 → 1.0，n=4 → 0.5，n=20 → 0.22
      stock = neutral + (raw - neutral) * share

    为什么均匀衰减而不是「让仓库派一个代表拿满分」：我们并不知道这 20 条里
    是哪一条挣来的星，挑代表等于凭空发明信息。

    中性值取**仓库级**中位数（一仓一票），否则 20 条的大仓会把中位数自己拉过去。
    顺带解决 stars=None：它们 share=0，落在正中性，不再被系统性压制。
    """
    cfg = config if config and "star" in config else resolve_config(config)
    exponent = float(cfg["star"]["share_exponent"])
    groups: dict[str, list[dict]] = {}
    for it in items:
        groups.setdefault(it.get("full_name") or "", []).append(it)

    per_repo: list[float] = []
    for fn, rows in groups.items():
        if not fn:
            continue
        vals = [v for v in (raw_stock(r) for r in rows) if v is not None]
        if vals:
            per_repo.append(max(vals))
    neutral = (
        statistics.median(per_repo) if per_repo
        else float(cfg["star"]["neutral_fallback"])
    )

    for fn, rows in groups.items():
        n = len(rows)
        share = 1.0 / (n ** exponent) if n > 0 else 1.0
        for r in rows:
            r["repo_items"] = n
            r["_star_share"] = share
            r["_stock_neutral"] = neutral
    return items


def shrink_to_neutral(raw: Optional[float], neutral: float, share: float) -> float:
    """证据越弱越靠近中性。raw 缺失（stars=None）时直接取中性，不惩罚。"""
    if raw is None:
        return neutral
    return neutral + (raw - neutral) * share


def completeness_score(item: dict) -> float:
    s = 0.0
    if item.get("skill_path"):
        s += 0.30
    desc = str(item.get("one_liner_zh") or item.get("description") or "")
    if len(desc) >= 40:
        s += 0.25
    if item.get("highlights_zh") or item.get("highlights"):
        s += 0.25
    if item.get("body_preview"):
        s += 0.20
    return min(1.0, s)


def is_new_item(item: dict, stats: Optional[ItemStats], cfg: dict, now: datetime) -> bool:
    grace = float(cfg["new_item"]["grace_days"])
    min_imp = int(cfg["new_item"]["min_impressions"])
    first = item.get("first_seen_at") or (stats.first_seen_at if stats else None)
    age = days_since(first, now)
    if age is None or age > grace:
        return False
    return (stats.total_impressions if stats else 0) < min_imp


def global_quality(
    item: dict,
    *,
    stats: Optional[ItemStats] = None,
    gstats: Optional[GlobalStats] = None,
    star_snapshot: Optional[dict] = None,
    config: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> tuple[float, str]:
    cfg = config if config and "global_parts" in config else resolve_config(config)
    now = now or datetime.now(timezone.utc)
    gstats = gstats or GlobalStats()
    parts = cfg["global_parts"]

    fresh_age = days_since(item.get("first_seen_at"), now)
    if fresh_age is None:
        fresh_age = 14.0  # 不知道入库时间就按中位数算，别当全新也别当陈旧
    work = dict(item)
    work["_age_days"] = fresh_age

    new_flag = is_new_item(item, stats, cfg, now)
    # 保护期内不因为「还没数据」被判死，取中性
    ratio = 1.0 if new_flag else ctr_ratio(item, stats, gstats, cfg)
    ctr_part = squash(ratio)

    # star 是仓库级信号，同仓多条子 skill 共享同一份证据，两项都要按证据强度收缩
    share = float(item.get("_star_share", 1.0))
    neutral = float(item.get("_stock_neutral", cfg["star"]["neutral_fallback"]))

    gain, conf = velocity_parts(work, star_snapshot)
    vel_raw = squash(gain / 30.0) * conf + 0.25 * (1 - conf)
    vel_part = 0.25 + (vel_raw - 0.25) * share

    stock_part = shrink_to_neutral(raw_stock(item), neutral, share)

    fresh_part = 0.5 ** (fresh_age / 14.0)
    comp_part = completeness_score(item)

    score = (
        parts["ctr"] * ctr_part
        + parts["velocity"] * vel_part
        + parts["stock"] * stock_part
        + parts["freshness"] * fresh_part
        + parts["completeness"] * comp_part
    )
    why = (
        f"ctr:{ctr_part:.2f} vel:{vel_part:.2f} stock:{stock_part:.2f} "
        f"fresh:{fresh_part:.2f} full:{comp_part:.2f}"
    )
    if new_flag:
        why += " new"
    return round(min(1.0, score), 4), why


# —— 相似度 / lookalike ——

_L2_PARENT: dict[str, str] = {
    l2_id: parent
    for parent, rows in scene_mod.SCENES_L2.items()
    for (l2_id, _label, _kw) in rows
}


def _item_tokens(item: dict) -> set[str]:
    blob = " ".join([
        str(item.get("name") or ""),
        str(item.get("description") or item.get("one_liner_zh") or ""),
        str(item.get("keywords") or ""),
    ])
    return rank_mod.tokenize(blob, query=False)


def similarity(a: dict, b: dict) -> float:
    """便宜可解释的相似度，不依赖 embedding。见设计文档 3.3。"""
    s = 0.0
    a_l2, b_l2 = a.get("scene_l2") or "", b.get("scene_l2") or ""
    a_s, b_s = a.get("scene") or "", b.get("scene") or ""
    if a_l2 and a_l2 == b_l2:
        s += 0.40
    elif a_s and a_s == b_s:
        s += 0.15
    ta, tb = _item_tokens(a), _item_tokens(b)
    if ta and tb:
        s += 0.25 * (len(ta & tb) / len(ta | tb))
    if a.get("owner") and a.get("owner") == b.get("owner"):
        s += 0.12
    if a.get("language") and a.get("language") == b.get("language"):
        s += 0.08
    return min(1.0, s)


def lookalike_score(item: dict, liked: list[dict]) -> float:
    """取 max 而非 mean：一个强相关就够了，均值会被无关项稀释成噪声。"""
    if not liked:
        return 0.0
    return max(similarity(item, j) for j in liked)


# —— 设备画像 ——

@dataclass
class DeviceProfile:
    """匿名设备画像。affinity: dim -> key -> (weight, updated_at)。"""

    device_id: str = ""
    affinity: dict[str, dict[str, tuple[float, Any]]] = field(default_factory=dict)
    focus: list[tuple[str, str]] = field(default_factory=list)
    suppress: list[dict] = field(default_factory=list)
    fatigue: dict[str, tuple[int, Any]] = field(default_factory=dict)
    opened_items: set[str] = field(default_factory=set)
    liked_items: list[dict] = field(default_factory=list)
    events: int = 0

    @property
    def has_focus(self) -> bool:
        return bool(self.focus)

    def top_scenes(self, n: int = 3) -> list[str]:
        rows = (self.affinity.get("scene") or {}).items()
        pos = [(k, w) for k, (w, _ts) in rows if w > 0]
        pos.sort(key=lambda x: -x[1])
        return [k for k, _ in pos[:n]]


def affinity_weight(profile: DeviceProfile, dim: str, key: str, cfg: dict, now: datetime) -> float:
    if not key:
        return 0.0
    row = (profile.affinity.get(dim) or {}).get(key)
    if not row:
        return 0.0
    weight, updated = row
    half = float(cfg["profile"]["half_life_days"].get(dim, 14))
    return decay(float(weight), days_since(updated, now), half)


def profile_confidence(profile: Optional[DeviceProfile], cfg: dict) -> float:
    if not profile:
        return 0.0
    need = max(1, int(cfg["profile"]["confidence_events"]))
    return min(1.0, profile.events / need)


def personal_affinity(
    item: dict,
    profile: Optional[DeviceProfile],
    cfg: dict,
    now: datetime,
) -> tuple[float, str]:
    """输出 (-1, 1)。"""
    if not profile:
        return 0.0, ""
    total = 0.0
    bits: list[str] = []
    for dim, key in (
        ("scene", item.get("scene") or ""),
        ("scene_l2", item.get("scene_l2") or ""),
        ("owner", item.get("owner") or ""),
        ("language", item.get("language") or ""),
    ):
        w = affinity_weight(profile, dim, key, cfg, now)
        if abs(w) > 1e-6:
            total += w
            bits.append(f"{dim}:{w:+.2f}")
    la = lookalike_score(item, profile.liked_items)
    if la > 0:
        total += la * float(cfg["weights"]["lookalike"])
        bits.append(f"look:{la:.2f}")
    scale = float(cfg["weights"]["personal_scale"]) or 1.0
    return math.tanh(total / scale), " ".join(bits)


def focus_affinity(
    item: dict,
    profile: Optional[DeviceProfile],
    cfg: dict,
) -> tuple[float, str]:
    """显式关注：直接命中 1.0，lookalike 命中 0.45。"""
    if not profile or not profile.focus:
        return 0.0, ""
    scene_id = item.get("scene") or ""
    l2 = item.get("scene_l2") or ""
    owner = item.get("owner") or ""
    tokens = _item_tokens(item)
    near = 0.0
    for dim, key in profile.focus:
        if dim == "scene" and key == scene_id:
            return 1.0, f"focus:{key}"
        if dim == "scene_l2" and key == l2:
            return 1.0, f"focus:{key}"
        if dim == "owner" and key == owner:
            return 1.0, f"focus:{key}"
        if dim == "keyword" and key and key.lower() in tokens:
            return 1.0, f"focus:{key}"
        # lookalike：关注的二级行业的同父行业、或关键词的 token 近邻
        if dim == "scene_l2" and _L2_PARENT.get(key) and _L2_PARENT.get(key) == scene_id:
            near = max(near, 0.45)
        if dim == "scene" and key == _L2_PARENT.get(l2, ""):
            near = max(near, 0.45)
    return near, ("focus~" if near else "")


# —— N：负反馈与疲劳 ——

def negative_penalty(
    item: dict,
    profile: Optional[DeviceProfile],
    cfg: dict,
    now: datetime,
) -> tuple[float, bool, str]:
    """返回 (惩罚, 是否硬隐藏, why)。"""
    if not profile:
        return 0.0, False, ""
    item_key = item.get("id") or item.get("full_name") or ""
    targets = {
        "item": item_key,
        "owner": item.get("owner") or "",
        "scene_l2": item.get("scene_l2") or "",
        "scene": item.get("scene") or "",
    }
    penalty = 0.0
    hidden = False
    bits: list[str] = []
    for row in profile.suppress:
        scope = row.get("scope") or ""
        key = row.get("key") or ""
        if not scope or not key or targets.get(scope) != key:
            continue
        expires = parse_ts(row.get("expires_at"))
        if expires and expires <= now:
            continue
        spec = cfg["suppress"].get(scope) or [0.2, 7, 0.02]
        w0 = float(row.get("weight") or spec[0])
        eff = decay(w0, days_since(row.get("created_at"), now), float(spec[1]))
        if eff < float(spec[2]):
            continue
        if scope == "item":
            hidden = True
            bits.append("hide:item")
            continue
        penalty += eff
        bits.append(f"sup:{scope}:{eff:.2f}")

    fat_row = profile.fatigue.get(item_key)
    if fat_row:
        count, last_at = fat_row
        age = days_since(last_at, now)
        fcfg = cfg["fatigue"]
        eff_count = decay(float(count), age, float(fcfg["half_life_days"]))
        if (
            count >= int(fcfg["hard_block_impressions"])
            and (age is None or age <= float(fcfg["hard_block_days"]))
        ):
            hidden = True
            bits.append("hide:fatigue")
        elif eff_count > 0:
            f = 1.0 - math.exp(-eff_count / float(fcfg["scale"]))
            penalty += f * float(cfg["weights"]["fatigue"])
            bits.append(f"fatigue:{f:.2f}")
    return penalty, hidden, " ".join(bits)


# —— 会话种子 ——

def session_jitter(item_key: str, seed: str, amp: float) -> float:
    if not seed or amp <= 0:
        return 0.0
    digest = hashlib.blake2b(f"{seed}:{item_key}".encode("utf-8"), digest_size=8).digest()
    frac = int.from_bytes(digest, "big") / float(1 << 64)
    return amp * (frac - 0.5)


# —— 多样性 ——

def _run_length(out: list[dict], scene_id: str) -> int:
    n = 0
    for prev in reversed(out):
        if (prev.get("scene") or "") == scene_id:
            n += 1
        else:
            break
    return n


def _violates(item: dict, out: list[dict], cfg: dict, relax: int, *, search: bool) -> bool:
    d = cfg["diversity"]
    window = int(d["window"])
    max_run = int(d["search_max_consecutive_scene"] if search else d["max_consecutive_scene"])
    if relax < 1 and item.get("_focus_hit"):
        tail = out[-(window - 1):] if window > 1 else []
        if sum(1 for p in tail if p.get("_focus_hit")) >= int(d["max_focus_per_window"]):
            return True
    if relax < 2:
        l2 = item.get("scene_l2") or ""
        if l2:
            tail10 = out[-9:]
            if sum(1 for p in tail10 if (p.get("scene_l2") or "") == l2) >= int(d["max_l2_per_10"]):
                return True
    if relax < 3:
        owner = item.get("owner") or ""
        if owner:
            tail = out[-(window - 1):] if window > 1 else []
            if sum(1 for p in tail if (p.get("owner") or "") == owner) >= int(d["max_owner_per_window"]):
                return True
    if relax < 4:
        if _run_length(out, item.get("scene") or "") >= max_run:
            return True
    return False


def apply_diversity(
    items: list[dict],
    cfg: dict,
    *,
    search: bool = False,
) -> list[dict]:
    """贪心 + 逐级放宽。不变量：输出集合恒等于输入集合，不丢不重。

    候选池被筛得很小时（长尾、行业筛选）约束必然冲突，此时按固定顺序放宽
    focus → l2 → owner → scene，而不是丢条目。relax=4 等于无约束，
    所以循环一定能取到候选，不会死循环。
    """
    remaining = list(items)
    out: list[dict] = []
    while remaining:
        pick = None
        for relax in range(0, 5):
            for idx, cand in enumerate(remaining):
                if not _violates(cand, out, cfg, relax, search=search):
                    pick = idx
                    break
            if pick is not None:
                break
        out.append(remaining.pop(pick if pick is not None else 0))
    return out


# —— 探索位 ——

def exploration_candidates(
    items: list[dict],
    profile: Optional[DeviceProfile],
    cfg: dict,
) -> list[dict]:
    """画像外的内容。忽略行业级负反馈——这是有意留的解封通道。

    没有画像时返回空：没有「圈内」就无所谓「破圈」，整个 feed 本来就是中立的，
    这时候硬标几个探索位只是给用户看不懂的标签。
    """
    tops = set(profile.top_scenes(3)) if profile else set()
    if not tops:
        return []
    pool = [
        it for it in items
        if not it.get("_hidden")
        and ((it.get("_affinity") or 0.0) <= 0 or (it.get("scene") or "") not in tops)
    ]
    pool.sort(key=lambda x: -float(x.get("global_score") or 0))
    return pool


def exploration_slots(total: int, cfg: dict) -> set[int]:
    window = int(cfg["diversity"]["window"])
    out: set[int] = set()
    for wstart in range(0, total, window):
        for s in cfg["exploration"]["slots"]:
            if wstart + int(s) < total:
                out.add(wstart + int(s))
    return out


def _pick_next(
    pool: list[dict],
    used: set[int],
    out: list[dict],
    cfg: dict,
    *,
    search: bool,
    only_new: bool = False,
    max_relax: int = 4,
) -> Optional[dict]:
    for relax in range(0, max_relax + 1):
        for cand in pool:
            if id(cand) in used:
                continue
            if only_new and not cand.get("is_new"):
                continue
            if not _violates(cand, out, cfg, relax, search=search):
                return cand
    return None


def arrange_feed(
    scored: list[dict],
    *,
    profile: Optional[DeviceProfile] = None,
    config: Optional[dict] = None,
    search: bool = False,
) -> list[dict]:
    """一次成型地填位：探索位从探索池取，其余位置从主池取。

    为什么不能「先排好再把探索条目挪进来」：从中间抽走一条，原本被它隔开的
    两条同行业内容会贴到一起，多样性约束当场失效（实测真实数据里首屏出现过
    连续 4 条同行业）。所以探索位必须参与同一趟贪心，而不是事后拼接。
    """
    cfg = config if config and "global_parts" in config else resolve_config(config)
    total = len(scored)
    if total == 0:
        return []
    if search:
        return apply_diversity(scored, cfg, search=search)

    explore_pool = exploration_candidates(scored, profile, cfg)
    if not explore_pool:
        return apply_diversity(scored, cfg, search=search)

    explore_ids = {id(x) for x in explore_pool}
    slots = exploration_slots(total, cfg)
    window = int(cfg["diversity"]["window"])
    min_new = int(cfg["exploration"]["min_new_per_window"])

    used: set[int] = set()
    out: list[dict] = []
    quota: dict[int, int] = {}
    for pos in range(total):
        wi = pos // window
        quota.setdefault(wi, min_new)
        pick = None
        if pos in slots:
            if quota[wi] > 0:
                # 新品配额是尽力而为：只在不破坏多样性的前提下优先，不为它放宽约束
                pick = _pick_next(
                    explore_pool, used, out, cfg, search=search,
                    only_new=True, max_relax=0,
                )
            if pick is None:
                pick = _pick_next(explore_pool, used, out, cfg, search=search)
        if pick is None:
            pick = _pick_next(scored, used, out, cfg, search=search)
        if pick is None:
            pick = next(x for x in scored if id(x) not in used)
        if pos in slots and id(pick) in explore_ids:
            pick["rank_slot"] = "exploration"
            if pick.get("is_new"):
                quota[wi] -= 1
        used.add(id(pick))
        out.append(pick)
    return out


# —— 主入口 ——

def rank_feed(
    items: list[dict],
    *,
    profile: Optional[DeviceProfile] = None,
    stats: Optional[dict[str, ItemStats]] = None,
    gstats: Optional[GlobalStats] = None,
    star_snapshot: Optional[dict] = None,
    config: Optional[dict] = None,
    query: str = "",
    scene_filter: str = "",
    scene_l2_filter: str = "",
    session_seed: str = "",
    now: Optional[datetime] = None,
    use_precomputed_global: bool = False,
) -> list[dict]:
    """完整仲裁流程：硬过滤 → 查询筛选 → 打分 → 排序 → 多样性 → 探索位。

    返回的是浅拷贝，不改原对象。
    """
    cfg = config if config and "global_parts" in config else resolve_config(config)
    now = now or datetime.now(timezone.utc)
    stats = stats or {}
    searching = bool((query or "").strip())

    # star 证据强度必须在打分前按整批算：它依赖同仓条目数这个批级信息
    if not use_precomputed_global:
        annotate_repo_share(items, config=cfg)

    # 0. 硬过滤 + 打分
    scored: list[dict] = []
    conf_p = profile_confidence(profile, cfg)
    w = cfg["weights"]
    w_g = float(w["global"]) - (float(w["global"]) - float(w["global_min"])) * conf_p
    w_p = float(w["personal_max"]) * conf_p
    w_f = float(w["focus"]) if (profile and profile.has_focus) else 0.0

    # 1. 搜索/筛选压过个性化：个性化降级成同档内的次级排序键
    if searching:
        w_p *= float(cfg["search"]["personal_scale"])
        w_f *= float(cfg["search"]["focus_scale"])

    for raw in items:
        it = dict(raw)
        if scene_filter and (it.get("scene") or "") != scene_filter:
            continue
        if scene_l2_filter and (it.get("scene_l2") or "") != scene_l2_filter:
            continue
        key = it.get("id") or it.get("full_name") or ""
        st = stats.get(key)

        if use_precomputed_global and it.get("global_score") is not None:
            g = float(it["global_score"])
            g_why = str(it.get("global_why") or "")
        else:
            g, g_why = global_quality(
                it, stats=st, gstats=gstats, star_snapshot=star_snapshot,
                config=cfg, now=now,
            )
        it["global_score"] = g
        it["global_why"] = g_why
        it["is_new"] = is_new_item(it, st, cfg, now)

        p, p_why = personal_affinity(it, profile, cfg, now)
        f, f_why = focus_affinity(it, profile, cfg)
        n, hidden, n_why = negative_penalty(it, profile, cfg, now)
        it["_affinity"] = p
        it["_focus_hit"] = f > 0
        it["_hidden"] = hidden

        rel = 0.0
        if searching:
            rel, _ = rank_mod.intent_overlap(it, query)
            if rel < float(cfg["search"]["min_relevance"]):
                continue
        it["_relevance"] = rel

        eps = session_jitter(key, session_seed, float(cfg["session"]["jitter_amp"]))
        score = w_g * g + w_p * p + w_f * f - n + eps
        it["affinity_score"] = round(p, 4)
        it["focus_score"] = round(f, 4)
        it["penalty"] = round(n, 4)
        # personal_score 沿用旧语义（最终排序分），前端和既有测试都依赖它
        it["personal_score"] = round(score, 4)
        it["rank_slot"] = "main"
        it["rank_debug"] = (
            f"g:{g:.2f}*{w_g:.2f} p:{p:+.2f}*{w_p:.2f} f:{f:.2f}*{w_f:.2f} "
            f"n:-{n:.2f} {g_why} {p_why} {f_why} {n_why}"
        ).strip()
        if hidden:
            continue
        scored.append(it)

    # 2/3. 排序。搜索态先按相关性分桶，个性化只在桶内起作用
    if searching:
        bucket = float(cfg["search"]["relevance_bucket"]) or 0.1
        scored.sort(key=lambda x: (
            -math.floor(float(x.get("_relevance") or 0) / bucket),
            -float(x.get("personal_score") or 0),
        ))
    else:
        scored.sort(key=lambda x: (
            -float(x.get("personal_score") or 0),
            -float(x.get("global_score") or 0),
        ))

    # 4/5. 多样性硬约束 + 探索位注入（同一趟贪心，见 arrange_feed 的说明）
    # 搜索态关闭探索位：用户在找具体东西，不是在逛
    ordered = arrange_feed(scored, profile=profile, config=cfg, search=searching)

    for it in ordered:
        it.pop("_hidden", None)
    return ordered
