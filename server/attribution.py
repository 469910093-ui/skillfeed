"""进站渠道归因：UTM + referrer → 可分析的 channel 枚举。

只服务运营看板与 CSV，不进排序打分。

规则 = 代码默认（下方 DEFAULT_*）+ 运营在后台「渠道配置」写的覆盖（SQLite
`channel_rules`）。覆盖按 (kind, value) 逐条生效：改渠道、停用默认、新增。
读库失败一律退回代码默认，归因不能因为配置表坏了就停摆。
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlencode, urlparse

# 稳定枚举；后台 KPI / CSV 只认这些值
CHANNELS = frozenset({
    "direct",
    "organic_search",
    "geo_agent",
    "social",
    "referral",
    "paid",
    "campaign",
    "internal",
})

CHANNEL_LABELS: dict[str, str] = {
    "direct": "直接",
    "organic_search": "搜索SEO",
    "geo_agent": "模型GEO",
    "social": "社交",
    "referral": "外链",
    "paid": "付费",
    "campaign": "活动UTM",
    "internal": "站内",
}

# host = 来源域名；source = utm_source；medium = utm_medium
RULE_KINDS = ("host", "source", "medium")

_SEARCH_HOSTS = (
    "google.", "bing.", "baidu.", "duckduckgo.", "yahoo.",
    "sogou.", "so.com", "yandex.", "ecosia.", "search.brave.",
)
_GEO_HOSTS = (
    "chat.openai.com", "chatgpt.com", "claude.ai", "perplexity.ai",
    "gemini.google.com", "bard.google.com", "you.com", "poe.com",
    "copilot.microsoft.com", "kimi.moonshot.cn", "tongyi.aliyun.com",
    "yuanbao.tencent.com", "doubao.com", "xinghuo.xfyun.cn",
)
_SOCIAL_HOSTS = (
    "weixin.qq.com", "mp.weixin.qq.com", "xiaohongshu.com", "xhslink.com",
    "douyin.com", "iesdouyin.com", "weibo.com", "t.cn",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "fb.com",
    "instagram.com", "zhihu.com", "bilibili.com", "tiktok.com",
)
_PAID_MEDIUM = (
    "cpc", "ppc", "paid", "paidsearch", "paid_social", "paidsocial",
    "display", "cpm", "cpa", "ads", "ad", "retargeting",
)
_OWN_HOSTS = ("skillfeeder.cn", "469910093-ui.github.io")

_GEO_SOURCES = ("chatgpt", "claude", "perplexity", "gemini", "geo", "agent", "llm")
_SEARCH_SOURCES = ("google", "baidu", "bing", "seo")
_SOCIAL_SOURCES = (
    "weixin", "wechat", "xiaohongshu", "xhs", "douyin", "weibo", "twitter", "linkedin",
)


def _table(*groups: tuple[tuple[str, ...], str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for values, channel in groups:
        for v in values:
            out.setdefault(v, channel)
    return out


DEFAULT_HOST_RULES = _table(
    (_OWN_HOSTS, "internal"),
    (_GEO_HOSTS, "geo_agent"),
    (_SEARCH_HOSTS, "organic_search"),
    (_SOCIAL_HOSTS, "social"),
)
DEFAULT_SOURCE_RULES = _table(
    (_GEO_SOURCES, "geo_agent"),
    (_SEARCH_SOURCES, "organic_search"),
    (_SOCIAL_SOURCES, "social"),
)
DEFAULT_MEDIUM_RULES = _table(
    (_PAID_MEDIUM, "paid"),
    (("organic", "seo"), "organic_search"),
    (("social", "social-organic"), "social"),
)

# 同一次访问命中多条规则时谁赢。UTM 侧：付费 > 模型 > 搜索 > 社交；
# 域名侧：自家域名最先（站内跳转不算外部来源），模型站排在搜索前
# （gemini.google.com 同时命中 "google."）。
_UTM_PRIORITY = (
    "paid", "geo_agent", "organic_search", "social",
    "internal", "referral", "campaign", "direct",
)
_HOST_PRIORITY = (
    "internal", "geo_agent", "organic_search", "social",
    "paid", "referral", "campaign", "direct",
)


@dataclass(frozen=True)
class ChannelRules:
    host: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_HOST_RULES))
    source: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_SOURCE_RULES))
    medium: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_MEDIUM_RULES))

    def table(self, kind: str) -> Mapping[str, str]:
        return {"host": self.host, "source": self.source, "medium": self.medium}[kind]


DEFAULT_RULES = ChannelRules()


def default_table(kind: str) -> Mapping[str, str]:
    return DEFAULT_RULES.table(kind)


# —— 规则值校验（后台写入口共用） ——

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,78}[a-z0-9.])?$")
_TOKEN_RE = re.compile(r"^[\w.\-]{1,40}$")


def normalize_rule_value(kind: str, raw: str) -> str:
    """规范化并校验一条规则的匹配值；不合法抛 ValueError（文案直接给运营看）。"""
    if kind not in RULE_KINDS:
        raise ValueError("规则类型不对")
    value = (raw or "").strip().lower()
    if kind == "host":
        if "://" in value:
            value = (urlparse(value).hostname or "")
        value = value.split("/")[0].split("?")[0]
        if value.startswith("www."):
            value = value[4:]
        if not value or "." not in value or ".." in value or not _HOST_RE.match(value):
            raise ValueError("域名只能填字母、数字、点和横线，例如 xiaohongshu.com")
        return value
    if not _TOKEN_RE.match(value):
        raise ValueError("参数值只能填字母、数字、下划线、点和横线，最多 40 个字")
    return value


def merge_rules(overrides: Iterable[Mapping[str, Any]]) -> ChannelRules:
    """代码默认 + 覆盖行。覆盖行字段：kind / value / channel / enabled。"""
    tables = {k: dict(default_table(k)) for k in RULE_KINDS}
    for row in overrides or ():
        kind = str(row["kind"] or "")
        value = str(row["value"] or "")
        if kind not in tables or not value:
            continue
        if not int(row["enabled"] or 0):
            tables[kind].pop(value, None)
            continue
        channel = str(row["channel"] or "")
        if channel in CHANNELS:
            tables[kind][value] = channel
    return ChannelRules(host=tables["host"], source=tables["source"], medium=tables["medium"])


def load_rules(conn: sqlite3.Connection) -> ChannelRules:
    try:
        rows = conn.execute(
            "SELECT kind, value, channel, enabled FROM channel_rules"
        ).fetchall()
    except sqlite3.Error:
        return DEFAULT_RULES
    return merge_rules(rows)


class RulesCache:
    """进程内缓存。后台写入时 invalidate；多 worker 靠 TTL 追上。"""

    def __init__(self, ttl_s: float = 30.0) -> None:
        self.ttl_s = ttl_s
        self._lock = threading.Lock()
        self._rules: Optional[ChannelRules] = None
        self._at = 0.0

    def get(self, conn: sqlite3.Connection) -> ChannelRules:
        now = time.monotonic()
        with self._lock:
            if self._rules is not None and now - self._at < self.ttl_s:
                return self._rules
        rules = load_rules(conn)
        with self._lock:
            self._rules = rules
            self._at = now
        return rules

    def invalidate(self) -> None:
        with self._lock:
            self._rules = None
            self._at = 0.0


# —— 分类 ——

def _host(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        # 已是 hostname，或带路径的残片
        raw = raw.split("/")[0].split("?")[0]
        return raw[4:] if raw.startswith("www.") else raw
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _match_host(host: str, needles: Iterable[str]) -> bool:
    if not host:
        return False
    padded = f".{host}."
    for n in needles:
        n = n.rstrip(".").lower()
        if not n:
            continue
        if host == n or host.endswith("." + n) or host.startswith(n + "."):
            return True
        if f".{n}." in padded:
            return True
    return False


def _pick(candidates: Iterable[Optional[str]], priority: tuple[str, ...]) -> str:
    found = {c for c in candidates if c in CHANNELS}
    for ch in priority:
        if ch in found:
            return ch
    return ""


def classify_channel(
    *,
    utm_source: str = "",
    utm_medium: str = "",
    utm_campaign: str = "",
    referrer: str = "",
    channel: str = "",
    rules: Optional[ChannelRules] = None,
) -> str:
    """优先信显式 channel；否则按 UTM / referrer 归类。不传 rules 用代码默认。"""
    explicit = (channel or "").strip().lower()
    if explicit in CHANNELS:
        return explicit

    rules = rules or DEFAULT_RULES
    medium = (utm_medium or "").strip().lower()
    source = (utm_source or "").strip().lower()
    campaign = (utm_campaign or "").strip()
    host = _host(referrer)

    utm_hits = [
        rules.medium.get(medium) if medium else None,
        rules.source.get(source) if source else None,
        # 老口径：utm_source 填成 cpc 之类的付费媒介也算付费
        "paid" if source and rules.medium.get(source) == "paid" else None,
    ]
    hit = _pick(utm_hits, _UTM_PRIORITY)
    if hit:
        return hit

    if host:
        host_hits = [ch for needle, ch in rules.host.items() if _match_host(host, (needle,))]
        hit = _pick(host_hits, _HOST_PRIORITY)
        if hit:
            return hit

    if source or medium or campaign:
        return "campaign"
    if host:
        return "referral"
    return "direct"


def sanitize_attr(
    raw: dict[str, Any] | None, *, rules: Optional[ChannelRules] = None,
) -> dict[str, str]:
    """从事件 payload 抽出可落库的归因字段。"""
    row = raw if isinstance(raw, dict) else {}
    utm_source = str(row.get("utm_source") or "")[:80]
    utm_medium = str(row.get("utm_medium") or "")[:40]
    utm_campaign = str(row.get("utm_campaign") or "")[:80]
    referrer = _host(str(row.get("referrer") or ""))[:120]
    landing = str(row.get("landing") or "")[:200]
    channel = classify_channel(
        utm_source=utm_source,
        utm_medium=utm_medium,
        utm_campaign=utm_campaign,
        referrer=referrer,
        channel=str(row.get("channel") or ""),
        rules=rules,
    )
    return {
        "channel": channel,
        "referrer": referrer,
        "landing": landing,
        "utm_source": utm_source,
        "utm_medium": utm_medium,
        "utm_campaign": utm_campaign,
    }


# —— 推广链接 ——

_LANDING_RE = re.compile(r"^/[^\s\"'<>\\`]*$")
_UTM_RE = re.compile(r"^[\w.\-]{0,80}$")


def normalize_utm_value(raw: str, *, lower: bool = False) -> str:
    value = (raw or "").strip()
    if lower:
        value = value.lower()
    if not _UTM_RE.match(value):
        raise ValueError("utm 参数只能填字母、数字、下划线、点和横线，最多 80 个字")
    return value


def normalize_landing(raw: str) -> str:
    path = (raw or "").strip() or "/"
    if len(path) > 200 or path.startswith("//") or not _LANDING_RE.match(path):
        raise ValueError("落地路径要以 / 开头，不能有空格和引号，最多 200 个字")
    return path


def build_link(
    base: str, landing: str, *, utm_source: str = "", utm_medium: str = "", utm_campaign: str = "",
) -> str:
    """站点根 + 落地路径 + utm 参数。落地路径里已有的同名 utm 参数会被替换。"""
    path = landing or "/"
    path, _, fragment = path.partition("#")
    path, _, query = path.partition("?")
    pairs = [
        p for p in (query.split("&") if query else [])
        if p and p.split("=", 1)[0] not in ("utm_source", "utm_medium", "utm_campaign")
    ]
    utm = [(k, v) for k, v in (
        ("utm_source", utm_source), ("utm_medium", utm_medium), ("utm_campaign", utm_campaign),
    ) if v]
    if utm:
        pairs.append(urlencode(utm))
    url = base.rstrip("/") + path
    if pairs:
        url += "?" + "&".join(pairs)
    if fragment:
        url += "#" + fragment
    return url
