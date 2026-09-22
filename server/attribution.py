"""进站渠道归因：UTM + referrer → 可分析的 channel 枚举。

只服务运营看板与 CSV，不进排序打分。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

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
_PAID_MEDIUM = frozenset({
    "cpc", "ppc", "paid", "paidsearch", "paid_social", "paidsocial",
    "display", "cpm", "cpa", "ads", "ad", "retargeting",
})
_OWN_HOSTS = ("skillfeeder.cn", "469910093-ui.github.io")


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


def _match_host(host: str, needles: tuple[str, ...]) -> bool:
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


def classify_channel(
    *,
    utm_source: str = "",
    utm_medium: str = "",
    utm_campaign: str = "",
    referrer: str = "",
    channel: str = "",
) -> str:
    """优先信显式 channel；否则按 UTM / referrer 归类。"""
    explicit = (channel or "").strip().lower()
    if explicit in CHANNELS:
        return explicit

    medium = (utm_medium or "").strip().lower()
    source = (utm_source or "").strip().lower()
    campaign = (utm_campaign or "").strip()
    host = _host(referrer)

    if medium in _PAID_MEDIUM or source in _PAID_MEDIUM:
        return "paid"
    if source in ("chatgpt", "claude", "perplexity", "gemini", "geo", "agent", "llm"):
        return "geo_agent"
    if medium in ("organic", "seo") or source in ("google", "baidu", "bing", "seo"):
        return "organic_search"
    if medium in ("social", "social-organic") or source in (
        "weixin", "wechat", "xiaohongshu", "xhs", "douyin", "weibo", "twitter", "linkedin",
    ):
        return "social"

    if _match_host(host, _OWN_HOSTS):
        return "internal"
    if _match_host(host, _GEO_HOSTS):
        return "geo_agent"
    if _match_host(host, _SEARCH_HOSTS):
        return "organic_search"
    if _match_host(host, _SOCIAL_HOSTS):
        return "social"

    if source or medium or campaign:
        return "campaign"
    if host:
        return "referral"
    return "direct"


def sanitize_attr(raw: dict[str, Any] | None) -> dict[str, str]:
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
    )
    return {
        "channel": channel,
        "referrer": referrer,
        "landing": landing,
        "utm_source": utm_source,
        "utm_medium": utm_medium,
        "utm_campaign": utm_campaign,
    }
