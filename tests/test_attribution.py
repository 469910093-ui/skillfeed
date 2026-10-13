"""进站渠道归因单测。"""

from __future__ import annotations

import sqlite3
import unittest

from server.attribution import (
    DEFAULT_RULES,
    build_link,
    classify_channel,
    load_rules,
    merge_rules,
    normalize_landing,
    normalize_rule_value,
    normalize_utm_value,
    sanitize_attr,
)


class TestClassifyChannel(unittest.TestCase):
    def test_direct(self):
        self.assertEqual(classify_channel(), "direct")

    def test_seo_referrer(self):
        self.assertEqual(
            classify_channel(referrer="https://www.google.com/search?q=skill"),
            "organic_search",
        )
        self.assertEqual(classify_channel(referrer="baidu.com"), "organic_search")

    def test_geo_referrer(self):
        self.assertEqual(classify_channel(referrer="chatgpt.com"), "geo_agent")
        self.assertEqual(classify_channel(referrer="www.perplexity.ai"), "geo_agent")
        self.assertEqual(
            classify_channel(utm_source="claude", utm_medium="referral"),
            "geo_agent",
        )

    def test_social(self):
        self.assertEqual(classify_channel(referrer="xiaohongshu.com"), "social")
        self.assertEqual(classify_channel(utm_source="weixin"), "social")

    def test_paid(self):
        self.assertEqual(
            classify_channel(utm_source="google", utm_medium="cpc"),
            "paid",
        )

    def test_campaign_utm(self):
        self.assertEqual(
            classify_channel(utm_source="newsletter", utm_campaign="sep"),
            "campaign",
        )

    def test_explicit_wins(self):
        self.assertEqual(
            classify_channel(channel="geo_agent", referrer="google.com"),
            "geo_agent",
        )

    def test_sanitize(self):
        row = sanitize_attr({
            "utm_source": "google",
            "utm_medium": "organic",
            "referrer": "https://www.google.com/",
            "landing": "/?q=周报",
        })
        self.assertEqual(row["channel"], "organic_search")
        self.assertEqual(row["referrer"], "google.com")
        self.assertIn("周报", row["landing"])

    def test_gemini_is_geo_not_search(self):
        self.assertEqual(classify_channel(referrer="gemini.google.com"), "geo_agent")

    def test_own_host_is_internal(self):
        self.assertEqual(classify_channel(referrer="https://skillfeeder.cn/s/x.html"), "internal")

    def test_paid_source_kept(self):
        self.assertEqual(classify_channel(utm_source="cpc"), "paid")

    def test_model_utm_source_domain_is_geo(self):
        """ChatGPT 等外链会自己挂 utm_source=域名，没有 referrer 也要归模型GEO。"""
        for src in ("chatgpt.com", "perplexity.ai", "claude.ai", "kimi.com",
                    "chat.deepseek.com", "metaso.cn", "www.doubao.com", "CHATGPT.COM"):
            with self.subTest(src=src):
                self.assertEqual(classify_channel(utm_source=src), "geo_agent")

    def test_domain_utm_source_falls_back_to_host_table(self):
        self.assertEqual(classify_channel(utm_source="m.sm.cn"), "organic_search")
        self.assertEqual(classify_channel(utm_source="xiaohongshu.com"), "social")
        # 自家域名当 utm_source 不算外部来源
        self.assertEqual(classify_channel(utm_source="skillfeeder.cn"), "campaign")
        self.assertEqual(classify_channel(utm_source="unknown.example"), "campaign")

    def test_paid_medium_still_beats_model_source(self):
        self.assertEqual(classify_channel(utm_source="chatgpt.com", utm_medium="cpc"), "paid")

    def test_domestic_models_are_geo(self):
        for ref in ("https://kimi.com/chat/1", "kimi.moonshot.cn", "chat.deepseek.com",
                    "www.deepseek.com", "metaso.cn", "www.doubao.com",
                    "yuanbao.tencent.com", "tongyi.aliyun.com", "www.tongyi.com",
                    "chat.qwen.ai", "chatglm.cn", "yiyan.baidu.com", "www.tiangong.cn",
                    "xinghuo.xfyun.cn", "hailuoai.com", "www.n.cn"):
            with self.subTest(ref=ref):
                self.assertEqual(classify_channel(referrer=ref), "geo_agent")

    def test_overseas_models_are_geo(self):
        for ref in ("copilot.microsoft.com", "grok.com", "www.meta.ai", "www.phind.com",
                    "chat.mistral.ai", "felo.ai", "www.genspark.ai"):
            with self.subTest(ref=ref):
                self.assertEqual(classify_channel(referrer=ref), "geo_agent")

    def test_model_subdomain_of_search_engine_stays_geo(self):
        self.assertEqual(classify_channel(referrer="yiyan.baidu.com"), "geo_agent")
        self.assertEqual(classify_channel(referrer="www.baidu.com"), "organic_search")

    def test_more_search_engines(self):
        for ref in ("m.sm.cn", "www.so.com", "m.so.com", "so.toutiao.com", "www.haosou.com",
                    "search.naver.com", "yandex.ru", "www.sogou.com", "duckduckgo.com"):
            with self.subTest(ref=ref):
                self.assertEqual(classify_channel(referrer=ref), "organic_search")
        # 头条正文页不是搜索
        self.assertEqual(classify_channel(referrer="www.toutiao.com"), "referral")

    def test_new_defaults_visible_in_default_tables(self):
        host = DEFAULT_RULES.table("host")
        for v in ("kimi.com", "chat.deepseek.com", "metaso.cn", "sm.cn", "so.toutiao.com"):
            self.assertIn(v, host)
        self.assertEqual(DEFAULT_RULES.table("source")["chatgpt.com"], "geo_agent")


def _ov(kind, value, channel, enabled=1):
    return {"kind": kind, "value": value, "channel": channel, "enabled": enabled}


class TestRuleOverrides(unittest.TestCase):
    def test_add_source_alias(self):
        rules = merge_rules([_ov("source", "jike", "social")])
        self.assertEqual(classify_channel(utm_source="jike"), "campaign")
        self.assertEqual(classify_channel(utm_source="jike", rules=rules), "social")

    def test_disable_default_host(self):
        rules = merge_rules([_ov("host", "zhihu.com", "social", enabled=0)])
        self.assertEqual(classify_channel(referrer="zhihu.com"), "social")
        self.assertEqual(classify_channel(referrer="zhihu.com", rules=rules), "referral")

    def test_change_default_channel(self):
        rules = merge_rules([_ov("source", "xhs", "campaign")])
        self.assertEqual(classify_channel(utm_source="xhs", rules=rules), "campaign")

    def test_add_paid_medium(self):
        rules = merge_rules([_ov("medium", "kol", "paid")])
        self.assertEqual(
            classify_channel(utm_source="xhs", utm_medium="kol", rules=rules), "paid",
        )

    def test_unknown_channel_or_kind_ignored(self):
        rules = merge_rules([_ov("source", "foo", "nope"), _ov("bogus", "x", "social")])
        self.assertEqual(classify_channel(utm_source="foo", rules=rules), "campaign")
        self.assertEqual(dict(rules.source), dict(DEFAULT_RULES.source))

    def test_defaults_untouched_by_merge(self):
        merge_rules([_ov("source", "xhs", "paid", enabled=0)])
        self.assertEqual(DEFAULT_RULES.source["xhs"], "social")

    def test_load_rules_falls_back_without_table(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self.assertIs(load_rules(conn), DEFAULT_RULES)

    def test_override_on_new_default_still_applies(self):
        rules = merge_rules([_ov("host", "kimi.com", "referral")])
        self.assertEqual(classify_channel(referrer="kimi.com", rules=rules), "referral")
        rules = merge_rules([_ov("source", "chatgpt.com", "campaign")])
        self.assertEqual(classify_channel(utm_source="chatgpt.com", rules=rules), "campaign")

    def test_domain_source_fallback_follows_host_overrides(self):
        rules = merge_rules([_ov("host", "jike.city", "social")])
        self.assertEqual(classify_channel(utm_source="jike.city"), "campaign")
        self.assertEqual(classify_channel(utm_source="jike.city", rules=rules), "social")
        rules = merge_rules([_ov("host", "metaso.cn", "geo_agent", enabled=0)])
        self.assertEqual(classify_channel(utm_source="metaso.cn", rules=rules), "campaign")

    def test_sanitize_uses_rules(self):
        rules = merge_rules([_ov("source", "jike", "social")])
        self.assertEqual(sanitize_attr({"utm_source": "jike"}, rules=rules)["channel"], "social")


class TestValidationAndLinks(unittest.TestCase):
    def test_host_value_normalized(self):
        self.assertEqual(
            normalize_rule_value("host", "https://www.Jike.city/u/abc"), "jike.city",
        )
        self.assertEqual(normalize_rule_value("host", "google."), "google.")

    def test_bad_values_rejected(self):
        for kind, raw in (
            ("host", "<script>"), ("host", "nodot"), ("host", "a..b"),
            ("source", "a b"), ("source", '"x"'), ("medium", ""), ("source", "x" * 41),
            ("nope", "x"),
        ):
            with self.assertRaises(ValueError, msg=(kind, raw)):
                normalize_rule_value(kind, raw)

    def test_utm_value(self):
        self.assertEqual(normalize_utm_value(" XHS ", lower=True), "xhs")
        self.assertEqual(normalize_utm_value("Note_1013"), "Note_1013")
        with self.assertRaises(ValueError):
            normalize_utm_value("a&b=c")

    def test_landing(self):
        self.assertEqual(normalize_landing(""), "/")
        self.assertEqual(normalize_landing("/s/x.html"), "/s/x.html")
        for bad in ("//evil.com", "https://evil.com", "/a b", "/\"x", "/<x>"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_landing(bad)

    def test_build_link(self):
        self.assertEqual(
            build_link("https://skillfeeder.cn", "/", utm_source="xhs", utm_medium="social",
                       utm_campaign="note"),
            "https://skillfeeder.cn/?utm_source=xhs&utm_medium=social&utm_campaign=note",
        )
        self.assertEqual(
            build_link("https://skillfeeder.cn/", "/?q=周报&utm_source=old#top", utm_source="wechat"),
            "https://skillfeeder.cn/?q=周报&utm_source=wechat#top",
        )
        self.assertEqual(build_link("https://skillfeeder.cn", "/skills.html"),
                         "https://skillfeeder.cn/skills.html")


if __name__ == "__main__":
    unittest.main()
