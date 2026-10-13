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
