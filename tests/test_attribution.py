"""进站渠道归因单测。"""

from __future__ import annotations

import unittest

from server.attribution import classify_channel, sanitize_attr


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


if __name__ == "__main__":
    unittest.main()
