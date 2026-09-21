"""Agent Surface：公开文件只有白名单字段，预览站不泄目录。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import geo
import skillfeed


SECRET_FEED = {
    "generated_at": "2026-09-21T00:00:00+00:00",
    "items": [
        {
            "full_name": "acme/weekly-skill",
            "name": "weekly-skill",
            "description": "make a weekly report",
            "one_liner": "weekly report helper",
            "url": "https://github.com/acme/weekly-skill",
            "source": "github-search",
            "kind": "skill",
            "scene": "content",
            "scene_label": "内容创作",
            "stars": 88,
            "personal_score": 0.91,
            "rank_why": "secret ranking",
            "rank_debug": {"w": 1},
            "from_corpus": True,
        },
        {
            "full_name": "acme/slop-skill",
            "name": "slop-skill",
            "description": "remove AI slop 去AI味",
            "url": "https://github.com/acme/slop-skill",
            "stars": 12,
            "personal_score": 0.2,
        },
    ],
    "corpus": [{"id": "keep-me-off-geo"}],
    "gates": {"details": [{"repo": "acme/weekly-skill", "score": 0.9}]},
}


class TestSanitize(unittest.TestCase):
    def test_secret_keys_are_stripped(self):
        cleaned = geo.sanitize_item(SECRET_FEED["items"][0])
        self.assertEqual(cleaned["full_name"], "acme/weekly-skill")
        self.assertEqual(cleaned["stars"], 88)
        self.assertEqual(cleaned["owner"], "acme")
        for key in geo.SECRET_KEYS:
            self.assertNotIn(key, cleaned)

    def test_search_ranks_intent(self):
        items = geo.sanitize_items(SECRET_FEED["items"])
        page, total = geo.search_items(items, query="weekly report", limit=5)
        self.assertEqual(total, 1)
        self.assertEqual(page[0]["full_name"], "acme/weekly-skill")


class TestWriteGeoSite(unittest.TestCase):
    def test_preview_writes_pointer_files_without_catalog_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            written = geo.write_geo_site(out, SECRET_FEED, full=False)
            names = {p.name for p in written}
            self.assertTrue(set(geo.GEO_FILENAMES) <= names)
            raw = (out / "llms.txt").read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", raw)
            self.assertIn("从 GitHub".encode("utf-8"), raw)
            llms = raw.decode("utf-8")
            self.assertTrue(llms.startswith("# SkillFeeder\n"))
            self.assertIn("> ", llms)
            self.assertIn("does **not** install", llms)
            self.assertIn("high-star", llms)
            self.assertIn("traffic", llms)
            self.assertIn("weekly report", llms)
            self.assertIn("会议纪要", llms)
            self.assertIn("https://skillfeeder.cn/llms.txt", llms)
            about = (out / "about.md").read_text(encoding="utf-8")
            self.assertIn("给发现者", about)
            self.assertIn("给发布者", about)
            faq = (out / "faq.md").read_text(encoding="utf-8")
            self.assertIn("靠谱", faq)
            self.assertIn("用户找到", faq)
            full_md = (out / "llms-full.txt").read_text(encoding="utf-8")
            self.assertNotIn("acme/weekly-skill", full_md)
            catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
            self.assertTrue(catalog["preview"])
            self.assertEqual(catalog["items"], [])
            self.assertNotIn("personal_score", (out / "catalog.json").read_text(encoding="utf-8"))
            robots = (out / "robots.txt").read_text(encoding="utf-8")
            self.assertIn("Disallow: /op", robots)
            self.assertIn("GPTBot", robots)
            self.assertNotIn("Allow: /op", robots)
            self.assertIn("Allow: /login", robots)
            self.assertIn("Allow: /publish", robots)
            self.assertNotIn("Disallow: /login", robots)
            self.assertNotIn("Disallow: /publish", robots)
            sitemap = (out / "sitemap.xml").read_text(encoding="utf-8")
            self.assertIn("/login", sitemap)
            self.assertIn("/publish", sitemap)
            self.assertTrue((out / "og.png").exists())
            self.assertTrue((out / "favicon.ico").exists())
            self.assertTrue((out / "favicon.png").exists())
            self.assertTrue((out / "apple-touch-icon.png").exists())

    def test_full_catalog_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, SECRET_FEED, full=True)
            catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
            self.assertFalse(catalog["preview"])
            self.assertEqual(len(catalog["items"]), 2)
            self.assertEqual(catalog["items"][0]["full_name"], "acme/weekly-skill")
            blob = (out / "catalog.json").read_text(encoding="utf-8")
            self.assertNotIn("personal_score", blob)
            self.assertNotIn("rank_why", blob)
            self.assertNotIn("keep-me-off-geo", blob)
            full_md = (out / "llms-full.txt").read_text(encoding="utf-8")
            self.assertIn("acme/weekly-skill", full_md)
            self.assertNotIn("secret ranking", full_md)


class TestPublishSiteWritesGeo(unittest.TestCase):
    def _publish(self, extra):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = Path(tmp.name) / "data"
        home.mkdir()
        out = Path(tmp.name) / "site"
        (home / "feed.json").write_text(
            json.dumps(SECRET_FEED, ensure_ascii=False), encoding="utf-8",
        )
        prev = os.environ.get("SKILLFEED_HOME")
        try:
            os.environ["SKILLFEED_HOME"] = str(home)
            skillfeed.refresh_paths()
            rc = skillfeed.cmd_publish_site(["--out", str(out), *extra])
        finally:
            if prev is None:
                os.environ.pop("SKILLFEED_HOME", None)
            else:
                os.environ["SKILLFEED_HOME"] = prev
            skillfeed.refresh_paths()
        self.assertEqual(rc, 0)
        return out

    def test_default_pages_shell_still_has_zero_feed_items(self):
        out = self._publish([])
        published = json.loads((out / "feed.json").read_text(encoding="utf-8"))
        self.assertEqual(published["items"], [])
        self.assertTrue((out / "llms.txt").exists())
        catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["items"], [])
        html = (out / "index.html").read_text(encoding="utf-8")
        self.assertIn('rel="describedby"', html)
        self.assertIn("<noscript>", html)
        self.assertIn("application/ld+json", html)
        self.assertIn("og:title", html)
        self.assertIn("已过滤的高星", html)
        self.assertIn("可靠流量渠道", html)
        self.assertIn("/og.png", html)
        self.assertIn('rel="icon"', html)
        self.assertIn("favicon.png", html)
        self.assertIn("apple-touch-icon.png", html)
        self.assertTrue((out / "favicon.ico").exists())
        self.assertNotIn("secret ranking", html)

    def test_full_publish_keeps_geo_sanitized(self):
        out = self._publish(["--full"])
        catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(catalog["items"]), 1)
        self.assertNotIn("personal_score", json.dumps(catalog))


if __name__ == "__main__":
    unittest.main()
