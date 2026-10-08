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
            self.assertIn("## Key Facts", llms)
            self.assertIn("/about.html", llms)
            quote = next(line[2:] for line in llms.splitlines() if line.startswith("> "))
            self.assertLessEqual(len(quote), 200)
            about = (out / "about.md").read_text(encoding="utf-8")
            self.assertIn("给发现者", about)
            self.assertIn("给发布者", about)
            faq = (out / "faq.md").read_text(encoding="utf-8")
            self.assertIn("靠谱", faq)
            self.assertIn("用户找到", faq)
            self.assertIn("哪里找靠谱的 Cursor", faq)
            about_html = (out / "about.html").read_bytes()
            self.assertFalse(about_html.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", about_html)
            self.assertTrue(about_html.startswith(b"<!DOCTYPE html>"))
            self.assertIn("给发现者".encode("utf-8"), about_html)
            self.assertIn(b"application/ld+json", about_html)
            full_md = (out / "llms-full.txt").read_text(encoding="utf-8")
            self.assertNotIn("acme/weekly-skill", full_md)
            catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
            self.assertTrue(catalog["preview"])
            self.assertEqual(catalog["items"], [])
            self.assertNotIn("personal_score", (out / "catalog.json").read_text(encoding="utf-8"))
            robots = (out / "robots.txt").read_text(encoding="utf-8")
            self.assertIn("Disallow: /op", robots)
            self.assertIn("GPTBot", robots)
            self.assertIn("OAI-SearchBot", robots)
            self.assertIn("Applebot-Extended", robots)
            self.assertIn("Bytespider", robots)
            self.assertNotIn("Allow: /op", robots)
            self.assertIn("Allow: /login", robots)
            self.assertIn("Allow: /publish", robots)
            self.assertIn("Allow: /about.html", robots)
            self.assertNotIn("Disallow: /login", robots)
            self.assertNotIn("Disallow: /publish", robots)
            sitemap = (out / "sitemap.xml").read_text(encoding="utf-8")
            self.assertIn("/login", sitemap)
            self.assertIn("/publish", sitemap)
            self.assertIn("/about.html", sitemap)
            self.assertIn("/faq.html", sitemap)
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


ZH_FEED = {
    "generated_at": "2026-10-08T00:00:00+00:00",
    "items": [
        {
            "id": "anthropics/skills::skills/internal-comms/SKILL.md",
            "full_name": "anthropics/skills",
            "name": "internal-comms",
            "skill_path": "skills/internal-comms/SKILL.md",
            "skill_url": "https://github.com/anthropics/skills/blob/HEAD/skills/internal-comms/SKILL.md",
            "url": "https://github.com/anthropics/skills",
            "description": "Write internal communications.",
            "one_liner_zh": "按公司格式写周报、状态更新和内部通讯。",
            "highlights_zh": ["写周报", "写项目进展"],
            "who_for_zh": "需要定期汇报的职场人",
            "scene": "content",
            "scene_label": "内容创作",
            "scene_l2": "writing",
            "scene_l2_label": "写作润色",
            "kind": "skill",
            "stars": 180085,
            "personal_score": 0.99,
            "rank_why": "secret ranking",
        },
        {
            "id": "anthropics/skills::skills/pptx/SKILL.md",
            "full_name": "anthropics/skills",
            "name": "pptx",
            "skill_path": "skills/pptx/SKILL.md",
            "url": "https://github.com/anthropics/skills",
            "one_liner_zh": "生成和编辑 PPT。",
            "scene": "content",
            "scene_label": "内容创作",
            "scene_l2": "slides",
            "scene_l2_label": "PPT",
            "stars": 180085,
        },
        {
            "id": "acme/weekly-skill",
            "full_name": "acme/weekly-skill",
            "name": "weekly-skill",
            "url": "https://github.com/acme/weekly-skill",
            "one_liner": "weekly report helper",
            "scene": "agent-tooling",
            "scene_label": "Agent工具链",
            "stars": 88,
        },
    ],
}


class TestSeoPages(unittest.TestCase):
    def test_slugs_are_stable_and_unique(self):
        items = geo.sanitize_items(ZH_FEED["items"])
        slugs = [slug for slug, _ in geo.assign_skill_slugs(items)]
        self.assertEqual(
            slugs,
            ["anthropics-skills-internal-comms", "anthropics-skills-pptx", "acme-weekly-skill"],
        )
        clash = [
            {"id": "a", "full_name": "a-b/c", "name": "c"},
            {"id": "b", "full_name": "a/b-c", "name": "b-c"},
        ]
        forward = dict((it["id"], s) for s, it in geo.assign_skill_slugs(clash))
        backward = dict((it["id"], s) for s, it in geo.assign_skill_slugs(list(reversed(clash))))
        self.assertEqual(forward, backward)
        self.assertNotEqual(forward["a"], forward["b"])

    def test_full_site_writes_detail_scene_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=True)
            detail = (out / "s" / "anthropics-skills-internal-comms.html").read_text(encoding="utf-8")
            self.assertTrue(detail.startswith("<!DOCTYPE html>"))
            self.assertIn("<h1>internal-comms</h1>", detail)
            self.assertIn("按公司格式写周报", detail)
            self.assertIn("需要定期汇报的职场人", detail)
            self.assertIn("打开 GitHub", detail)
            self.assertIn("skills/internal-comms/SKILL.md", detail)
            self.assertIn("SoftwareSourceCode", detail)
            self.assertIn("BreadcrumbList", detail)
            self.assertIn("https://skillfeeder.cn/s/anthropics-skills-internal-comms.html", detail)
            self.assertIn("/s/anthropics-skills-pptx.html", detail)
            self.assertIn("/scene/content.html", detail)
            self.assertIn("session_start", detail)
            self.assertIn("sf_device_token", detail)
            self.assertNotIn("secret ranking", detail)
            self.assertNotIn("personal_score", detail)

            scene = (out / "scene" / "content.html").read_text(encoding="utf-8")
            self.assertIn("内容创作 Skill 推荐", scene)
            self.assertIn("<h2>写作润色</h2>", scene)
            self.assertIn("<h2>PPT</h2>", scene)
            self.assertIn("ItemList", scene)

            index = (out / "skills.html").read_text(encoding="utf-8")
            self.assertIn("/scene/content.html", index)
            self.assertIn("/scene/agent-tooling.html", index)

            sitemap = (out / "sitemap.xml").read_text(encoding="utf-8")
            self.assertIn("https://skillfeeder.cn/skills.html", sitemap)
            self.assertIn("https://skillfeeder.cn/s/acme-weekly-skill.html", sitemap)
            self.assertIn("https://skillfeeder.cn/scene/content.html", sitemap)

            about = (out / "about.html").read_text(encoding="utf-8")
            self.assertIn("/skills.html", about)
            self.assertIn("session_start", about)

    def test_republish_drops_stale_pages_and_preview_writes_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=True)
            smaller = {"items": ZH_FEED["items"][2:]}
            geo.write_geo_site(out, smaller, full=True)
            self.assertEqual(
                sorted(p.name for p in (out / "s").iterdir()), ["acme-weekly-skill.html"],
            )
            self.assertFalse((out / "scene" / "content.html").exists())

            geo.write_geo_site(out, ZH_FEED, full=False)
            self.assertFalse((out / "s").exists())
            self.assertFalse((out / "scene").exists())
            self.assertFalse((out / "skills.html").exists())
            sitemap = (out / "sitemap.xml").read_text(encoding="utf-8")
            self.assertNotIn("/s/", sitemap)


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
        self.assertIn("Organization", html)
        self.assertIn("哪里找靠谱的 Claude", html)
        self.assertIn("og:title", html)
        self.assertIn("og:locale:alternate", html)
        self.assertIn("/about.html", html)
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
