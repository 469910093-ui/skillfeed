"""Agent Surface：公开文件只有白名单字段，预览站不泄目录。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
            # 未登录访问 /publish 会 302 到 /login，不进 sitemap
            self.assertNotIn("/publish", sitemap)
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


class TestSitemap(unittest.TestCase):
    def _full_sitemap(self, feed=None):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, feed or ZH_FEED, full=True)
            pages = sorted(
                str(p.relative_to(out)) for p in out.rglob("*.html")
            )
            return (out / "sitemap.xml").read_text(encoding="utf-8"), pages

    def test_only_indexable_html_urls(self):
        sitemap, _ = self._full_sitemap()
        locs = re.findall(r"<loc>([^<]+)</loc>", sitemap)
        self.assertEqual(len(locs), len(set(locs)), "sitemap 里有重复 URL")
        for loc in locs:
            with self.subTest(loc=loc):
                self.assertTrue(loc.startswith("https://skillfeeder.cn/"))
                path = loc[len("https://skillfeeder.cn"):]
                self.assertTrue(path in ("/", "/login") or path.endswith(".html"), path)
        for banned in (".md<", ".txt<", ".json<", "/publish<", "/api/", "/op", "/admin", "/auth/"):
            self.assertNotIn(banned, sitemap)

    def test_every_seo_page_is_listed(self):
        sitemap, pages = self._full_sitemap()
        for rel in pages:
            with self.subTest(rel=rel):
                self.assertIn(f"<loc>https://skillfeeder.cn/{rel}</loc>", sitemap)
        self.assertTrue(any(p.startswith("s/") for p in pages))
        self.assertTrue(any(p.startswith("scene/") for p in pages))

    def test_every_url_has_a_real_lastmod(self):
        feed = dict(ZH_FEED, generated_at="2026-10-11T06:00:00+00:00")
        sitemap, _ = self._full_sitemap(feed)
        urls = re.findall(r"<url>(.*?)</url>", sitemap, flags=re.S)
        self.assertTrue(urls)
        for block in urls:
            self.assertRegex(block, r"<lastmod>\d{4}-\d{2}-\d{2}</lastmod>")
        self.assertIn(
            "<loc>https://skillfeeder.cn/</loc>\n    <lastmod>2026-10-11</lastmod>", sitemap,
        )
        self.assertIn(
            "<loc>https://skillfeeder.cn/about.html</loc>\n"
            f"    <lastmod>{geo.STATIC_COPY_LASTMOD}</lastmod>", sitemap,
        )

    def test_canonical_matches_sitemap_loc(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=True)
            for rel in ("about.html", "skills.html", "scene/content.html",
                        "s/acme-weekly-skill.html"):
                with self.subTest(rel=rel):
                    page = (out / rel).read_text(encoding="utf-8")
                    self.assertIn(
                        f'<link rel="canonical" href="https://skillfeeder.cn/{rel}">', page,
                    )
                    self.assertNotIn("noindex", page)

    def test_robots_points_at_sitemap(self):
        robots = geo.render_robots_txt()
        self.assertIn("Sitemap: https://skillfeeder.cn/sitemap.xml", robots)


class TestIcpFooter(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(geo.normalize_icp("  京ICP备 12345678号-1 "), "京ICP备 12345678号-1")
        for bad in ("", None, "待补充", "x" * 60 + "ICP"):
            with self.subTest(bad=bad):
                self.assertEqual(geo.normalize_icp(bad), "")

    def test_env_wins_over_config(self):
        cfg = {"icp_beian": "沪ICP备11111111号"}
        with mock.patch.dict(os.environ, {"SKILLFEED_ICP": ""}):
            self.assertEqual(geo.resolve_icp(cfg), "沪ICP备11111111号")
            self.assertEqual(geo.resolve_icp({}), "")
        with mock.patch.dict(os.environ, {"SKILLFEED_ICP": "京ICP备22222222号"}):
            self.assertEqual(geo.resolve_icp(cfg), "京ICP备22222222号")

    def test_link_is_escaped_and_points_at_miit(self):
        link = geo.icp_link_html("京ICP备<b>1</b>号")
        self.assertIn('href="https://beian.miit.gov.cn/"', link)
        self.assertIn('rel="noopener noreferrer"', link)
        self.assertNotIn("<b>", link)

    def test_full_site_pages_carry_icp_preview_does_not(self):
        icp = "京ICP备00000000号-1"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=True, icp=icp)
            for rel in ("about.html", "faq.html", "compare.html", "skills.html",
                        "scene/content.html", "s/acme-weekly-skill.html"):
                with self.subTest(rel=rel):
                    self.assertIn(icp, (out / rel).read_text(encoding="utf-8"))
            self.assertNotIn(icp, (out / "llms.txt").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=False, icp=icp)
            self.assertNotIn(icp, (out / "about.html").read_text(encoding="utf-8"))

    def test_no_icp_no_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            geo.write_geo_site(out, ZH_FEED, full=True)
            about = (out / "about.html").read_text(encoding="utf-8")
            self.assertNotIn("beian", about)
            self.assertNotIn('class="site-icp"', about)


_BEACON_HARNESS = r"""
const vm = require('vm');
const src = require('fs').readFileSync(0, 'utf8');
function store(init) {
  const m = new Map(Object.entries(init || {}));
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), _m: m };
}
const local = store();
const session = store();
const sent = [];
function visit(href, referrer, origin) {
  const u = new URL(href);
  const ctx = {
    window: {}, localStorage: local, sessionStorage: session, URL, URLSearchParams, JSON, Date, Math, String,
    location: { href, search: u.search, pathname: u.pathname, origin: origin || u.origin },
    document: { referrer },
    fetch: (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return Promise.resolve({ ok: true, json: () => Promise.resolve({ device_token: 'tok' }) }); },
  };
  vm.runInNewContext(src, ctx);
  return sent[sent.length - 1];
}
const out = [];
out.push(visit('https://skillfeeder.cn/login?next=%2Fpublish%3Futm_source%3Dchatgpt.com', 'https://www.google.com/'));
out.push(visit('https://skillfeeder.cn/?tab=me', 'https://github.com/'));
out.push(visit('https://skillfeeder.cn/?utm_source=xhs&utm_medium=social', ''));
out.push(visit('https://example.github.io/skillfeed/', '', 'https://example.github.io'));
setTimeout(() => {
  out.push({ token: local.getItem('sf_device_token') });
  process.stdout.write(JSON.stringify(out));
}, 0);
"""


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestLandingBeaconBehaviour(unittest.TestCase):
    """用 node 真跑一遍进站脚本：授权回跳不能把外部渠道冲成 github.com 外链。"""

    @classmethod
    def setUpClass(cls):
        js = geo.landing_beacon_js("https://skillfeeder.cn")
        proc = subprocess.run(
            ["node", "-e", _BEACON_HARNESS], input=js, capture_output=True,
            text=True, timeout=30, check=True,
        )
        cls.rows = json.loads(proc.stdout)

    def test_utm_inside_next_is_picked_up(self):
        ev = self.rows[0]["body"]["events"][0]
        self.assertEqual(ev["action"], "session_start")
        self.assertEqual(ev["utm_source"], "chatgpt.com")
        self.assertEqual(ev["referrer"], "google.com")
        self.assertTrue(ev["landing"].startswith("/login"))
        self.assertEqual(self.rows[0]["url"], "https://skillfeeder.cn/api/events")

    def test_oauth_return_keeps_first_external_source(self):
        first = self.rows[0]["body"]
        back = self.rows[1]["body"]
        self.assertEqual(first["session_id"], back["session_id"])
        self.assertEqual(first["device_id"], back["device_id"])
        ev = back["events"][0]
        self.assertEqual(ev["referrer"], "google.com")
        self.assertEqual(ev["utm_source"], "chatgpt.com")
        self.assertEqual(ev["landing"], "/?tab=me")

    def test_new_utm_in_same_session_wins(self):
        ev = self.rows[2]["body"]["events"][0]
        self.assertEqual(ev["utm_source"], "xhs")
        self.assertEqual(ev["referrer"], "")

    def test_device_token_is_stored(self):
        self.assertEqual(self.rows[-1]["token"], "tok")

    def test_bad_api_base_is_dropped(self):
        self.assertIn('var base = "";', geo.landing_beacon_js("javascript:alert(1)"))
        self.assertIn('var base = "";', geo.landing_beacon_js('https://x.cn/"'))


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

    def test_icp_only_on_full_main_site(self):
        icp = "京ICP备00000000号-1"
        with mock.patch.dict(os.environ, {"SKILLFEED_ICP": icp}):
            full = self._publish(["--full"])
            preview = self._publish([])
        for rel in ("index.html", "about.html", "skills.html"):
            with self.subTest(rel=rel):
                self.assertIn(icp, (full / rel).read_text(encoding="utf-8"))
        self.assertNotIn(icp, (full / "embed.html").read_text(encoding="utf-8"))
        for rel in ("index.html", "embed.html", "about.html"):
            with self.subTest(preview=rel):
                self.assertNotIn(icp, (preview / rel).read_text(encoding="utf-8"))
        self.assertNotIn(icp, (preview / "feed.json").read_text(encoding="utf-8"))

    def test_full_publish_keeps_geo_sanitized(self):
        out = self._publish(["--full"])
        catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(catalog["items"]), 1)
        self.assertNotIn("personal_score", json.dumps(catalog))


if __name__ == "__main__":
    unittest.main()
