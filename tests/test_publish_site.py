import json
import os
import tempfile
import unittest
from pathlib import Path
import skillfeed


class TestPublishSite(unittest.TestCase):
    def test_publish_writes_index_and_marks_hosting(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "data"
            home.mkdir()
            out = Path(tmp) / "site"
            feed = {
                "generated_at": "2026-07-28T00:00:00+00:00",
                "items": [{
                    "full_name": "acme/demo-skill",
                    "name": "demo-skill",
                    "description": "demo description long enough",
                    "url": "https://github.com/acme/demo-skill",
                    "source": "github-search",
                    "kind": "skill",
                    "scene_label": "内容创作",
                    "cover_url": "https://opengraph.githubassets.com/1/acme/demo-skill",
                    "body_preview": "# Demo\n\nBody preview text.",
                }],
                "corpus": [],
                "ui": {"cta": "open_github", "variant": "full"},
            }
            (home / "feed.json").write_text(
                json.dumps(feed, ensure_ascii=False), encoding="utf-8",
            )
            prev = os.environ.get("SKILLFEED_HOME")
            try:
                os.environ["SKILLFEED_HOME"] = str(home)
                skillfeed.refresh_paths()
                rc = skillfeed.cmd_publish_site(["--out", str(out)])
            finally:
                if prev is None:
                    os.environ.pop("SKILLFEED_HOME", None)
                else:
                    os.environ["SKILLFEED_HOME"] = prev
                skillfeed.refresh_paths()
            self.assertEqual(rc, 0)
            self.assertTrue((out / "index.html").exists())
            self.assertTrue((out / "embed.html").exists())
            self.assertTrue((out / "feed.json").exists())
            self.assertTrue((out / ".nojekyll").exists())
            published = json.loads((out / "feed.json").read_text(encoding="utf-8"))
            self.assertEqual(published["ui"]["hosting"], "pages")
            html = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn('"hosting": "pages"', html)
            self.assertIn("variant-full", html)
            self.assertIn("demo-skill", html)
            self.assertIn("Body preview text", html)
            lite = (out / "embed.html").read_text(encoding="utf-8")
            self.assertIn("variant-lite", lite)
            self.assertIn("demo-skill", lite)
            verify = out / "MP_verify_0f8Gbjnu3FsQQhRC.txt"
            self.assertTrue(verify.exists(), verify)
            self.assertEqual(verify.read_text(encoding="utf-8").strip(),
                             "0f8Gbjnu3FsQQhRC")


class TestCustomDomain(unittest.TestCase):
    """自有域名靠 artifact 里的 CNAME 生效，放仓库根没用——上传的是 site/。

    默认必须是不写。Pages 一旦认了自有域名就会把 `<user>.github.io/<repo>`
    301 重定向过去，所以 DNS 没就位时写这个文件等于把两个地址一起弄死。
    这条顺序约束只能靠「默认关」来保证。
    """

    FEED = {
        "generated_at": "2026-09-09T00:00:00+00:00",
        "items": [{
            "full_name": "acme/demo-skill",
            "name": "demo-skill",
            "description": "demo description long enough",
            "url": "https://github.com/acme/demo-skill",
            "source": "github-search",
            "kind": "skill",
            "scene_label": "内容创作",
            "body_preview": "# Demo\n\nBody preview text.",
        }],
        "corpus": [],
        "ui": {"cta": "open_github", "variant": "full"},
    }

    def publish(self, domain):
        """跑一次 publish-site，返回 site 目录里 CNAME 的内容（没有则 None）。"""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "data"
            home.mkdir()
            out = Path(tmp) / "site"
            (home / "feed.json").write_text(
                json.dumps(self.FEED, ensure_ascii=False), encoding="utf-8",
            )
            keep = {k: os.environ.get(k)
                    for k in ("SKILLFEED_HOME", "SKILLFEED_SITE_DOMAIN")}
            try:
                os.environ["SKILLFEED_HOME"] = str(home)
                if domain is None:
                    os.environ.pop("SKILLFEED_SITE_DOMAIN", None)
                else:
                    os.environ["SKILLFEED_SITE_DOMAIN"] = domain
                skillfeed.refresh_paths()
                rc = skillfeed.cmd_publish_site(["--out", str(out)])
            finally:
                for k, v in keep.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                skillfeed.refresh_paths()
            self.assertEqual(rc, 0)
            cname = out / "CNAME"
            return cname.read_text(encoding="utf-8") if cname.exists() else None

    def test_no_cname_by_default(self):
        self.assertIsNone(self.publish(None))

    def test_empty_value_is_the_same_as_unset(self):
        self.assertIsNone(self.publish(""))
        self.assertIsNone(self.publish("   "))

    def test_the_domain_lands_in_the_artifact(self):
        self.assertEqual(self.publish("skillfeeder.cn"), "skillfeeder.cn\n")

    def test_surrounding_whitespace_is_trimmed(self):
        # CI 里的变量常带回车或空格，Pages 会把整行当域名
        self.assertEqual(self.publish("  skillfeeder.cn \n"), "skillfeeder.cn\n")

    def test_a_leading_dot_is_dropped(self):
        # 有人会照 DNS 的写法填 .skillfeeder.cn
        self.assertEqual(self.publish(".skillfeeder.cn"), "skillfeeder.cn\n")

    def test_the_rest_of_the_artifact_is_unaffected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "data"
            home.mkdir()
            out = Path(tmp) / "site"
            (home / "feed.json").write_text(
                json.dumps(self.FEED, ensure_ascii=False), encoding="utf-8",
            )
            keep = os.environ.get("SKILLFEED_HOME")
            try:
                os.environ["SKILLFEED_HOME"] = str(home)
                os.environ["SKILLFEED_SITE_DOMAIN"] = "skillfeeder.cn"
                skillfeed.refresh_paths()
                skillfeed.cmd_publish_site(["--out", str(out)])
            finally:
                os.environ.pop("SKILLFEED_SITE_DOMAIN", None)
                if keep is None:
                    os.environ.pop("SKILLFEED_HOME", None)
                else:
                    os.environ["SKILLFEED_HOME"] = keep
                skillfeed.refresh_paths()
            for name in ("index.html", "embed.html", "feed.json", ".nojekyll"):
                self.assertTrue((out / name).exists(), name)


class TestPublishedUiBlock(unittest.TestCase):
    """`ui` 块会随 feed.json 发布到公开站点，只许放我们自己的取值。

    这条拦的是一个真实上线过的问题：`ui.style` 的值曾经是某个第三方 App 的名字，
    全库没有任何代码读它，但它跟着 feed.json 一起进了生产产物 —— index.html /
    embed.html / feed.json 三个公开 URL 上都能搜到。死字段不会有人去看，
    所以只能靠断言拦住。

    这里查的是**我们自己写的配置值**，不是内容。条目描述里出现第三方产品名是正当的
    指名提及（feed 里本来就有做 Instagram 运营的 skill），不在这条管辖范围内。
    """

    # 拿几个最可能被当作「风格标签」写进来的消费类 App 名字做样本，不求穷举：
    # 目的是让人在 code review 时想起这条规矩，而不是做一个永远追不全的黑名单。
    THIRD_PARTY_APPS = ("instagram", "tiktok", "douyin", "xiaohongshu",
                        "twitter", "pinterest", "snapchat")

    def test_ui_config_values_name_no_third_party_app(self):
        from feed_pack import pack_feed

        pack = pack_feed(
            passed=[], corpus_rows=[], meta={}, gates_summary={}, funnel={},
        )
        for key, value in (pack.get("ui") or {}).items():
            if not isinstance(value, str):
                continue
            for app in self.THIRD_PARTY_APPS:
                with self.subTest(key=key, app=app):
                    self.assertNotIn(
                        app, value.lower(),
                        f"ui.{key} = {value!r} 把第三方 App 名当成了自己的取值；"
                        f"这个块会发布到公开站点，换成描述功能的词",
                    )


if __name__ == "__main__":
    unittest.main()
