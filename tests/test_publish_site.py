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
                "ui": {"style": "instagram"},
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


if __name__ == "__main__":
    unittest.main()
