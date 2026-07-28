import tempfile
import unittest
from pathlib import Path

import corpus
import feed_pack


class TestFeedPack(unittest.TestCase):
    def test_normalize_and_soft_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            content = data / "hg" / "content"
            content.mkdir(parents=True)
            (content / "HelloGitHub123.md").write_text(
                "### Skills\n"
                "1、[stop-slop](https://github.com/hardikpandya/stop-slop)：去 AI 味写作技能包，润色文案。\n"
                "2、[ponytail](https://github.com/DietrichGebert/ponytail)：让 AI 少写代码，防止过度工程。\n"
                "### Python 项目\n"
                "3、[black](https://github.com/psf/black)：Python 代码格式化工具，统一风格非常省心。\n",
                encoding="utf-8",
            )
            corpus.ingest_hellogithub(data, hg_repo=data / "hg", max_issues=0)
            rows = corpus.load_corpus_items(data, limit=50)
            skills = corpus.load_skill_candidates(data, limit=20)
            self.assertGreaterEqual(len(skills), 2)

            passed = [{
                "full_name": "acme/live-skill",
                "name": "live-skill",
                "description": "A live probed Claude Cursor agent skill with workflows.",
                "source": "github-search",
                "kind": "skill",
                "skill_path": "SKILL.md",
                "stars": 10,
                "url": "https://github.com/acme/live-skill",
                "rel_score": 0.4,
            }]
            feed = feed_pack.pack_feed(
                passed=passed,
                corpus_rows=rows,
                meta={"source": "test"},
                gates_summary={"passed": 1, "rejected": {}},
                funnel={"passed": 1},
                skill_pool=skills,
                soft_limit=10,
            )
            names = {i["full_name"] for i in feed["items"]}
            self.assertIn("acme/live-skill", names)
            self.assertTrue(any(i.get("soft") for i in feed["items"]))
            self.assertTrue(any(i["full_name"] == "hardikpandya/stop-slop" for i in feed["items"]))
            # Explore backup 应含非 skill
            self.assertTrue(any(i.get("kind") == "oss" for i in feed["corpus"]))
            slim = feed["items"][0]
            self.assertIn("one_liner", slim)
            self.assertIn("cover_url", slim)
            self.assertIn("problem", slim)
            self.assertIn("highlights", slim)
            self.assertTrue(slim["cover_url"].startswith("https://opengraph.githubassets.com/"))
            live = next(i for i in feed["items"] if i["full_name"] == "acme/live-skill")
            self.assertEqual(live["cover_url"], "https://opengraph.githubassets.com/1/acme/live-skill")
            self.assertTrue(live["problem"])
            self.assertTrue(live["highlights"])


if __name__ == "__main__":
    unittest.main()
