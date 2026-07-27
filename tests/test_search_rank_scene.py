import tempfile
import unittest
from pathlib import Path
from unittest import mock

import feed_dashboard
import github_search
import rank
import scene


class TestSceneL2(unittest.TestCase):
    def test_writing_l2(self):
        item = scene.apply_scene({
            "name": "stop-slop",
            "description": "去掉 AI 味写作技能包，润色文案减少套话",
            "keywords": "writing",
            "hg_section": "Skills",
        })
        self.assertEqual(item["scene"], "content")
        self.assertEqual(item["scene_l2"], "writing")
        self.assertEqual(item["scene_l2_label"], "写作润色")

    def test_l2_tree(self):
        tree = scene.scene_l2_tree()
        self.assertIn("content", tree)
        ids = {c["id"] for c in tree["content"]}
        self.assertIn("writing", ids)
        self.assertIn("short-video", ids)


class TestPersonalRank(unittest.TestCase):
    def test_rerank_prefers_feedback_scene(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "feedback.jsonl").write_text(
                '{"action":"useful","scene":"content","scene_l2":"writing","full_name":"a/stop"}\n'
                '{"action":"opened_github","scene":"content","full_name":"a/stop"}\n'
                '{"action":"bad","scene":"quality","full_name":"b/bug"}\n',
                encoding="utf-8",
            )
            aff = rank.load_feedback_affinity(data)
            self.assertGreater(aff["scene_boost"].get("content", 0), 0)
            self.assertGreater(aff["repo_penalty"].get("b/bug", 0), 0)
            items = [
                {
                    "full_name": "b/bug",
                    "name": "bug",
                    "description": "debug testing qa",
                    "rel_score": 0.5,
                    "scene": "quality",
                    "scene_l2": "debug",
                    "stars": 100,
                    "source": "github-search",
                },
                {
                    "full_name": "a/stop",
                    "name": "stop-slop",
                    "description": "writing copy",
                    "rel_score": 0.4,
                    "scene": "content",
                    "scene_l2": "writing",
                    "stars": 10,
                    "source": "hellogithub",
                },
            ]
            ranked = rank.rerank(items, affinity=aff, intent="写作润色")
            self.assertEqual(ranked[0]["full_name"], "a/stop")
            self.assertIn("personal_score", ranked[0])


class TestGitHubSearch(unittest.TestCase):
    def test_repo_row(self):
        row = github_search._repo_row({
            "full_name": "acme/skills",
            "html_url": "https://github.com/acme/skills",
            "description": "agent skills",
            "language": "Python",
            "stargazers_count": 42,
            "score": 1.2,
        })
        self.assertEqual(row["source"], "github-search")
        self.assertEqual(row["stars"], 42)

    def test_fetch_uses_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            cache = data / "cache"
            cache.mkdir(parents=True)
            (cache / "github_search.json").write_text(
                '{"fetched_at":"2099-01-01T00:00:00+00:00","items":[{"full_name":"x/y","source":"github-search","stars":1,"url":"https://github.com/x/y","description":"d","language":"","stars_today":0,"kind":"skill"}],"meta":{}}',
                encoding="utf-8",
            )
            items, meta = github_search.fetch_search_candidates(
                data, user_agent="test", force=False, ttl_hours=24,
            )
            self.assertTrue(meta.get("from_cache"))
            self.assertEqual(items[0]["full_name"], "x/y")

    def test_search_repos_parses(self):
        fake = {
            "items": [{
                "full_name": "acme/agent-skills",
                "html_url": "https://github.com/acme/agent-skills",
                "description": "Claude skills",
                "language": "MD",
                "stargazers_count": 99,
                "score": 10,
            }],
        }
        with mock.patch.object(github_search, "_http_json", return_value=(200, fake, {})):
            rows, meta = github_search.search_repos("ua", token="", queries=['"SKILL.md" in:readme'], sleep_s=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["full_name"], "acme/agent-skills")
        self.assertEqual(meta["returned"], 1)


class TestFeedUI(unittest.TestCase):
    def test_l2_and_search_labels(self):
        feed = {
            "meta": {},
            "scenes": scene.scene_chips(),
            "scenes_l2": scene.scene_l2_tree(),
            "items": [{
                "full_name": "a/b",
                "name": "b",
                "description": "desc long enough",
                "source": "github-search",
                "scene": "content",
                "scene_label": "内容创作",
                "scene_l2": "writing",
                "scene_l2_label": "写作润色",
                "personal_score": 0.55,
                "rank_why": "rel:0.4 · intent:写作",
                "kind": "skill",
                "url": "https://github.com/a/b",
            }],
            "corpus": [],
        }
        html = feed_dashboard.build_feed_html(feed)
        self.assertIn("二级场景", html)
        self.assertIn("GitHub Search", html)
        self.assertIn("写作润色", html)
        self.assertIn("personal_score", html)
        self.assertNotIn("/api/install", html)


if __name__ == "__main__":
    unittest.main()
