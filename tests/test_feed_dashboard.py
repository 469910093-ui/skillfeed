import json
import unittest

import feed_dashboard


class TestFeedDashboard(unittest.TestCase):
    def test_build_contains_items_and_open_github(self):
        feed = {
            "meta": {"source": "github.com/trending", "since": "daily"},
            "config": {"min_stars": 20},
            "funnel": {"trending_repos": 25, "probed": 3, "passed": 1},
            "items": [{
                "full_name": "acme/agent-skills",
                "name": "agent-skills",
                "description": "demo skill description long enough",
                "body_preview": "# Agent Skills\n\nUse this skill to automate weekly reviews.",
                "cover_url": "https://opengraph.githubassets.com/1/acme/agent-skills",
                "stars": 100,
                "stars_today": 5,
                "rel_score": 0.4,
                "rel_why": "domain:skill",
                "language": "Python",
                "url": "https://github.com/acme/agent-skills",
                "source": "github.com/trending",
                "scene": "agent-tooling",
                "scene_label": "Agent工具链",
                "kind": "skill",
            }],
            "corpus": [{
                "full_name": "hardikpandya/stop-slop",
                "name": "stop-slop",
                "description": "去 AI 味写作技能包",
                "source": "hellogithub",
                "hg_section": "Skills",
                "scene": "content",
                "scene_label": "内容创作",
                "kind": "skill",
                "from_corpus": True,
                "url": "https://github.com/hardikpandya/stop-slop",
            }],
        }
        html = feed_dashboard.build_feed_html(feed)
        self.assertIn("skill-feed", html)
        self.assertIn("acme/agent-skills", html)
        self.assertIn("打开 GitHub", html)
        self.assertIn("/api/feedback", html)
        self.assertNotIn("/api/install", html)
        self.assertNotIn("安装到本机", html)
        self.assertIn("下滑加载更多", html)
        self.assertIn("内容创作", html)
        self.assertIn("opengraph.githubassets.com", html)
        self.assertIn("class=\"pitch\"", html)
        self.assertIn("extractHighlightsClient", html)
        self.assertIn("js-publisher", html)
        self.assertIn("openPublisher", html)
        self.assertNotIn("aria-label=\"more\"", html)
        self.assertIn("sv-cover", html)
        self.assertIn("object-fit: contain", html)
        self.assertNotIn("background-size: cover; background-position: center;", html)
        self.assertIn("发现", html)
        self.assertIn("发布", html)
        self.assertIn("我的", html)
        self.assertIn("countMode", html)
        self.assertNotIn('data-mode="skills"', html)
        self.assertIn('"full_name": "acme/agent-skills"', json.dumps(feed))


if __name__ == "__main__":
    unittest.main()
