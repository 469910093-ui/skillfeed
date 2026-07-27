import tempfile
import unittest
from pathlib import Path

import corpus
import feedback
import gates
import hellogithub
import rank
import scene
import skill_detect


class TestSkillDetect(unittest.TestCase):
    def test_parse_skill_md(self):
        text = (Path(__file__).parent / "fixtures" / "skill_sample.md").read_text(encoding="utf-8")
        meta = skill_detect.parse_skill_md(text)
        self.assertEqual(meta["name"], "weekly-report")
        self.assertGreaterEqual(len(meta["description"]), 10)
        self.assertIn("周报", meta["description"])

    def test_looks_like_skill(self):
        self.assertTrue(skill_detect.looks_like_skill_repo("Claude skill pack", "x/y"))
        self.assertFalse(skill_detect.looks_like_skill_repo("HTTP client library", "foo/bar"))


class TestGates(unittest.TestCase):
    def setUp(self):
        self.trending = {"acme/agent-skills", "low/stars", "bad/parse", "off/source"}
        self.interest = rank.load_interest_tokens(None)

    def _base(self, full_name, **kw):
        row = {
            "full_name": full_name,
            "source": "github.com/trending",
            "stars": 100,
            "name": "agent-skills",
            "description": "A collection of Claude Cursor agent skills with SKILL.md workflows.",
            "keywords": "skill agent",
            "body_preview": "agent skills automation",
            "skill_path": "SKILL.md",
            "stars_today": 10,
            "url": f"https://github.com/{full_name}",
            "language": "Python",
        }
        row.update(kw)
        return row

    def test_pass(self):
        cands = [self._base("acme/agent-skills")]
        passed, summary = gates.run_gates(
            cands,
            trending_names=self.trending,
            min_stars=20,
            min_rel=0.05,
            interest_toks=self.interest,
        )
        self.assertEqual(len(passed), 1)
        self.assertEqual(summary["passed"], 1)
        self.assertIn("rel_score", passed[0])

    def test_reject_star(self):
        cands = [self._base("low/stars", stars=5)]
        passed, summary = gates.run_gates(
            cands,
            trending_names=self.trending,
            min_stars=20,
            min_rel=0.05,
            interest_toks=self.interest,
        )
        self.assertEqual(passed, [])
        self.assertEqual(summary["rejected"]["G_star"], 1)

    def test_reject_source_unknown(self):
        cands = [self._base("not/on-trending", source="mystery")]
        passed, summary = gates.run_gates(
            cands,
            trending_names=self.trending,
            min_stars=20,
            min_rel=0.05,
            interest_toks=self.interest,
        )
        self.assertEqual(summary["rejected"]["G_source"], 1)

    def test_hellogithub_source_pass_without_stars(self):
        cands = [self._base(
            "hardikpandya/stop-slop",
            source="hellogithub",
            stars=None,
            name="stop-slop",
            description="去掉 AI 味的写作技能包，润色审稿时规避套话。",
            hg_section="Skills",
        )]
        passed, summary = gates.run_gates(
            cands,
            trending_names=set(),
            min_stars=20,
            min_rel=0.05,
            interest_toks=self.interest,
        )
        self.assertEqual(len(passed), 1)
        self.assertEqual(passed[0]["gates"]["G_star"], "SKIP")

    def test_reject_parse(self):
        cands = [self._base("bad/parse", name="x", description="short")]
        passed, summary = gates.run_gates(
            cands,
            trending_names=self.trending,
            min_stars=20,
            min_rel=0.05,
            interest_toks=self.interest,
        )
        self.assertEqual(summary["rejected"]["G_parse"], 1)


class TestScene(unittest.TestCase):
    def test_content_scene(self):
        item = scene.apply_scene({
            "name": "stop-slop",
            "description": "去掉 AI 味写作技能包，润色文案",
            "keywords": "writing",
            "hg_section": "Skills",
        })
        self.assertEqual(item["scene"], "content")
        self.assertEqual(item["scene_label"], "内容创作")

    def test_frontmatter_wins(self):
        item = scene.apply_scene({
            "name": "x",
            "description": "something about debugging tests and qa gates",
            "frontmatter": {"category": "research"},
        })
        self.assertEqual(item["scene"], "research")


class TestHelloGitHub(unittest.TestCase):
    def test_parse_issue_skills(self):
        sample = """### Skills
24、[stop-slop](https://hellogithub.com/periodical/statistics/click?target=https://github.com/hardikpandya/stop-slop)：让 AI 写作少一些套路。这是一个专门用于去掉 AI 味的写作技能包。
### 人工智能
30、[GOD](https://github.com/XiaoLuoLYG/GOD)：AI 智能体小镇。这是一款本地优先的多智能体模拟平台。
"""
        items = hellogithub.parse_issue_md(sample, 123)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["full_name"], "hardikpandya/stop-slop")
        self.assertEqual(items[0]["hg_section"], "Skills")
        self.assertEqual(items[0]["source"], "hellogithub")


class TestCorpusFeedback(unittest.TestCase):
    def test_corpus_ingest_and_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            # 用迷你 HG 仓库
            content = data / "hg" / "content"
            content.mkdir(parents=True)
            (content / "HelloGitHub123.md").write_text(
                "### Skills\n"
                "1、[stop-slop](https://github.com/hardikpandya/stop-slop)：去 AI 味写作技能包，润色文案减少套话。\n"
                "### Python 项目\n"
                "2、[black](https://github.com/psf/black)：省心的 Python 代码格式化工具，统一风格。\n",
                encoding="utf-8",
            )
            meta = corpus.ingest_hellogithub(data, hg_repo=data / "hg", max_issues=0)
            self.assertEqual(meta["added"], 2)
            rows = corpus.load_corpus_items(data, limit=10)
            self.assertEqual(len(rows), 2)
            r = feedback.append_feedback(data, {
                "action": "opened_github",
                "full_name": "hardikpandya/stop-slop",
                "source": "hellogithub",
                "scene": "content",
            })
            self.assertTrue(r["ok"])
            summary = feedback.summarize(data)
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["by_action"]["opened_github"], 1)


if __name__ == "__main__":
    unittest.main()
