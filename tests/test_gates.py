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


class TestRelevanceGateSignal(unittest.TestCase):
    """G_rel 只在有查询侧信号时才该设卡。

    公开站点上没有"某个人"，interest 退化成 DOMAIN_TOKENS。而那 19 个词恰好是
    本语料里最普遍的词，df≈n 把 idf 压到 log(2)，命中它们几乎不得分——阈值筛的
    就不再是相关性。实测 429 进 175 出、G_rel 一家拒 253 条，被拒分数中位数正好
    0.0800（= skill_path 那 +0.08，即有真 SKILL.md 的条目），名单里是
    antfu/skills、microsoft/azure-skills、vercel-labs/agent-skills。

    这个类之前是空的——358 个测试里没有一个跑过"无兴趣信号"这条路径，所以线上
    腰斩了两个月没人发现。
    """

    def _repo(self, full_name, name, description, **kw):
        row = {
            "full_name": full_name,
            "source": "catalog",
            "stars": 300,
            "name": name,
            "description": description,
            "keywords": "",
            "body_preview": "",
            "skill_path": f"skills/{name}/SKILL.md",
            "url": f"https://github.com/{full_name}",
        }
        row.update(kw)
        return row

    def _run(self, cands, *, interest, min_rel=0.15, intent=""):
        return gates.run_gates(
            cands,
            trending_names=set(),
            min_stars=20,
            min_rel=min_rel,
            interest_toks=interest,
            allowed_sources={"catalog"},
            intent=intent,
        )

    def test_canonical_skill_repos_survive_without_a_query_side(self):
        """线上那 253 条的直接回归：分数确实低于阈值，但必须放行。

        断言里先自证「这些条目在原逻辑下会被拒」，再断言现在过了。不这样写的话，
        哪天打分变了让它们天然过线，这个测试就变成了永真式的空壳。
        """
        cands = [
            self._repo("antfu/skills", "vitesse", "Opinionated config presets for editors."),
            self._repo("microsoft/azure-skills", "bicep", "Authoring helpers for cloud templates."),
            self._repo("vercel-labs/agent-skills", "ship", "Deploy previews from a branch."),
        ]
        interest = rank.load_interest_tokens(None)
        self.assertEqual(interest, rank.DOMAIN_TOKENS,
                         "前提变了：无 catalog 时兴趣词表应恰为域词表")

        docs = [f"{c['name']} {c['description']}" for c in cands]
        df, n = rank.build_df(docs)
        for c in cands:
            score, _ = rank.relevance_score(c, interest, df, n)
            self.assertLess(score, 0.15,
                            f"{c['full_name']} 分数 {score} 不再低于阈值，样本需重造")

        passed, summary = self._run(cands, interest=interest)
        self.assertEqual(len(passed), 3)
        self.assertEqual(summary["rejected"]["G_rel"], 0)
        self.assertEqual(summary["rel_gate"], "skip:no-interest-signal")
        for item in passed:
            self.assertEqual(item["gates"]["G_rel"], "SKIP")

    def test_score_still_recorded_when_gate_is_skipped(self):
        """跳过设卡不等于不算分——rel_score 还要给排序用。"""
        passed, _ = self._run(
            [self._repo("acme/one", "alpha", "Some helper for editor configuration.")],
            interest=rank.load_interest_tokens(None),
        )
        self.assertIn("rel_score", passed[0])
        self.assertIn("rel_why", passed[0])

    def test_gate_is_active_when_a_local_catalog_supplies_interest(self):
        """本机装了 skill-picker 就有真查询侧，此时该照常设卡。"""
        cands = [self._repo("acme/unrelated", "ledger", "Double entry bookkeeping for shops.")]
        interest = rank.DOMAIN_TOKENS | {"周报", "复盘", "bigquery", "飞书"}
        passed, summary = self._run(cands, interest=interest, min_rel=0.9)
        self.assertEqual(passed, [])
        self.assertEqual(summary["rejected"]["G_rel"], 1)
        self.assertEqual(summary["rel_gate"], "on")

    def test_gate_is_active_when_intent_is_explicit(self):
        """没有 catalog 但用户明确说了要干什么，intent 本身就是查询侧。"""
        cands = [self._repo("acme/unrelated", "ledger", "Double entry bookkeeping for shops.")]
        _, summary = self._run(
            cands, interest=rank.load_interest_tokens(None), min_rel=0.9, intent="生成周报"
        )
        self.assertEqual(summary["rel_gate"], "on")
        self.assertEqual(summary["rejected"]["G_rel"], 1)

    def test_skip_does_not_leak_past_the_other_gates(self):
        """跳过的只有 G_rel。星数、源、解析三道仍须照常拦。"""
        cands = [
            self._repo("low/stars", "alpha", "A helper for editor configuration.", stars=3),
            self._repo("bad/parse", "beta", "short"),
            self._repo("off/source", "gamma", "A helper for editor configuration.",
                       source="mystery"),
        ]
        passed, summary = self._run(cands, interest=rank.load_interest_tokens(None))
        self.assertEqual(passed, [])
        self.assertEqual(summary["rejected"]["G_star"], 1)
        self.assertEqual(summary["rejected"]["G_parse"], 1)
        self.assertEqual(summary["rejected"]["G_source"], 1)


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
