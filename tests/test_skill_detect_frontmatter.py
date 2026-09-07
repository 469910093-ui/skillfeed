"""SKILL.md frontmatter 解析：YAML 块标量与格式变体。

fixture 全部是 2026-09-03 那轮 refresh 里被 G_parse 拒掉的真实文件原文，
不要改成手写的简化版本——正是这些真实写法把 81 条供给挡在门外的。
"""

from __future__ import annotations

import unittest

import gates
import skill_detect

# blader/humanizer :: SKILL.md —— literal 块标量 `|`，后面还跟着 license / 嵌套 metadata
HUMANIZER = (
    "---\n"
    "name: humanizer\n"
    "description: |\n"
    "  Rewrite AI-sounding text so it reads naturally without changing what it says.\n"
    "  Use when editing or reviewing prose for inflated claims,\n"
    "  sales language, vague sources, repetitive structure, stock AI words, passive\n"
    '  voice, filler, or chatbot artifacts. Based on Wikipedia\'s "Signs of AI writing."\n'
    "license: MIT\n"
    "metadata:\n"
    '  version: "2.11.2"\n'
    "---\n"
    "\n"
    "# Humanizer: remove AI writing patterns\n"
)

# anthropics/skills :: skills/claude-api/SKILL.md —— `|-`（strip chomping）
CLAUDE_API = (
    "---\n"
    "name: claude-api\n"
    "description: |-\n"
    "  Reference for the Claude API / Anthropic SDK — model ids, pricing, params,\n"
    "  streaming, tool use, MCP, agents, caching, token counting, model migration.\n"
    "  TRIGGER — read BEFORE opening the target file.\n"
    "---\n"
    "\n"
    "# Claude API\n"
)

# bytedance/deer-flow :: skills/public/bootstrap/SKILL.md —— `>-`（folded + strip）
BOOTSTRAP = (
    "---\n"
    "name: bootstrap\n"
    "description: >-\n"
    "  Generate a personalized SOUL.md through a warm, adaptive onboarding conversation.\n"
    "  Trigger when the user wants to create, set up, or initialize their AI partner's\n"
    '  identity — e.g., "create my SOUL.md", "bootstrap my agent".\n'
    "---\n"
    "\n"
    "# Bootstrap Soul\n"
)

# JuliusBrussee/caveman :: skills/caveman-commit/SKILL.md —— folded `>`
CAVEMAN_COMMIT = (
    "---\n"
    "name: caveman-commit\n"
    "description: >\n"
    "  Write a Conventional Commits message compressed to intent only. Use for\n"
    '  "write a commit", "commit message", /commit or /caveman-commit.\n'
    "---\n"
    "\n"
    "Write commit messages terse and exact.\n"
)

# nexu-io/open-design :: skills/ad-creative/SKILL.md —— 块标量后面紧跟 YAML 列表和嵌套 map
AD_CREATIVE = (
    "---\n"
    "name: ad-creative\n"
    "description: |\n"
    "  Generate and iterate ad creative including headlines, descriptions, and primary\n"
    "  text. Useful for paid social and search ad iteration.\n"
    "triggers:\n"
    '  - "ad creative"\n'
    '  - "ad headline"\n'
    "od:\n"
    "  mode: design-system\n"
    "  category: marketing-creative\n"
    "---\n"
    "\n"
    "# ad-creative\n"
)

# alchaincyf/nuwa-skill :: SKILL.md —— 中文块标量
NUWA = (
    "---\n"
    "name: huashu-nuwa\n"
    "description: |\n"
    "  女娲造人：输入人名/主题/甚至只是模糊需求，自动深度调研→思维框架提炼→生成可运行的人物Skill。\n"
    "  两种入口：(1)明确人名→直接蒸馏 (2)模糊需求→诊断推荐→再蒸馏。\n"
    "---\n"
    "\n"
    "# 女娲 · Skill造人术\n"
)

# 老写法：单行 plain 标量，必须保持原样通过
PLAIN = (
    "---\n"
    "name: stop-slop\n"
    "description: Remove AI writing patterns from prose.\n"
    "tags: writing, editing\n"
    "---\n"
    "\n"
    "# stop-slop\n"
)


class BlockScalarTest(unittest.TestCase):
    def test_literal_block(self):
        m = skill_detect.parse_skill_md(HUMANIZER)
        self.assertEqual(m["name"], "humanizer")
        self.assertTrue(m["description"].startswith("Rewrite AI-sounding text"))
        self.assertIn("chatbot artifacts", m["description"])
        self.assertNotIn("\n", m["description"])

    def test_literal_strip_chomping(self):
        m = skill_detect.parse_skill_md(CLAUDE_API)
        self.assertTrue(m["description"].startswith("Reference for the Claude API"))
        self.assertIn("model migration", m["description"])

    def test_folded_strip_chomping(self):
        m = skill_detect.parse_skill_md(BOOTSTRAP)
        self.assertTrue(m["description"].startswith("Generate a personalized SOUL.md"))
        self.assertIn("bootstrap my agent", m["description"])

    def test_folded_block(self):
        m = skill_detect.parse_skill_md(CAVEMAN_COMMIT)
        self.assertTrue(m["description"].startswith("Write a Conventional Commits"))

    def test_cjk_block(self):
        m = skill_detect.parse_skill_md(NUWA)
        self.assertEqual(m["name"], "huashu-nuwa")
        self.assertTrue(m["description"].startswith("女娲造人"))
        self.assertIn("模糊需求", m["description"])

    def test_block_scalar_stops_before_next_key(self):
        """块标量不能把后面的 license / metadata 吞进描述里。"""
        m = skill_detect.parse_skill_md(HUMANIZER)
        self.assertNotIn("license", m["description"])
        self.assertNotIn("2.11.2", m["description"])
        self.assertEqual(m["frontmatter"]["license"], "MIT")

    def test_yaml_list_value_not_folded_into_keywords(self):
        """`triggers:` / `tags:` 是列表时值留空，不能拼成 '- ad creative' 这种假关键词。"""
        m = skill_detect.parse_skill_md(AD_CREATIVE)
        self.assertTrue(m["description"].startswith("Generate and iterate ad creative"))
        self.assertNotIn("ad headline", m["description"])
        self.assertEqual(m["frontmatter"]["triggers"], "")
        self.assertEqual(m["keywords"], "")

    def test_body_preview_excludes_frontmatter(self):
        m = skill_detect.parse_skill_md(CAVEMAN_COMMIT)
        self.assertFalse(m["body_preview"].startswith("---"))
        self.assertNotIn("description:", m["body_preview"])


class RegressionTest(unittest.TestCase):
    def test_plain_single_line_unchanged(self):
        m = skill_detect.parse_skill_md(PLAIN)
        self.assertEqual(m["name"], "stop-slop")
        self.assertEqual(m["description"], "Remove AI writing patterns from prose.")
        self.assertEqual(m["keywords"], "writing, editing")

    def test_no_frontmatter_falls_back_to_body(self):
        text = "# Export To Vue\n\nUse this plugin when the user wants to hand off an accepted design.\n"
        m = skill_detect.parse_skill_md(text)
        self.assertEqual(m["name"], "Export To Vue")
        self.assertTrue(m["description"].startswith("Use this plugin"))

    def test_quoted_value_still_unquoted(self):
        m = skill_detect.parse_skill_md('---\nname: "foo"\ndescription: "a fairly long description"\n---\n\n# foo\n')
        self.assertEqual(m["name"], "foo")
        self.assertEqual(m["description"], "a fairly long description")

    def test_empty_block_scalar_falls_back_to_body(self):
        text = "---\nname: foo\ndescription: |\n---\n\n# foo\n\nFallback sentence from the body.\n"
        m = skill_detect.parse_skill_md(text)
        self.assertEqual(m["description"], "Fallback sentence from the body.")


class GateRescueTest(unittest.TestCase):
    """这些条目原本 100% 撞 G_parse（description 被解析成 '>' / '|'）。"""

    FIXTURES = (HUMANIZER, CLAUDE_API, BOOTSTRAP, CAVEMAN_COMMIT, AD_CREATIVE, NUWA)

    def test_block_scalar_items_pass_gparse(self):
        cands = []
        for i, text in enumerate(self.FIXTURES):
            m = skill_detect.parse_skill_md(text)
            cands.append({
                "full_name": f"acme/repo-{i}",
                "source": "catalog",
                "stars": 100,
                "name": m["name"],
                "description": m["description"],
                "keywords": m["keywords"],
                "body_preview": m["body_preview"],
                "skill_path": "SKILL.md",
            })
        _, summary = gates.run_gates(
            cands,
            trending_names=set(),
            min_stars=20,
            min_rel=0.0,
            interest_toks={"skill", "design"},
        )
        self.assertEqual(summary["rejected"]["G_parse"], 0)

    def test_reject_detail_carries_skill_path_and_reason(self):
        """被拒明细要能定位到具体文件，否则只剩一个计数没法复盘。"""
        _, summary = gates.run_gates(
            [{
                "full_name": "acme/mono", "source": "catalog", "stars": 100,
                "name": "broken", "description": ">", "skill_path": "skills/broken/SKILL.md",
            }],
            trending_names=set(),
            min_stars=20,
            min_rel=0.0,
            interest_toks={"skill"},
        )
        detail = [d for d in summary["details"] if d.get("gate") == "G_parse"][0]
        self.assertEqual(detail["skill_path"], "skills/broken/SKILL.md")
        self.assertEqual(detail["reason"], "short_description")
        self.assertEqual(detail["description"], ">")
        self.assertEqual(detail["source"], "catalog")


if __name__ == "__main__":
    unittest.main()
