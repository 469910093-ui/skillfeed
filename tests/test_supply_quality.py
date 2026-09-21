"""供给端成色：单条 skill 的质量分，以及重复供给的去重。

背景（线上 554 条实测）：
  - 旧 completeness 四项里三项是常数（skill_path 98.6% / highlights 100% /
    body_preview 98.6%），只落在 3 个取值上、96% 挤在 0.75，对 global_score
    的区分度贡献恰好是 0.0000。
  - 旧口径读 `one_liner_zh or description`，而 one_liner_zh 在打分之后才由 i18n
    生成，同一函数在两个时点给出两个答案（13.2% 不一致）。
  - 一条能力会因为仓库把同一份 SKILL.md 摆进多个宿主目录而摊成多张卡；
    soft skill 池还会把同一条喂两遍。

这些测试锁的是「不许退回去」，不是「分数必须等于某个数」。
"""

import unittest

import feed_pack
import ranking
import skill_detect

CFG = ranking.resolve_config(None)

RICH_BODY = """# Do the thing

## When to use
Use this when you need to ship.

## Steps
1. First read the config.
2. Then run the command.
3. Verify the output.

```bash
run --now
```
"""

BARE_BODY = "Just one sentence of prose and nothing else at all."


def item(**kw):
    row = {
        "description": "A reasonably detailed description of what this skill does "
                       "and when an agent should reach for it instead of guessing.",
        "body_preview": RICH_BODY,
        "skill_path": "skills/demo/SKILL.md",
    }
    row.update(kw)
    return row


# ---------------------------------------------------------------- 字段与量纲

class TestReadsTheRightField(unittest.TestCase):
    def test_short_chinese_one_liner_does_not_shadow_a_long_description(self):
        """旧口径把 one_liner_zh 摆在 description 前面，于是拿 28 字的摘要去过
        40 字的门槛——真正 244 字的描述根本没被看一眼。"""
        long_desc = item()
        with_zh = item(one_liner_zh="调用 Claude API 构建生产级应用")
        self.assertEqual(
            ranking.completeness_score(long_desc),
            ranking.completeness_score(with_zh),
        )

    def test_description_actually_moves_the_score(self):
        thin = ranking.completeness_score(item(description="x"))
        thick = ranking.completeness_score(item())
        self.assertGreater(thick, thin)

    def test_highlights_no_longer_buy_anything(self):
        """线上 554 条 100% 都有 highlights，它是常数不是证据。"""
        self.assertEqual(
            ranking.completeness_score(item()),
            ranking.completeness_score(item(highlights=["a", "b"], highlights_zh=["c"])),
        )

    def test_highlights_cannot_stand_in_for_a_skill_md(self):
        """出处那一路只认 skill_path。highlights 人人都有，拿它兜底等于把这一路
        又变回常数——纯仓库条目也能白拿满分。"""
        bare = item(skill_path="")
        self.assertEqual(
            ranking.completeness_score(bare),
            ranking.completeness_score(dict(bare, highlights=["a"], highlights_zh=["甲"])),
        )
        self.assertLess(ranking.completeness_score(bare), ranking.completeness_score(item()))


class TestLengthIsMeasuredInInformationNotCharacters(unittest.TestCase):
    def test_cjk_counts_double(self):
        self.assertEqual(ranking.text_weight("ab"), 2)
        self.assertEqual(ranking.text_weight("中文"), 4)

    def test_mixed_text_adds_up(self):
        self.assertEqual(ranking.text_weight("ab中"), 4)

    def test_empty_and_none_are_zero(self):
        self.assertEqual(ranking.text_weight(""), 0)
        self.assertEqual(ranking.text_weight(None), 0)

    def test_japanese_and_korean_also_count_double(self):
        self.assertEqual(ranking.text_weight("かな"), 4)
        self.assertEqual(ranking.text_weight("한글"), 4)

    def test_a_chinese_and_an_english_description_of_equal_substance_tie(self):
        """同一条 skill 翻成中文就不合格、翻成英文就合格，是量纲错误不是质量差异。
        线上实测 one_liner_en 99.8% 过线、one_liner_zh 只有 9.2% 过线。"""
        zh = ranking.completeness_score(item(description="把" * 120))
        en = ranking.completeness_score(item(description="a" * 240))
        self.assertAlmostEqual(zh, en, places=6)

    def test_a_pure_chinese_description_can_reach_full_marks(self):
        self.assertEqual(
            ranking.completeness_score(item(description="解" * 200)),
            ranking.completeness_score(item(description="a" * 400)),
        )


# ---------------------------------------------------------------- 时点稳定

class TestScoreDoesNotDriftWithTime(unittest.TestCase):
    """打分发生在 i18n 和 normalize 之前，事后重算不许给出不同答案。"""

    def test_i18n_fields_appearing_later_change_nothing(self):
        before = item()
        after = item(one_liner_zh="短摘要", one_liner_en="a longer english one liner",
                     highlights_zh=["甲"], who_for_zh="给谁用")
        self.assertEqual(
            ranking.completeness_score(before),
            ranking.completeness_score(after),
        )

    def test_normalize_truncation_changes_nothing(self):
        """normalize_item 把 description 截到 400、body_preview 截到 700。
        斜坡终点必须落在截断线以内，否则截断本身就在改分数。"""
        row = item(description="a" * 900, body_preview=RICH_BODY + "x" * 2000)
        trimmed = dict(row)
        trimmed["description"] = row["description"][:400]
        trimmed["body_preview"] = row["body_preview"][:feed_pack.BODY_PREVIEW_MAX]
        self.assertEqual(
            ranking.completeness_score(row),
            ranking.completeness_score(trimmed),
        )

    def test_the_desc_ramp_tops_out_before_the_truncation_limit(self):
        self.assertLessEqual(CFG["completeness"]["desc_hi"], 400)

    def test_the_body_ramp_tops_out_before_the_truncation_limit(self):
        self.assertLessEqual(CFG["completeness"]["body_hi"], feed_pack.BODY_PREVIEW_MAX)

    def test_only_published_fields_are_read(self):
        """读了不随 feed.json 发布的字段，就等于埋下一个新的时点漂移。"""
        row = item()
        noise = dict(row)
        for k in ("keywords", "frontmatter", "repo_description", "topics", "license"):
            noise[k] = "something"
        self.assertEqual(
            ranking.completeness_score(row), ranking.completeness_score(noise),
        )


# ---------------------------------------------------------------- 区分度

class TestStructureIsWhatDiscriminates(unittest.TestCase):
    def test_sections_steps_and_code_each_add(self):
        base = item(body_preview=BARE_BODY)
        sections = item(body_preview=BARE_BODY + "\n\n## A section\ntext here")
        steps = item(body_preview=BARE_BODY + "\n\n- one item\n- two item")
        code = item(body_preview=BARE_BODY + "\n\n```py\nx = 1\n```")
        plain = ranking.completeness_score(base)
        for label, row in (("小节", sections), ("列表", steps), ("代码块", code)):
            with self.subTest(label):
                self.assertGreater(ranking.completeness_score(row), plain)

    def test_a_structured_skill_beats_a_prose_blob_of_the_same_length(self):
        blob = "word " * 200
        structured = RICH_BODY + "\n" + "word " * 150
        self.assertGreater(
            ranking.completeness_score(item(body_preview=structured)),
            ranking.completeness_score(item(body_preview=blob)),
        )

    def test_a_compatibility_shim_lands_near_the_bottom(self):
        """larksuite/cli 的 lark-minutes/lark-note：正文自称不处理业务、130 字、
        无小节。旧口径给它 0.75，和结构齐全的 skill 同档。"""
        shim = ranking.completeness_score(item(
            description="仅当用户或上游配置显式指定 lark-note 时使用，"
                        "相关请求统一交由 lark-meeting 技能处理。",
            body_preview="# Compatibility entry\n\n本技能只用于兼容旧名称，不直接处理业务。",
        ))
        self.assertLess(shim, ranking.completeness_score(item()))
        self.assertLess(shim, 0.45)

    def test_no_skill_md_costs_the_provenance_part(self):
        self.assertLess(
            ranking.completeness_score(item(skill_path="")),
            ranking.completeness_score(item()),
        )

    def test_the_score_stays_in_range(self):
        for row in (item(), item(description="", body_preview="", skill_path=""),
                    item(description="是" * 999, body_preview=RICH_BODY * 40)):
            s = ranking.completeness_score(row)
            self.assertGreaterEqual(s, 0.0)
            self.assertLessEqual(s, 1.0)

    def test_an_empty_item_does_not_crash(self):
        self.assertEqual(ranking.completeness_score({}), 0.0)

    def test_a_misconfigured_weight_still_cannot_exceed_one(self):
        """权重是运行时可调的，配错了（三项加起来 >1）也不能让这一路溢出去，
        否则 global_quality 那边的加权和就不再是 0-1。"""
        bad = ranking.resolve_config({"ranking": {"completeness": {"p_desc": 2.0,
                                                                   "p_structure": 2.0,
                                                                   "p_provenance": 2.0}}})
        self.assertEqual(ranking.completeness_score(item(), config=bad), 1.0)

    def test_weights_are_a_partition(self):
        c = CFG["completeness"]
        self.assertAlmostEqual(
            c["p_desc"] + c["p_structure"] + c["p_provenance"], 1.0, places=6)
        self.assertAlmostEqual(
            c["w_sections"] + c["w_steps"] + c["w_code"] + c["w_body_len"],
            1.0, places=6)

    def test_config_can_retune_without_editing_code(self):
        loud = ranking.resolve_config({"ranking": {"completeness": {"p_desc": 1.0,
                                                                    "p_structure": 0.0,
                                                                    "p_provenance": 0.0}}})
        thin = item(description="x", body_preview=RICH_BODY)
        self.assertLess(
            ranking.completeness_score(thin, config=loud),
            ranking.completeness_score(thin),
        )

    def test_global_quality_uses_the_configured_completeness(self):
        """global_quality 必须把 config 传下去，否则页面上调不动这一路。"""
        cfg = ranking.resolve_config({"ranking": {"completeness": {"p_provenance": 0.0,
                                                                    "p_desc": 0.5,
                                                                    "p_structure": 0.5}}})
        row = item()
        a, _ = ranking.global_quality(row, config=CFG)
        b, _ = ranking.global_quality(row, config=cfg)
        self.assertNotEqual(a, b)


# ---------------------------------------------------------------- 去重

class TestSoftPoolDoesNotEmitTheSameSkillTwice(unittest.TestCase):
    """调用方喂的池子是 skill_pool + corpus_rows，两段读同一份 corpus。"""

    def _row(self, key="a/b", **kw):
        row = {"full_name": key, "id": f"hg:1:{key}", "kind": "skill",
               "description": "d"}
        row.update(kw)
        return row

    def test_duplicate_rows_collapse(self):
        out = feed_pack.soft_skills_from_corpus(
            [self._row(), self._row()], exclude=set(), limit=40)
        self.assertEqual(len(out), 1)

    def test_three_copies_still_collapse_to_one(self):
        out = feed_pack.soft_skills_from_corpus(
            [self._row()] * 3, exclude=set(), limit=40)
        self.assertEqual(len(out), 1)

    def test_distinct_skills_are_both_kept(self):
        out = feed_pack.soft_skills_from_corpus(
            [self._row("a/b"), self._row("c/d")], exclude=set(), limit=40)
        self.assertEqual(len(out), 2)

    def test_same_repo_different_skill_path_are_both_kept(self):
        a = self._row("a/b", id=None, skill_path="skills/one/SKILL.md")
        b = self._row("a/b", id=None, skill_path="skills/two/SKILL.md")
        out = feed_pack.soft_skills_from_corpus([a, b], exclude=set(), limit=40)
        self.assertEqual(len(out), 2)

    def test_exclude_still_wins(self):
        out = feed_pack.soft_skills_from_corpus(
            [self._row(), self._row()], exclude={"hg:1:a/b"}, limit=40)
        self.assertEqual(out, [])

    def test_limit_counts_unique_rows(self):
        rows = [self._row(f"o/r{i}") for i in range(3) for _ in range(2)]
        out = feed_pack.soft_skills_from_corpus(rows, exclude=set(), limit=2)
        self.assertEqual(len(out), 2)
        self.assertEqual(len({r["id"] for r in out}), 2)

    def test_mcp_kind_stays_mcp(self):
        row = self._row("github/github-mcp-server", kind="mcp")
        out = feed_pack.soft_skills_from_corpus([row], exclude=set(), limit=40)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "mcp")


class TestVendoredCopiesCollapse(unittest.TestCase):
    """一个仓为了同时伺候 Claude/Codex/Cursor，会把同一份 SKILL.md 摆好几处。"""

    REPO = {"full_name": "acme/mono", "description": "agent skills", "stars": 10}

    def _run(self, files, *, max_skills=6):
        """用假的取文件函数跑 enrich_repo_multi，不出网。"""
        orig_find = skill_detect.find_skill_paths
        orig_fetch = skill_detect.fetch_raw_skill
        skill_detect.find_skill_paths = lambda *a, **k: list(files)
        skill_detect.fetch_raw_skill = lambda o, r, p, ua, tok="": files.get(p)
        try:
            return skill_detect.enrich_repo_multi(
                dict(self.REPO), "ua", always_probe=True, max_skills=max_skills)
        finally:
            skill_detect.find_skill_paths = orig_find
            skill_detect.fetch_raw_skill = orig_fetch

    def test_identical_file_under_two_host_dirs_yields_one_card(self):
        text = "---\nname: pr-sweep\ndescription: sweep prs\n---\n\n## Do it\n"
        out = self._run({
            ".claude/skills/pr-sweep/SKILL.md": text,
            ".agents/skills/pr-sweep/SKILL.md": text,
        })
        self.assertEqual(len(out), 1)

    def test_the_first_path_in_priority_order_wins(self):
        text = "---\nname: x\ndescription: d\n---\nbody\n"
        out = self._run({
            ".claude/skills/x/SKILL.md": text,
            ".agents/skills/x/SKILL.md": text,
        })
        self.assertEqual(out[0]["skill_path"], ".claude/skills/x/SKILL.md")

    def test_same_body_but_different_frontmatter_stays_two_cards(self):
        """larksuite/cli 的 lark-minutes 与 lark-note 是两个独立的兼容壳：正文
        逐字节相同、只有 frontmatter 的名字和描述不同。拿正文当去重键会合掉一个。"""
        body = "\n# Compatibility entry\n\n转交 lark-meeting 处理。\n"
        out = self._run({
            "skills/lark-minutes/SKILL.md":
                "---\nname: lark-minutes\ndescription: 显式指定 lark-minutes 时用\n---" + body,
            "skills/lark-note/SKILL.md":
                "---\nname: lark-note\ndescription: 显式指定 lark-note 时用\n---" + body,
        })
        self.assertEqual(len(out), 2)
        self.assertEqual({x["name"] for x in out}, {"lark-minutes", "lark-note"})

    def test_all_discovered_paths_are_still_reported(self):
        """skill_paths 是「在哪儿找到过」的记录，去重不该把它删薄。"""
        text = "---\nname: x\ndescription: d\n---\nbody\n"
        out = self._run({
            ".claude/skills/x/SKILL.md": text,
            ".agents/skills/x/SKILL.md": text,
        })
        self.assertEqual(len(out[0]["skill_paths"]), 2)

    def test_dedup_frees_a_slot_for_a_real_skill(self):
        """去重不能只是丢掉一张卡——省下的额度要拿去装真 skill，
        否则一个到处摆副本的仓会把自己的配额浪费光。"""
        dup = "---\nname: dup\ndescription: d\n---\nbody\n"
        files = {
            ".claude/skills/dup/SKILL.md": dup,
            ".agents/skills/dup/SKILL.md": dup,
            "skills/real-one/SKILL.md": "---\nname: real-one\ndescription: r\n---\nb\n",
            "skills/real-two/SKILL.md": "---\nname: real-two\ndescription: r\n---\nb\n",
        }
        out = self._run(files, max_skills=3)
        self.assertEqual(len(out), 3)
        self.assertEqual(len({x["name"] for x in out}), 3)

    def test_max_skills_is_still_respected(self):
        files = {f"skills/s{i}/SKILL.md": f"---\nname: s{i}\ndescription: d\n---\nb\n"
                 for i in range(10)}
        self.assertEqual(len(self._run(files, max_skills=4)), 4)

    def test_digest_is_the_whole_file_not_the_body(self):
        a = "---\nname: a\n---\nsame body\n"
        b = "---\nname: b\n---\nsame body\n"
        self.assertNotEqual(
            skill_detect._content_digest(a), skill_detect._content_digest(b))

    def test_digest_is_stable_and_handles_empty(self):
        self.assertEqual(
            skill_detect._content_digest("x"), skill_detect._content_digest("x"))
        self.assertEqual(
            skill_detect._content_digest(""), skill_detect._content_digest(None))


class TestMcpRepoHeuristic(unittest.TestCase):
    def _fn(self):
        import sys
        from pathlib import Path

        scripts = Path(__file__).resolve().parents[1] / "scripts"
        if str(scripts) not in sys.path:
            sys.path.insert(0, str(scripts))
        from gate_waytoagi_feed import is_mcp_repo

        return is_mcp_repo

    def test_named_mcp_and_official_servers(self):
        is_mcp_repo = self._fn()
        self.assertTrue(is_mcp_repo("github/github-mcp-server", "github-mcp-server", "GitHub official MCP"))
        self.assertTrue(is_mcp_repo("modelcontextprotocol/servers", "servers", "Model Context Protocol Servers"))
        self.assertTrue(is_mcp_repo("semgrep/mcp", "mcp", "A MCP server for Semgrep"))
        self.assertFalse(is_mcp_repo("VoltAgent/awesome-agent-skills", "awesome-agent-skills", "curated agent skills"))
        self.assertFalse(is_mcp_repo("QwenLM/Qwen-Agent", "Qwen-Agent", "Agent framework built upon Qwen"))


if __name__ == "__main__":
    unittest.main()
