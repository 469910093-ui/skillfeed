"""i18n 的三条约束：违禁词可满足、缓存指纹覆盖产出契约、英文长度受控。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import i18n


def _fields(**over) -> dict:
    base = {
        "one_liner_zh": "把设计规范写成机器可读契约，约束前端产出",
        "one_liner_en": "Turn design rules into a machine-readable contract",
        "highlights_zh": ["生成可执行的排版与配色阈值", "自动比对实现与规范差异", "输出可复用的组件清单"],
        "highlights_en": [
            "Generates typography and color thresholds",
            "Diffs implementation against the spec",
            "Exports a reusable component list",
        ],
        "who_for_zh": "前端与设计系统维护者",
        "who_for_en": "Frontend and design-system owners",
    }
    base.update(over)
    return base


def _item(**over) -> dict:
    base = {
        "full_name": "acme/skill-pack",
        "skill_path": "skills/demo/SKILL.md",
        "name": "demo",
        "description": "Demo skill",
        "body_preview": "body",
    }
    base.update(over)
    return base


class BannedRules(unittest.TestCase):
    """违禁词表：拦「模型在描述它读的文件」，放行「skill 的产出就是某个文件」。"""

    def test_output_artifact_md_is_allowed(self):
        # stitch-design-taste 的功能就是生成 DESIGN.md。裸 `\.md\b` 让任何忠实
        # 摘要都必然违规，是逻辑上不可满足的约束——这里锁住它不会回归。
        for text in (
            "生成 DESIGN.md 设计规范，约束 UI 一致性",
            "Generates a DESIGN.md contract your agent must follow",
            "输出 ADR.md 架构决策记录",
        ):
            self.assertEqual(i18n._banned_reason(text), "", text)

    def test_source_file_names_are_banned(self):
        for text in ("Follow the workflow in SKILL.md", "更新 AGENTS.md 与 CLAUDE.md"):
            self.assertEqual(i18n._banned_reason(text), "source_file", text)

    def test_directory_paths_are_banned(self):
        for text in (
            "先读取 references/style.md 再执行",
            "参考 scripts/build.sh 的实现",
            "Reads ./config/settings.yaml at startup",
        ):
            self.assertEqual(i18n._banned_reason(text), "path", text)

    def test_slashed_tech_names_are_not_paths(self):
        # 旧的宽松路径正则会把这些当成文件路径（实测在 4304 条已生效译文上误伤 3 条）
        for text in (
            "自动应用 Vercel 官方 React/Next.js 性能优化规则重构代码",
            "Detect WCAG 2.1/2.2 violations across all levels",
            "Ships CI/CD pipelines for Node and Python",
        ):
            self.assertEqual(i18n._banned_reason(text), "", text)

    def test_requires_as_ordinary_verb_is_allowed(self):
        # 旧表的裸 `Requires\b` 会拦掉这些正当用法
        for text in (
            "Requires running verification commands before you claim done",
            "Enforces a review pass that requires technical rigor",
        ):
            self.assertEqual(i18n._banned_reason(text), "", text)

    def test_real_dependency_declarations_are_banned(self):
        for text in ("Requires Python 3.11", "依赖 Node 18.0 环境", "Prerequisites: a GitHub token"):
            self.assertTrue(i18n._banned_reason(text), text)

    def test_install_commands_and_urls_banned(self):
        self.assertEqual(i18n._banned_reason("Run pip install foo first"), "install_cmd")
        self.assertEqual(i18n._banned_reason("详见 https://example.com"), "url")


class LengthGate(unittest.TestCase):
    def test_width_counts_han_as_two(self):
        self.assertEqual(i18n._display_width("abc"), 3)
        self.assertEqual(i18n._display_width("中文"), 4)

    def test_long_english_highlight_rejected_on_fresh_output(self):
        long_en = "Supports six different card types including titles, lower-thirds and quotes"
        obj = _fields(highlights_en=[long_en, long_en, long_en])
        fields, reason = i18n._check_fields(obj, enforce_length=True)
        self.assertIsNone(fields)
        self.assertTrue(reason.startswith("too_few:highlights_en"), reason)

    def test_one_over_long_highlight_is_dropped_not_fatal(self):
        obj = _fields(
            highlights_en=[
                "Generates typography and color thresholds",
                "Diffs implementation against the spec",
                "Supports six different card types including titles, lower-thirds and quotes",
            ]
        )
        fields, reason = i18n._check_fields(obj, enforce_length=True)
        self.assertIsNotNone(fields)
        self.assertEqual(len(fields["highlights_en"]), 2)

    def test_length_gate_off_for_cached_and_human_rows(self):
        """_valid_fields 是缓存命中判定和多维表格人工稿共用的入口。

        对它开长度门槛会一次性判废 38.4% 存量缓存并冲掉已验收译稿，所以它必须
        只做结构校验。
        """
        long_en = "Supports six different card types including titles, lower-thirds and quotes"
        obj = _fields(highlights_en=[long_en, long_en, long_en], one_liner_en=long_en * 2)
        self.assertIsNotNone(i18n._valid_fields(obj))

    def test_caps_are_wider_than_prompt_targets(self):
        # 硬上限只拦离群值，目标值靠 prompt 引导；反过来会把重试成本抬起来
        for key, target in i18n._TARGET_WIDTH.items():
            self.assertGreater(i18n._MAX_WIDTH[key], target, key)

    def test_prompt_states_english_budget_in_characters(self):
        # 中英不能共用字数上限：英文按词数写会让实际占宽变成中文的近两倍
        self.assertIn("105 个字符", i18n.USER_TEMPLATE)
        self.assertIn("60 个字符", i18n.USER_TEMPLATE)
        self.assertNotIn("≤22 words", i18n.USER_TEMPLATE)


class ContractFingerprint(unittest.TestCase):
    def test_model_and_temperature_change_contract(self):
        base = i18n.contract_hash(model="qwen-plus")
        self.assertNotEqual(base, i18n.contract_hash(model="qwen-max"))
        self.assertNotEqual(base, i18n.contract_hash(model="qwen-plus", temperature=0.9))
        self.assertNotEqual(base, i18n.contract_hash(model="qwen-plus", body_limit=900))

    def test_prompt_edit_changes_contract(self):
        base = i18n.contract_hash(model="qwen-plus")
        original = i18n.USER_TEMPLATE
        try:
            i18n.USER_TEMPLATE = original + "\n多一行要求"
            self.assertNotEqual(base, i18n.contract_hash(model="qwen-plus"))
        finally:
            i18n.USER_TEMPLATE = original


class CacheHit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, *rows: dict) -> None:
        p = i18n.cache_path(self.data)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
            encoding="utf-8",
        )

    def _run(self, items, **kw):
        # 不给 api_key：任何未命中缓存的条目都会落进 skipped，一眼看得出是否重烧
        return i18n.enrich_items(self.data, items, api_key="", **kw)

    def test_legacy_row_without_contract_still_hits(self):
        """迁移策略：老缓存行没有 contract 字段，必须照旧命中。

        否则这次加指纹等于一次性作废全部存量译稿、全量重烧。
        """
        it = _item()
        self._write({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": i18n.content_hash(it), "model": "qwen-plus", "fields": _fields(),
        })
        stats = self._run([dict(it)])
        self.assertEqual(stats["cached"], 1)
        self.assertEqual(stats["skipped"], 0)

    def test_legacy_row_invalidated_under_strict_contract(self):
        it = _item()
        self._write({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": i18n.content_hash(it), "model": "qwen-plus", "fields": _fields(),
        })
        stats = self._run([dict(it)], strict_contract=True)
        self.assertEqual(stats["cached"], 0)
        self.assertEqual(stats["skipped"], 1)

    def test_stale_contract_triggers_retranslation(self):
        """带 contract 的新行在换模型后必须失效——这才是加指纹的目的。"""
        it = _item()
        self._write({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": i18n.content_hash(it),
            "contract": i18n.contract_hash(model="qwen-plus"),
            "model": "qwen-plus", "fields": _fields(),
        })
        self.assertEqual(self._run([dict(it)], model="qwen-plus")["cached"], 1)
        stats = self._run([dict(it)], model="qwen-max")
        self.assertEqual(stats["cached"], 0)
        self.assertEqual(stats["skipped"], 1)

    def test_locked_row_survives_contract_and_hash_change(self):
        """已验收永不重译：人工审校过的稿子不该因为我们改了 prompt 就被冲掉。"""
        it = _item()
        self._write({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": "totally-stale-hash",
            "contract": "totally-stale-contract",
            "locked": True, "model": "qwen-plus", "fields": _fields(),
        })
        for kw in ({}, {"model": "qwen-max"}, {"strict_contract": True}):
            target = dict(it)
            stats = self._run([target], **kw)
            self.assertEqual(stats["locked"], 1, kw)
            self.assertEqual(stats["cached"], 1, kw)
            self.assertEqual(stats["skipped"], 0, kw)
            self.assertEqual(target["one_liner_zh"], _fields()["one_liner_zh"])

    def test_locked_row_beats_a_fresh_unlocked_row(self):
        """locked 分支优先级最高：即使同键还有一条内容/契约都新鲜的行也不覆盖它。"""
        it = _item()
        locked = _fields(one_liner_zh="人工审校过的一句话")
        self._write(
            {"full_name": it["full_name"], "skill_path": it["skill_path"],
             "hash": i18n.content_hash(it), "contract": i18n.contract_hash(),
             "model": "qwen-plus", "fields": _fields()},
            {"full_name": it["full_name"], "skill_path": it["skill_path"],
             "hash": "stale", "contract": "stale", "locked": True,
             "model": "qwen-plus", "fields": locked},
        )
        target = dict(it)
        self.assertEqual(self._run([target])["locked"], 1)
        self.assertEqual(target["one_liner_zh"], "人工审校过的一句话")

    def test_content_change_still_invalidates(self):
        it = _item()
        self._write({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": i18n.content_hash(it), "contract": i18n.contract_hash(),
            "model": "qwen-plus", "fields": _fields(),
        })
        changed = dict(it, description="Totally different description")
        self.assertEqual(self._run([changed])["cached"], 0)


class DegradedRows(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_degraded_row_stops_the_per_build_burn(self):
        """校验失败的条目落一条 degraded 行，同输入同契约下不再调模型。"""
        it = _item()
        p = i18n.cache_path(self.data)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "full_name": it["full_name"], "skill_path": it["skill_path"],
            "hash": i18n.content_hash(it), "contract": i18n.contract_hash(),
            "model": "qwen-plus", "fields": {}, "degraded": True,
            "fail_reason": "banned:source_file:one_liner_zh", "attempts": 2,
        }, ensure_ascii=False) + "\n", encoding="utf-8")
        calls = []

        def fake_chat(item, **kw):
            calls.append(kw)
            return {}, ""

        orig, i18n._chat = i18n._chat, fake_chat
        try:
            stats = i18n.enrich_items(self.data, [dict(it)], api_key="k")
        finally:
            i18n._chat = orig
        self.assertEqual(stats["degraded"], 1)
        self.assertEqual(calls, [])

    def test_retry_feeds_the_reason_back_and_then_degrades(self):
        seen = []

        def fake_chat(item, **kw):
            seen.append(kw.get("hint", ""))
            return _fields(one_liner_zh="按 SKILL.md 的流程执行"), ""

        orig, i18n._chat = i18n._chat, fake_chat
        try:
            stats = i18n.enrich_items(self.data, [_item()], api_key="k", attempts=2)
        finally:
            i18n._chat = orig
        self.assertEqual(stats["calls"], 2)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["degraded"], 1)
        self.assertEqual(seen[0], "")
        self.assertIn("source_file", seen[1])
        rows = i18n.load_cache(self.data)
        row = rows[i18n.cache_key(_item())]
        self.assertTrue(row["degraded"])
        self.assertEqual(row["fail_reason"], "banned:source_file:one_liner_zh")

    def test_network_failure_does_not_pin_the_item(self):
        """断网是环境问题，不能落 degraded 把条目钉死。"""
        def fake_chat(item, **kw):
            return None, "api_error"

        orig, i18n._chat = i18n._chat, fake_chat
        try:
            stats = i18n.enrich_items(self.data, [_item()], api_key="k", attempts=2)
        finally:
            i18n._chat = orig
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["degraded"], 0)
        self.assertEqual(i18n.load_cache(self.data), {})

    def test_retry_recovers(self):
        state = {"n": 0}

        def fake_chat(item, **kw):
            state["n"] += 1
            if state["n"] == 1:
                return _fields(one_liner_en="See README.md for the full flow"), ""
            return _fields(), ""

        orig, i18n._chat = i18n._chat, fake_chat
        try:
            target = _item()
            stats = i18n.enrich_items(self.data, [target], api_key="k", attempts=2)
        finally:
            i18n._chat = orig
        self.assertEqual(stats["translated"], 1)
        self.assertEqual(stats["calls"], 2)
        self.assertTrue(target["i18n_ready"])


class Compaction(unittest.TestCase):
    def test_compaction_preserves_load_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            p = i18n.cache_path(data)
            p.parent.mkdir(parents=True, exist_ok=True)
            rows = [
                {"full_name": "a/b", "skill_path": "s1", "hash": "h1", "fields": _fields()},
                {"full_name": "a/b", "skill_path": "s1", "hash": "h2",
                 "fields": _fields(one_liner_zh="后写的这份才生效")},
                {"full_name": "a/b", "skill_path": "s2", "hash": "h3", "fields": _fields()},
            ]
            p.write_text(
                "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                encoding="utf-8",
            )
            before = i18n.load_cache(data)
            stats = i18n.compact_cache(data)
            self.assertEqual(stats, {"before": 3, "after": 2, "dropped": 1})
            self.assertEqual(i18n.load_cache(data), before)
            self.assertTrue(p.with_suffix(p.suffix + ".bak").exists())


if __name__ == "__main__":
    unittest.main()
