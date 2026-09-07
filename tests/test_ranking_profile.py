"""设备画像构建、负反馈作用域、曝光统计、star 快照、登录并档。"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedback
import impressions
import rank
import ranking
import ranking_profile
import star_history

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
CFG = ranking.resolve_config(None)


def ev(action, *, key="acme/x::SKILL.md", days_ago=0.0, **kw):
    row = {
        "action": action,
        "item_key": key,
        "scene": kw.pop("scene", "content"),
        "scene_l2": kw.pop("scene_l2", "writing"),
        "owner": kw.pop("owner", "acme"),
        "language": kw.pop("language", "Python"),
        "ts": (NOW - timedelta(days=days_ago)).isoformat(),
    }
    row.update(kw)
    return row


class TestSkipFastGuards(unittest.TestCase):
    def test_fling_is_discarded_entirely(self):
        """<200ms 是甩屏，卡片可能都没渲染完，既不算曝光也不算判断。"""
        self.assertIsNone(
            ranking_profile.classify_dwell({"dwell_ms": 120, "item_key": "a"}, CFG, set()),
        )

    def test_fast_skip_is_negative(self):
        self.assertEqual(
            ranking_profile.classify_dwell({"dwell_ms": 900, "item_key": "a"}, CFG, set()),
            "skip_fast",
        )

    def test_already_opened_item_is_exempt(self):
        """已经打开过 GitHub 的条目再快速划走不算负信号：已经转化过了。"""
        self.assertIsNone(
            ranking_profile.classify_dwell({"dwell_ms": 900, "item_key": "a"}, CFG, {"a"}),
        )

    def test_long_dwell_is_positive(self):
        self.assertEqual(
            ranking_profile.classify_dwell({"dwell_ms": 9000, "item_key": "a"}, CFG, set()),
            "dwell_long",
        )

    def test_end_to_end_exemption(self):
        opened = ranking_profile.build_profile("d", [
            ev("open_github"), ev("dwell", dwell_ms=500),
        ], config=CFG, now=NOW)
        plain = ranking_profile.build_profile("d", [
            ev("dwell", dwell_ms=500),
        ], config=CFG, now=NOW)
        self.assertGreater(
            ranking.affinity_weight(opened, "scene", "content", CFG, NOW),
            ranking.affinity_weight(plain, "scene", "content", CFG, NOW),
        )


class TestAffinityDecay(unittest.TestCase):
    def test_old_events_weigh_less(self):
        fresh = ranking_profile.build_profile("d", [ev("open_github")], config=CFG, now=NOW)
        aged = ranking_profile.build_profile(
            "d", [ev("open_github", days_ago=21)], config=CFG, now=NOW,
        )
        w_fresh = ranking.affinity_weight(fresh, "scene", "content", CFG, NOW)
        w_aged = ranking.affinity_weight(aged, "scene", "content", CFG, NOW)
        self.assertAlmostEqual(w_aged, w_fresh / 2, places=2)

    def test_per_event_decay_not_bulk(self):
        """三周前 4 次 + 今天 1 次，不能被当成今天 5 次。

        条数刻意压在 MAX_AFFINITY 以下，否则两边都被截顶就测不出衰减。
        """
        mixed = ranking_profile.build_profile(
            "d",
            [ev("open_github", days_ago=21) for _ in range(4)] + [ev("open_github")],
            config=CFG, now=NOW,
        )
        recent = ranking_profile.build_profile(
            "d", [ev("open_github") for _ in range(5)], config=CFG, now=NOW,
        )
        self.assertLess(
            ranking.affinity_weight(mixed, "scene", "content", CFG, NOW),
            ranking.affinity_weight(recent, "scene", "content", CFG, NOW),
        )

    def test_confidence_needs_meaningful_events(self):
        """只被曝光过不算有画像——看到卡片不等于表达了偏好。"""
        seen_only = ranking_profile.build_profile(
            "d", [ev("impression", key=f"k{n}") for n in range(30)], config=CFG, now=NOW,
        )
        self.assertEqual(seen_only.events, 0)
        self.assertEqual(ranking.profile_confidence(seen_only, CFG), 0.0)

        engaged = ranking_profile.build_profile(
            "d", [ev("open_github", key=f"k{n}") for n in range(12)], config=CFG, now=NOW,
        )
        self.assertEqual(ranking.profile_confidence(engaged, CFG), 1.0)


class TestSuppressScope(unittest.TestCase):
    def test_missing_scope_degrades_to_item(self):
        """前端埋点补上之前会有不带 scope 的事件，按最保守的单条处理。"""
        self.assertEqual(ranking_profile.normalize_scope(None), "item")
        self.assertEqual(ranking_profile.normalize_scope(""), "item")
        self.assertEqual(ranking_profile.normalize_scope("nonsense"), "item")
        self.assertEqual(ranking_profile.normalize_scope("scene"), "scene")

    def test_no_scope_only_hides_that_card(self):
        prof = ranking_profile.build_profile(
            "d", [ev("not_interested")], config=CFG, now=NOW,
        )
        same = {"id": "acme/x::SKILL.md", "scene": "content",
                "scene_l2": "writing", "owner": "acme"}
        sibling = {"id": "acme/y::SKILL.md", "scene": "content",
                   "scene_l2": "writing", "owner": "acme"}
        _, hidden_same, _ = ranking.negative_penalty(same, prof, CFG, NOW)
        pen_sib, hidden_sib, _ = ranking.negative_penalty(sibling, prof, CFG, NOW)
        self.assertTrue(hidden_same)
        self.assertFalse(hidden_sib)
        self.assertEqual(pen_sib, 0.0)

    def test_scene_scope_does_not_kill_the_category(self):
        """一级行业压制必须轻到不足以把整个品类踢出候选。"""
        prof = ranking_profile.build_profile(
            "d", [ev("not_interested", scope="scene")], config=CFG, now=NOW,
        )
        other = {"id": "z/z::SKILL.md", "scene": "content",
                 "scene_l2": "podcast", "owner": "z"}
        pen, hidden, _ = ranking.negative_penalty(other, prof, CFG, NOW)
        self.assertFalse(hidden)
        self.assertLessEqual(pen, 0.2)


class TestFatigue(unittest.TestCase):
    def test_no_action_impressions_accumulate(self):
        prof = ranking_profile.build_profile(
            "d", [ev("impression") for _ in range(4)], config=CFG, now=NOW,
        )
        self.assertEqual(prof.fatigue["acme/x::SKILL.md"][0], 4)

    def test_positive_action_clears_fatigue(self):
        prof = ranking_profile.build_profile(
            "d", [ev("impression"), ev("impression"), ev("open_github")],
            config=CFG, now=NOW,
        )
        self.assertNotIn("acme/x::SKILL.md", prof.fatigue)

    def test_hard_block_after_threshold(self):
        prof = ranking_profile.build_profile(
            "d", [ev("impression") for _ in range(6)], config=CFG, now=NOW,
        )
        _, hidden, _ = ranking.negative_penalty(
            {"id": "acme/x::SKILL.md"}, prof, CFG, NOW,
        )
        self.assertTrue(hidden)


class TestMergeOnLogin(unittest.TestCase):
    def test_affinity_sums(self):
        a = {"scene": {"content": (1.0, NOW)}}
        b = {"scene": {"content": (2.0, NOW), "design": (1.0, NOW)}}
        merged = ranking_profile.merge_affinity(a, b)
        self.assertEqual(merged["scene"]["content"][0], 3.0)
        self.assertEqual(merged["scene"]["design"][0], 1.0)

    def test_affinity_is_capped(self):
        a = {"scene": {"content": (5.0, NOW)}}
        b = {"scene": {"content": (5.0, NOW)}}
        merged = ranking_profile.merge_affinity(a, b)
        self.assertLessEqual(merged["scene"]["content"][0], ranking_profile.MAX_AFFINITY)

    def test_focus_is_union_without_dupes(self):
        merged = ranking_profile.merge_focus(
            [("scene", "content")], [("scene", "content"), ("scene_l2", "figma")],
        )
        self.assertEqual(len(merged), 2)
        self.assertIn(("scene_l2", "figma"), merged)

    def test_suppress_keeps_later_expiry(self):
        early = {"scope": "owner", "key": "acme", "weight": 0.45,
                 "created_at": "2026-01-01T00:00:00+00:00",
                 "expires_at": "2026-02-01T00:00:00+00:00"}
        late = {"scope": "owner", "key": "acme", "weight": 0.45,
                "created_at": "2026-03-01T00:00:00+00:00",
                "expires_at": "2026-04-01T00:00:00+00:00"}
        merged = ranking_profile.merge_suppress([early], [late])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["expires_at"], "2026-04-01T00:00:00+00:00")


class TestImpressions(unittest.TestCase):
    def test_aggregate_bands_and_clicks(self):
        rows = [
            {"action": "impression", "item_key": "a", "position": 1},
            {"action": "impression", "item_key": "a", "position": 30},
            {"action": "open_github", "item_key": "a", "position": 1},
            {"action": "useful", "item_key": "a", "position": 1},
        ]
        stats = impressions.aggregate(rows, config=CFG)
        self.assertEqual(stats["a"].total_impressions, 2)
        # useful 不算 CTR 分子：态度不是转化
        self.assertEqual(stats["a"].total_clicks, 1)
        self.assertEqual(stats["a"].impressions[0], 1)
        self.assertEqual(stats["a"].impressions[2], 1)

    def test_fling_impression_is_dropped(self):
        rows = [{"action": "impression", "item_key": "a", "position": 1, "dwell_ms": 50}]
        self.assertEqual(impressions.aggregate(rows, config=CFG), {})

    def test_global_stats_derives_band_ctr(self):
        stats = {
            "a": ranking.ItemStats(impressions={0: 100}, clicks={0: 20}),
            "b": ranking.ItemStats(impressions={3: 100}, clicks={3: 2}),
        }
        items = [{"id": "a", "scene_l2": "writing"}, {"id": "b", "scene_l2": "writing"}]
        gs = ranking.build_global_stats(stats, items)
        self.assertAlmostEqual(gs.ctr_overall, 0.11, places=4)
        self.assertAlmostEqual(gs.band_ctr(0), 0.20, places=4)
        self.assertAlmostEqual(gs.band_ctr(3), 0.02, places=4)


class TestFeedbackFile(unittest.TestCase):
    def test_new_actions_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            feedback.append_feedback(data, {
                "action": "impression", "item_key": "a/b::SKILL.md",
                "position": 3, "device_id": "dev1", "session_id": "s1",
            })
            feedback.append_feedback(data, {
                "action": "not_interested", "item_key": "a/b::SKILL.md",
                "device_id": "dev1",
            })
            rows = feedback.load_events(data, device_id="dev1")
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1]["scope"], "item")
            # item_key 能还原出 full_name，否则按 full_name 聚合的老逻辑会丢数
            self.assertEqual(rows[0]["full_name"], "a/b")

    def test_legacy_action_name_is_aliased(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            feedback.append_feedback(data, {
                "action": "opened_github", "full_name": "a/b",
            })
            rows = feedback.load_events(data)
            self.assertEqual(rows[0]["action"], "open_github")

    def test_bad_row_does_not_kill_the_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            res = feedback.append_many(data, [
                {"action": "impression", "item_key": "a"},
                {"action": "nonsense"},
                {"action": "open_github", "item_key": "a"},
            ])
            self.assertEqual(res["accepted"], 2)
            self.assertEqual(res["rejected"], 1)


class TestLegacyBoostAbsoluteEvidence(unittest.TestCase):
    """build 期仍在用 rank.load_feedback_affinity，它按同维最大值归一，
    导致「点 1 次就拿满档」。实测 5 条历史反馈就能让头部 top-10 全换人。"""

    def _boost(self, n):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "feedback.jsonl").write_text(
                "".join(
                    '{"action":"useful","scene":"content","full_name":"a/x"}\n'
                    for _ in range(n)
                ),
                encoding="utf-8",
            )
            return rank.load_feedback_affinity(data)["scene_boost"]["content"]

    def test_boost_grows_with_absolute_evidence(self):
        one, three, ten = self._boost(1), self._boost(3), self._boost(10)
        self.assertLess(one, three)
        self.assertLess(three, ten)

    def test_single_click_does_not_max_out(self):
        self.assertLess(self._boost(1), 0.22 / 2)

    def test_boost_stays_capped(self):
        self.assertLessEqual(self._boost(500), 0.22)

    def test_new_profile_does_not_inherit_the_defect(self):
        """新画像走绝对权重 + 置信度门控，一次点击的实际影响必须极小。"""
        def influence(n):
            evs = [ev("useful") for _ in range(n)]
            prof = ranking_profile.build_profile("d", evs, config=CFG, now=NOW)
            row = {"id": "z", "scene": "content", "scene_l2": "writing", "owner": "z"}
            p, _ = ranking.personal_affinity(row, prof, CFG, NOW)
            return float(CFG["weights"]["personal_max"]) * \
                ranking.profile_confidence(prof, CFG) * p

        self.assertLess(influence(1), 0.02)
        self.assertLess(influence(1), influence(3))
        self.assertLess(influence(3), influence(10))


class TestStarHistory(unittest.TestCase):
    def test_velocity_needs_two_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            rows = [{"full_name": "a/b", "stars": 100}]
            snap = star_history.observe(rows, data_dir=data, now=NOW - timedelta(days=4))
            self.assertEqual(snap, {})
            snap = star_history.observe(
                [{"full_name": "a/b", "stars": 140}], data_dir=data, now=NOW,
            )
            self.assertAlmostEqual(snap["a/b"]["daily_gain"], 10.0, places=1)

    def test_same_day_rerun_does_not_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            star_history.observe(
                [{"full_name": "a/b", "stars": 100}], data_dir=data, now=NOW - timedelta(days=2),
            )
            for _ in range(3):
                snap = star_history.observe(
                    [{"full_name": "a/b", "stars": 120}], data_dir=data, now=NOW,
                )
            self.assertAlmostEqual(snap["a/b"]["daily_gain"], 10.0, places=1)

    def test_first_seen_is_remembered(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            old = NOW - timedelta(days=9)
            star_history.observe([{"full_name": "a/b", "stars": 10}], data_dir=data, now=old)
            seen = star_history.first_seen_map(
                [{"full_name": "a/b"}], data_dir=data, now=NOW,
            )
            self.assertTrue(seen["a/b"].startswith(old.isoformat()[:10]))

    def test_monorepo_siblings_write_one_trajectory(self):
        """同仓 20 条带的是同一个仓库星数，快照按 full_name 存，不该出现 20 份。"""
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            siblings = [
                {"full_name": "acme/mono", "stars": 1000, "id": f"acme/mono::s{k}"}
                for k in range(20)
            ]
            star_history.observe(siblings, data_dir=data, now=NOW - timedelta(days=3))
            for s in siblings:
                s["stars"] = 1060
            snap = star_history.observe(siblings, data_dir=data, now=NOW)
            raw = json.loads(star_history.snapshot_path(data).read_text(encoding="utf-8"))
            self.assertEqual(list(raw.keys()), ["acme/mono"])
            self.assertEqual(len(raw["acme/mono"]), 2)
            self.assertAlmostEqual(snap["acme/mono"]["daily_gain"], 20.0, places=1)

    def test_unknown_repo_falls_back_to_now(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = star_history.first_seen_map(
                [{"full_name": "new/repo"}], data_dir=Path(tmp), now=NOW,
            )
            self.assertEqual(seen["new/repo"], NOW.isoformat())


if __name__ == "__main__":
    unittest.main()
