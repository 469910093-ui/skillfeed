"""反馈链路：摄入可观测、丢弃原因、点赞/收藏分离、站内热度多来源。

这一组用例针对的是一个具体事故：feedback.jsonl 自 7 月 27 日起零新增，
一个多月没人发现。所以断言的重点不只是「写得进去」，还有
「写不进去的时候外面看得出来」。
"""

import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import feedback
import impressions
import rank
import ranking
from server import metrics

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
CFG = ranking.resolve_config(None)


class TestIngestMetrics(unittest.TestCase):
    def test_counts_accumulate_and_expose_reasons(self):
        m = metrics.IngestMetrics()
        m.record(accepted=3, deduped=1, rejected={"fling": 2, "unknown_action": 1},
                 by_action={"impression": 3})
        m.record(accepted=1, rejected={"fling": 1}, by_action={"open_github": 1})
        snap = m.snapshot()
        self.assertEqual(snap["accepted"], 4)
        self.assertEqual(snap["deduped"], 1)
        self.assertEqual(snap["rejected_by_reason"], {"fling": 3, "unknown_action": 1})
        self.assertEqual(snap["accepted_by_action"], {"impression": 3, "open_github": 1})
        self.assertEqual(snap["requests"], 2)

    def test_zero_reasons_are_not_reported_as_noise(self):
        m = metrics.IngestMetrics()
        m.record(accepted=1)
        self.assertEqual(m.snapshot()["rejected_by_reason"], {})

    def test_last_accepted_only_moves_on_real_writes(self):
        m = metrics.IngestMetrics()
        m.record(rejected={"ratelimited": 5})
        self.assertIsNone(m.snapshot()["last_accepted_at"])
        m.record(accepted=1)
        self.assertIsNotNone(m.snapshot()["last_accepted_at"])

    def test_staleness_distinguishes_never_from_long_ago(self):
        self.assertIsNone(metrics.staleness(None, now=NOW))
        age = metrics.staleness((NOW - timedelta(days=2)).isoformat(), now=NOW)
        self.assertAlmostEqual(age, 172800, delta=1)


class TestFeedbackRejectReasons(unittest.TestCase):
    def test_batch_reports_reasons_not_just_a_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = feedback.append_many(Path(tmp), [
                {"action": "impression", "item_key": "a/b::SKILL.md"},
                {"action": "nonsense", "item_key": "a/b::SKILL.md"},
                "not-a-dict",
                {"action": "open_github"},          # 条目级动作却没带 item_key
            ])
        self.assertEqual(res["accepted"], 1)
        self.assertEqual(res["rejected"], 3)
        self.assertEqual(res["rejected_by_reason"], {
            "unknown_action": 1, "not_a_dict": 1, "missing_item_key": 1,
        })

    def test_session_and_focus_events_need_no_item_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = feedback.append_many(Path(tmp), [
                {"action": "session_start"},
                {"action": "focus_set", "focus": [{"dim": "scene", "key": "content"}]},
            ])
        self.assertEqual(res["accepted"], 2)
        self.assertEqual(res["rejected"], 0)

    def test_accepted_by_action_uses_normalized_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = feedback.append_many(Path(tmp), [
                {"action": "opened_github", "full_name": "a/b"},
            ])
        self.assertEqual(res["accepted_by_action"], {"open_github": 1})


class TestIngestHealth(unittest.TestCase):
    """这就是「一个多月零新增没人发现」的对策：断了要自己说。"""

    def _health(self, rows, *, now=NOW, stale_after=86400.0):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            if rows:
                (data / "feedback.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8",
                )
            return feedback.ingest_health(
                data, stale_after_s=stale_after, now=now,
            )

    def test_empty_file_is_not_stale(self):
        h = self._health([])
        self.assertTrue(h["empty"])
        self.assertFalse(h["stale"])
        self.assertIsNone(h["last_event_age_s"])

    def test_month_old_last_event_is_stale(self):
        h = self._health([
            {"action": "useful", "item_key": "a/b",
             "ts": (NOW - timedelta(days=38)).isoformat()},
        ])
        self.assertTrue(h["stale"])
        self.assertEqual(h["total"], 1)
        self.assertGreater(h["last_event_age_s"], 86400)

    def test_fresh_event_is_healthy(self):
        h = self._health([
            {"action": "useful", "item_key": "a/b",
             "ts": (NOW - timedelta(minutes=5)).isoformat()},
        ])
        self.assertFalse(h["stale"])
        self.assertFalse(h["empty"])

    def test_by_action_normalizes_legacy_name(self):
        h = self._health([
            {"action": "opened_github", "item_key": "a/b", "ts": NOW.isoformat()},
        ])
        self.assertEqual(h["by_action"], {"open_github": 1})


class TestSaveOutranksLike(unittest.TestCase):
    """点赞和收藏是两个信号：收藏指向未来行动，点赞只是情绪，且能被双击误触。"""

    def test_event_weights_ordered(self):
        ew = CFG["event_weights"]
        self.assertGreater(ew["open_github"], ew["save"])
        self.assertGreater(ew["save"], ew["useful"])
        # 差距必须是量级上的，不是四舍五入的差别
        self.assertGreaterEqual(ew["save"], ew["useful"] * 1.8)

    def test_save_moves_profile_more_than_like(self):
        import ranking_profile

        def influence(action):
            evs = [{
                "action": action, "item_key": "a/b::SKILL.md", "full_name": "a/b",
                "scene": "content", "scene_l2": "writing", "owner": "a",
                "ts": NOW.isoformat(),
            }]
            prof = ranking_profile.build_profile("d", evs, config=CFG, now=NOW)
            row = {"id": "z", "scene": "content", "scene_l2": "writing", "owner": "a"}
            score, _ = ranking.personal_affinity(row, prof, CFG, NOW)
            return score

        self.assertGreater(influence("save"), influence("useful"))

    def test_build_time_affinity_uses_the_same_ordering(self):
        """rank.load_feedback_affinity 过去把 useful 排在 open_github 之上。"""
        def boost(action):
            with tempfile.TemporaryDirectory() as tmp:
                data = Path(tmp)
                (data / "feedback.jsonl").write_text(
                    json.dumps({
                        "action": action, "scene": "content", "full_name": "a/x",
                    }) + "\n",
                    encoding="utf-8",
                )
                return rank.load_feedback_affinity(data)["repo_boost"]["a/x"]

        self.assertGreater(boost("open_github"), boost("save"))
        self.assertGreater(boost("save"), boost("useful"))
        # 旧写盘名与新名必须同权重，否则改名当天历史转化记录集体降级
        self.assertEqual(boost("opened_github"), boost("open_github"))


class TestStatsSources(unittest.TestCase):
    """静态形态没有服务端，但「站内热度」是全站聚合量，可以在 build 期烧进去。"""

    def _stats(self, imp, clk, band=0):
        st = ranking.ItemStats()
        st.impressions[band] = imp
        st.clicks[band] = clk
        return st

    def test_merge_adds_per_band(self):
        merged = impressions.merge(
            {"a": self._stats(10, 1)},
            {"a": self._stats(5, 2), "b": self._stats(3, 0)},
        )
        self.assertEqual(merged["a"].total_impressions, 15)
        self.assertEqual(merged["a"].total_clicks, 3)
        self.assertEqual(merged["b"].total_impressions, 3)

    def test_merge_keeps_earliest_first_seen(self):
        early = ranking.ItemStats(first_seen_at="2026-01-01T00:00:00+00:00")
        late = ranking.ItemStats(first_seen_at="2026-06-01T00:00:00+00:00")
        merged = impressions.merge({"a": late}, {"a": early})
        self.assertEqual(merged["a"].first_seen_at, "2026-01-01T00:00:00+00:00")

    def test_reads_server_sqlite_without_importing_the_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "server.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE item_stats (item_key TEXT, position_band INTEGER, "
                "impressions INTEGER, clicks INTEGER, first_seen_at TEXT)",
            )
            conn.execute(
                "INSERT INTO item_stats VALUES ('a/b::SKILL.md', 0, 40, 6, NULL)",
            )
            conn.commit()
            conn.close()
            stats = impressions.from_sqlite(db_path)
        self.assertEqual(stats["a/b::SKILL.md"].total_impressions, 40)
        self.assertEqual(stats["a/b::SKILL.md"].total_clicks, 6)

    def test_missing_or_schemaless_db_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(impressions.from_sqlite(Path(tmp) / "nope.db"), {})
            blank = Path(tmp) / "blank.db"
            sqlite3.connect(blank).close()
            # 服务端从没跑过 → 表不存在，这是正常状态不是故障
            self.assertEqual(impressions.from_sqlite(blank), {})

    def test_export_snapshot_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / impressions.STATS_EXPORT_NAME
            path.write_text(json.dumps({"items": [
                {"item_key": "a/b::SKILL.md", "position_band": 1,
                 "impressions": 7, "clicks": 2},
            ]}), encoding="utf-8")
            stats = impressions.from_stats_export(path)
        self.assertEqual(stats["a/b::SKILL.md"].impressions[1], 7)

    def test_load_stats_unions_all_three_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "feedback.jsonl").write_text(
                json.dumps({"action": "impression", "item_key": "a/b::SKILL.md",
                            "position": 0}) + "\n",
                encoding="utf-8",
            )
            (home / impressions.STATS_EXPORT_NAME).write_text(
                json.dumps({"items": [{"item_key": "a/b::SKILL.md",
                                       "position_band": 0, "impressions": 9,
                                       "clicks": 1}]}),
                encoding="utf-8",
            )
            conn = sqlite3.connect(home / "server.db")
            conn.execute(
                "CREATE TABLE item_stats (item_key TEXT, position_band INTEGER, "
                "impressions INTEGER, clicks INTEGER, first_seen_at TEXT)",
            )
            conn.execute("INSERT INTO item_stats VALUES ('a/b::SKILL.md', 0, 5, 3, NULL)")
            conn.commit()
            conn.close()
            stats = impressions.load_stats(home, config=CFG)
        self.assertEqual(stats["a/b::SKILL.md"].total_impressions, 1 + 5 + 9)
        self.assertEqual(stats["a/b::SKILL.md"].total_clicks, 3 + 1)


if __name__ == "__main__":
    unittest.main()
