"""路径判断层：不改 G/P/F/N 分数，只处理冲突与近邻同分。"""

from __future__ import annotations

import unittest

import ranking
import ranking_path

CFG = ranking.resolve_config(None)


def _profile(**kw) -> ranking.DeviceProfile:
    return ranking.DeviceProfile(**kw)


class TestJudgeFeedPath(unittest.TestCase):
    def test_query_picks_task_when_unambiguous(self):
        d = ranking_path.judge_feed_path(
            _profile(device_id="d1", events=8), query="周报", config=CFG,
        )
        self.assertEqual(d.path, "task")
        self.assertGreaterEqual(d.confidence, 0.55)
        self.assertFalse(d.conflict)

    def test_cold_start_without_query_does_not_invent_publisher(self):
        d = ranking_path.judge_feed_path(
            _profile(device_id="cold", events=1), query="", config=CFG,
        )
        self.assertIn(d.path, ("default", "reliable"))
        self.assertNotEqual(d.path, "publisher")

    def test_publish_journey_and_query_conflict_sticks(self):
        d = ranking_path.judge_feed_path(
            _profile(device_id="mix", events=20),
            query="ppt",
            extras={"recent_actions": ["publish_view"]},
            config=CFG,
        )
        self.assertTrue(d.conflict or d.path in ("default", "reliable"))
        self.assertLess(d.confidence, 0.55)

    def test_same_device_is_sticky_on_conflict(self):
        a = ranking_path.judge_feed_path(
            _profile(device_id="sticky-1", events=3),
            query="周报",
            extras={"recent_actions": ["publish_view"]},
            config=CFG,
        )
        b = ranking_path.judge_feed_path(
            _profile(device_id="sticky-1", events=3),
            query="周报",
            extras={"recent_actions": ["publish_view"]},
            config=CFG,
        )
        self.assertEqual(a.path, b.path)


class TestTiebreak(unittest.TestCase):
    def test_does_not_change_personal_score(self):
        items = [
            {"id": "a", "personal_score": 0.80, "stars": 10},
            {"id": "b", "personal_score": 0.80, "stars": 900},
        ]
        d = ranking_path.PathDecision(path="reliable", confidence=0.8)
        out = ranking_path.apply_path_tiebreak(items, d, CFG)
        self.assertEqual([x["personal_score"] for x in out], [0.80, 0.80])
        self.assertEqual([x["id"] for x in out], ["b", "a"])

    def test_large_score_gap_keeps_original_order(self):
        items = [
            {"id": "lowstar", "personal_score": 0.90, "stars": 3},
            {"id": "highstar", "personal_score": 0.40, "stars": 9000},
        ]
        d = ranking_path.PathDecision(path="reliable", confidence=0.9)
        out = ranking_path.apply_path_tiebreak(items, d, CFG)
        self.assertEqual([x["id"] for x in out], ["lowstar", "highstar"])

    def test_default_or_low_confidence_is_noop(self):
        items = [
            {"id": "a", "personal_score": 0.50, "stars": 1},
            {"id": "b", "personal_score": 0.50, "stars": 99},
        ]
        d0 = ranking_path.PathDecision(path="default", confidence=0.9)
        d1 = ranking_path.PathDecision(path="reliable", confidence=0.2)
        self.assertEqual(
            [x["id"] for x in ranking_path.apply_path_tiebreak(items, d0, CFG)],
            ["a", "b"],
        )
        self.assertEqual(
            [x["id"] for x in ranking_path.apply_path_tiebreak(items, d1, CFG)],
            ["a", "b"],
        )


if __name__ == "__main__":
    unittest.main()
