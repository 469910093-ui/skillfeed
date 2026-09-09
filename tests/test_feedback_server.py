"""服务端反馈链路：会话内负反馈、埋点可观测端点、点赞/收藏分列。"""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ranking
from server import ranking_service

try:
    from fastapi.testclient import TestClient
    import server.app as server_app
    from server.config import Settings
    HAS_SERVER = True
except ImportError:
    HAS_SERVER = False

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
CFG = ranking.resolve_config(None)


def _row(**kw):
    base = {"item_key": "a/b::SKILL.md", "owner": "acme",
            "scene": "content", "scene_l2": "writing", "scope": "item"}
    base.update(kw)
    return base


class TestSessionEcho(unittest.TestCase):
    """点「不感兴趣」必须当前会话就有感，否则那句 toast 就是空头承诺。"""

    def test_item_scope_echoes_to_l2_and_owner(self):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        got = {(r["scope"], r["key"]) for r in cache.session_echo("d", "s", now=1.0)}
        self.assertEqual(got, {("scene_l2", "writing"), ("owner", "acme")})

    def test_scene_scope_is_never_widened_by_the_server(self):
        """一级行业占库存三分之一，只能由用户显式选，服务端不自己放大到那一层。"""
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s", _row(scope="scene"), config=CFG, now=0.0)
        self.assertEqual(cache.session_echo("d", "s", now=1.0), [])

        cache2 = ranking_service.SessionOrderCache(ttl_s=1800)
        cache2.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        scopes = {r["scope"] for r in cache2.session_echo("d", "s", now=1.0)}
        self.assertNotIn("scene", scopes)

    def test_l2_scope_only_echoes_owner(self):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s", _row(scope="scene_l2"), config=CFG, now=0.0)
        got = {r["scope"] for r in cache.session_echo("d", "s", now=1.0)}
        self.assertEqual(got, {"owner"})

    def test_repeated_hits_accumulate_but_stay_capped(self):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        for _ in range(20):
            cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        weights = [r["weight"] for r in cache.session_echo("d", "s", now=1.0)]
        cap = float(CFG["session"]["echo"]["max"])
        self.assertTrue(all(w <= cap for w in weights))
        # 连点十次不该等于永久拉黑：上限必须明显低于 owner 级持久压制的初始值
        self.assertLess(cap, float(CFG["suppress"]["owner"][0]))

    def test_echo_dies_with_the_session(self):
        cache = ranking_service.SessionOrderCache(ttl_s=100)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        self.assertTrue(cache.session_echo("d", "s", now=50.0))
        self.assertEqual(cache.session_echo("d", "s", now=500.0), [])

    def test_echo_is_scoped_to_one_session(self):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s1", _row(), config=CFG, now=0.0)
        self.assertEqual(cache.session_echo("d", "s2", now=1.0), [])
        self.assertEqual(cache.session_echo("other", "s1", now=1.0), [])

    def test_echo_can_be_switched_off(self):
        cfg = ranking.resolve_config(
            {"ranking": {"session": {"echo": {"enabled": False}}}},
        )
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s", _row(), config=cfg, now=0.0)
        self.assertEqual(cache.session_echo("d", "s", now=1.0), [])

    def test_echo_rows_actually_penalize_but_do_not_hide(self):
        """回声是压分不是隐藏：压错了探索位仍能把这个行业捞回来。"""
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        prof = ranking.DeviceProfile(
            device_id="d", suppress=cache.session_echo("d", "s", now=1.0, wall_now=NOW),
        )
        item = {"id": "x/y::SKILL.md", "owner": "acme",
                "scene": "content", "scene_l2": "writing"}
        penalty, hidden, _ = ranking.negative_penalty(item, prof, CFG, NOW)
        self.assertGreater(penalty, 0)
        self.assertFalse(hidden)

        untouched = {"id": "q/r::SKILL.md", "owner": "other",
                     "scene": "content", "scene_l2": "video"}
        clean, _, _ = ranking.negative_penalty(untouched, prof, CFG, NOW)
        self.assertEqual(clean, 0.0)


class TestServedPrefixFreeze(unittest.TestCase):
    """即时性 vs 会话稳定性：已送出的冻结，未送出的重排。"""

    def _cache(self, served):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        key = ranking_service.cache_key("d", "s", "sig")
        cache.put(key, [f"i{n}" for n in range(20)], now=0.0)
        cache.mark_served(key, served, now=0.0)
        return cache, key

    def test_not_interested_truncates_order_to_high_water_mark(self):
        cache, key = self._cache(6)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        self.assertEqual(cache.get(key, now=1.0), [f"i{n}" for n in range(6)])

    def test_seen_prefix_keeps_its_exact_order(self):
        cache, key = self._cache(6)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        kept = cache.get(key, now=1.0)
        # 用户已经滑过的卡一张都不能移位，否则「刷新后找不到刚看的那张」
        self.assertEqual(kept, [f"i{n}" for n in range(6)])

    def test_nothing_served_yet_means_everything_reranks(self):
        cache, key = self._cache(0)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        self.assertEqual(cache.get(key, now=1.0), [])

    def test_high_water_mark_only_grows(self):
        cache, key = self._cache(10)
        cache.mark_served(key, 4, now=0.0)
        self.assertEqual(cache.served_upto(key), 10)

    def test_all_filters_of_the_same_session_are_truncated(self):
        """换了筛选条件是另一份缓存，但负反馈对它们同样成立。"""
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        k1 = ranking_service.cache_key("d", "s", "sigA")
        k2 = ranking_service.cache_key("d", "s", "sigB")
        for k in (k1, k2):
            cache.put(k, ["a", "b", "c", "d"], now=0.0)
            cache.mark_served(k, 2, now=0.0)
        cache.note_not_interested("d", "s", _row(), config=CFG, now=0.0)
        self.assertEqual(cache.get(k1, now=1.0), ["a", "b"])
        self.assertEqual(cache.get(k2, now=1.0), ["a", "b"])

    def test_other_sessions_are_untouched(self):
        cache = ranking_service.SessionOrderCache(ttl_s=1800)
        mine = ranking_service.cache_key("d", "s1", "sig")
        theirs = ranking_service.cache_key("d", "s2", "sig")
        for k in (mine, theirs):
            cache.put(k, ["a", "b", "c"], now=0.0)
            cache.mark_served(k, 1, now=0.0)
        cache.note_not_interested("d", "s1", _row(), config=CFG, now=0.0)
        self.assertEqual(cache.get(mine, now=1.0), ["a"])
        self.assertEqual(cache.get(theirs, now=1.0), ["a", "b", "c"])


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestIngestObservability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.dev_mode = True
        s.dev_auth = True
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # 同 test_ranking_server：留空会退回本地产物，指到不存在的路径保持隔离
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 登录门禁默认开启（V1 强制登录），这里测的是 feedback 链路
        s.require_login = False
        s.github_client_id = ""
        s.github_client_secret = ""
        s.metrics_token = "ops-token"
        self.settings = s
        self.app = server_app.create_app(s)
        self.client = TestClient(self.app)

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def _post(self, events, device="dev1", session="s1"):
        return self.client.post("/api/events", json={
            "device_id": device, "session_id": session, "events": events,
        })

    def _ops(self):
        return {"X-Metrics-Token": "ops-token"}

    def test_response_reports_why_events_were_dropped(self):
        r = self._post([
            {"action": "impression", "item_key": "a/b::SKILL.md",
             "position": 1, "client_ts": "t1"},
            {"action": "made_up", "item_key": "a/b::SKILL.md", "client_ts": "t2"},
            {"action": "open_github", "client_ts": "t3"},          # 缺 item_key
            {"action": "impression", "item_key": "a/b::SKILL.md",
             "dwell_ms": 50, "client_ts": "t4"},                   # 甩屏
        ])
        body = r.json()
        self.assertEqual(body["accepted"], 1)
        self.assertEqual(body["rejected"], 3)
        self.assertEqual(body["rejected_by_reason"], {
            "unknown_action": 1, "missing_item_key": 1, "fling": 1,
        })

    def test_health_endpoint_needs_ops_credentials(self):
        self.assertEqual(self.client.get("/api/events/health").status_code, 401)
        self.assertEqual(
            self.client.get(
                "/api/events/health", headers={"X-Metrics-Token": "wrong"},
            ).status_code, 401,
        )
        self.assertEqual(
            self.client.get("/api/events/health", headers=self._ops()).status_code, 200,
        )

    def test_health_separates_never_from_long_ago(self):
        blank = self.client.get("/api/events/health", headers=self._ops()).json()
        self.assertTrue(blank["empty"])
        self.assertFalse(blank["stale"])
        self.assertIsNone(blank["last_event_age_s"])

        self._post([{"action": "open_github", "item_key": "a/b::SKILL.md",
                     "position": 0, "client_ts": "t1"}])
        live = self.client.get("/api/events/health", headers=self._ops()).json()
        self.assertFalse(live["empty"])
        self.assertFalse(live["stale"])
        self.assertEqual(live["events_by_action"], {"open_github": 1})
        self.assertEqual(live["clicks_total"], 1)

    def test_health_flags_a_dead_pipeline(self):
        """就是「7 月 27 日之后零新增」那个场景：断了要能被自动发现。"""
        from server import db
        old = (datetime.now(timezone.utc) - timedelta(days=38)).isoformat()
        with db.db_session(self.settings.db_path) as conn:
            db.insert_events(conn, [{
                "device_id": "d", "session_id": "s", "item_key": "a/b::SKILL.md",
                "action": "open_github", "position": 0, "position_band": 0,
                "dwell_ms": None, "scene": "", "scene_l2": "", "owner": "",
                "language": "", "source": "", "scope": None,
                "ts": old, "client_ts": "old",
            }])
        health = self.client.get("/api/events/health", headers=self._ops()).json()
        self.assertTrue(health["stale"])
        self.assertGreater(health["last_event_age_s"], 86400)
        # 公开健康检查也带这个标志，外部探针不用凭据就能盯住
        self.assertTrue(self.client.get("/health").json()["ingest_stale"])

    def test_public_health_does_not_leak_ratelimit_counters(self):
        public = self.client.get("/health").json()
        self.assertNotIn("process", public)
        self.assertNotIn("rejected_by_reason", public)

    def test_ratelimited_events_are_counted_even_though_dropped_silently(self):
        from server.ratelimit import EventLimiter
        self.app.state.event_limiter = EventLimiter({"ratelimit": {
            "window_s": 300, "max_events_per_ip": 2, "max_events_per_device": 2,
        }})
        r = self._post([
            {"action": "impression", "item_key": f"a/b{n}::SKILL.md",
             "position": 1, "client_ts": f"t{n}"}
            for n in range(6)
        ])
        self.assertEqual(r.status_code, 200)   # 静默丢弃，不给 429
        proc = self.client.get(
            "/api/events/health", headers=self._ops(),
        ).json()["process"]
        self.assertEqual(proc["rejected_by_reason"]["ratelimited"], 4)

    def test_stats_export_is_aggregate_only_and_gated(self):
        self._post([
            {"action": "impression", "item_key": "a/b::SKILL.md",
             "position": 1, "client_ts": "t1"},
            {"action": "open_github", "item_key": "a/b::SKILL.md",
             "position": 1, "client_ts": "t2"},
        ])
        self.assertEqual(self.client.get("/api/stats/items").status_code, 401)
        rows = self.client.get("/api/stats/items", headers=self._ops()).json()["items"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["impressions"], 1)
        self.assertEqual(rows[0]["clicks"], 1)
        # 导出里不能出现任何设备维度信息
        self.assertNotIn("device_id", rows[0])
        self.assertNotIn("session_id", rows[0])


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestReactionsPanel(unittest.TestCase):
    """点了赞却无处可查，那个动作对用户就是纯粹的空转。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.dev_mode = True
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # 同 test_ranking_server：留空会退回本地产物，指到不存在的路径保持隔离
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 登录门禁默认开启（V1 强制登录），这里测的是 feedback 链路
        s.require_login = False
        s.github_client_id = ""
        s.github_client_secret = ""
        self.settings = s
        self.app = server_app.create_app(s)
        self.client = TestClient(self.app)

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def _seed(self, device="dev1"):
        r = self.client.post("/api/events", json={
            "device_id": device, "session_id": "s1", "events": [
                {"action": "useful", "item_key": "a/liked::SKILL.md",
                 "owner": "a", "scene": "content", "client_ts": "t1"},
                {"action": "save", "item_key": "b/saved::SKILL.md",
                 "owner": "b", "scene": "design", "client_ts": "t2"},
                {"action": "open_github", "item_key": "c/opened::SKILL.md",
                 "owner": "c", "position": 0, "client_ts": "t3"},
            ],
        })
        return r.json()["device_token"]

    def test_like_and_save_are_separate_lists(self):
        token = self._seed()
        body = self.client.get(
            "/api/profile/reactions",
            headers={"X-Device-Id": "dev1", "X-Device-Token": token},
        ).json()
        self.assertEqual([i["item_key"] for i in body["liked"]], ["a/liked::SKILL.md"])
        self.assertEqual([i["item_key"] for i in body["saved"]], ["b/saved::SKILL.md"])
        self.assertEqual([i["item_key"] for i in body["opened"]], ["c/opened::SKILL.md"])

    def test_reading_someone_elses_history_needs_the_device_credential(self):
        self._seed(device="victim")
        r = self.client.get(
            "/api/profile/reactions", headers={"X-Device-Id": "victim"},
        )
        self.assertEqual(r.status_code, 403)
        forged = self.client.get(
            "/api/profile/reactions",
            headers={"X-Device-Id": "victim", "X-Device-Token": "nope"},
        )
        self.assertEqual(forged.status_code, 403)

    def test_repeat_taps_do_not_duplicate_rows(self):
        token = self._seed()
        self.client.post("/api/events", json={
            "device_id": "dev1", "session_id": "s2", "events": [
                {"action": "useful", "item_key": "a/liked::SKILL.md", "client_ts": "t9"},
            ],
        })
        body = self.client.get(
            "/api/profile/reactions",
            headers={"X-Device-Id": "dev1", "X-Device-Token": token},
        ).json()
        self.assertEqual(len(body["liked"]), 1)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestNotInterestedReachesTheSessionCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.dev_mode = True
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # 同 test_ranking_server：留空会退回本地产物，指到不存在的路径保持隔离
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 登录门禁默认开启（V1 强制登录），这里测的是 feedback 链路
        s.require_login = False
        s.github_client_id = ""
        s.github_client_secret = ""
        self.app = server_app.create_app(s)
        self.client = TestClient(self.app)

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_event_creates_both_persistent_and_session_suppression(self):
        cache = self.app.state.order_cache
        key = ranking_service.cache_key("dev1", "s1", "sig")
        cache.put(key, [f"i{n}" for n in range(10)])
        cache.mark_served(key, 3)

        self.client.post("/api/events", json={
            "device_id": "dev1", "session_id": "s1", "events": [
                {"action": "not_interested", "item_key": "a/b::SKILL.md",
                 "owner": "acme", "scene": "content", "scene_l2": "writing",
                 "client_ts": "t1"},
            ],
        })

        from server import db
        with db.db_session(self.app.state.settings.db_path) as conn:
            persisted = db.load_device_suppress(conn, "dev1")
        # 持久层仍然只压用户显式选的那一条（scope 缺失降级为 item）
        self.assertEqual([(r["scope"], r["key"]) for r in persisted],
                         [("item", "a/b::SKILL.md")])
        # 会话层更宽，但只活到会话过期
        echo = {r["scope"] for r in cache.session_echo("dev1", "s1")}
        self.assertEqual(echo, {"scene_l2", "owner"})
        # 未送出的部分被丢弃，下次请求重排；已送出的 3 条原样保留
        self.assertEqual(cache.get(key), ["i0", "i1", "i2"])


if __name__ == "__main__":
    unittest.main()
