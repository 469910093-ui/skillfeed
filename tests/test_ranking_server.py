"""服务端排序链路：埋点入库、CTR 汇总、限流、并档、会话内顺序稳定。"""

import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    import server.app as server_app
    from server.config import Settings
    HAS_SERVER = True
except ImportError:
    HAS_SERVER = False

from server.ratelimit import EventLimiter, SlidingWindow


class TestSlidingWindow(unittest.TestCase):
    def test_allows_up_to_limit_then_drops(self):
        w = SlidingWindow(window_s=60)
        self.assertEqual(w.check("k", 5, 3, now=0.0), 3)
        self.assertEqual(w.check("k", 5, 3, now=1.0), 2)
        self.assertEqual(w.check("k", 5, 3, now=2.0), 0)

    def test_window_slides(self):
        w = SlidingWindow(window_s=60)
        self.assertEqual(w.check("k", 2, 2, now=0.0), 2)
        self.assertEqual(w.check("k", 2, 2, now=10.0), 0)
        self.assertEqual(w.check("k", 2, 2, now=100.0), 2)

    def test_keys_are_independent(self):
        w = SlidingWindow(window_s=60)
        self.assertEqual(w.check("a", 1, 1, now=0.0), 1)
        self.assertEqual(w.check("b", 1, 1, now=0.0), 1)

    def test_device_limit_applies_under_shared_ip(self):
        limiter = EventLimiter({"ratelimit": {
            "window_s": 60, "max_events_per_ip": 100, "max_events_per_device": 3,
        }})
        self.assertEqual(limiter.allow(ip="1.1.1.1", device_id="d1", count=5), 3)
        # 同 IP 换设备仍有额度，不会被前一个设备连坐
        self.assertEqual(limiter.allow(ip="1.1.1.1", device_id="d2", count=2), 2)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestEventsAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.dev_mode = True
        s.dev_auth = True
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # official_feed_url 留空时服务端会退回读本地 publish-site 产物
        # （默认 ~/.skill-feed/site/feed.json）。指到临时目录里的不存在路径，
        # 否则这些测试会随「开发机上恰好有没有跑过 publish-site」时绿时红。
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 这里测的是排序/埋点链路，不是登录门禁；门禁默认是开的（V1 强制登录），
        # 所以要显式关掉。门禁本身的测试在 tests/test_server_api.py
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

    def _post(self, events, device="dev1", session="s1"):
        return self.client.post("/api/events", json={
            "device_id": device, "session_id": session, "events": events,
        })

    def test_requires_ids(self):
        r = self.client.post("/api/events", json={"events": []})
        self.assertEqual(r.status_code, 400)

    def test_impression_and_click_update_stats(self):
        r = self._post([
            {"action": "impression", "item_key": "a/b::SKILL.md",
             "position": 2, "client_ts": "t1"},
            {"action": "open_github", "item_key": "a/b::SKILL.md",
             "position": 2, "client_ts": "t2"},
        ])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["accepted"], 2)

        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            stats = ranking_service.load_item_stats(conn)
        self.assertEqual(stats["a/b::SKILL.md"].total_impressions, 1)
        self.assertEqual(stats["a/b::SKILL.md"].total_clicks, 1)

    def test_retry_does_not_double_count(self):
        """离线补报会重发同样的事件，client_ts 相同就必须去重，否则点击数被刷高。"""
        payload = [{"action": "open_github", "item_key": "a/b::SKILL.md",
                    "position": 0, "client_ts": "same-ts"}]
        self._post(payload)
        second = self._post(payload)
        self.assertEqual(second.json()["accepted"], 0)
        self.assertEqual(second.json()["deduped"], 1)

        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            stats = ranking_service.load_item_stats(conn)
        self.assertEqual(stats["a/b::SKILL.md"].total_clicks, 1)

    def test_fling_impression_never_reaches_stats(self):
        self._post([{"action": "impression", "item_key": "a/b::SKILL.md",
                     "position": 1, "dwell_ms": 80, "client_ts": "t"}])
        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            self.assertEqual(ranking_service.load_item_stats(conn), {})

    def test_not_interested_creates_scoped_suppression(self):
        self._post([{"action": "not_interested", "item_key": "a/b::SKILL.md",
                     "owner": "acme", "scene": "content", "scene_l2": "writing",
                     "scope": "owner", "client_ts": "t"}])
        from server import db
        with db.db_session(self.settings.db_path) as conn:
            rows = db.load_device_suppress(conn, "dev1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scope"], "owner")
        self.assertEqual(rows[0]["key"], "acme")

    def test_not_interested_without_scope_degrades_to_item(self):
        self._post([{"action": "not_interested", "item_key": "a/b::SKILL.md",
                     "owner": "acme", "scene": "content", "client_ts": "t"}])
        from server import db
        with db.db_session(self.settings.db_path) as conn:
            rows = db.load_device_suppress(conn, "dev1")
        self.assertEqual(rows[0]["scope"], "item")
        self.assertEqual(rows[0]["key"], "a/b::SKILL.md")

    def test_focus_set_is_full_overwrite(self):
        self._post([{"action": "focus_set", "client_ts": "t1", "focus": [
            {"dim": "scene", "key": "content"}, {"dim": "scene_l2", "key": "writing"},
        ]}])
        self._post([{"action": "focus_set", "client_ts": "t2", "focus": [
            {"dim": "scene", "key": "design"},
        ]}])
        from server import db
        with db.db_session(self.settings.db_path) as conn:
            focus = db.load_device_focus(conn, "dev1")
        self.assertEqual(focus, [("scene", "design")])

    def test_rate_limit_drops_silently(self):
        """超限返回 200：给刷的人 429 等于告诉他阈值在哪。"""
        self.app.state.event_limiter = EventLimiter({"ratelimit": {
            "window_s": 300, "max_events_per_ip": 2, "max_events_per_device": 2,
        }})
        events = [
            {"action": "impression", "item_key": f"a/b{n}::SKILL.md",
             "position": 1, "client_ts": f"t{n}"}
            for n in range(10)
        ]
        r = self._post(events)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["accepted"], 2)

        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            stats = ranking_service.load_item_stats(conn)
        self.assertEqual(len(stats), 2)

    def test_profile_reflects_behavior(self):
        self._post([
            {"action": "open_github", "item_key": "a/b::SKILL.md", "position": 1,
             "scene": "content", "scene_l2": "writing", "owner": "a", "client_ts": "t1"},
        ])
        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            prof = ranking_service.load_profile(conn, "dev1", config=self.app.state.ranking_config)
        self.assertGreater(prof.affinity["scene"]["content"][0], 0)
        self.assertIn("a/b::SKILL.md", prof.opened_items)

    def test_claim_merges_anonymous_profile(self):
        ra = self._post([{"action": "open_github", "item_key": "a/b::SKILL.md",
                          "scene": "content", "position": 1, "client_ts": "t1"}], device="devA")
        rb = self._post([{"action": "open_github", "item_key": "c/d::SKILL.md",
                          "scene": "design", "position": 1, "client_ts": "t2"}], device="devB")
        tok_a, tok_b = ra.json()["device_token"], rb.json()["device_token"]

        self.client.get("/auth/dev-login", follow_redirects=False)
        first = self.client.post(
            "/api/profile/claim", json={"device_id": "devA", "device_token": tok_a},
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertFalse(first.json()["merged"])

        second = self.client.post(
            "/api/profile/claim", json={"device_id": "devB", "device_token": tok_b},
        )
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["merged"])
        self.assertEqual(second.json()["primary"], "devA")

        # 并档幂等：重复调用不再改变归属
        again = self.client.post(
            "/api/profile/claim", json={"device_id": "devB", "device_token": tok_b},
        )
        self.assertEqual(again.json()["primary"], "devA")

        from server import db, ranking_service
        with db.db_session(self.settings.db_path) as conn:
            self.assertEqual(db.resolve_device(conn, "devB"), "devA")
            prof = ranking_service.load_profile(
                conn, "devB", config=self.app.state.ranking_config,
            )
        # 用旧 device_id 请求也应拿到并档后的画像
        self.assertIn("design", prof.affinity.get("scene", {}))
        self.assertIn("content", prof.affinity.get("scene", {}))

    def test_claim_requires_login(self):
        r = self.client.post("/api/profile/claim", json={"device_id": "devZ"})
        self.assertEqual(r.status_code, 401)

    def test_claim_rejects_foreign_device_id(self):
        """只校验登录态是不够的：知道别人的 device_id 就能并走他的匿名画像。"""
        victim = self._post(
            [{"action": "open_github", "item_key": "a/b::SKILL.md",
              "scene": "content", "position": 1, "client_ts": "v1"}],
            device="victim-device",
        )
        self.assertIn("device_token", victim.json())

        self.client.get("/auth/dev-login?login=attacker", follow_redirects=False)
        # 攻击者知道 device_id，但拿不到只在首次注册时下发过的凭据
        stolen = self.client.post(
            "/api/profile/claim", json={"device_id": "victim-device"},
        )
        self.assertEqual(stolen.status_code, 403)
        forged = self.client.post(
            "/api/profile/claim",
            json={"device_id": "victim-device", "device_token": "not-a-real-token"},
        )
        self.assertEqual(forged.status_code, 403)

        from server import db
        with db.db_session(self.settings.db_path) as conn:
            # 受害者设备没有被并走，仍然是独立的
            self.assertEqual(db.resolve_device(conn, "victim-device"), "victim-device")

    def test_device_token_is_issued_once(self):
        """凭据只在首次注册时返回。否则攻击者拿别人的 device_id 请求一次就能补领。"""
        first = self._post(
            [{"action": "impression", "item_key": "a/b::SKILL.md",
              "position": 1, "client_ts": "t1"}], device="once",
        )
        self.assertIn("device_token", first.json())
        second = self._post(
            [{"action": "impression", "item_key": "a/b::SKILL.md",
              "position": 2, "client_ts": "t2"}], device="once",
        )
        self.assertNotIn("device_token", second.json())

    def test_device_id_accepted_via_header(self):
        """query param 会进 access log 和 Referer，头部是首选通道。"""
        r = self.client.post(
            "/api/events",
            json={"session_id": "s1", "events": [
                {"action": "impression", "item_key": "h/x::SKILL.md",
                 "position": 1, "client_ts": "t"},
            ]},
            headers={"X-Device-Id": "hdr-device"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        from server import db
        with db.db_session(self.settings.db_path) as conn:
            rows = db.load_device_events(conn, "hdr-device")
        self.assertEqual(len(rows), 1)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestClientIpSpoofing(unittest.TestCase):
    """X-Forwarded-For 的首段是客户端写的，无条件信任等于把限流关掉。"""

    def _req(self, xff: str = "", peer: str = "203.0.113.9"):
        from starlette.requests import Request as StarletteRequest
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return StarletteRequest({
            "type": "http", "headers": headers, "client": (peer, 12345),
            "method": "GET", "path": "/", "scheme": "http",
            "query_string": b"", "server": ("t", 80),
        })

    NGINX = frozenset({"127.0.0.1"})

    def test_header_ignored_by_default(self):
        ip = server_app._client_ip(self._req("1.2.3.4"), trusted_hops=0)
        self.assertEqual(ip, "203.0.113.9")

    def test_hops_without_trusted_ips_is_inert(self):
        """只配跳数不配受信代理地址不生效：没有可信对端就判断不了是否走过代理。"""
        ip = server_app._client_ip(self._req("1.2.3.4"), trusted_hops=1, trusted_ips=None)
        self.assertEqual(ip, "203.0.113.9")

    def test_direct_connection_cannot_forge(self):
        """绕过 Nginx 直连应用端口时，对端不是受信代理，XFF 一律不认。"""
        ip = server_app._client_ip(
            self._req("1.2.3.4", peer="203.0.113.9"), trusted_hops=1,
            trusted_ips=self.NGINX,
        )
        self.assertEqual(ip, "203.0.113.9")

    def test_forged_prefix_cannot_change_bucket(self):
        """经 Nginx 时取右起第 1 跳，拿到的是 Nginx 实际看到的地址。"""
        chain = "9.9.9.9, 8.8.8.8, 198.51.100.7"
        ip = server_app._client_ip(
            self._req(chain, peer="127.0.0.1"), trusted_hops=1, trusted_ips=self.NGINX,
        )
        self.assertEqual(ip, "198.51.100.7")

    def test_attacker_cannot_rotate_buckets(self):
        """攻击者轮换伪造前缀，Nginx 追加的真实地址始终在最右边。"""
        seen = {
            server_app._client_ip(
                self._req(f"{n}.{n}.{n}.{n}, 198.51.100.7", peer="127.0.0.1"),
                trusted_hops=1, trusted_ips=self.NGINX,
            )
            for n in range(1, 20)
        }
        self.assertEqual(seen, {"198.51.100.7"})

    def test_two_proxy_layers(self):
        chain = "1.2.3.4, 198.51.100.7, 10.0.0.1"
        ip = server_app._client_ip(
            self._req(chain, peer="127.0.0.1"), trusted_hops=2, trusted_ips=self.NGINX,
        )
        self.assertEqual(ip, "198.51.100.7")

    def test_short_chain_falls_back_to_peer(self):
        """跳数不足说明请求没走完整代理链，不能拿伪造的那段当真。"""
        ip = server_app._client_ip(
            self._req("1.2.3.4", peer="127.0.0.1"), trusted_hops=2,
            trusted_ips=self.NGINX,
        )
        self.assertEqual(ip, "127.0.0.1")


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestFailClosedConfig(unittest.TestCase):
    def _settings(self, **kw):
        s = Settings()
        s.db_path = Path(tempfile.mkdtemp()) / "t.db"
        s.public_url = "http://testserver"
        s.github_client_id = ""
        s.github_client_secret = ""
        for k, v in kw.items():
            setattr(s, k, v)
        return s

    def test_missing_secret_refuses_to_boot(self):
        s = self._settings(session_secret="", dev_mode=False)
        with self.assertRaises(RuntimeError):
            server_app.create_app(s)

    def test_published_default_secret_is_rejected(self):
        """这个常量就在公开仓库里，用它等于任何人都能自签 cookie。"""
        s = self._settings(session_secret="dev-only-change-me", dev_mode=False)
        with self.assertRaises(RuntimeError):
            server_app.create_app(s)

    def test_dev_mode_generates_ephemeral_secret(self):
        import os
        os.environ["SKILLFEED_DEV"] = "1"
        try:
            s = Settings()
            self.assertEqual(s.session_secret_source, "ephemeral")
            self.assertTrue(s.session_secret)
            self.assertNotIn(s.session_secret, ["dev-only-change-me", ""])
        finally:
            os.environ.pop("SKILLFEED_DEV", None)

    def test_dev_auth_needs_both_switches(self):
        import os
        os.environ["SKILLFEED_DEV_AUTH"] = "1"
        os.environ.pop("SKILLFEED_DEV", None)
        try:
            # 只设 DEV_AUTH 不生效：漏配环境变量不该把站点变成点一下就登进去
            self.assertFalse(Settings().dev_auth)
        finally:
            os.environ.pop("SKILLFEED_DEV_AUTH", None)

    def test_dev_login_disabled_on_https(self):
        s = self._settings(
            session_secret="x", dev_mode=True, dev_auth=True,
            public_url="https://skillfeeder.example.com",
        )
        self.assertFalse(s.dev_login_allowed)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestAuthRoutesFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # official_feed_url 留空时服务端会退回读本地 publish-site 产物
        # （默认 ~/.skill-feed/site/feed.json）。指到临时目录里的不存在路径，
        # 否则这些测试会随「开发机上恰好有没有跑过 publish-site」时绿时红。
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 这里测的是排序/埋点链路，不是登录门禁；门禁默认是开的（V1 强制登录），
        # 所以要显式关掉。门禁本身的测试在 tests/test_server_api.py
        s.require_login = False
        s.github_client_id = ""
        s.github_client_secret = ""
        s.dev_mode = False       # 模拟生产：DEV 开关没开
        s.dev_auth = False
        self.settings = s
        self.client = TestClient(server_app.create_app(s))

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_github_login_does_not_downgrade_to_dev_login(self):
        """OAuth 没配时不能静默跳到无凭据登录——接微信登录改造期漏配就会踩这条。"""
        r = self.client.get("/auth/github", follow_redirects=False)
        self.assertEqual(r.status_code, 503)
        self.assertNotIn("dev-login", r.headers.get("location", ""))

    def test_dev_login_is_404_without_switches(self):
        r = self.client.get("/auth/dev-login", follow_redirects=False)
        self.assertEqual(r.status_code, 404)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestSecurityHeaders(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        s = Settings()
        s.db_path = Path(self.tmp.name) / "t.db"
        s.session_secret = "test-secret"
        s.public_url = "http://testserver"
        s.official_feed_url = ""
        # official_feed_url 留空时服务端会退回读本地 publish-site 产物
        # （默认 ~/.skill-feed/site/feed.json）。指到临时目录里的不存在路径，
        # 否则这些测试会随「开发机上恰好有没有跑过 publish-site」时绿时红。
        s.official_feed_file = s.db_path.parent / "no-such-feed.json"
        s.site_dir = s.db_path.parent / "no-such-site"
        # 这里测的是排序/埋点链路，不是登录门禁；门禁默认是开的（V1 强制登录），
        # 所以要显式关掉。门禁本身的测试在 tests/test_server_api.py
        s.require_login = False
        self.client = TestClient(server_app.create_app(s))

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_html_pages_get_nonce_csp_and_still_render(self):
        for path in ("/", "/publish"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            csp = r.headers["content-security-policy"]
            self.assertIn("script-src 'self' 'nonce-", csp)
            self.assertIn("object-src 'none'", csp)
            # 模板占位符必须被替换掉，否则页面上会留下裸的 {{csp_nonce}}
            self.assertNotIn("{{csp_nonce}}", r.text)

    def test_inline_script_carries_the_same_nonce(self):
        r = self.client.get("/publish")
        csp = r.headers["content-security-policy"]
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">', r.text)

    def test_nonce_differs_per_response(self):
        a = self.client.get("/publish").headers["content-security-policy"]
        b = self.client.get("/publish").headers["content-security-policy"]
        self.assertNotEqual(a, b)

    def test_inline_style_attributes_are_not_broken(self):
        """模板里有 style="display:none"，nonce 覆盖不到 style 属性，
        所以 style-src 必须保留 unsafe-inline，否则页面直接白屏。"""
        csp = self.client.get("/publish").headers["content-security-policy"]
        self.assertIn("style-src", csp)
        self.assertIn("'unsafe-inline'", csp.split("style-src")[1].split(";")[0])
        html = self.client.get("/publish").text
        self.assertNotIn('style="display:none"', html)
        self.assertIn('id="okBanner"', html)
        self.assertIn("hide", html)

    def test_api_responses_get_locked_down_csp(self):
        r = self.client.get("/health")
        self.assertEqual(r.headers["content-security-policy"], server_app.CSP_API)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["referrer-policy"], "no-referrer")


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestSessionOrder(unittest.TestCase):
    def test_cache_keeps_order_within_session(self):
        from server.ranking_service import SessionOrderCache, apply_cached_order
        cache = SessionOrderCache(ttl_s=100)
        cache.put("k", ["c", "a", "b"], now=0.0)
        self.assertEqual(cache.get("k", now=1.0), ["c", "a", "b"])
        items = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        self.assertEqual(
            [i["id"] for i in apply_cached_order(items, ["c", "a", "b"])],
            ["c", "a", "b"],
        )

    def test_expired_entry_is_dropped(self):
        from server.ranking_service import SessionOrderCache
        cache = SessionOrderCache(ttl_s=10)
        cache.put("k", ["a"], now=0.0)
        self.assertIsNone(cache.get("k", now=50.0))

    def test_new_items_go_to_the_tail_not_lost(self):
        from server.ranking_service import apply_cached_order
        items = [{"id": "a"}, {"id": "b"}, {"id": "fresh"}]
        out = apply_cached_order(items, ["b", "a"])
        self.assertEqual([i["id"] for i in out], ["b", "a", "fresh"])

    def test_filter_signature_changes_with_query(self):
        from server.ranking_service import filter_signature
        self.assertNotEqual(filter_signature(q="figma"), filter_signature(q=""))
        self.assertEqual(filter_signature(q="figma"), filter_signature(q="figma"))


if __name__ == "__main__":
    unittest.main()
