"""服务端 API：登录门禁、微信登录、手机号验证码、UGC 发布。

这些测试的取向是**证明安全行为存在**，不是覆盖 happy path。写断言时的自查：
把被测的那道防护删掉，这条测试会不会红？不会红的就不是在测防护。

出网调用（微信换 token / 拿用户信息、短信网关）全部 mock 到模块级函数上，
CI 不需要真凭据，也不会真发短信。
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# 可选依赖：未安装 fastapi 时跳过
try:
    from fastapi.testclient import TestClient
    import server.app as server_app
    from server import auth, db, sms
    from server.config import Settings
    HAS_SERVER = True
except ImportError:
    HAS_SERVER = False

from server.ratelimit import SmsLimiter


def _settings(tmpdir: str, **over) -> "Settings":
    s = Settings()
    s.db_path = Path(tmpdir) / "t.db"
    s.backup_dir = Path(tmpdir) / "backups"
    s.backup_keep = 3
    s.session_secret = "test-secret"
    s.public_url = "http://testserver"
    s.github_client_id = ""
    s.github_client_secret = ""
    s.official_feed_url = ""
    # 隔离：留空 URL 时服务端会退回读本地 publish-site 产物
    s.official_feed_file = Path(tmpdir) / "no-such-feed.json"
    s.site_dir = Path(tmpdir) / "no-such-site"
    s.dev_mode = False
    s.dev_auth = False
    s.require_login = True
    s.operator_logins = frozenset()
    s.submit_per_day = 3
    s.free_daily_feed_items = 8
    s.subscriber_days = 365
    s.activation_codes = frozenset()
    s.sku_year_fen = 9900
    s.wechat_pay_mchid = ""
    s.wechat_pay_api_v3_key = ""
    s.wechat_pay_serial = ""
    for k, v in over.items():
        setattr(s, k, v)
    return s


# —— 登录门禁 ——

@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestLoginGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(self.tmp.name)
        self.client = TestClient(
            server_app.create_app(self.settings), follow_redirects=False,
        )

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_anonymous_home_redirects_to_login(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/login")
        # 前端用 redirect:"manual" 时靠这个头判断，不用去 parse Location
        self.assertEqual(r.headers.get("x-login-required"), "1")

    def test_anonymous_api_is_also_redirected_not_200(self):
        """/api/* 未登录也是 302（产品口径），关键是**绝不能**返回数据。"""
        for path in ("/api/posts/me", "/feed.json", "/api/stats/items",
                     "/api/pay/create", "/api/pay/orders"):
            with self.subTest(path=path):
                r = self.client.get(path) if path != "/api/pay/create" else self.client.post(path, json={})
                self.assertEqual(r.status_code, 302, path)
                self.assertTrue(r.headers["location"].startswith("/login"))

    def test_wechat_pay_notify_is_public_but_does_not_grant(self):
        """回调必须免登录，否则微信服务器会被 302 到登录页。未配置时不能开通。"""
        r = self.client.post("/api/pay/wechat/notify", content=b"{}")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["code"], "FAIL")
        self.assertNotIn("SUCCESS", r.text)

    def test_redirect_carries_next_target(self):
        r = self.client.get("/api/posts/me?limit=5")
        self.assertEqual(r.status_code, 302)
        self.assertIn("next=", r.headers["location"])
        self.assertIn("limit%3D5", r.headers["location"])

    def test_anonymous_feed_is_public_but_only_approved(self):
        """发现流全量免费：未登录也能拉混排，但看不到 pending。"""
        r = self.client.get("/api/feed?source=ugc&limit=5")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("items", data)
        self.assertIsInstance(data["items"], list)
        for item in data["items"]:
            self.assertNotEqual(item.get("status"), "pending")

    def test_exempt_paths_are_not_gated(self):
        """豁免路径必须真的不被拦，否则登录页自己会无限重定向。"""
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/api/feed").status_code, 200)
        self.assertEqual(self.client.get("/api/site-config").status_code, 200)
        posted = self.client.post("/api/events", json={
            "device_id": "web-anon", "session_id": "s-anon",
            "events": [{"action": "session_start", "client_ts": "boot1"}],
        })
        self.assertEqual(posted.status_code, 200, posted.text)
        self.assertGreaterEqual(posted.json().get("accepted", 0), 1)
        # /auth/me 免登录返回 200 + user:null，前端靠它判断登录态
        me = self.client.get("/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertIsNone(me.json()["user"])

    def test_gate_is_default_deny_for_new_routes(self):
        """新增路由忘了登记豁免时，应该落到「需要登录」。

        直接往 app 上挂一个没在豁免表里的路径，它必须被拦。
        这条就是「默认拒绝」这个设计的回归测试：哪天有人把中间件改成
        黑名单式（列出要拦的路径），这里会立刻变红。
        """
        app = server_app.create_app(_settings(self.tmp.name))

        @app.get("/brand-new-route-nobody-registered")
        def _new():  # pragma: no cover - 只需要它存在
            return {"secret": "leaked"}

        client = TestClient(app, follow_redirects=False)
        r = client.get("/brand-new-route-nobody-registered")
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("leaked", r.text)

    def test_docs_are_gated(self):
        """/docs 和 /openapi.json 也在门禁后面：接口清单不对未登录者公开。"""
        for path in ("/docs", "/openapi.json"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 302)

    def test_gate_off_lets_anonymous_through(self):
        """REQUIRE_LOGIN=0 时不拦 —— 也就是说上面那些 302 真的来自门禁。"""
        app = server_app.create_app(_settings(self.tmp.name, require_login=False))
        client = TestClient(app, follow_redirects=False)
        self.assertEqual(client.get("/").status_code, 200)

    def test_require_login_defaults_on(self):
        """默认值必须是「开」：漏配环境变量的后果应该是更严，不是门禁消失。"""
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("SKILLFEED_REQUIRE_LOGIN", None)
            self.assertTrue(Settings().require_login)

    def test_safe_next_rejects_open_redirect(self):
        for bad in (
            "https://evil.example/x", "//evil.example/x", "/\\evil.example",
            "/x\r\nSet-Cookie: a=b", '/x"><script>', "", "javascript:alert(1)",
        ):
            with self.subTest(bad=bad):
                self.assertEqual(server_app._safe_next(bad), "/")
        self.assertEqual(server_app._safe_next("/api/feed?q=a"), "/api/feed?q=a")

    def test_login_page_does_not_leak_credentials(self):
        s = _settings(
            self.tmp.name,
            wechat_app_id="wxAPPID123", wechat_app_secret="TOP-SECRET-APPSECRET",
            sms_access_key_secret="TOP-SECRET-AK",
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        body = client.get("/login").text
        self.assertNotIn("TOP-SECRET-APPSECRET", body)
        self.assertNotIn("TOP-SECRET-AK", body)
        # AppID 也不下发：微信跳转是服务端在 /auth/wechat 里拼的
        self.assertNotIn("wxAPPID123", body)

    def test_login_page_hides_github_by_default(self):
        """2.13：GitHub 降为可选绑定，默认不给入口，但路由必须还在。"""
        s = _settings(
            self.tmp.name, github_client_id="cid", github_client_secret="csec",
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        self.assertIn('id="githubBlock" class="hide"', client.get("/login").text)
        self.assertIn('{{github_enabled}}', "" .join(["{{github_enabled}}"]))
        # 路由没被删：配置打开时应能发起。必须是 200 中转页而不是 302——
        # 手机 WebView 会丢掉 302 上的 Set-Cookie，回调变成 bad oauth state。
        s2 = _settings(
            self.tmp.name, github_client_id="cid", github_client_secret="csec",
        )
        c2 = TestClient(server_app.create_app(s2), follow_redirects=False)
        start = c2.get("/auth/github")
        self.assertEqual(start.status_code, 200)
        self.assertIn("github.com/login/oauth/authorize", start.text)
        self.assertTrue(c2.cookies.get(auth.STATE_COOKIE["github"]))
        self.assertNotIn("TOP-SECRET", start.text)

    def test_login_page_github_primary_when_only_live_method(self):
        """生产未接通微信/短信时，登录页必须把 GitHub 当主按钮，并写明内置浏览器走不通。"""
        s = _settings(
            self.tmp.name,
            github_client_id="cid", github_client_secret="csec",
            github_login_visible=True,
        )
        body = TestClient(server_app.create_app(s), follow_redirects=False).get("/login").text
        self.assertIn("使用 GitHub 登录", body)
        self.assertIn("onlyGithubHint", body)
        self.assertIn("内置浏览器", body)
        self.assertIn("Safari", body)
        self.assertIn("micromessenger", body)

    def test_health_reports_switches_not_secrets(self):
        s = _settings(
            self.tmp.name,
            wechat_app_id="wxid", wechat_app_secret="sekrit",
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        data = client.get("/health").json()
        self.assertTrue(data["wechat"])
        self.assertTrue(data["require_login"])
        self.assertNotIn("sekrit", client.get("/health").text)

    def test_settings_repr_redacts_secrets(self):
        s = _settings(self.tmp.name, wechat_app_secret="sekrit", sms_access_key_secret="ak")
        self.assertNotIn("sekrit", repr(s))
        self.assertNotIn("ak", repr(s))


# —— 微信网页授权 ——

@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestWechatLogin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(
            self.tmp.name, wechat_app_id="wx-app-id", wechat_app_secret="wx-secret",
        )
        self.client = TestClient(
            server_app.create_app(self.settings), follow_redirects=False,
        )

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def _start(self, next_path: str = "/") -> str:
        r = self.client.get(f"/auth/wechat?next={next_path}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("open.weixin.qq.com", r.text)
        self.assertIn("appid=wx-app-id", r.text)
        self.assertIn("#wechat_redirect", r.text)
        # state 由服务端签发并落在 HttpOnly cookie 里
        state = self.client.cookies.get(auth.STATE_COOKIE["wechat"])
        self.assertTrue(state)
        return state

    def _fake_wechat(self, openid="oPENID-1", unionid="", nickname="小明"):
        async def _token(settings, code):
            self.assertEqual(code, "the-code")
            return {"access_token": "at", "openid": openid, "unionid": unionid}

        async def _info(settings, access_token, oid):
            return {"openid": oid, "nickname": nickname, "headimgurl": "https://x/y.png",
                    "unionid": unionid}

        return (
            mock.patch.object(auth, "exchange_wechat_code", _token),
            mock.patch.object(auth, "fetch_wechat_userinfo", _info),
        )

    def test_secret_never_appears_in_redirect(self):
        r = self.client.get("/auth/wechat")
        self.assertNotIn("wx-secret", r.headers.get("location", ""))
        self.assertNotIn("wx-secret", r.text)

    def test_callback_creates_user_and_session(self):
        state = self._start("/api/posts/me")
        p1, p2 = self._fake_wechat(nickname="小明")
        with p1, p2:
            r = self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/api/posts/me")

        me = self.client.get("/auth/me").json()
        self.assertIsNotNone(me["user"])
        self.assertEqual(me["user"]["display_name"], "小明")
        self.assertEqual(me["user"]["providers"], ["wechat"])
        # openid / unionid 不出现在公开用户对象里
        self.assertNotIn("wechat_openid", me["user"])
        self.assertNotIn("oPENID-1", self.client.get("/auth/me").text)

    def test_callback_rejects_forged_state(self):
        """state 必须服务端校验。回传一个自造的值要被拒。"""
        self._start()
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get("/auth/wechat/callback?code=the-code&state=i-made-this-up")
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])

    def test_callback_rejects_when_state_cookie_missing(self):
        """签名合法但没有 cookie → 拒。这条挡的是登录 CSRF：

        攻击者在自己浏览器里走完授权拿到 (code, state)，把回调链接发给受害者，
        受害者点开就被登成攻击者的账号。cookie 只存在于发起流程的浏览器里。
        """
        state = self._start()
        self.client.cookies.delete(auth.STATE_COOKIE["wechat"])
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        self.assertEqual(r.status_code, 400)

    def test_callback_rejects_state_not_matching_the_cookie(self):
        """签名合法、cookie 也存在，但两者是**不同的两次**流程 → 必须拒。

        这才是登录 CSRF 的真实形态：攻击者自己走一遍授权，拿到一个由我们
        正常签发的 (code, state_A)，把回调链接发给受害者；受害者浏览器里
        有他自己那次流程的 state_B。只验签名不比 cookie 的话，state_A 签名
        完全合法，受害者一点就被登成攻击者的账号。
        """
        victim_state = self._start()          # 受害者浏览器里的 cookie
        attacker_state = auth.issue_state(self.settings, "wechat")  # 攻击者手里的
        self.assertNotEqual(victim_state, attacker_state)
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get(
                f"/auth/wechat/callback?code=the-code&state={attacker_state}",
            )
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])

    def test_callback_rejects_state_signed_with_other_secret(self):
        """cookie 和 query 一致但签名不是我们的 → 拒。

        少了签名校验，攻击者自造 state 并同时塞一个同值 cookie（他自己的浏览器，
        cookie 当然由他控制）就能绕过纯 cookie 比对。
        """
        other = _settings(self.tmp.name, session_secret="someone-elses-secret",
                          wechat_app_id="a", wechat_app_secret="b")
        forged = auth.issue_state(other, "wechat")
        self.client.cookies.set(auth.STATE_COOKIE["wechat"], forged)
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get(f"/auth/wechat/callback?code=the-code&state={forged}")
        self.assertEqual(r.status_code, 400)

    def test_state_is_bound_to_purpose(self):
        """github 用途的 state 不能拿去过微信回调，反之亦然。"""
        gh_state = auth.issue_state(self.settings, "github")
        self.assertFalse(auth.verify_state(self.settings, "wechat", gh_state, gh_state))
        self.assertTrue(auth.verify_state(self.settings, "github", gh_state, gh_state))

    def test_state_expires(self):
        """过期的 state 不能再用。

        issue_state 的 TTL 有 `max(30, ...)` 下限（防止误配成 0 让登录永远失败），
        所以不能靠把 TTL 设成负数来造过期件，得把时钟往前拨。
        """
        s = _settings(self.tmp.name, oauth_state_ttl_s=60)
        with mock.patch("server.auth.time.time", return_value=1_000_000.0):
            state = auth.issue_state(s, "wechat")
            self.assertTrue(auth.verify_state(s, "wechat", state, state))
        with mock.patch("server.auth.time.time", return_value=1_000_000.0 + 3600):
            self.assertFalse(auth.verify_state(s, "wechat", state, state))

    def test_session_cookie_flags(self):
        """SameSite 必须是 Lax 而不是 Strict。

        微信回调是**跨站顶层 GET 导航**回到本站的，Strict 在那一跳不发 cookie，
        state cookie 读不到 → 每次微信登录都 400。宣发来自小红书/抖音的站外
        点击同理，Strict 会让已登录用户在落地页表现为未登录。
        """
        state = self._start()
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        raw = r.headers.get("set-cookie", "")
        self.assertIn("skillfeed_session=", raw)
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=lax", raw.replace("SameSite=Lax", "SameSite=lax"))
        self.assertNotIn("strict", raw.lower())

    def test_secure_flag_follows_https_public_url(self):
        s = _settings(self.tmp.name, public_url="https://skillfeeder.cn",
                      wechat_app_id="a", wechat_app_secret="b")
        self.assertTrue(auth.cookie_flags(s)["secure"])
        self.assertEqual(auth.cookie_flags(s)["samesite"], "lax")

    def test_unconfigured_wechat_is_503_not_silent_downgrade(self):
        client = TestClient(
            server_app.create_app(_settings(self.tmp.name)), follow_redirects=False,
        )
        self.assertEqual(client.get("/auth/wechat").status_code, 503)

    def test_unionid_wins_over_openid_for_identity(self):
        """同一个人从第二个入口进来（openid 不同、unionid 相同）不该开新账号。"""
        state = self._start()
        p1, p2 = self._fake_wechat(openid="openid-A", unionid="UNION-1")
        with p1, p2:
            self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        first = self.client.get("/auth/me").json()["user"]["id"]

        self.client.post("/auth/logout")
        state = self._start()
        p1, p2 = self._fake_wechat(openid="openid-B", unionid="UNION-1")
        with p1, p2:
            self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        self.assertEqual(self.client.get("/auth/me").json()["user"]["id"], first)


# —— 手机号验证码 ——

@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestSmsLogin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(
            self.tmp.name,
            dev_mode=True, sms_provider="console",
            sms_resend_cooldown_s=0,  # 逐条断言重发限流的用例自己开回来
        )
        self.app = server_app.create_app(self.settings)
        self.client = TestClient(self.app, follow_redirects=False)
        self.sent: list[tuple[str, str]] = []

        async def _fake_send(settings, phone, code):
            self.sent.append((phone, code))
            return {"ok": True, "provider": "test"}

        self.patch = mock.patch.object(sms, "send_code", _fake_send)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def _send(self, phone="13800138000"):
        return self.client.post("/auth/sms/send", json={"phone": phone})

    def test_send_then_verify_logs_in(self):
        r = self._send()
        self.assertEqual(r.status_code, 200, r.text)
        phone, code = self.sent[-1]
        v = self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
        self.assertEqual(v.status_code, 200, v.text)
        me = self.client.get("/auth/me").json()
        self.assertIsNotNone(me["user"])
        self.assertEqual(me["user"]["providers"], ["phone"])
        # 手机号只以掩码形式回给前端
        self.assertEqual(me["user"]["phone_masked"], "138****8000")
        self.assertNotIn("13800138000", self.client.get("/auth/me").text)

    def test_send_response_never_contains_the_code(self):
        r = self._send()
        _, code = self.sent[-1]
        self.assertNotIn(code, r.text)

    def test_code_is_not_stored_in_plaintext(self):
        self._send()
        _, code = self.sent[-1]
        conn = sqlite3.connect(str(self.settings.db_path))
        try:
            rows = conn.execute("SELECT phone, code_hash FROM sms_codes").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertNotIn(code, rows[0][1])
        # 摘要要真的是那个码的摘要（否则「不含明文」可以靠存垃圾骗过）
        self.assertEqual(
            rows[0][1],
            auth.hash_sms_code(self.settings.session_secret, "13800138000", code),
        )

    def test_code_hash_needs_the_server_secret(self):
        """裸 sha256 的 6 位码等于明文（100 万种取值毫秒级枚举完）。

        换个密钥算出来的摘要必须不同，才说明摘要真的绑定了服务端密钥。
        """
        a = auth.hash_sms_code("secret-a", "13800138000", "123456")
        b = auth.hash_sms_code("secret-b", "13800138000", "123456")
        self.assertNotEqual(a, b)

    def test_code_is_single_use(self):
        self._send()
        phone, code = self.sent[-1]
        self.assertEqual(
            self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
            .status_code, 200,
        )
        self.client.post("/auth/logout")
        again = self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
        self.assertEqual(again.status_code, 400)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])

    def test_code_expires(self):
        """过期的验证码不能用。

        put_sms_code 的 TTL 有 `max(1, ...)` 下限，所以造过期件的方式是
        直接把库里的 expires_at 改到过去，而不是把 TTL 设成负数。
        """
        self._send("13800138001")
        phone, code = self.sent[-1]
        conn = sqlite3.connect(str(self.settings.db_path))
        try:
            conn.execute(
                "UPDATE sms_codes SET expires_at=? WHERE phone=?",
                ("2020-01-01T00:00:00+00:00", phone),
            )
            conn.commit()
        finally:
            conn.close()
        r = self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
        self.assertEqual(r.status_code, 400)
        self.assertIn("过期", r.json()["detail"])
        # 过期的行要被清掉，不能留在库里等着被下一次尝试碰上
        self.assertIsNone(self.client.get("/auth/me").json()["user"])

    def test_wrong_code_attempts_are_capped(self):
        """失败计数必须真的落库、真的封顶。

        这条同时是「不要在 db_session 里抛异常」的回归测试：那样 rollback 会把
        attempts+1 一起回滚掉，验证码就变成可以无限次猜。
        """
        self._send()
        phone, code = self.sent[-1]
        wrong = "000000" if code != "000000" else "111111"
        codes = []
        for _ in range(self.settings.sms_max_attempts):
            codes.append(self.client.post(
                "/auth/sms/verify", json={"phone": phone, "code": wrong},
            ).status_code)
        # 前几次是 400（码不对），第 N 次触顶后码被作废
        self.assertTrue(all(c in (400, 429) for c in codes), codes)
        # 触顶后连**正确**的码也不再能用 —— 说明是作废了而不是只在文案上拒绝
        final = self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
        self.assertIn(final.status_code, (400, 429))
        self.assertIsNone(self.client.get("/auth/me").json()["user"])
        # 触顶就删行，不是「留着但每次拒」：留着的话调高 sms_max_attempts
        # 或者任何一处判断被改坏，这个码就又活了
        conn = sqlite3.connect(str(self.settings.db_path))
        try:
            left = conn.execute(
                "SELECT COUNT(*) FROM sms_codes WHERE phone=?", (phone,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(left, 0)

    def test_stale_row_over_attempt_cap_is_rejected_and_dropped(self):
        """库里已经超过尝试上限的行，即使码是对的也要被拒并作废。

        这条覆盖的是校验入口那道**前置**检查（而不是「猜错后 +1 再看是否触顶」
        那道）。两道都要在：调低 sms_max_attempts 之后，库里存量的高 attempts
        行必须立刻失效，而不是等它再被猜一次才作废。
        """
        self._send("13800138777")
        phone, code = self.sent[-1]
        conn = sqlite3.connect(str(self.settings.db_path))
        try:
            conn.execute(
                "UPDATE sms_codes SET attempts=? WHERE phone=?",
                (self.settings.sms_max_attempts + 3, phone),
            )
            conn.commit()
        finally:
            conn.close()
        r = self.client.post("/auth/sms/verify", json={"phone": phone, "code": code})
        self.assertEqual(r.status_code, 429)
        self.assertIsNone(self.client.get("/auth/me").json()["user"])
        # 作废了：把 attempts 复位也没用，行已经不在了
        conn = sqlite3.connect(str(self.settings.db_path))
        try:
            left = conn.execute(
                "SELECT COUNT(*) FROM sms_codes WHERE phone=?", (phone,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(left, 0)

    def test_resend_cooldown_is_enforced_and_survives_restart(self):
        s = _settings(
            self.tmp.name, dev_mode=True, sms_provider="console",
            sms_resend_cooldown_s=600,
        )
        c1 = TestClient(server_app.create_app(s), follow_redirects=False)
        self.assertEqual(c1.post("/auth/sms/send", json={"phone": "13800138002"}).status_code, 200)
        self.assertEqual(c1.post("/auth/sms/send", json={"phone": "13800138002"}).status_code, 429)
        # 换一个 app 实例 = 进程重启：滑动窗口清零了，但库里的冷却还在
        c2 = TestClient(server_app.create_app(s), follow_redirects=False)
        self.assertEqual(c2.post("/auth/sms/send", json={"phone": "13800138002"}).status_code, 429)

    def test_per_phone_ratelimit_rejects(self):
        s = _settings(
            self.tmp.name, dev_mode=True, sms_provider="console",
            sms_resend_cooldown_s=0, sms_max_per_phone=3, sms_max_per_ip=1000,
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        got = [
            client.post("/auth/sms/send", json={"phone": "13800138003"}).status_code
            for _ in range(5)
        ]
        self.assertEqual(got[:3], [200, 200, 200])
        self.assertEqual(got[3:], [429, 429])
        # 超限的那两次没有真的调网关
        self.assertEqual(len([p for p, _ in self.sent if p == "13800138003"]), 3)

    def test_per_ip_ratelimit_rejects_across_phones(self):
        """换手机号绕过「同号限频」的批量烧钱，要由 IP 那道挡住。"""
        s = _settings(
            self.tmp.name, dev_mode=True, sms_provider="console",
            sms_resend_cooldown_s=0, sms_max_per_phone=1000, sms_max_per_ip=2,
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        got = [
            client.post("/auth/sms/send", json={"phone": f"1380013900{i}"}).status_code
            for i in range(4)
        ]
        self.assertEqual(got, [200, 200, 429, 429])

    def test_verify_ratelimit_rejects_bruteforce_across_phones(self):
        s = _settings(
            self.tmp.name, dev_mode=True, sms_provider="console",
            sms_max_verify_per_ip=3,
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        got = [
            client.post(
                "/auth/sms/verify", json={"phone": f"1380014000{i}", "code": "123456"},
            ).status_code
            for i in range(5)
        ]
        self.assertEqual(got[-2:], [429, 429])

    def test_bad_phone_never_reaches_gateway(self):
        """格式校验在花钱之前：不校验的话任意字符串都会被送去短信网关。"""
        for bad in ("", "12345", "23800138000", "1380013800a", "+8613800138000x"):
            with self.subTest(bad=bad):
                r = self._send(bad)
                self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(self.sent, [])

    def test_phone_normalization(self):
        self.assertEqual(auth.normalize_phone("+86 138 0013 8000"), "13800138000")
        self.assertEqual(auth.normalize_phone("008613800138000"), "13800138000")
        self.assertEqual(auth.normalize_phone("13800138000"), "13800138000")
        self.assertEqual(auth.normalize_phone("12800138000"), "")

    def test_unconfigured_sms_is_503(self):
        """未配置通道时不能静默降级成「把验证码打到日志」。"""
        client = TestClient(
            server_app.create_app(_settings(self.tmp.name)), follow_redirects=False,
        )
        r = client.post("/auth/sms/send", json={"phone": "13800138000"})
        self.assertEqual(r.status_code, 503)

    def test_console_provider_refuses_outside_dev(self):
        s = _settings(self.tmp.name, dev_mode=False, sms_provider="console")
        self.assertFalse(s.sms_configured)
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        self.assertEqual(
            client.post("/auth/sms/send", json={"phone": "13800138000"}).status_code, 503,
        )

    def test_generated_code_is_six_digits(self):
        codes = {auth.new_sms_code() for _ in range(200)}
        self.assertTrue(all(len(c) == 6 and c.isdigit() for c in codes))
        # CSPRNG 出来的 200 个码不该大量重复
        self.assertGreater(len(codes), 150)


class TestSmsLimiterUnit(unittest.TestCase):
    def test_phone_bucket_does_not_consume_ip_bucket(self):
        lim = SmsLimiter(window_s=60, max_per_phone=1, max_per_ip=5)
        self.assertEqual(lim.allow_send(phone="p1", ip="i1"), "")
        self.assertEqual(lim.allow_send(phone="p1", ip="i1"), "phone")
        # 被轰炸的号码把自己的桶打满，不该把同 IP 的其他人一起限死
        self.assertEqual(lim.allow_send(phone="p2", ip="i1"), "")

    def test_ip_bucket_catches_phone_rotation(self):
        lim = SmsLimiter(window_s=60, max_per_phone=99, max_per_ip=2)
        self.assertEqual(lim.allow_send(phone="a", ip="i"), "")
        self.assertEqual(lim.allow_send(phone="b", ip="i"), "")
        self.assertEqual(lim.allow_send(phone="c", ip="i"), "ip")


# —— 数据迁移 ——

@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestUserSchemaMigration(unittest.TestCase):
    """老库（github_id NOT NULL UNIQUE、没有微信列）要能原地抬到新形状。

    一改就把现存用户读不出来是这次改动最现实的风险：users 有 posts / reactions
    两张子表指着它，而 SQLite 只能靠「建新表 + 搬数据 + 改名」来摘 NOT NULL。
    """

    OLD_SCHEMA = """
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      github_id INTEGER NOT NULL UNIQUE,
      login TEXT NOT NULL,
      avatar_url TEXT,
      name TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body_md TEXT NOT NULL,
      description TEXT,
      github_url TEXT,
      full_name TEXT,
      scene TEXT, scene_l2 TEXT, scene_label TEXT, scene_l2_label TEXT,
      cover_url TEXT,
      status TEXT NOT NULL DEFAULT 'published',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(author_id) REFERENCES users(id)
    );
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "old.db"
        conn = sqlite3.connect(str(self.db))
        conn.executescript(self.OLD_SCHEMA)
        conn.execute(
            "INSERT INTO users (id, github_id, login, avatar_url, name, created_at) "
            "VALUES (7, 4242, 'legacy-user', 'https://a/b.png', 'Legacy', '2026-01-01T00:00:00+00:00')",
        )
        conn.execute(
            "INSERT INTO posts (id, author_id, title, body_md, description, github_url, "
            "full_name, scene, scene_l2, scene_label, scene_l2_label, cover_url, status, "
            "created_at, updated_at) VALUES "
            "(1, 7, 'old post', 'body', 'desc', '', 'a/b', 'other', '', '其他', '', '', "
            "'published', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_existing_user_and_posts_survive(self):
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            user = db.get_user(conn, 7)
            self.assertIsNotNone(user)
            self.assertEqual(user["login"], "legacy-user")
            self.assertEqual(user["github_id"], 4242)
            # 新列存在且是 NULL（不是 ''，否则部分唯一索引会把它们判成重复）
            self.assertIsNone(user["wechat_openid"])
            self.assertIsNone(user["phone"])
            # 子表的外键指向没断
            post = db.get_post(conn, 1)
            self.assertEqual(post["author_login"], "legacy-user")

    def test_github_id_is_optional_after_migration(self):
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            u = db.upsert_wechat_user(conn, openid="ox1", nickname="微信用户")
            self.assertIsNone(u["github_id"])
            v = db.upsert_phone_user(conn, phone="13800138000")
            self.assertIsNone(v["github_id"])
            self.assertNotEqual(u["id"], v["id"])

    def test_migration_is_idempotent(self):
        db.init_db(self.db)
        db.init_db(self.db)
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1,
            )

    def test_duplicate_wechat_openid_is_rejected(self):
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            db.upsert_wechat_user(conn, openid="same")
        with self.assertRaises(sqlite3.IntegrityError):
            with db.db_session(self.db) as conn:
                conn.execute(
                    "INSERT INTO users (wechat_openid, login, created_at) VALUES (?,?,?)",
                    ("same", "dup", "2026-01-01T00:00:00+00:00"),
                )

    def test_many_users_without_identity_columns_coexist(self):
        """部分唯一索引的意义：一堆 NULL 身份列不能互相冲突。"""
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            for i in range(3):
                conn.execute(
                    "INSERT INTO users (login, created_at) VALUES (?,?)",
                    (f"anon-{i}", "2026-01-01T00:00:00+00:00"),
                )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 4,
            )

    def test_synthetic_login_does_not_leak_identifier(self):
        db.init_db(self.db)
        with db.db_session(self.db) as conn:
            u = db.upsert_wechat_user(conn, openid="oVeryPrivateOpenId")
            p = db.upsert_phone_user(conn, phone="13900139000")
        # login 会作为 author_login 出现在公开 Feed 里，不能夹带 openid / 手机号
        self.assertNotIn("VeryPrivateOpenId", u["login"])
        self.assertNotIn("13900139000", p["login"])
        self.assertNotIn("9000", p["login"])


# —— UGC（既有行为的回归）——

@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestServerAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # 无凭据登录现在是 fail-closed 的：必须同时显式打开 dev_mode 和 dev_auth，
        # 缺任一即 404。这里两个都设，正是为了证明它需要刻意开启
        self.settings = _settings(
            self.tmp.name, dev_mode=True, dev_auth=True,
            operator_logins=frozenset({"dev-user"}),
        )
        self.app = server_app.create_app(self.settings)
        self.client = TestClient(self.app)

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_health_and_dev_login_publish_feed(self):
        h = self.client.get("/health")
        self.assertEqual(h.status_code, 200)
        self.assertTrue(h.json()["dev_auth"])

        r = self.client.get("/auth/dev-login", follow_redirects=False)
        self.assertIn(r.status_code, (302, 303))

        me = self.client.get("/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["user"]["login"], "dev-user")
        self.assertEqual(me.json()["user"]["plan"], "free")
        self.assertEqual(me.json()["user"]["trust_level"], "new")
        self.assertEqual(me.json()["user"]["approved_count"], 0)
        self.assertFalse(me.json()["user"]["subscriber"])
        self.assertTrue(me.json()["quota"]["unlimited"])
        self.assertIsNone(me.json()["quota"]["limit"])

        page = self.client.get("/publish")
        self.assertEqual(page.status_code, 200)
        self.assertIn('class="shell"', page.text)
        self.assertIn('class="me-panel"', page.text)
        self.assertIn('class="pub-form"', page.text)
        self.assertIn("/login?next=/publish", page.text)
        self.assertNotIn("发布需要 GitHub 登录", page.text)
        self.assertNotIn('name="body_md"', page.text)

        created = self.client.post("/api/posts", json={
            "title": "手搓周报结构",
            "description": "把一周工作收成固定四段：结论、数字、风险、下周。",
            "github_url": "https://github.com/dev-user/week-report",
        })
        self.assertEqual(created.status_code, 200, created.text)
        self.assertTrue(created.json()["ok"])
        self.assertEqual(created.json()["post"]["status"], "pending")
        post_id = created.json()["post"]["id"]

        feed = self.client.get("/api/feed?source=ugc")
        self.assertEqual(feed.status_code, 200)
        self.assertEqual(feed.json()["items"], [])

        denied = self.client.post("/api/posts", json={
            "title": "别人的仓",
            "description": "想认领一个不是自己的仓库。",
            "github_url": "https://github.com/hardikpandya/stop-slop",
        })
        self.assertEqual(denied.status_code, 400)

        approved = self.client.post(f"/api/op/posts/{post_id}", json={"action": "approve"})
        self.assertEqual(approved.status_code, 200, approved.text)

        feed = self.client.get("/api/feed?source=ugc")
        self.assertEqual(len(feed.json()["items"]), 1)
        self.assertEqual(feed.json()["items"][0]["name"], "手搓周报结构")
        self.assertTrue(feed.json()["items"][0].get("ugc"))

        mine = self.client.get("/api/posts/me")
        self.assertEqual(len(mine.json()["posts"]), 1)

    def test_auth_me_returns_user_saved_and_liked_arrays(self):
        """D2：/auth/me 返回账号收藏/点赞的 full_name 数组，前端用它做跨设备一致的「查看收藏」列表与计数。"""
        # 1) 设备先匿名点几条赞/收藏（拿 device_token）
        r = self.client.post("/api/events", json={
            "device_id": "devA", "session_id": "s1", "events": [
                {"action": "save", "item_key": "acme/saved::SKILL.md", "client_ts": "t1"},
                {"action": "useful", "item_key": "acme/liked::SKILL.md", "client_ts": "t2"},
                {"action": "save", "item_key": "other/skip::SKILL.md", "client_ts": "t3"},
            ],
        })
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["device_token"]

        # 2) 登录并把这台设备并档到账号
        self.client.get("/auth/dev-login", follow_redirects=False)
        claim = self.client.post("/api/profile/claim", json={
            "device_id": "devA", "device_token": token,
        })
        self.assertEqual(claim.status_code, 200, claim.text)

        # 3) /auth/me 应返 saved/liked 数组，跨设备聚合、去重
        me = self.client.get("/auth/me").json()
        self.assertEqual(me["user"]["login"], "dev-user")
        self.assertEqual(sorted(me["saved"]),
                         ["acme/saved::SKILL.md", "other/skip::SKILL.md"])
        self.assertEqual(me["liked"], ["acme/liked::SKILL.md"])

        # 4) 未登录时 saved/liked 不出现（user 为 null）
        self.client.post("/auth/logout")
        me2 = self.client.get("/auth/me").json()
        self.assertIsNone(me2["user"])
        self.assertNotIn("saved", me2)
        self.assertNotIn("liked", me2)

    def test_prepare_rejects_empty(self):
        from server import ugc
        with self.assertRaises(ValueError):
            ugc.prepare_post_payload(title="", github_url="", description="")

    def test_full_feed_after_login_reads_local_artifact(self):
        """2.10/2.11：登录后拿到的 full Feed 来自服务器本地产物，不出网。"""
        site = Path(self.tmp.name) / "site"
        site.mkdir()
        (site / "feed.json").write_text(
            '{"items": [{"id": "official:1", "full_name": "acme/tool", '
            '"name": "tool", "description": "本地产物里的官方条目"}]}',
            encoding="utf-8",
        )
        s = _settings(
            self.tmp.name, dev_mode=True, dev_auth=True,
            site_dir=site, official_feed_file=site / "feed.json",
        )
        client = TestClient(server_app.create_app(s))
        client.get("/auth/dev-login")
        feed = client.get("/api/feed?source=official")
        self.assertEqual(feed.status_code, 200)
        self.assertEqual(
            [i["full_name"] for i in feed.json()["items"]], ["acme/tool"],
        )
        # 同源 feed.json 端点也能拿到，且在门禁后面
        self.assertEqual(client.get("/feed.json").status_code, 200)

    def test_free_login_sees_the_whole_official_feed(self):
        site = Path(self.tmp.name) / "site"
        site.mkdir()
        items = [
            {"id": f"off-{i}", "full_name": f"acme/s-{i}", "name": f"s-{i}"}
            for i in range(12)
        ]
        (site / "feed.json").write_text(
            json.dumps({"items": items, "corpus": [{"id": "keep"}]}),
            encoding="utf-8",
        )
        s = _settings(
            self.tmp.name, dev_mode=True, dev_auth=True,
            site_dir=site, official_feed_file=site / "feed.json",
            activation_codes=frozenset({"VIP-TEST"}),
            subscriber_days=365,
        )
        client = TestClient(server_app.create_app(s))
        client.get("/auth/dev-login")
        first = client.get("/api/feed?source=official&limit=40")
        self.assertEqual(first.status_code, 200)
        body = first.json()
        self.assertEqual(len(body["items"]), 12)
        self.assertEqual(body["total"], 12)
        self.assertTrue(body["quota"]["unlimited"])
        dumped = client.get("/feed.json")
        self.assertEqual(len(dumped.json()["items"]), 12)
        self.assertEqual(dumped.json()["corpus"], [{"id": "keep"}])

        ok = client.post("/api/account/activate", json={"code": "VIP-TEST"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertTrue(ok.json()["user"]["subscriber"])
        unlimited = client.get("/api/feed?source=official&limit=40")
        self.assertEqual(len(unlimited.json()["items"]), 12)
        self.assertTrue(unlimited.json()["quota"]["unlimited"])

    def test_gate_off_anonymous_is_not_quotad(self):
        site = Path(self.tmp.name) / "site"
        site.mkdir()
        items = [
            {"id": f"off-{i}", "full_name": f"acme/s-{i}", "name": f"s-{i}"}
            for i in range(12)
        ]
        (site / "feed.json").write_text(
            json.dumps({"items": items}), encoding="utf-8",
        )
        s = _settings(
            self.tmp.name, require_login=False,
            site_dir=site, official_feed_file=site / "feed.json",
        )
        client = TestClient(server_app.create_app(s))
        feed = client.get("/api/feed?source=official&limit=40")
        self.assertEqual(len(feed.json()["items"]), 12)
        self.assertIsNone(feed.json()["quota"])

    def test_default_official_feed_url_is_not_github_io(self):
        """2.11：默认不再指向 github.io。"""
        import os
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SKILLFEED_OFFICIAL_FEED_URL", None)
            self.assertEqual(Settings().official_feed_url, "")


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestPayOrders(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(
            self.tmp.name, dev_mode=True, dev_auth=True, sku_year_fen=9900,
        )
        self.client = TestClient(server_app.create_app(self.settings))
        self.client.get("/auth/dev-login")

    def tearDown(self):
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_create_then_dev_notify_unlocks(self):
        catalog = self.client.get("/api/pay/catalog")
        self.assertEqual(catalog.status_code, 200)
        self.assertTrue(catalog.json()["dev_notify"])
        self.assertFalse(catalog.json()["wechat_pay"])
        created = self.client.post("/api/pay/create", json={"sku": "subscriber_year"})
        self.assertEqual(created.status_code, 200, created.text)
        order = created.json()["order"]
        self.assertEqual(order["status"], "pending")
        self.assertEqual(order["amount_fen"], 9900)
        paid = self.client.post(
            "/api/pay/dev-notify", json={"out_trade_no": order["out_trade_no"]},
        )
        self.assertEqual(paid.status_code, 200, paid.text)
        self.assertFalse(paid.json()["replay"])
        self.assertTrue(paid.json()["user"]["subscriber"])
        again = self.client.post(
            "/api/pay/dev-notify", json={"out_trade_no": order["out_trade_no"]},
        )
        self.assertTrue(again.json()["replay"])
        self.assertEqual(
            again.json()["order"]["plan_until"], paid.json()["order"]["plan_until"],
        )
        mine = self.client.get("/api/pay/orders")
        self.assertEqual(len(mine.json()["orders"]), 1)
        self.assertEqual(mine.json()["orders"][0]["status"], "paid")

    def test_dev_notify_off_when_not_dev(self):
        s = _settings(self.tmp.name, dev_mode=False, require_login=False)
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        r = client.post("/api/pay/dev-notify", json={"out_trade_no": "SF1"})
        self.assertEqual(r.status_code, 404)

    def test_cannot_notify_someone_elses_order(self):
        created = self.client.post("/api/pay/create", json={})
        trade_no = created.json()["order"]["out_trade_no"]
        other = TestClient(server_app.create_app(self.settings))
        other.get("/auth/dev-login?login=other-user")
        stolen = other.post("/api/pay/dev-notify", json={"out_trade_no": trade_no})
        self.assertEqual(stolen.status_code, 403)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestReviewNotify(unittest.TestCase):
    def test_empty_webhook_is_a_no_op(self):
        from server import notify
        from server.config import Settings

        s = Settings()
        s.review_webhook = ""
        s.public_url = "https://skillfeeder.cn"
        self.assertFalse(notify.notify_pending_review(s, {"title": "x"}))

    def test_feishu_webhook_posts_text(self):
        from server import notify

        s = _settings(
            tempfile.mkdtemp(),
            review_webhook="https://open.feishu.cn/open-apis/bot/v2/hook/test",
            public_url="https://skillfeeder.cn",
        )
        with mock.patch("server.notify.httpx.post") as post:
            post.return_value.raise_for_status = mock.Mock()
            ok = notify.notify_pending_review(s, {
                "title": "手搓周报",
                "author_login": "alice",
                "github_url": "https://github.com/alice/week-report",
            })
        self.assertTrue(ok)
        args, kwargs = post.call_args
        self.assertEqual(args[0], s.review_webhook)
        body = kwargs["json"]
        self.assertEqual(body["msg_type"], "text")
        self.assertIn("手搓周报", body["content"]["text"])
        self.assertIn("/op?tab=review", body["content"]["text"])

    def test_webhook_can_come_from_site_settings(self):
        from server import db as sdb
        from server import notify

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = _settings(tmp.name, review_webhook="", public_url="https://skillfeeder.cn")
        sdb.init_db(s.db_path)
        with sdb.db_session(s.db_path) as conn:
            sdb.set_site_setting(
                conn, "review_webhook",
                "https://open.feishu.cn/open-apis/bot/v2/hook/from-db",
            )
        with mock.patch("server.notify.httpx.post") as post:
            post.return_value.raise_for_status = mock.Mock()
            ok = notify.notify_pending_review(s, {"title": "涨了么"})
        self.assertTrue(ok)
        self.assertEqual(
            post.call_args[0][0],
            "https://open.feishu.cn/open-apis/bot/v2/hook/from-db",
        )

    def test_submit_does_not_fail_when_notify_raises(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = _settings(
            tmp.name,
            github_client_id="cid",
            github_client_secret="csec",
            github_login_visible=True,
            operator_logins=frozenset({"dev-user"}),
            dev_mode=True,
            dev_auth=True,
            review_webhook="https://open.feishu.cn/open-apis/bot/v2/hook/test",
        )
        client = TestClient(server_app.create_app(s), follow_redirects=False)
        client.get("/auth/dev-login")
        with mock.patch("server.notify.httpx.post", side_effect=RuntimeError("down")):
            created = client.post("/api/posts", json={
                "title": "手搓周报结构",
                "description": "把一周工作收成固定四段：结论、数字、风险、下周。",
                "github_url": "https://github.com/dev-user/week-report",
            })
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(created.json()["post"]["status"], "pending")


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestAdminSite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(
            self.tmp.name,
            github_client_id="cid",
            github_client_secret="csec",
            operator_logins=frozenset({"dev-user"}),
            dev_mode=True,
            dev_auth=True,
        )
        self.client = TestClient(server_app.create_app(self.settings), follow_redirects=False)

    def tearDown(self):
        self.tmp.cleanup()

    def test_site_config_is_public_and_hides_webhook(self):
        r = self.client.get("/api/site-config")
        self.assertEqual(r.status_code, 200)
        cfg = r.json()["config"]
        self.assertIn("slogan", cfg)
        self.assertNotIn("review_webhook", cfg)

    def test_operator_can_save_copy_and_webhook(self):
        self.client.get("/auth/dev-login")
        saved = self.client.post("/api/op/settings", json={
            "slogan": "测一口号",
            "search_placeholder": "搜技能",
            "logo_url": "",
            "review_webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/test",
        })
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertTrue(saved.json()["webhook_on"])
        public = self.client.get("/api/site-config").json()["config"]
        self.assertEqual(public["slogan"], "测一口号")
        self.assertNotIn("review_webhook", public)

    def test_anonymous_cannot_write_settings(self):
        r = self.client.post("/api/op/settings", json={"slogan": "x"})
        self.assertEqual(r.status_code, 302)

    def test_admin_aliases_require_login(self):
        for path in ("/op", "/op/", "/admin", "/admin/"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers.get("location", ""), path)

    def test_missing_card_short_link_is_404(self):
        r = self.client.get("/p/no-such-skill")
        self.assertEqual(r.status_code, 404)

    def test_operator_can_read_journeys(self):
        self.client.post("/api/events", json={
            "device_id": "web-op", "session_id": "s-op",
            "events": [
                {"action": "session_start", "client_ts": "j1"},
                {"action": "view_tab", "item_key": "all", "client_ts": "j2"},
                {"action": "search", "item_key": "周报", "client_ts": "j3"},
            ],
        })
        self.client.get("/auth/dev-login")
        r = self.client.get("/api/op/journeys?hours=24")
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertGreaterEqual(data["kpis"]["sessions"], 1)
        paths = " ".join(s.get("path") or "" for s in data["sessions"])
        self.assertIn("进入", paths)
        csv = self.client.get("/api/op/journeys.csv?hours=24")
        self.assertEqual(csv.status_code, 200)
        self.assertIn("session_start", csv.text)

    def test_stranger_cannot_read_journeys(self):
        self.client.get("/auth/dev-login?login=other-user")
        r = self.client.get("/api/op/journeys")
        self.assertEqual(r.status_code, 403)


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestIdentityBind(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = _settings(
            self.tmp.name,
            wechat_app_id="wx-app-id", wechat_app_secret="wx-secret",
            sms_provider="console", sms_resend_cooldown_s=0,
            dev_mode=True, dev_auth=True,
            operator_logins=frozenset({"dev-user"}),
        )
        self.client = TestClient(server_app.create_app(self.settings), follow_redirects=False)
        self.sent: list[tuple[str, str]] = []

        async def _fake_send(settings, phone, code):
            self.sent.append((phone, code))
            return {"ok": True}

        self.patch = mock.patch.object(sms, "send_code", _fake_send)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _wechat_state(self):
        r = self.client.get("/auth/wechat")
        return self.client.cookies.get(auth.STATE_COOKIE["wechat"])

    def _fake_wechat(self, openid="oBIND-1", unionid=""):
        async def _token(settings, code):
            return {"access_token": "at", "openid": openid, "unionid": unionid}

        async def _info(settings, access_token, oid):
            return {"openid": oid, "nickname": "绑", "headimgurl": "", "unionid": unionid}

        return (
            mock.patch.object(auth, "exchange_wechat_code", _token),
            mock.patch.object(auth, "fetch_wechat_userinfo", _info),
        )

    def test_logged_in_github_user_can_bind_wechat_and_phone(self):
        self.client.get("/auth/dev-login")
        before = self.client.get("/auth/me").json()["user"]
        self.assertIn("github", before["providers"])
        uid = before["id"]
        state = self._wechat_state()
        p1, p2 = self._fake_wechat()
        with p1, p2:
            r = self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        self.assertEqual(r.status_code, 302)
        self.client.post("/auth/sms/send", json={"phone": "13900139000"})
        _, code = self.sent[-1]
        v = self.client.post("/auth/sms/verify", json={"phone": "13900139000", "code": code})
        self.assertEqual(v.status_code, 200, v.text)
        me = self.client.get("/auth/me").json()["user"]
        self.assertEqual(me["id"], uid)
        self.assertEqual(set(me["providers"]), {"github", "wechat", "phone"})
        exported = self.client.get("/api/me/export")
        self.assertEqual(exported.status_code, 200)
        self.assertNotIn("13900139000", exported.text)
        self.assertIn("skillfeeder-account.json", exported.headers.get("content-disposition", ""))

    def test_cannot_steal_another_users_wechat(self):
        state = self._wechat_state()
        p1, p2 = self._fake_wechat(openid="oTAKEN")
        with p1, p2:
            self.client.get(f"/auth/wechat/callback?code=the-code&state={state}")
        first = self.client.get("/auth/me").json()["user"]["id"]
        other = TestClient(server_app.create_app(self.settings), follow_redirects=False)
        other.get("/auth/dev-login?login=other-user")
        state2 = other.cookies.get(auth.STATE_COOKIE["wechat"])
        other.get("/auth/wechat")
        state2 = other.cookies.get(auth.STATE_COOKIE["wechat"])
        p3, p4 = self._fake_wechat(openid="oTAKEN")
        with p3, p4:
            stolen = other.get(f"/auth/wechat/callback?code=the-code&state={state2}")
        self.assertEqual(stolen.status_code, 302)
        self.assertIn("bind=taken", stolen.headers.get("location", ""))
        self.assertEqual(other.get("/auth/me").json()["user"]["id"], other.get("/auth/me").json()["user"]["id"])
        self.assertNotEqual(other.get("/auth/me").json()["user"]["id"], first)
        self.assertNotIn("wechat", other.get("/auth/me").json()["user"]["providers"])

    def test_operator_can_backup_ledger(self):
        self.client.get("/auth/dev-login")
        r = self.client.post("/api/op/backup")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertGreaterEqual(r.json()["count"], 1)
        stats = self.client.get("/api/op/stats").json()
        self.assertGreaterEqual(stats["backup"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
