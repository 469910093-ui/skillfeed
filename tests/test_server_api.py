import tempfile
import unittest
from pathlib import Path

# 可选依赖：未安装 fastapi 时跳过
try:
    from fastapi.testclient import TestClient
    import server.app as server_app
    from server.config import Settings
    HAS_SERVER = True
except ImportError:
    HAS_SERVER = False


@unittest.skipUnless(HAS_SERVER, "requirements-server.txt not installed")
class TestServerAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self.settings = Settings()
        self.settings.db_path = self.db
        self.settings.dev_auth = True
        self.settings.session_secret = "test-secret"
        self.settings.public_url = "http://testserver"
        self.settings.official_feed_url = ""
        self.settings.github_client_id = ""
        self.settings.github_client_secret = ""
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

        created = self.client.post("/api/posts", json={
            "title": "my-writing-skill",
            "body_md": (
                "---\nname: my-writing-skill\n"
                "description: 去掉 AI 味写作技能包，润色文案减少套话\n---\n\n"
                "# Writing\n\nCut filler phrases from prose.\n"
            ),
            "github_url": "https://github.com/acme/my-writing-skill",
        })
        self.assertEqual(created.status_code, 200, created.text)
        self.assertTrue(created.json()["ok"])
        self.assertEqual(created.json()["feed_item"]["source"], "ugc")

        feed = self.client.get("/api/feed?source=ugc")
        self.assertEqual(feed.status_code, 200)
        items = feed.json()["items"]
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "my-writing-skill")
        self.assertTrue(items[0].get("ugc"))

        mine = self.client.get("/api/posts/me")
        self.assertEqual(len(mine.json()["posts"]), 1)

    def test_prepare_rejects_empty(self):
        from server import ugc
        with self.assertRaises(ValueError):
            ugc.prepare_post_payload(title="", body_md="", github_url="")


if __name__ == "__main__":
    unittest.main()
