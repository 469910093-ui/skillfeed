"""发现流全量免费：配额逻辑不再切条，不打 HTTP。"""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from server import db
from server import entitlement


def _user(uid=1, plan="free", plan_until=None):
    return {"id": uid, "login": "u", "plan": plan, "plan_until": plan_until}


def _items(n):
    return [{"id": f"it-{i}", "full_name": f"acme/s-{i}", "name": f"s-{i}"} for i in range(n)]


class TestSubscriberFlag(unittest.TestCase):
    def test_missing_plan_is_free(self):
        self.assertFalse(entitlement.is_subscriber({"id": 1, "login": "x"}))

    def test_lifetime_subscriber(self):
        self.assertTrue(entitlement.is_subscriber(_user(plan="subscriber")))

    def test_expired_subscriber_is_free(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.assertFalse(entitlement.is_subscriber(_user(plan="subscriber", plan_until=past)))

    def test_future_expiry_is_still_subscribed(self):
        future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        self.assertTrue(entitlement.is_subscriber(_user(plan="subscriber", plan_until=future)))


class TestDailyQuota(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "t.db"
        db.init_db(self.db_path)
        self.conn = db.connect(self.db_path)
        self.conn.execute(
            "INSERT INTO users (login, created_at, plan) VALUES ('free-user', 't', 'free')"
        )
        self.uid = int(self.conn.execute("SELECT id FROM users").fetchone()[0])
        self.user = db.get_user(self.conn, self.uid)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_anonymous_is_unlimited(self):
        items = _items(12)
        visible, quota = entitlement.apply_daily_quota(self.conn, None, items)
        self.assertEqual(len(visible), 12)
        self.assertIsNone(quota)

    def test_free_user_sees_the_whole_catalog(self):
        items = _items(12)
        first, q1 = entitlement.apply_daily_quota(self.conn, self.user, items)
        self.assertEqual(len(first), 12)
        self.assertTrue(q1["unlimited"])
        self.assertIsNone(q1["limit"])
        ids = [it["id"] for it in first]
        again, q2 = entitlement.apply_daily_quota(self.conn, self.user, items)
        self.assertEqual([it["id"] for it in again], ids)
        self.assertTrue(q2["unlimited"])

    def test_claim_false_still_returns_everything(self):
        visible, quota = entitlement.apply_daily_quota(
            self.conn, self.user, _items(12), claim=False,
        )
        self.assertEqual(len(visible), 12)
        self.assertTrue(quota["unlimited"])

    def test_subscriber_sees_everything(self):
        db.set_user_plan(self.conn, self.uid, "subscriber", None)
        user = db.get_user(self.conn, self.uid)
        visible, quota = entitlement.apply_daily_quota(self.conn, user, _items(12))
        self.assertEqual(len(visible), 12)
        self.assertTrue(quota["unlimited"])


class TestPlanMigration(unittest.TestCase):
    def test_old_users_table_gets_plan_and_unlocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  github_id INTEGER,
                  login TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO users (github_id, login, created_at) VALUES (1, 'old', 't')"
            )
            conn.commit()
            conn.close()
            db.init_db(path)
            conn = db.connect(path)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            self.assertIn("plan", cols)
            self.assertIn("plan_until", cols)
            row = dict(conn.execute("SELECT * FROM users WHERE login='old'").fetchone())
            self.assertEqual(row.get("plan") or "free", "free")
            pub = db.user_public(row)
            self.assertEqual(pub["plan"], "free")
            self.assertFalse(pub["subscriber"])
            self.assertNotIn("phone", pub)
            conn.execute("SELECT COUNT(*) FROM feed_unlocks")
            conn.close()


if __name__ == "__main__":
    unittest.main()
