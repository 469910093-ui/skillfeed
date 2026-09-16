"""订单到账开通：同一笔 notify 两次不能把订阅再顺延一年。"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from server import db, entitlement, pay


def _settings(**over):
    s = SimpleNamespace(subscriber_days=365, sku_year_fen=9900)
    for k, v in over.items():
        setattr(s, k, v)
    return s


class TestPayNotifyIdempotent(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "t.db"
        db.init_db(self.db_path)
        self.conn = db.connect(self.db_path)
        self.conn.execute(
            "INSERT INTO users (login, created_at, plan) VALUES ('buyer', 't', 'free')"
        )
        self.uid = int(self.conn.execute("SELECT id FROM users").fetchone()[0])
        self.settings = _settings()

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _create(self):
        return pay.create_order(
            self.conn, user_id=self.uid, sku_id=pay.SKU_YEAR, settings=self.settings,
        )

    def test_first_notify_opens_subscription(self):
        order = self._create()
        self.assertEqual(order["status"], "pending")
        paid, replay = pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1",
            amount_fen=9900,
            settings=self.settings,
        )
        self.assertFalse(replay)
        self.assertEqual(paid["status"], "paid")
        user = db.get_user(self.conn, self.uid)
        self.assertTrue(entitlement.is_subscriber(user))
        self.assertTrue(user["plan_until"])

    def test_replay_does_not_extend_plan_until(self):
        order = self._create()
        first, _ = pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1",
            settings=self.settings,
        )
        again, replay = pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1-replay",
            settings=self.settings,
        )
        self.assertTrue(replay)
        self.assertEqual(again["plan_until"], first["plan_until"])
        self.assertEqual(again["provider_txn_id"], first["provider_txn_id"])

    def test_amount_mismatch_is_rejected(self):
        order = self._create()
        with self.assertRaises(pay.PayError) as ctx:
            pay.apply_paid_notify(
                self.conn,
                out_trade_no=order["out_trade_no"],
                provider_txn_id="wx-1",
                amount_fen=1,
                settings=self.settings,
            )
        self.assertEqual(ctx.exception.status, 400)
        user = db.get_user(self.conn, self.uid)
        self.assertFalse(entitlement.is_subscriber(user))

    def test_unknown_sku_rejected_on_create(self):
        with self.assertRaises(pay.PayError) as ctx:
            pay.create_order(
                self.conn, user_id=self.uid, sku_id="nope", settings=self.settings,
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_second_order_extends_from_current_expiry(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first = self._create()
        pay.apply_paid_notify(
            self.conn,
            out_trade_no=first["out_trade_no"],
            provider_txn_id="wx-1",
            settings=self.settings,
            now=now,
        )
        second = self._create()
        paid, replay = pay.apply_paid_notify(
            self.conn,
            out_trade_no=second["out_trade_no"],
            provider_txn_id="wx-2",
            settings=self.settings,
            now=now + timedelta(days=10),
        )
        self.assertFalse(replay)
        exp = entitlement.parse_plan_until(paid["plan_until"])
        self.assertEqual(exp, now + timedelta(days=730))


class TestWechatNotifyStub(unittest.TestCase):
    def test_unconfigured_never_looks_like_success(self):
        settings = SimpleNamespace(wechat_pay_configured=False)
        with self.assertRaises(pay.PayError) as ctx:
            pay.verify_wechat_notify(b"{}", {}, settings)
        self.assertEqual(ctx.exception.status, 503)

    def test_configured_but_verify_not_wired(self):
        settings = SimpleNamespace(wechat_pay_configured=True)
        with self.assertRaises(pay.PayError) as ctx:
            pay.verify_wechat_notify(b"{}", {}, settings)
        self.assertEqual(ctx.exception.status, 503)
        self.assertIn("尚未接入", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
