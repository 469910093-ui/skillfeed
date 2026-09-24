"""订单到账开通：同一笔 notify 两次不能把订阅再顺延。"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from server import db, entitlement, pay


def _settings(**over):
    s = SimpleNamespace(
        subscriber_days=365,
        sku_month_cont_fen=2900,
        sku_quarter_cont_fen=7800,
        sku_year_cont_fen=22800,
        sku_month_once_fen=3900,
        sku_quarter_once_fen=10500,
        sku_year_once_fen=29900,
        sku_year_fen=22800,
    )
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

    def _create(self, sku=pay.SKU_YEAR_CONT):
        return pay.create_order(
            self.conn, user_id=self.uid, sku_id=sku, settings=self.settings,
        )

    def test_first_notify_opens_subscription(self):
        order = self._create()
        self.assertEqual(order["status"], "pending")
        paid, replay = pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1",
            amount_fen=22800,
            settings=self.settings,
        )
        self.assertFalse(replay)
        self.assertEqual(paid["status"], "paid")
        user = db.get_user(self.conn, self.uid)
        self.assertTrue(entitlement.is_subscriber(user))
        self.assertTrue(user["plan_until"])
        self.assertEqual(int(user["seat_limit"]), 3)
        self.assertEqual(user["billing"], "continuous")

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

    def test_month_cont_with_assign_pack(self):
        order = self._create(pay.SKU_MONTH_CONT)
        self.assertEqual(order["amount_fen"], 2900)
        paid, replay = pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="dev-pack",
            amount_fen=2900,
            settings=self.settings,
            assign_pack="shelf-ecom",
        )
        self.assertFalse(replay)
        self.assertEqual(paid["status"], "paid")
        user = db.get_user(self.conn, self.uid)
        self.assertTrue(entitlement.is_subscriber(user))
        self.assertEqual(int(user["seat_limit"]), 1)
        self.assertEqual(db.list_active_pack_ids(self.conn, self.uid), ["shelf-ecom"])
        self.assertTrue(db.user_can_access_pack(self.conn, self.uid, "shelf-ecom"))

    def test_over_limit_grants_are_trimmed_on_open(self):
        """旧买断留下的第二个场景，在月档（1 席）开通时被收掉。"""
        now = datetime.now(timezone.utc)
        self.conn.execute(
            """
            INSERT INTO pack_grants (user_id, pack_id, order_id, granted_at)
            VALUES (?, 'cross-border', 0, ?)
            """,
            (self.uid, "2026-01-01T00:00:00+00:00"),
        )
        order = self._create(pay.SKU_MONTH_CONT)
        pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-trim",
            settings=self.settings,
            now=now,
            assign_pack="shelf-ecom",
        )
        self.assertEqual(db.list_user_pack_ids(self.conn, self.uid), ["shelf-ecom"])
        self.assertFalse(db.user_can_access_pack(self.conn, self.uid, "cross-border"))

    def test_read_trims_existing_over_limit(self):
        db.set_user_plan(
            self.conn, self.uid, "subscriber",
            "2099-01-01T00:00:00+00:00",
            seat_limit=1, billing="continuous",
        )
        self.conn.execute(
            """
            INSERT INTO pack_grants (user_id, pack_id, order_id, granted_at) VALUES
            (?, 'cross-border', 0, '2026-01-01T00:00:00+00:00'),
            (?, 'shelf-ecom', 0, '2026-02-01T00:00:00+00:00')
            """,
            (self.uid, self.uid),
        )
        active = db.list_active_pack_ids(self.conn, self.uid)
        self.assertEqual(active, ["shelf-ecom"])
        self.assertEqual(db.list_user_pack_ids(self.conn, self.uid), ["shelf-ecom"])

    def test_pack_sku_no_longer_sold(self):
        with self.assertRaises(pay.PayError) as ctx:
            pay.create_order(
                self.conn, user_id=self.uid, sku_id="shelf-ecom", settings=self.settings,
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_sku_rejected_on_create(self):
        with self.assertRaises(pay.PayError) as ctx:
            pay.create_order(
                self.conn, user_id=self.uid, sku_id="nope", settings=self.settings,
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_legacy_subscriber_year_alias(self):
        order = pay.create_order(
            self.conn, user_id=self.uid, sku_id="subscriber_year", settings=self.settings,
        )
        self.assertEqual(order["sku"], pay.SKU_YEAR_CONT)
        self.assertEqual(order["amount_fen"], 22800)

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

    def test_seat_full_blocks_second_pack_on_month(self):
        order = self._create(pay.SKU_MONTH_CONT)
        pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1",
            settings=self.settings,
            assign_pack="shelf-ecom",
        )
        with self.assertRaises(db.SeatError) as ctx:
            db.assign_pack_seat(
                self.conn, user_id=self.uid, pack_id="cross-border",
            )
        self.assertEqual(ctx.exception.status, 409)


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
