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
        self.assertEqual(int(user["seat_limit"]), 5)
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
        self.assertEqual(int(user["seat_limit"]), 2)
        self.assertEqual(db.list_active_pack_ids(self.conn, self.uid), ["shelf-ecom"])
        self.assertTrue(db.user_can_access_pack(self.conn, self.uid, "shelf-ecom"))

    def test_over_limit_grants_are_trimmed_on_open(self):
        """旧占用超过月档（2 席）时，开通指定的场景留下，更早的被收掉。"""
        now = datetime.now(timezone.utc)
        self.conn.execute(
            """
            INSERT INTO pack_grants (user_id, pack_id, order_id, granted_at) VALUES
            (?, 'marketing', 0, '2026-01-01T00:00:00+00:00'),
            (?, 'cross-border', 0, '2026-02-01T00:00:00+00:00')
            """,
            (self.uid, self.uid),
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
        self.assertEqual(
            db.list_user_pack_ids(self.conn, self.uid),
            ["cross-border", "shelf-ecom"],
        )
        self.assertFalse(db.user_can_access_pack(self.conn, self.uid, "marketing"))
        self.assertTrue(db.user_can_access_pack(self.conn, self.uid, "shelf-ecom"))

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

    def test_seat_full_blocks_third_pack_on_month(self):
        order = self._create(pay.SKU_MONTH_CONT)
        pay.apply_paid_notify(
            self.conn,
            out_trade_no=order["out_trade_no"],
            provider_txn_id="wx-1",
            settings=self.settings,
            assign_pack="shelf-ecom",
        )
        db.assign_pack_seat(
            self.conn, user_id=self.uid, pack_id="cross-border",
        )
        with self.assertRaises(db.SeatError) as ctx:
            db.assign_pack_seat(
                self.conn, user_id=self.uid, pack_id="marketing",
            )
        self.assertEqual(ctx.exception.status, 409)


class TestWechatNative(unittest.TestCase):
    def test_unconfigured_never_looks_like_success(self):
        settings = SimpleNamespace(
            wechat_pay_mchid="",
            wechat_pay_api_v3_key="",
            wechat_pay_serial="",
            wechat_pay_private_key_file="",
            wechat_pay_public_key_file="",
            wechat_pay_public_key_id="",
            wechat_pay_appid="",
            wechat_app_id="",
            public_url="http://127.0.0.1:8787",
        )
        with self.assertRaises(pay.PayError) as ctx:
            pay.verify_wechat_notify(b"{}", {}, settings)
        self.assertEqual(ctx.exception.status, 503)

    def _ready(self, tmp: Path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = tmp / "apiclient_key.pem"
        pub = tmp / "wechat_pub.pem"
        priv.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        pub.write_bytes(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        settings = SimpleNamespace(
            wechat_pay_mchid="1900000001",
            wechat_pay_api_v3_key="a" * 32,
            wechat_pay_serial="CERTSERIAL",
            wechat_pay_private_key_file=str(priv),
            wechat_pay_public_key_file=str(pub),
            wechat_pay_public_key_id="PUBKEYID",
            wechat_pay_appid="wxappid",
            wechat_app_id="",
            public_url="https://skillfeeder.cn",
            subscriber_days=365,
            sku_month_cont_fen=2900,
            sku_quarter_cont_fen=7800,
            sku_year_cont_fen=22800,
            sku_month_once_fen=3900,
            sku_quarter_once_fen=10500,
            sku_year_once_fen=29900,
        )
        return key, settings

    def test_prepay_rejects_non_weixin_code(self):
        from server import wechat_pay
        with tempfile.TemporaryDirectory() as tmp:
            _, settings = self._ready(Path(tmp))

            def transport(method, url, body, headers):
                del method, url, body, headers
                return 200, '{"code_url":"https://evil.example/qr"}'

            with self.assertRaises(pay.PayError) as ctx:
                wechat_pay.native_prepay(
                    settings, out_trade_no="SF202610080001abcd",
                    amount_fen=2900, description="连续包月", transport=transport,
                )
            self.assertEqual(ctx.exception.status, 502)

    def test_notify_grants_once_and_seats_saved_pack(self):
        import json as jsonlib
        import time
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from server import wechat_pay
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            key, settings = self._ready(tmp)
            home = tmp / "db"
            home.mkdir()
            db.init_db(home / "t.db")
            conn = db.connect(home / "t.db")
            try:
                conn.execute(
                    "INSERT INTO users (login, created_at, plan) VALUES ('payer', 't', 'free')"
                )
                uid = int(conn.execute("SELECT id FROM users").fetchone()[0])
                order = pay.create_order(
                    conn, user_id=uid, sku_id=pay.SKU_MONTH_CONT,
                    settings=settings, assign_pack="shelf-ecom",
                )
                conn.commit()
                plain = {
                    "mchid": "1900000001",
                    "appid": "wxappid",
                    "out_trade_no": order["out_trade_no"],
                    "transaction_id": "4200000001",
                    "trade_state": "SUCCESS",
                    "amount": {"total": 2900, "currency": "CNY"},
                }
                nonce = "n" * 12
                blob = AESGCM(b"a" * 32).encrypt(
                    nonce.encode("utf-8"),
                    jsonlib.dumps(plain).encode("utf-8"),
                    b"transaction",
                )
                import base64
                body = jsonlib.dumps({
                    "resource": {
                        "nonce": nonce,
                        "associated_data": "transaction",
                        "ciphertext": base64.b64encode(blob).decode("ascii"),
                    }
                }).encode("utf-8")
                ts = str(int(time.time()))
                message = f"{ts}\nnonceval\n{body.decode('utf-8')}\n".encode("utf-8")
                sig = base64.b64encode(key.sign(
                    message, padding.PKCS1v15(), hashes.SHA256(),
                )).decode("ascii")
                headers = {
                    "Wechatpay-Serial": "PUBKEYID",
                    "Wechatpay-Timestamp": ts,
                    "Wechatpay-Nonce": "nonceval",
                    "Wechatpay-Signature": sig,
                }
                payload = wechat_pay.verify_notify(body, headers, settings)
                self.assertFalse(payload["skip"])
                paid, replay = pay.apply_paid_notify(
                    conn,
                    out_trade_no=payload["out_trade_no"],
                    provider_txn_id=payload["transaction_id"],
                    amount_fen=payload["amount_fen"],
                    settings=settings,
                )
                self.assertFalse(replay)
                self.assertEqual(paid["status"], "paid")
                self.assertIn("shelf-ecom", db.list_active_pack_ids(conn, uid))
                again, replay2 = pay.apply_paid_notify(
                    conn,
                    out_trade_no=payload["out_trade_no"],
                    provider_txn_id=payload["transaction_id"],
                    amount_fen=payload["amount_fen"],
                    settings=settings,
                )
                self.assertTrue(replay2)
                self.assertEqual(again["plan_until"], paid["plan_until"])
                headers["Wechatpay-Signature"] = "YmFk"
                with self.assertRaises(pay.PayError) as bad:
                    wechat_pay.verify_notify(body, headers, settings)
                self.assertEqual(bad.exception.status, 401)
            finally:
                conn.close()

    def test_non_success_skips_grant(self):
        import json as jsonlib
        import time
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from server import wechat_pay
        with tempfile.TemporaryDirectory() as raw:
            key, settings = self._ready(Path(raw))
            plain = {
                "mchid": "1900000001",
                "appid": "wxappid",
                "out_trade_no": "SF202610080001abcd",
                "transaction_id": "4200000002",
                "trade_state": "NOTPAY",
                "amount": {"total": 2900},
            }
            nonce = "m" * 12
            blob = AESGCM(b"a" * 32).encrypt(
                nonce.encode("utf-8"),
                jsonlib.dumps(plain).encode("utf-8"),
                b"transaction",
            )
            body = jsonlib.dumps({
                "resource": {
                    "nonce": nonce,
                    "associated_data": "transaction",
                    "ciphertext": base64.b64encode(blob).decode("ascii"),
                }
            }).encode("utf-8")
            ts = str(int(time.time()))
            sig = base64.b64encode(key.sign(
                f"{ts}\nnonce2\n{body.decode('utf-8')}\n".encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )).decode("ascii")
            payload = wechat_pay.verify_notify(body, {
                "Wechatpay-Serial": "PUBKEYID",
                "Wechatpay-Timestamp": ts,
                "Wechatpay-Nonce": "nonce2",
                "Wechatpay-Signature": sig,
            }, settings)
            self.assertTrue(payload["skip"])


if __name__ == "__main__":
    unittest.main()
