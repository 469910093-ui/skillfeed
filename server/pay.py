"""订阅订单与到账开通。

真微信支付（统一下单 / APIv3 验签）还没接。这里先把两件必须先对的事钉死：

1. 下单只写 pending，不发权益。
2. 到账回调按 out_trade_no 幂等开通：同一笔付两次，plan_until 不变。

测开通用 `/api/pay/dev-notify`（SKILLFEED_DEV=1 + 已登录 + 只能操作自己的单）。

变现：场景包无买断。卖的是月/季/年订阅（连续续费更便宜；单独买同周期更贵），
期内按席位选用场景包；过期停更、停手册、停席位访问。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import sqlite3

from server import db
from server.config import Settings
from server.entitlement import next_plan_until

# 连续续费（默认推）
SKU_MONTH_CONT = "subscriber_month_cont"
SKU_QUARTER_CONT = "subscriber_quarter_cont"
SKU_YEAR_CONT = "subscriber_year_cont"
# 单独买同周期（不自动续，更贵）
SKU_MONTH_ONCE = "subscriber_month_once"
SKU_QUARTER_ONCE = "subscriber_quarter_once"
SKU_YEAR_ONCE = "subscriber_year_once"
# 兼容旧客户端 / 测试：等同连续包年
SKU_YEAR = SKU_YEAR_CONT

PROVIDER_WECHAT = "wechat"
STATUS_PENDING = "pending"
STATUS_PAID = "paid"

BILLING_CONTINUOUS = "continuous"
BILLING_ONCE = "once"

# 备选价：月入口更低。单位分。
# 连续 29 / 78 / 228；单独 39 / 105 / 299。
_DEFAULT_FEN = {
    SKU_MONTH_CONT: 2900,
    SKU_QUARTER_CONT: 7800,
    SKU_YEAR_CONT: 22800,
    SKU_MONTH_ONCE: 3900,
    SKU_QUARTER_ONCE: 10500,
    SKU_YEAR_ONCE: 29900,
}


class PayError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class Sku:
    id: str
    plan: str
    days: int
    amount_fen: int
    title: str
    kind: str = "plan"
    seats: int = 1
    billing: str = BILLING_CONTINUOUS
    period: str = "month"  # month | quarter | year
    pack_id: str = ""


def _fen(settings: Settings, sku_id: str, attr: str, default: int) -> int:
    raw = getattr(settings, attr, None)
    try:
        val = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        val = default
    return max(1, val)


def catalog(settings: Settings) -> dict[str, Sku]:
    """订阅货架。场景包本身不进收银台，靠席位在订阅期内选用。"""
    items = {
        SKU_MONTH_CONT: Sku(
            id=SKU_MONTH_CONT,
            plan="subscriber",
            days=30,
            amount_fen=_fen(settings, SKU_MONTH_CONT, "sku_month_cont_fen", _DEFAULT_FEN[SKU_MONTH_CONT]),
            title="连续包月",
            seats=1,
            billing=BILLING_CONTINUOUS,
            period="month",
        ),
        SKU_QUARTER_CONT: Sku(
            id=SKU_QUARTER_CONT,
            plan="subscriber",
            days=90,
            amount_fen=_fen(settings, SKU_QUARTER_CONT, "sku_quarter_cont_fen", _DEFAULT_FEN[SKU_QUARTER_CONT]),
            title="连续包季",
            seats=2,
            billing=BILLING_CONTINUOUS,
            period="quarter",
        ),
        SKU_YEAR_CONT: Sku(
            id=SKU_YEAR_CONT,
            plan="subscriber",
            days=365,
            amount_fen=_fen(settings, SKU_YEAR_CONT, "sku_year_cont_fen", _DEFAULT_FEN[SKU_YEAR_CONT]),
            title="连续包年",
            seats=3,
            billing=BILLING_CONTINUOUS,
            period="year",
        ),
        SKU_MONTH_ONCE: Sku(
            id=SKU_MONTH_ONCE,
            plan="subscriber",
            days=30,
            amount_fen=_fen(settings, SKU_MONTH_ONCE, "sku_month_once_fen", _DEFAULT_FEN[SKU_MONTH_ONCE]),
            title="单独买一个月",
            seats=1,
            billing=BILLING_ONCE,
            period="month",
        ),
        SKU_QUARTER_ONCE: Sku(
            id=SKU_QUARTER_ONCE,
            plan="subscriber",
            days=90,
            amount_fen=_fen(settings, SKU_QUARTER_ONCE, "sku_quarter_once_fen", _DEFAULT_FEN[SKU_QUARTER_ONCE]),
            title="单独买一季",
            seats=2,
            billing=BILLING_ONCE,
            period="quarter",
        ),
        SKU_YEAR_ONCE: Sku(
            id=SKU_YEAR_ONCE,
            plan="subscriber",
            days=365,
            amount_fen=_fen(settings, SKU_YEAR_ONCE, "sku_year_once_fen", _DEFAULT_FEN[SKU_YEAR_ONCE]),
            title="单独买一年",
            seats=3,
            billing=BILLING_ONCE,
            period="year",
        ),
    }
    return items


def resolve_sku_id(sku_id: str) -> str:
    raw = (sku_id or "").strip()
    if raw in ("subscriber_year", SKU_YEAR):
        return SKU_YEAR_CONT
    return raw


def sku_public(sku: Sku) -> dict[str, Any]:
    return {
        "id": sku.id,
        "title": sku.title,
        "plan": sku.plan,
        "days": sku.days,
        "amount_fen": sku.amount_fen,
        "currency": "CNY",
        "kind": sku.kind,
        "seats": sku.seats,
        "billing": sku.billing,
        "period": sku.period,
        "pack_id": sku.pack_id,
    }


def order_public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "out_trade_no": row["out_trade_no"],
        "sku": row["sku"],
        "amount_fen": row["amount_fen"],
        "currency": row.get("currency") or "CNY",
        "status": row["status"],
        "provider": row.get("provider") or PROVIDER_WECHAT,
        "paid_at": row.get("paid_at") or "",
        "plan_until": row.get("plan_until") or "",
        "created_at": row["created_at"],
    }


def new_out_trade_no() -> str:
    """微信支付要求 6–32 位字母数字。"""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"SF{stamp}{secrets.token_hex(4)}"


def create_order(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    sku_id: str,
    settings: Settings,
) -> dict[str, Any]:
    items = catalog(settings)
    sku = items.get(resolve_sku_id(sku_id))
    if sku is None:
        raise PayError(400, "未知商品")
    now = datetime.now(timezone.utc).isoformat()
    return db.insert_order(conn, {
        "out_trade_no": new_out_trade_no(),
        "user_id": int(user_id),
        "sku": sku.id,
        "amount_fen": sku.amount_fen,
        "currency": "CNY",
        "status": STATUS_PENDING,
        "provider": PROVIDER_WECHAT,
        "created_at": now,
        "updated_at": now,
    })


def apply_paid_notify(
    conn: sqlite3.Connection,
    *,
    out_trade_no: str,
    provider_txn_id: str,
    amount_fen: Optional[int] = None,
    settings: Settings,
    now: Optional[datetime] = None,
    assign_pack: str = "",
) -> tuple[dict[str, Any], bool]:
    """把一笔 pending 单标成已付并开通订阅。

    返回 (order, replay)。replay=True 表示这是重复通知，权益没有再发一次。
    assign_pack：开通时顺带占一个场景席位（须在席位上限内）。
    """
    trade_no = (out_trade_no or "").strip()
    txn = (provider_txn_id or "").strip()
    if not trade_no:
        raise PayError(400, "缺少 out_trade_no")
    if not txn:
        raise PayError(400, "缺少支付单号")

    order = db.get_order_by_trade_no(conn, trade_no)
    if order is None:
        raise PayError(404, "订单不存在")
    if amount_fen is not None and int(amount_fen) != int(order["amount_fen"]):
        raise PayError(400, "金额与订单不一致")
    if order["status"] == STATUS_PAID:
        return order, True
    if order["status"] != STATUS_PENDING:
        raise PayError(409, f"订单状态不可支付：{order['status']}")

    items = catalog(settings)
    sku = items.get(resolve_sku_id(order["sku"]))
    if sku is None:
        raise PayError(400, "订单商品已下架")

    stamp = now or datetime.now(timezone.utc)
    user = db.get_user(conn, int(order["user_id"]))
    if user is None:
        raise PayError(404, "订单用户不存在")

    until = next_plan_until(user, sku.days, now=stamp)
    db.set_user_plan(
        conn,
        int(user["id"]),
        sku.plan,
        until,
        seat_limit=int(sku.seats),
        billing=sku.billing,
    )
    pack = (assign_pack or "").strip()
    # 旧买断占用可能已经超过本档席位。先腾位，再占用本次指定的场景。
    db.trim_pack_seats(conn, int(user["id"]), reserve_for=pack)
    if pack:
        try:
            db.assign_pack_seat(
                conn,
                user_id=int(user["id"]),
                pack_id=pack,
                order_id=int(order["id"]),
                granted_at=stamp.isoformat(),
            )
        except db.SeatError as exc:
            raise PayError(exc.status, exc.detail) from exc
    db.trim_pack_seats(conn, int(user["id"]), keep=pack)

    paid = db.mark_order_paid(
        conn,
        int(order["id"]),
        provider_txn_id=txn[:64],
        paid_at=stamp.isoformat(),
        plan_until=until,
    )
    return paid, False


def verify_wechat_notify(raw: bytes, headers: Any, settings: Settings) -> dict[str, Any]:
    """验签入口。商户号没齐或验签未写时一律拒绝，避免空回调误开通。"""
    del raw, headers
    if not settings.wechat_pay_configured:
        raise PayError(503, "微信支付未配置")
    raise PayError(503, "微信支付验签尚未接入")
