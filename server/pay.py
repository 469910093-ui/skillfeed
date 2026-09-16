"""订阅订单与到账开通。

真微信支付（统一下单 / APIv3 验签）还没接。这里先把两件必须先对的事钉死：

1. 下单只写 pending，不发权益。
2. 到账回调按 out_trade_no 幂等开通：同一笔付两次，plan_until 不变。

测开通用 `/api/pay/dev-notify`（SKILLFEED_DEV=1 + 已登录 + 只能操作自己的单）。
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

SKU_YEAR = "subscriber_year"
PROVIDER_WECHAT = "wechat"
STATUS_PENDING = "pending"
STATUS_PAID = "paid"


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


def catalog(settings: Settings) -> dict[str, Sku]:
    days = int(settings.subscriber_days)
    return {
        SKU_YEAR: Sku(
            id=SKU_YEAR,
            plan="subscriber",
            days=days,
            amount_fen=int(settings.sku_year_fen),
            title="订阅一年（定价未锁定）",
        ),
    }


def sku_public(sku: Sku) -> dict[str, Any]:
    return {
        "id": sku.id,
        "title": sku.title,
        "plan": sku.plan,
        "days": sku.days,
        "amount_fen": sku.amount_fen,
        "currency": "CNY",
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
    sku = items.get((sku_id or SKU_YEAR).strip() or SKU_YEAR)
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
) -> tuple[dict[str, Any], bool]:
    """把一笔 pending 单标成已付并开通订阅。

    返回 (order, replay)。replay=True 表示这是重复通知，权益没有再发一次。
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
    sku = items.get(order["sku"])
    if sku is None:
        raise PayError(400, "订单商品已下架")

    stamp = now or datetime.now(timezone.utc)
    user = db.get_user(conn, int(order["user_id"]))
    if user is None:
        raise PayError(404, "订单用户不存在")
    until = next_plan_until(user, sku.days, now=stamp)
    db.set_user_plan(conn, int(user["id"]), sku.plan, until)
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
