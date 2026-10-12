"""微信支付 API v3：Native 扫码下单 + 回调验签解密。

商户私钥、APIv3 密钥、微信支付公钥只从环境变量指向的文件读取，不进日志、不入库。
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Callable, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config import Settings
from server.pay import PayError

NATIVE_PATH = "/v3/pay/transactions/native"
_TIMEOUT = 10.0
_SKEW_S = 300


def pay_appid(settings: Settings) -> str:
    return (getattr(settings, "wechat_pay_appid", "") or getattr(settings, "wechat_app_id", "") or "").strip()


def notify_url(settings: Settings) -> str:
    base = (settings.public_url or "").rstrip("/")
    return f"{base}/api/pay/wechat/notify"


def missing_pay_fields(settings: Settings) -> list[str]:
    """缺哪些配置名。只返回变量名，不返回值。"""
    missing: list[str] = []
    if not (settings.wechat_pay_mchid or "").strip():
        missing.append("SKILLFEED_WECHAT_PAY_MCHID")
    key = (settings.wechat_pay_api_v3_key or "").strip()
    if len(key.encode("utf-8")) != 32:
        missing.append("SKILLFEED_WECHAT_PAY_API_V3_KEY")
    if not (settings.wechat_pay_serial or "").strip():
        missing.append("SKILLFEED_WECHAT_PAY_SERIAL")
    if not _read_pem(getattr(settings, "wechat_pay_private_key_file", "")):
        missing.append("SKILLFEED_WECHAT_PAY_PRIVATE_KEY_FILE")
    if not _read_pem(getattr(settings, "wechat_pay_public_key_file", "")):
        missing.append("SKILLFEED_WECHAT_PAY_PUBLIC_KEY_FILE")
    if not (getattr(settings, "wechat_pay_public_key_id", "") or "").strip():
        missing.append("SKILLFEED_WECHAT_PAY_PUBLIC_KEY_ID")
    if not pay_appid(settings):
        missing.append("SKILLFEED_WECHAT_PAY_APPID")
    if not (settings.public_url or "").startswith("https://"):
        missing.append("SKILLFEED_PUBLIC_URL(https)")
    return missing


def _read_pem(path: str) -> str:
    text = (path or "").strip()
    if not text:
        return ""
    try:
        from pathlib import Path
        raw = Path(text).expanduser().read_text(encoding="utf-8")
    except OSError:
        return ""
    if "-----BEGIN" not in raw:
        return ""
    return raw


def _private_key(settings: Settings):
    pem = _read_pem(getattr(settings, "wechat_pay_private_key_file", ""))
    if not pem:
        raise PayError(503, "微信支付还没开通")
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _public_key(settings: Settings):
    pem = _read_pem(getattr(settings, "wechat_pay_public_key_file", ""))
    if not pem:
        raise PayError(503, "微信支付还没开通")
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def _public_key_for_serial(settings: Settings, serial: str):
    """根据 serial_no 返回对应的公钥，支持主备证书轮换。

    微信支付密钥轮换时，新旧证书会在窗口期内同时使用。
    通过 SKILLFEED_WECHAT_PAY_PUBLIC_KEY_ID_BACKUP 和
    SKILLFEED_WECHAT_PAY_PUBLIC_KEY_FILE_BACKUP 配置备证书。
    """
    primary_serial = (getattr(settings, "wechat_pay_public_key_id", "") or "").strip()
    if serial == primary_serial:
        return _public_key(settings)

    backup_serial = (getattr(settings, "wechat_pay_public_key_id_backup", "") or "").strip()
    backup_file = (getattr(settings, "wechat_pay_public_key_file_backup", "") or "").strip()
    if serial == backup_serial and backup_file:
        pem = _read_pem(backup_file)
        if pem:
            return serialization.load_pem_public_key(pem.encode("utf-8"))

    raise PayError(401, "支付通知证书不在已知列表中")


def _sign(private_key, message: str) -> str:
    sig = private_key.sign(message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode("ascii")


def authorization(settings: Settings, *, method: str, path: str, body: str) -> str:
    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    message = f"{method}\n{path}\n{ts}\n{nonce}\n{body}\n"
    signature = _sign(_private_key(settings), message)
    mchid = settings.wechat_pay_mchid.strip()
    serial = settings.wechat_pay_serial.strip()
    return (
        "WECHATPAY2-SHA256-RSA2048 "
        f'mchid="{mchid}",nonce_str="{nonce}",signature="{signature}",'
        f'timestamp="{ts}",serial_no="{serial}"'
    )


def decrypt_resource(api_v3_key: str, resource: dict[str, Any]) -> dict[str, Any]:
    key = (api_v3_key or "").encode("utf-8")
    if len(key) != 32:
        raise PayError(503, "微信支付还没开通")
    nonce = str(resource.get("nonce") or "").encode("utf-8")
    adata = str(resource.get("associated_data") or "").encode("utf-8")
    try:
        blob = base64.b64decode(str(resource.get("ciphertext") or ""))
        plain = AESGCM(key).decrypt(nonce, blob, adata)
    except Exception as exc:
        raise PayError(400, "支付通知无法解密") from exc
    try:
        data = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayError(400, "支付通知无法解密") from exc
    if not isinstance(data, dict):
        raise PayError(400, "支付通知无法解密")
    return data


def _sanitize_svg_markup(svg: str) -> str:
    """Strip event-handler attributes and <script> elements from SVG markup.

    Defense-in-depth: segno output is trusted, but we sanitize before sending
    to the client so a compromised dependency or MITM cannot inject JS via
    innerHTML on the frontend.
    """
    import re as _re
    svg = _re.sub(r'''\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*')''', '', svg, flags=_re.I)
    svg = _re.sub(r"<script[\s\S]*?</script>", "", svg, flags=_re.I)
    return svg


def qr_svg(code_url: str) -> str:
    import io
    import segno
    buf = io.BytesIO()
    segno.make(code_url, error="m").save(buf, kind="svg", xmldecl=False, scale=4)
    svg = buf.getvalue().decode("utf-8")
    if "<script" in svg.lower():
        return ""
    return _sanitize_svg_markup(svg)


Transport = Callable[[str, str, str, dict[str, str]], tuple[int, str]]


def _http_post(url: str, body: str, headers: dict[str, str]) -> tuple[int, str]:
    with httpx.Client(timeout=_TIMEOUT) as client:
        resp = client.post(url, content=body.encode("utf-8"), headers=headers)
    return resp.status_code, resp.text


def native_prepay(
    settings: Settings,
    *,
    out_trade_no: str,
    amount_fen: int,
    description: str,
    transport: Optional[Transport] = None,
) -> dict[str, str]:
    """向微信下 Native 单，返回 code_url 和二维码 SVG。"""
    if missing_pay_fields(settings):
        raise PayError(503, "微信支付还没开通")
    payload = {
        "appid": pay_appid(settings),
        "mchid": settings.wechat_pay_mchid.strip(),
        "description": (description or "SkillFeeder")[:127],
        "out_trade_no": out_trade_no,
        "notify_url": notify_url(settings),
        "amount": {"total": int(amount_fen), "currency": "CNY"},
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    headers = {
        "Authorization": authorization(settings, method="POST", path=NATIVE_PATH, body=body),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "skill-feed",
    }
    url = "https://api.mch.weixin.qq.com" + NATIVE_PATH
    if transport is None:
        status, text = _http_post(url, body, headers)
    else:
        status, text = transport("POST", url, body, headers)
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        data = {}
    code_url = str((data or {}).get("code_url") or "")
    if status != 200 or not code_url.startswith("weixin://"):
        raise PayError(502, "微信支付下单没有成功")
    return {"code_url": code_url, "qr_svg": qr_svg(code_url)}


def _header(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    value = getter(name)
    if value:
        return str(value).strip()
    # 普通 dict 大小写敏感；微信头是 Wechatpay-*
    lower = name.lower()
    for key, item in getattr(headers, "items", lambda: [])():
        if str(key).lower() == lower and item:
            return str(item).strip()
    return ""


def verify_notify(raw: bytes, headers: Any, settings: Settings) -> dict[str, Any]:
    """验签并解密。trade_state 不是 SUCCESS 时返回 skip，不给权益。"""
    if missing_pay_fields(settings):
        raise PayError(503, "微信支付未配置")
    serial = _header(headers, "Wechatpay-Serial")
    timestamp = _header(headers, "Wechatpay-Timestamp")
    nonce = _header(headers, "Wechatpay-Nonce")
    signature = _header(headers, "Wechatpay-Signature")
    if not serial or not timestamp or not nonce or not signature:
        raise PayError(401, "支付通知验签失败")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise PayError(401, "支付通知验签失败") from exc
    if abs(int(time.time()) - ts) > _SKEW_S:
        raise PayError(401, "支付通知验签失败")
    message = f"{timestamp}\n{nonce}\n{raw.decode('utf-8')}\n"
    try:
        _public_key_for_serial(settings, serial).verify(
            base64.b64decode(signature),
            message.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise PayError(401, "支付通知验签失败") from exc
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayError(400, "支付通知无法解密") from exc
    resource = envelope.get("resource") if isinstance(envelope, dict) else None
    if not isinstance(resource, dict):
        raise PayError(400, "支付通知无法解密")
    data = decrypt_resource(settings.wechat_pay_api_v3_key, resource)
    if str(data.get("mchid") or "") != settings.wechat_pay_mchid.strip():
        raise PayError(400, "支付通知商户不符")
    if str(data.get("appid") or "") != pay_appid(settings):
        raise PayError(400, "支付通知应用不符")
    if str(data.get("trade_state") or "") != "SUCCESS":
        return {"skip": True}
    amount = data.get("amount") if isinstance(data.get("amount"), dict) else {}
    total = amount.get("total")
    return {
        "skip": False,
        "out_trade_no": str(data.get("out_trade_no") or ""),
        "transaction_id": str(data.get("transaction_id") or ""),
        "amount_fen": int(total) if total is not None else None,
    }
