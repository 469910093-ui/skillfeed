"""短信验证码出口。

抽成单独模块的目的有两个：

1. **测试可 mock 到一个点**。测试只替换 `send_code`，不用碰任何限流 / 存储 /
   门禁逻辑，那些断言才是真的在测安全行为而不是在测桩。
2. **凭据只在这个文件里被读**。AccessKeySecret 从 Settings 取、参与签名、
   然后就地丢弃；不返回、不入库、不进异常消息。上层拿到的只有「成功/失败」。

provider 语义：
- `""`（未配置）→ 抛 503。**不静默降级成 console**：漏配一个变量的后果应该是
  「登不进去」，不是「验证码打到日志里、谁看日志谁能登任意号」。
- `"console"` → 只打服务端日志，且 `Settings.sms_configured` 只在 dev 下认它。
- `"aliyun"` → 真发。签名按阿里云 RPC 规范手写，不引 SDK（少一条依赖链）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from server.config import Settings

ALIYUN_ENDPOINT = "https://dysmsapi.aliyuncs.com/"
ALIYUN_VERSION = "2017-05-25"


class SmsError(RuntimeError):
    """网关侧失败。消息里只允许出现错误码，不允许回显请求参数。"""


def _percent(value: str) -> str:
    """阿里云 RPC 签名要求的 percent encoding（RFC3986 + 三处修正）。"""
    out = quote(str(value), safe="")
    return out.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _sign(params: dict[str, str], access_key_secret: str) -> str:
    canonical = "&".join(
        f"{_percent(k)}={_percent(params[k])}" for k in sorted(params)
    )
    string_to_sign = f"GET&{_percent('/')}&{_percent(canonical)}"
    digest = hmac.new(
        f"{access_key_secret}&".encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


async def _send_aliyun(settings: Settings, phone: str, code: str) -> dict[str, Any]:
    params = {
        "Action": "SendSms",
        "Version": ALIYUN_VERSION,
        "RegionId": settings.sms_region,
        "PhoneNumbers": phone,
        "SignName": settings.sms_sign_name,
        "TemplateCode": settings.sms_template_code,
        # 模板里的变量名按阿里云控制台里那份模板来，默认用最常见的 ${code}
        "TemplateParam": f'{{"code":"{code}"}}',
        "Format": "JSON",
        "AccessKeyId": settings.sms_access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": secrets.token_hex(16),
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    query = dict(params)
    query["Signature"] = _sign(params, settings.sms_access_key_secret)
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(ALIYUN_ENDPOINT, params=query)
    try:
        data = r.json()
    except ValueError as e:
        raise SmsError(f"sms gateway http {r.status_code}") from e
    if not isinstance(data, dict) or data.get("Code") != "OK":
        # 只带 Code。阿里云的 Message 会把手机号和签名名回显出来，
        # 而这个异常可能被上层打进日志
        raise SmsError(f"sms gateway rejected (Code={(data or {}).get('Code')})")
    return {"ok": True, "provider": "aliyun", "biz_id": data.get("BizId") or ""}


async def send_code(settings: Settings, phone: str, code: str) -> dict[str, Any]:
    """把验证码发给手机号。测试替换的就是这个函数。

    返回值只给服务端自己看（会进日志），所以里面不能有验证码。
    """
    provider = settings.sms_provider
    if provider == "aliyun":
        return await _send_aliyun(settings, phone, code)
    if provider == "console":
        if not settings.dev_mode:
            # 双保险：Settings.sms_configured 已经拦了一道，这里再拦一次。
            # 这两处任何一处被改坏，另一处还在
            raise HTTPException(503, "console 短信 provider 仅在 SKILLFEED_DEV=1 下可用")
        print(f"[sms][dev] {phone} -> {code} （仅本地开发；生产会拒绝这个 provider）")
        return {"ok": True, "provider": "console"}
    raise HTTPException(
        503,
        "短信通道未配置：需要 SKILLFEED_SMS_PROVIDER=aliyun 以及 "
        "SKILLFEED_SMS_ACCESS_KEY_ID / SKILLFEED_SMS_ACCESS_KEY_SECRET / "
        "SKILLFEED_SMS_SIGN_NAME / SKILLFEED_SMS_TEMPLATE_CODE。",
    )


def now_s() -> float:
    return time.time()
