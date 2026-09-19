"""登录：微信服务号网页授权 / 手机号验证码 / GitHub OAuth（可选）+ HMAC 签名 Cookie 会话。

会话机制只有一套：`sign_session` / `verify_session` 的 HMAC 签名 Cookie。
三种登录方式的差别只在「怎么确认你是谁」，确认完统一调 `set_session_cookie`。

## SameSite 这个坑（微信授权回调会跨站跳回来）

会话 Cookie 和 OAuth state Cookie 都用 `SameSite=Lax`，**不能用 Strict**：

- 微信授权流程是 `我们的域 → open.weixin.qq.com → 我们的域/auth/wechat/callback`。
  最后一跳是**跨站的顶层 GET 导航**。Strict 在这种导航里不发送 Cookie，
  于是回调里读不到 state Cookie，每一次微信登录都会以 "bad oauth state" 失败。
  Lax 明确允许「跨站顶层 GET 导航」带上 Cookie，正好覆盖这一跳。
- 会话 Cookie 同理：宣发在小红书 / 抖音 / 公众号，用户是从站外点进来的。
  Strict 会让已登录用户在落地的第一个页面上表现为未登录，被门禁弹回 /login。
- Lax 仍然挡住了 CSRF 的主要形态：跨站 **POST**（表单自动提交、fetch）不带 Cookie。
  写操作全是 POST，所以放宽到 Lax 没有把 CSRF 面打开。

`Secure` 由 `SKILLFEED_PUBLIC_URL` 是否 https 决定 —— 本地 http 调试若强上 Secure，
浏览器会直接丢掉 Cookie，表现为「登录成功但立刻又未登录」。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, Response

from server.config import Settings

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_USER = "https://api.github.com/user"

WECHAT_AUTHORIZE = "https://open.weixin.qq.com/connect/oauth2/authorize"
WECHAT_TOKEN = "https://api.weixin.qq.com/sns/oauth2/access_token"
WECHAT_USERINFO = "https://api.weixin.qq.com/sns/userinfo"

# OAuth state 的 Cookie 名，按 provider 分开：微信和 GitHub 的流程可能同时在途
STATE_COOKIE = {"github": "skillfeed_oauth_state", "wechat": "skillfeed_wx_state"}


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def sign_session(secret: str, payload: dict[str, Any], *, max_age: int) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + max_age
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64e(raw)}.{_b64e(sig)}"


def verify_session(secret: str, token: str) -> Optional[dict[str, Any]]:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = _b64d(raw_b64)
        sig = _b64d(sig_b64)
        expect = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return None
        data = json.loads(raw.decode("utf-8"))
        if int(data.get("exp") or 0) < int(time.time()):
            return None
        return data
    except Exception:  # noqa: BLE001
        return None


# —— 匿名设备凭据 ——
#
# device_id 是客户端自铸的，服务端凭什么相信「这个 device_id 属于你」？答案是：
# 单凭 device_id 不能相信。所以服务端在**首次见到**某个 device_id 时下发一枚
# HMAC 凭据，之后不再补发；并档时校验这枚凭据。
#
# 攻击者即使知道受害者的 device_id，也拿不到对应凭据（它只在注册那一次返回过），
# 而伪造 HMAC 需要 session_secret。攻击者抢先用一个别人还没用过的 device_id
# 注册在理论上可行，但那要求先猜中一个尚未使用的 uuid4，不构成现实威胁。

def device_token(secret: str, device_id: str) -> str:
    mac = hmac.new(
        secret.encode("utf-8"), f"device:{device_id}".encode("utf-8"), hashlib.sha256,
    ).digest()
    return _b64e(mac)


def verify_device_token(secret: str, device_id: str, token: str) -> bool:
    if not device_id or not token:
        return False
    return hmac.compare_digest(device_token(secret, device_id), token)


def cookie_flags(settings: Settings) -> dict[str, Any]:
    """所有 Cookie 的安全属性从这里出，别在调用点各写一遍。

    `samesite="lax"` 是必须的而不是随手写的，理由见模块头「SameSite 这个坑」。
    """
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": settings.public_url.startswith("https://"),
        "path": "/",
    }


def set_session_cookie(resp: Response, settings: Settings, user_id: int, login: str) -> None:
    token = sign_session(
        settings.session_secret,
        {"uid": user_id, "login": login},
        max_age=settings.cookie_max_age,
    )
    resp.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.cookie_max_age,
        **cookie_flags(settings),
    )


def clear_session_cookie(resp: Response, settings: Settings) -> None:
    resp.delete_cookie(settings.cookie_name, path="/")


def session_user_id(request: Request, settings: Settings) -> Optional[int]:
    token = request.cookies.get(settings.cookie_name) or ""
    if not token:
        return None
    data = verify_session(settings.session_secret, token)
    if not data:
        return None
    try:
        return int(data["uid"])
    except (KeyError, TypeError, ValueError):
        return None


def require_user_id(request: Request, settings: Settings) -> int:
    uid = session_user_id(request, settings)
    if uid is None:
        raise HTTPException(status_code=401, detail="login required")
    return uid


def require_operator(request: Request, settings: Settings, login: str) -> int:
    uid = require_user_id(request, settings)
    if (login or "").lower() not in settings.operator_logins:
        raise HTTPException(status_code=403, detail="operator only")
    return uid


# —— OAuth state：签名 + Cookie 双绑 ——
#
# 「回传的 state 等于我发出去的 state」这件事有两种验证方式，这里两个都要：
#
# 1. **签名**：state 本身是 `nonce.exp.HMAC(secret, nonce|exp|purpose)`。
#    服务端不查库就能判断「这串是不是我签的、过期没有」。少了它，攻击者可以
#    自造一个 state 并同时塞一个同值 Cookie（Cookie 是他自己浏览器里的，
#    他当然能控制），纯 Cookie 比对就被绕过了。
# 2. **Cookie 绑定**：state 同时写进 HttpOnly Cookie，回调里要求两边相等。
#    少了它，签名合法的 state 可以被拿去做登录 CSRF —— 攻击者在自己浏览器里
#    走到微信授权页拿到 code，再把 `callback?code=..&state=..` 这条链接发给受害者，
#    受害者点开就被登录成攻击者的账号（之后受害者的收藏行为都记在攻击者账号上）。
#    Cookie 只存在于发起流程的那个浏览器里，绑上它这条路就走不通。
#
# 两条都由服务端判定，没有「客户端说什么就是什么」的部分。


def issue_state(settings: Settings, purpose: str) -> str:
    nonce = secrets.token_urlsafe(16)
    exp = int(time.time()) + max(30, int(settings.oauth_state_ttl_s))
    payload = f"{nonce}.{exp}.{purpose}"
    sig = hmac.new(
        settings.session_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256,
    ).digest()
    return f"{nonce}.{exp}.{_b64e(sig)}"


def verify_state(settings: Settings, purpose: str, state: str, cookie_value: str) -> bool:
    """服务端校验 state：签名有效 + 未过期 + 与 Cookie 一致。任一不成立即拒。"""
    if not state or not cookie_value:
        return False
    # 先比 Cookie：长度不等时 compare_digest 仍是常量时间的
    if not hmac.compare_digest(state.encode("utf-8"), cookie_value.encode("utf-8")):
        return False
    parts = state.split(".")
    if len(parts) != 3:
        return False
    nonce, exp_raw, sig_b64 = parts
    try:
        exp = int(exp_raw)
    except ValueError:
        return False
    if exp < int(time.time()):
        return False
    expect = hmac.new(
        settings.session_secret.encode("utf-8"),
        f"{nonce}.{exp}.{purpose}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    try:
        got = _b64d(sig_b64)
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(got, expect)


def set_state_cookie(resp: Response, settings: Settings, purpose: str, state: str) -> None:
    resp.set_cookie(
        STATE_COOKIE[purpose],
        state,
        max_age=max(30, int(settings.oauth_state_ttl_s)),
        **cookie_flags(settings),
    )


def clear_state_cookie(resp: Response, purpose: str) -> None:
    resp.delete_cookie(STATE_COOKIE[purpose], path="/")


# —— 微信服务号网页授权 ——

def wechat_authorize_url(settings: Settings, state: str) -> str:
    q = urlencode({
        "appid": settings.wechat_app_id,
        "redirect_uri": f"{settings.public_url}/auth/wechat/callback",
        "response_type": "code",
        "scope": settings.wechat_scope,
        "state": state,
    })
    # #wechat_redirect 是微信要求的锚点，少了它在微信客户端里会打不开
    return f"{WECHAT_AUTHORIZE}?{q}#wechat_redirect"


def _wechat_raise(data: dict[str, Any]) -> None:
    """把微信的业务错误转成 4xx。

    只透出 errcode，不透 errmsg 里可能夹带的请求参数 —— 那里面会带上 appid，
    而我们的 502/400 响应体是要发给浏览器的。
    """
    code = data.get("errcode")
    if code:
        raise HTTPException(status_code=400, detail=f"wechat oauth failed (errcode={code})")


async def exchange_wechat_code(settings: Settings, code: str) -> dict[str, Any]:
    """code → {access_token, openid, unionid?}。

    AppSecret 在这里作为 query 参数发给微信（微信只提供这一种形式）。
    它不进日志、不进异常消息、不进任何响应体。
    """
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(WECHAT_TOKEN, params={
            "appid": settings.wechat_app_id,
            "secret": settings.wechat_app_secret,
            "code": code,
            "grant_type": "authorization_code",
        })
        r.raise_for_status()
        data = r.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="wechat token: unexpected payload")
    _wechat_raise(data)
    if not data.get("openid") or not data.get("access_token"):
        raise HTTPException(status_code=502, detail="wechat token: missing openid")
    return data


async def fetch_wechat_userinfo(
    settings: Settings, access_token: str, openid: str,
) -> dict[str, Any]:
    """拿昵称头像。scope=snsapi_base 时这一步会失败，调用方要能容忍。"""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(WECHAT_USERINFO, params={
            "access_token": access_token, "openid": openid, "lang": "zh_CN",
        })
        r.raise_for_status()
        data = r.json()
    if not isinstance(data, dict) or data.get("errcode"):
        return {}
    return data


# —— 手机号 / 验证码 ——

def normalize_phone(raw: str) -> str:
    """只接受中国大陆 11 位手机号，返回规范化结果或空串。

    白名单式校验：非法输入直接变空串，调用方看到空串就 400。
    这道校验同时是短信费用的闸门 —— 不校验格式，任意字符串都会被送去
    短信网关，每条都要付钱。

    先卡字符集再抽数字，顺序很重要：反过来（直接 filter isdigit）会把
    `+8613800138000x` 里的字母静默剥掉后判成合法号码，等于「随便夹点垃圾
    就能绕过格式校验」。只容忍人类真会输入的分隔符。
    """
    text = (raw or "").strip()
    if not text or len(text) > 24:
        return ""
    if any(ch not in "0123456789 -()+" for ch in text):
        return ""
    digits = "".join(ch for ch in text if ch.isdigit())
    if digits.startswith("0086"):
        digits = digits[4:]
    elif digits.startswith("86") and len(digits) == 13:
        digits = digits[2:]
    if len(digits) != 11 or digits[0] != "1" or digits[1] not in "3456789":
        return ""
    return digits


def hash_sms_code(secret: str, phone: str, code: str) -> str:
    """验证码入库前的摘要。

    用 HMAC + session_secret 而不是裸 sha256：验证码只有 6 位十进制，
    裸哈希的全部 100 万种取值可以在毫秒级枚举完，落库的摘要等于明文。
    加了服务端密钥，拿到库的人没有密钥就没法反查。
    """
    return _b64e(hmac.new(
        secret.encode("utf-8"),
        f"sms:{phone}:{code}".encode("utf-8"),
        hashlib.sha256,
    ).digest())


def new_sms_code() -> str:
    """6 位数字验证码，用 CSPRNG。

    不用 random.randint：那是可预测的 Mersenne Twister，观察到几个验证码之后
    就能推出后续的，等于任意账号可登。
    """
    return f"{secrets.randbelow(1000000):06d}"


def github_redirect_uri(settings: Settings) -> str:
    """Must match the GitHub OAuth App callback exactly."""
    return f"{settings.public_url.rstrip('/')}/auth/github/callback"


def github_authorize_url(settings: Settings, state: str) -> str:
    q = urlencode({
        "client_id": settings.github_client_id,
        "redirect_uri": github_redirect_uri(settings),
        "scope": "read:user",
        "state": state,
    })
    return f"{GITHUB_AUTHORIZE}?{q}"


def oauth_handoff_html(authorize_url: str, *, heading: str, nonce: str) -> str:
    """200 HTML 中转页：先落下 state Cookie，再跳到 GitHub / 微信。

    不要对第三方授权页直接 302。iOS Safari、微信/小红书/抖音 WebView 经常
    **丢掉 302 响应上的 Set-Cookie**，回调里就读不到 state，表现为「电脑能登、
    手机完全不行」。200 先让浏览器提交 Cookie，再 `location.replace`。
    """
    from html import escape as html_escape

    safe_attr = html_escape(authorize_url, quote=True)
    safe_js = json.dumps(authorize_url)
    safe_heading = html_escape(heading)
    return (
        "<!DOCTYPE html><html lang=\"zh-CN\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<meta http-equiv=\"refresh\" content=\"1;url={safe_attr}\">"
        f"<title>{safe_heading}</title>"
        "<style>body{margin:0;min-height:100vh;display:flex;align-items:center;"
        "justify-content:center;font-family:\"PingFang SC\",\"Microsoft YaHei\",sans-serif;"
        "background:#0c1020;color:#f4f7ff}.box{text-align:center;padding:24px;line-height:1.6}"
        "a{color:#64e2d4}</style></head><body><div class=\"box\">"
        f"<p>{safe_heading}</p>"
        f"<p><a href=\"{safe_attr}\">如果没有自动跳转，点这里继续</a></p>"
        "</div>"
        f"<script nonce=\"{nonce}\">setTimeout(function(){{location.replace({safe_js});}},220);"
        "</script></body></html>"
    )


async def exchange_github_code(settings: Settings, code: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(
            GITHUB_TOKEN,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": github_redirect_uri(settings),
            },
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access = token_data.get("access_token")
        if not access:
            raise HTTPException(status_code=400, detail=token_data.get("error") or "oauth failed")
        user_resp = await client.get(
            GITHUB_USER,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access}",
                "User-Agent": "skill-feed-api",
            },
        )
        user_resp.raise_for_status()
        return user_resp.json()
