#!/usr/bin/env python3
"""每日把 sitemap 里的页面推给百度搜索资源平台（普通收录 · API 提交）。

百度按站点给每日额度（新站 6 条）。按优先级挑当天该推的页面：
首页与说明页 → 场景页 → Skill 详情页；没推过的先推，全推过一轮后从最早推的开始轮。
已推记录存在 --state（Actions 里靠 cache 跨天保存），丢了只是重推，不会出错。

  BAIDU_PUSH_TOKEN=xxx python scripts/baidu_push.py --state .baidu-push/state.json
  python scripts/baidu_push.py --state ... --mark URL [URL ...]   # 只记账不推
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SITE = "https://skillfeeder.cn"
SITEMAP_URL = f"{SITE}/sitemap.xml"
PUSH_ENDPOINT = "http://data.zz.baidu.com/urls"
DEFAULT_QUOTA = 6
TIMEOUT = 20
# 百度额度按北京时间自然日重置
BEIJING = timezone(timedelta(hours=8))

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")
_TOP_PATHS = ("/", "/skills.html", "/about.html", "/faq.html", "/compare.html")


def today() -> str:
    return datetime.now(BEIJING).strftime("%Y-%m-%d")


def parse_sitemap(xml: str) -> list[str]:
    seen: set[str] = set()
    out = []
    for url in _LOC_RE.findall(xml):
        if url.startswith(SITE + "/") and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _tier(url: str) -> int:
    path = url[len(SITE):] or "/"
    if path in _TOP_PATHS:
        return 0
    if path.startswith("/scene/"):
        return 1
    return 2


def pick_batch(urls: list[str], pushed: dict[str, str], quota: int) -> list[str]:
    """没推过的按优先级在前；全推过后按上次推送日期从早到晚轮。"""
    order = {u: i for i, u in enumerate(urls)}
    fresh = sorted((u for u in urls if u not in pushed), key=lambda u: (_tier(u), order[u]))
    if len(fresh) >= quota:
        return fresh[:quota]
    stale = sorted((u for u in urls if u in pushed), key=lambda u: (pushed[u], _tier(u), order[u]))
    return (fresh + stale)[:quota]


def load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"pushed": {}, "quota": DEFAULT_QUOTA}
    if not isinstance(data, dict):
        return {"pushed": {}, "quota": DEFAULT_QUOTA}
    data.setdefault("pushed", {})
    data.setdefault("quota", DEFAULT_QUOTA)
    return data


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")


def fetch_sitemap() -> str:
    req = urllib.request.Request(SITEMAP_URL, headers={"User-Agent": "skillfeed-baidu-push"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8")


def push(urls: list[str], token: str) -> tuple[int, dict]:
    query = urllib.parse.urlencode({"site": SITE, "token": token})
    req = urllib.request.Request(
        f"{PUSH_ENDPOINT}?{query}",
        data="\n".join(urls).encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"message": body[:200]}


def summary(lines: list[str]) -> None:
    text = "\n".join(lines)
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", type=Path, required=True)
    ap.add_argument("--mark", nargs="*", default=None, help="只把这些 URL 记为今天已推，不调用百度")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    state = load_state(args.state)
    day = today()

    mark = args.mark if args.mark is not None else os.environ.get("BAIDU_PUSH_MARK", "").split()
    if mark:
        for url in mark:
            if url.startswith(SITE + "/"):
                state["pushed"][url] = day
        save_state(args.state, state)
        summary([f"百度推送：只记账 {len(mark)} 条（{day}），未调用接口"])
        return 0

    token = (os.environ.get("BAIDU_PUSH_TOKEN") or "").strip()
    if not token and not args.dry_run:
        summary(["::error title=百度推送未执行::缺少 BAIDU_PUSH_TOKEN（仓库 Secrets）"])
        return 1

    try:
        urls = parse_sitemap(fetch_sitemap())
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as e:
        summary([f"::error title=百度推送未执行::拉 sitemap 失败：{e}"])
        return 1
    if not urls:
        summary(["::error title=百度推送未执行::sitemap 里没有本站 URL"])
        return 1

    quota = max(1, int(state.get("quota") or DEFAULT_QUOTA))
    batch = pick_batch(urls, state["pushed"], quota)
    if args.dry_run:
        summary([f"百度推送 dry-run：sitemap {len(urls)} 条，今天会推 {len(batch)} 条"] + batch)
        return 0

    status, body = push(batch, token)
    success = int(body.get("success") or 0)
    if status != 200 or success == 0:
        msg = body.get("message") or body
        if "over quota" in str(msg).lower():
            summary([f"::warning title=百度推送额度已满::今天额度已用完（{msg}），明天自动继续"])
            return 0
        summary([f"::error title=百度推送失败::HTTP {status}：{msg}"])
        return 1

    for url in batch[:success]:
        state["pushed"][url] = day
    remain = int(body.get("remain") or 0)
    # 百度会给老站加额度：当天第一次推的 success + remain 就是今天的额度
    state["quota"] = max(DEFAULT_QUOTA, success + remain)
    state["last_run"] = {"day": day, "success": success, "remain": remain}
    save_state(args.state, state)

    covered = sum(1 for u in urls if u in state["pushed"])
    head = (f"百度推送成功 {success} 条，今日剩余额度 {remain}；"
            f"sitemap {len(urls)} 条里已推过 {covered} 条")
    summary([head, *(f"- {u}" for u in batch[:success])])
    return 0


if __name__ == "__main__":
    sys.exit(main())
