#!/usr/bin/env python3
"""用本机 Chrome（含媒讯助手扩展）打开小红书搜索并采集笔记卡片。

复用媒讯助手 content_scripts/xiaohongshu 的选择器逻辑，在已登录的用户 Profile 下滚动抓取。
输出写入 ~/.skill-feed/xhs/mentions.json（经 xiaohongshu.merge_crawl_notes）。

用法：
  python scripts/xhs_meixun_crawl.py
  python scripts/xhs_meixun_crawl.py --keyword "Claude Skills" --max 30
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import xiaohongshu  # noqa: E402

DEFAULT_KEYWORDS = [
    "Claude Skills",
    "Claude Code Skills",
    "Cursor Skills",
    "SKILL.md",
    "Agent Skills",
    "去AI味 skill",
]

# 媒讯助手 keyword_search 同源选择器（简化版列表采集）
SCRAPE_JS = r"""
() => {
  const cards = [];
  const seen = new Set();
  const anchors = Array.from(document.querySelectorAll(
    'a.cover[href*="/explore/"], a[href*="/explore/"], a[href*="/search_result/"], a[href*="/discovery/item/"]'
  ));
  for (const a of anchors) {
    const href = a.href || a.getAttribute('href') || '';
    const m = href.match(/\/(?:explore|discovery\/item|search_result)\/([a-zA-Z0-9]+)/);
    if (!m) continue;
    const id = m[1];
    if (seen.has(id)) continue;
    seen.add(id);
    let root = a.closest('section') || a.closest('[class*="note"]') || a.parentElement;
    for (let i = 0; i < 5 && root; i++) {
      if ((root.innerText || '').length > 20) break;
      root = root.parentElement;
    }
    const text = (root && root.innerText) || '';
    const lines = text.split(/\n+/).map(s => s.trim()).filter(Boolean);
    const title = lines[0] || '';
    let likes = 0;
    const lm = text.match(/(\d+(?:\.\d+)?)\s*[万wW]?/);
    // 更稳：找带赞/收藏样式的数字
    const nums = text.match(/(\d+(?:\.\d+)?)\s*万|\b\d{2,}\b/g) || [];
    if (nums.length) {
      const raw = nums[nums.length - 1];
      if (/万/.test(raw)) likes = Math.round(parseFloat(raw) * 10000);
      else likes = parseInt(raw.replace(/[^\d]/g, ''), 10) || 0;
    }
    const author = (lines.find(l => l.startsWith('@') || l.length <= 16) || '').replace(/^@/, '');
    cards.push({
      id,
      title: title.slice(0, 120),
      desc: lines.slice(0, 6).join(' · ').slice(0, 400),
      url: href.startsWith('http') ? href.split('?')[0] : ('https://www.xiaohongshu.com/explore/' + id),
      likes,
      author,
    });
  }
  return cards;
}
"""


def _chrome_user_data() -> Path:
    local = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    return local


def crawl_keyword(page, keyword: str, *, max_items: int, week_filter: bool) -> list[dict]:
    q = keyword.replace(" ", "%20")
    # sortBy=popularity_descending & filter by week when possible
    url = (
        f"https://www.xiaohongshu.com/search_result?keyword={q}"
        f"&source=web_search_result_notes&type=51"
    )
    if week_filter:
        url += "&filterNotesType=1"  # best-effort; UI 侧一周筛选可能需点击
    page.goto(url, wait_until="domcontentloaded", timeout=60000)
    time.sleep(3.5)
    # 尝试点「一周内」筛选项（文案匹配）
    if week_filter:
        try:
            for label in ("一周内", "一周", "最新"):
                loc = page.get_by_text(label, exact=False).first
                if loc.count() > 0:
                    loc.click(timeout=1500)
                    time.sleep(1.5)
                    break
        except Exception:  # noqa: BLE001
            pass
    # 尝试点「最多点赞 / 综合」
    try:
        for label in ("最多点赞", "综合"):
            loc = page.get_by_text(label, exact=True).first
            if loc.count() > 0:
                loc.click(timeout=1500)
                time.sleep(1.2)
                break
    except Exception:  # noqa: BLE001
        pass

    collected: dict[str, dict] = {}
    for _ in range(12):
        batch = page.evaluate(SCRAPE_JS) or []
        for c in batch:
            cid = c.get("id") or c.get("url")
            if not cid:
                continue
            prev = collected.get(cid)
            if not prev or int(c.get("likes") or 0) > int(prev.get("likes") or 0):
                c["keyword"] = keyword
                collected[cid] = c
        if len(collected) >= max_items:
            break
        page.mouse.wheel(0, 2400)
        time.sleep(1.2)
    return list(collected.values())[:max_items]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keyword", action="append", dest="keywords", help="可重复")
    ap.add_argument("--max", type=int, default=25, help="每个关键词最多条数")
    ap.add_argument("--data-dir", default=str(Path.home() / ".skill-feed"))
    ap.add_argument("--headed", action="store_true", default=True)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--no-week-filter", action="store_true")
    args = ap.parse_args()
    keywords = args.keywords or DEFAULT_KEYWORDS
    data_dir = Path(args.data_dir).expanduser()
    headed = not args.headless

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[xhs] playwright 不可用，仅写入种子 mentions", file=sys.stderr)
        payload = xiaohongshu.ensure_seed_mentions(data_dir)
        print(json.dumps({"ok": False, "seed_only": True, "repos": len(payload.get("repos") or [])}, ensure_ascii=False))
        return 0

    user_data = _chrome_user_data()
    if not user_data.is_dir():
        print(f"[xhs] Chrome User Data 不存在: {user_data}", file=sys.stderr)
        xiaohongshu.ensure_seed_mentions(data_dir)
        return 1

    # 使用临时 profile 目录复制扩展思路不可行；改用 channel=chrome + 独立临时目录，
    # 并加载已安装的媒讯助手扩展路径（可登录态可能丢失）。
    # 优先：launch_persistent_context 指向 Default（需 Chrome 未占用）。
    ext_id = "mmfpehmdkkgbldpbddjljedhaebeiohj"
    ext_root = user_data / "Default" / "Extensions" / ext_id
    ext_ver = None
    if ext_root.is_dir():
        vers = sorted([p for p in ext_root.iterdir() if p.is_dir()], reverse=True)
        if vers:
            ext_ver = vers[0]

    all_notes: list[dict] = []
    meta = {"extension": str(ext_ver) if ext_ver else "", "keywords": keywords}

    with sync_playwright() as p:
        # 独立上下文 + 加载媒讯助手扩展（用户可在弹出窗口完成登录）
        args_chrome = [
            "--disable-blink-features=AutomationControlled",
            "--profile-directory=Default",
        ]
        context = None
        try:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(user_data),
                channel="chrome",
                headless=False if headed else True,
                args=args_chrome,
                viewport={"width": 1280, "height": 900},
                locale="zh-CN",
            )
        except Exception as e:  # noqa: BLE001
            print(f"[xhs] persistent Default 失败（Chrome 可能已打开）: {e}", file=sys.stderr)
            # fallback：临时目录 + 加载扩展
            tmp = data_dir / "xhs" / "chrome-profile"
            tmp.mkdir(parents=True, exist_ok=True)
            launch_args = ["--disable-blink-features=AutomationControlled"]
            if ext_ver:
                launch_args.append(f"--disable-extensions-except={ext_ver}")
                launch_args.append(f"--load-extension={ext_ver}")
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(tmp),
                channel="chrome",
                headless=False if headed else True,
                args=launch_args,
                viewport={"width": 1280, "height": 900},
                locale="zh-CN",
            )
            meta["fallback_profile"] = str(tmp)

        page = context.new_page()
        # 打开媒讯助手 side panel（提示扩展已加载）
        if ext_ver:
            try:
                page.goto(
                    f"chrome-extension://{ext_id}/side_panel/side_panel.html",
                    wait_until="domcontentloaded",
                    timeout=15000,
                )
                time.sleep(1.0)
                meta["meixun_panel"] = "opened"
            except Exception as e:  # noqa: BLE001
                meta["meixun_panel"] = f"skip: {e}"

        for kw in keywords:
            print(f"[xhs] keyword={kw!r}")
            try:
                notes = crawl_keyword(
                    page, kw, max_items=args.max, week_filter=not args.no_week_filter,
                )
                print(f"[xhs]   notes={len(notes)}")
                all_notes.extend(notes)
            except Exception as e:  # noqa: BLE001
                print(f"[xhs]   FAIL: {e}", file=sys.stderr)
            time.sleep(1.5)

        context.close()

    payload = xiaohongshu.merge_crawl_notes(data_dir, all_notes)
    out = {
        "ok": True,
        "notes_crawled": len(all_notes),
        "repos": len(payload.get("repos") or []),
        "path": str(xiaohongshu.mentions_path(data_dir)),
        "meta": meta,
        "top_titles": [n.get("title") for n in all_notes[:12]],
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
