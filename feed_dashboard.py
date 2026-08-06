"""生成 Instagram 风格无限下滑 Feed HTML（只推荐到 GitHub）。"""

from __future__ import annotations

import json
from pathlib import Path

import scene


def _resolve_variant(feed: dict, variant: str | None = None) -> str:
    v = (variant or (feed.get("ui") or {}).get("variant") or "full").strip().lower()
    return v if v in ("full", "lite") else "full"


def build_feed_html(feed: dict, *, variant: str | None = None) -> str:
    """生成 Feed HTML。

    variant:
      - full：独立网页产品（Stories/关注/发布/我的）
      - lite：给 skill-picker 嵌入的发现子页（无关注/发布/个人后台）
    """
    variant = _resolve_variant(feed, variant)
    feed = dict(feed)
    ui = dict(feed.get("ui") or {})
    ui["variant"] = variant
    feed["ui"] = ui
    payload = json.dumps(feed, ensure_ascii=False)
    scenes = json.dumps(feed.get("scenes") or scene.scene_chips(), ensure_ascii=False)
    scenes_l2 = json.dumps(feed.get("scenes_l2") or scene.scene_l2_tree(), ensure_ascii=False)
    page_title = "去 GitHub 发现" if variant == "lite" else "skill-feed"
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>{page_title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Billabong&family=Cookie&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #fafafa;
    --ink: #262626;
    --muted: #8e8e8e;
    --line: #dbdbdb;
    --card: #ffffff;
    --like: #ed4956;
    --link: #00376b;
    --ring: linear-gradient(45deg, #f09433 0%, #e6683c 25%, #dc2743 50%, #cc2366 75%, #bc1888 100%);
    --font: "Outfit", "PingFang SC", "Microsoft YaHei", sans-serif;
    --logo: "Cookie", "Billabong", cursive;
    --phone: 470px;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; background: #efefef; color: var(--ink); font-family: var(--font); }}
  body {{ min-height: 100vh; }}

  .shell {{
    max-width: var(--phone);
    margin: 0 auto;
    min-height: 100vh;
    background: var(--bg);
    border-left: 1px solid var(--line);
    border-right: 1px solid var(--line);
    position: relative;
  }}

  .topbar {{
    position: sticky; top: 0; z-index: 40;
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 14px 8px;
    background: rgba(250,250,250,.92);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }}
  .top-left {{ display: flex; flex-direction: column; gap: 2px; min-width: 0; }}
  .logo {{
    font-family: var(--logo);
    font-size: 2rem;
    line-height: 1;
    letter-spacing: .02em;
    background: var(--ring);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }}
  .logo span {{ color: var(--ink); background: none; -webkit-background-clip: unset; background-clip: unset; }}
  .status {{
    font-size: .62rem; color: var(--muted); font-weight: 600;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}
  .top-actions {{ display: flex; gap: 14px; align-items: center; flex-shrink: 0; }}
  .icon-btn {{
    appearance: none; border: 0; background: transparent; padding: 0;
    cursor: pointer; color: var(--ink); display: inline-flex;
  }}
  .icon-btn svg {{ width: 24px; height: 24px; }}
  .icon-btn.demo-on {{ color: var(--like); }}
  .demo-badge {{
    font-size: .65rem; font-weight: 700; color: #fff;
    background: var(--like); border-radius: 999px; padding: 2px 7px;
    margin-left: -6px; margin-top: -12px;
  }}

  .search-wrap {{ padding: 8px 12px 0; background: var(--bg); }}
  .search {{
    width: 100%; border: 0; border-radius: 10px;
    background: #efefef; padding: 9px 12px;
    font: inherit; font-size: .9rem; color: var(--ink);
  }}
  .search::placeholder {{ color: var(--muted); }}
  .search:focus {{ outline: 2px solid #c7c7c7; outline-offset: 0; background: #fff; }}
  .intent-keys {{
    display: flex; flex-wrap: wrap; align-items: center; gap: 6px;
    padding: 6px 2px 2px; font-size: .72rem; color: var(--muted);
  }}
  .intent-keys[hidden] {{ display: none !important; }}
  .intent-keys b {{ color: var(--ink); font-weight: 700; }}
  .intent-keys .ik {{
    border: 1px solid var(--line); background: #fff; border-radius: 999px;
    padding: 2px 8px; color: var(--ink); font-weight: 600;
  }}

  .stories-wrap {{
    background: var(--card); border-bottom: 1px solid var(--line);
  }}
  .stories-wrap.hidden {{ display: none; }}
  .stories-hint {{
    display: flex; align-items: flex-start; gap: 8px;
    padding: 10px 12px 0; font-size: .72rem; line-height: 1.45; color: var(--muted);
  }}
  .stories-hint b {{ color: var(--ink); font-weight: 700; }}
  .stories-hint .hint-close {{
    appearance: none; border: 0; background: transparent; color: var(--muted);
    cursor: pointer; font-size: 1rem; line-height: 1; padding: 0 2px; margin-left: auto;
  }}
  .stories-hint.flash {{
    animation: hintFlash 1.2s ease;
  }}
  @keyframes hintFlash {{
    0%, 100% {{ background: transparent; }}
    30% {{ background: rgba(237,73,86,.08); }}
  }}
  .stories {{
    display: flex; gap: 14px; overflow-x: auto; padding: 12px 12px 12px;
    scrollbar-width: none;
  }}
  .stories::-webkit-scrollbar {{ display: none; }}
  .story {{
    flex: 0 0 auto; width: 72px; text-align: center; cursor: pointer;
    background: transparent; border: 0; padding: 0; font: inherit; color: inherit;
  }}
  .story .ring {{
    width: 66px; height: 66px; margin: 0 auto 6px; padding: 2px;
    border-radius: 50%; background: #dbdbdb;
  }}
  .story.hot .ring, .story.has-new .ring {{ background: var(--ring); }}
  .story.guide .ring {{ background: #e8e8e8; }}
  .story .face {{
    width: 100%; height: 100%; border-radius: 50%;
    background: #fff; padding: 2px; display: grid; place-items: center;
  }}
  .story .face i {{
    width: 100%; height: 100%; border-radius: 50%;
    display: grid; place-items: center;
    font-style: normal; font-weight: 700; font-size: .85rem; color: #fff;
  }}
  .story.guide .face i {{
    background: #f5f5f5 !important; color: var(--ink); font-size: 1.35rem; font-weight: 500;
  }}
  .story .label {{
    display: block; font-size: .68rem; color: var(--ink);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 72px;
  }}

  .filter-strip {{
    display: none; gap: 8px; overflow-x: auto; padding: 8px 12px;
    background: var(--card); border-bottom: 1px solid var(--line);
    scrollbar-width: none;
  }}
  .filter-strip.show {{ display: flex; }}
  .filter-strip::-webkit-scrollbar {{ display: none; }}
  .pill {{
    flex: 0 0 auto; border: 1px solid var(--line); background: #fff;
    border-radius: 999px; padding: 6px 12px; font-size: .75rem; font-weight: 600;
    color: var(--ink); cursor: pointer; white-space: nowrap;
  }}
  .pill.on {{ background: var(--ink); color: #fff; border-color: var(--ink); }}
  .sr-only {{ position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); }}

  .feed {{ background: var(--bg); padding-bottom: 88px; }}
  .post {{
    background: var(--card);
    border-bottom: 1px solid var(--line);
    margin: 0;
    animation: postIn .45s ease both;
  }}
  .post.corpus .media {{ filter: saturate(.85); }}
  .post.soft .media {{ filter: saturate(.92) brightness(1.02); }}
  @keyframes postIn {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to {{ opacity: 1; transform: none; }}
  }}
  .post.focus {{ box-shadow: inset 3px 0 0 var(--like); }}

  .post-head {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px;
  }}
  .avatar {{
    width: 36px; height: 36px; border-radius: 50%;
    padding: 2px; background: var(--ring); flex: 0 0 auto;
  }}
  .avatar span {{
    display: grid; place-items: center; width: 100%; height: 100%;
    border-radius: 50%; background: #fff; font-weight: 700; font-size: .75rem;
  }}
  .avatar span b {{
    display: grid; place-items: center; width: 100%; height: 100%;
    border-radius: 50%; color: #fff; font-weight: 700;
  }}
  .who {{ flex: 1; min-width: 0; }}
  .who .name {{ font-weight: 700; font-size: .9rem; }}
  .who .sub {{ font-size: .72rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .more {{ border: 0; background: transparent; font-size: 1.2rem; cursor: pointer; color: var(--ink); }}

  /* Real cover (GitHub OG) + SKILL.md document preview */
  .media {{
    position: relative;
    width: 100%;
    aspect-ratio: 2 / 1;
    overflow: hidden;
    cursor: pointer;
    user-select: none;
    background: #0d1117;
  }}
  .media .cover {{
    position: absolute; inset: 0;
    width: 100%; height: 100%;
    object-fit: contain; object-position: center;
    display: block;
    background: #0d1117;
  }}
  .media.no-cover .cover {{ display: none; }}
  .media .cover-fallback {{
    display: none; position: absolute; inset: 0;
    padding: 16px; color: #fff;
    background: linear-gradient(145deg, #24292f, #0d1117);
  }}
  .media.no-cover .cover-fallback {{ display: flex; flex-direction: column; justify-content: flex-end; gap: 6px; }}
  .media .cover-fallback .t {{ font-size: 1.2rem; font-weight: 700; }}
  .media .cover-fallback .d {{ font-size: .8rem; opacity: .85; line-height: 1.35; }}
  .media .badges {{
    position: absolute; left: 10px; top: 10px; z-index: 2;
    display: flex; flex-wrap: wrap; gap: 6px;
  }}
  .media .badge {{
    font-size: .66rem; font-weight: 700; color: #fff;
    background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.22);
    backdrop-filter: blur(6px); border-radius: 999px; padding: 3px 8px;
  }}
  .media .badge.kb {{ background: rgba(237,73,86,.85); border-color: transparent; }}
  .media .badge.soft {{ background: rgba(255,193,7,.92); color: #262626; border-color: transparent; }}
  .heart-burst {{
    position: absolute; left: 50%; top: 50%; width: 90px; height: 90px;
    margin: -45px 0 0 -45px; opacity: 0; pointer-events: none; z-index: 3;
    color: #fff; filter: drop-shadow(0 4px 12px rgba(0,0,0,.35));
  }}
  .heart-burst.go {{ animation: burst .7s ease forwards; }}
  @keyframes burst {{
    0% {{ opacity: 0; transform: scale(.3); }}
    25% {{ opacity: 1; transform: scale(1.15); }}
    100% {{ opacity: 0; transform: scale(1.4); }}
  }}

  .pitch {{
    margin: 0; padding: 12px 14px 6px;
    background: #fff;
  }}
  .pitch .problem {{
    font-size: .95rem; font-weight: 650; line-height: 1.35;
    margin: 0 0 10px; letter-spacing: -.01em;
  }}
  .pitch .problem em {{
    font-style: normal; font-size: .68rem; font-weight: 700;
    color: #fff; background: var(--ink); border-radius: 6px;
    padding: 2px 6px; margin-right: 6px; vertical-align: 1px;
  }}
  .pitch .highlights {{
    list-style: none; margin: 0; padding: 0; display: grid; gap: 6px;
  }}
  .pitch .highlights li {{
    position: relative; padding: 8px 10px 8px 28px;
    background: #f6f8fa; border: 1px solid #eaeef2; border-radius: 10px;
    font-size: .8rem; line-height: 1.35; color: #24292f;
  }}
  .pitch .highlights li::before {{
    content: "✦"; position: absolute; left: 10px; top: 8px;
    color: var(--like); font-size: .75rem;
  }}
  .pitch .doc-link {{
    display: inline-block; margin-top: 10px;
    font-size: .75rem; font-weight: 600; color: var(--link); text-decoration: none;
  }}
  .who.clickable {{ cursor: pointer; }}
  .who.clickable:hover .name {{ text-decoration: underline; }}
  .avatar.clickable {{ cursor: pointer; }}
  .pub-panel {{ padding: 16px 14px 28px; }}
  .pub-head {{
    display: flex; gap: 12px; align-items: center; margin-bottom: 14px;
  }}
  .pub-head .ava {{
    width: 56px; height: 56px; border-radius: 50%;
    display: grid; place-items: center; color: #fff; font-weight: 700; font-size: 1.1rem;
  }}
  .pub-head h2 {{ margin: 0; font-size: 1.2rem; }}
  .pub-head p {{ margin: 4px 0 0; font-size: .8rem; color: var(--muted); }}
  .pub-actions {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }}
  .pub-actions a, .pub-actions button {{
    appearance: none; border: 1px solid var(--line); background: #fff; color: var(--ink);
    border-radius: 999px; padding: 7px 12px; font: inherit; font-size: .78rem; font-weight: 600;
    cursor: pointer; text-decoration: none;
  }}
  .pub-actions a.primary, .pub-actions button.primary {{
    background: var(--ink); color: #fff; border-color: var(--ink);
  }}
  .pub-actions button.following {{ background: #efefef; color: var(--ink); border-color: var(--line); }}
  .follow-mini {{
    appearance: none; flex: 0 0 auto; margin-left: auto;
    border: 1px solid var(--ink); background: var(--ink); color: #fff;
    border-radius: 8px; padding: 5px 10px; font: inherit; font-size: .72rem; font-weight: 700;
    cursor: pointer;
  }}
  .follow-mini.on {{ background: #fff; color: var(--ink); border-color: var(--line); }}
  .media .badge.clickable {{ cursor: pointer; text-decoration: underline; text-underline-offset: 2px; }}
  .sheet {{
    position: fixed; inset: 0; z-index: 90; display: none;
    background: rgba(0,0,0,.45); align-items: flex-end; justify-content: center;
  }}
  .sheet.open {{ display: flex; }}
  .sheet-panel {{
    width: min(100%, var(--phone)); background: #fff; border-radius: 16px 16px 0 0;
    padding: 16px 16px calc(18px + env(safe-area-inset-bottom));
    max-height: 72vh; overflow: auto;
  }}
  .sheet-panel h3 {{ margin: 0 0 6px; font-size: 1.05rem; }}
  .sheet-panel .lead {{ margin: 0 0 12px; font-size: .8rem; color: var(--muted); line-height: 1.45; }}
  .sheet-row {{
    display: flex; align-items: center; gap: 10px; width: 100%;
    border: 1px solid var(--line); background: #fff; border-radius: 12px;
    padding: 10px 12px; margin-bottom: 8px; font: inherit; text-align: left; cursor: pointer;
  }}
  .sheet-row .ava {{
    width: 36px; height: 36px; border-radius: 50%; flex: 0 0 auto;
    display: grid; place-items: center; color: #fff; font-weight: 700; font-size: .75rem;
  }}
  .sheet-row .meta {{ flex: 1; min-width: 0; }}
  .sheet-row .meta b {{ display: block; font-size: .88rem; }}
  .sheet-row .meta span {{ font-size: .72rem; color: var(--muted); }}
  .sheet-row .act-label {{ font-size: .72rem; font-weight: 700; color: var(--like); white-space: nowrap; }}
  .sheet-close {{
    appearance: none; width: 100%; margin-top: 8px; border: 0; background: #efefef;
    border-radius: 10px; padding: 10px; font: inherit; font-weight: 700; cursor: pointer;
  }}
  .follow-chip {{
    display: inline-flex; align-items: center; gap: 6px; margin: 0 6px 6px 0;
    border: 1px solid var(--line); background: #fff; border-radius: 999px;
    padding: 5px 10px; font-size: .75rem; font-weight: 600; cursor: pointer;
  }}
  .follow-chip button {{
    appearance: none; border: 0; background: transparent; color: var(--muted);
    cursor: pointer; font-size: .85rem; padding: 0; line-height: 1;
  }}
  .pub-sec {{ font-size: .72rem; font-weight: 700; color: var(--muted); letter-spacing: .04em;
    text-transform: uppercase; margin: 14px 0 8px; }}
  .pub-item {{
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 12px; margin-bottom: 8px; cursor: pointer;
  }}
  .pub-item strong {{ display: block; margin-bottom: 4px; }}
  .pub-item p {{ margin: 0; font-size: .8rem; color: var(--muted); line-height: 1.4; }}
  .pub-item .meta {{ margin-top: 6px; font-size: .72rem; color: var(--muted); }}

  .actions {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 10px 2px;
  }}
  .actions-left {{ display: flex; gap: 14px; }}
  .act {{
    appearance: none; border: 0; background: transparent; padding: 4px;
    cursor: pointer; color: var(--ink); display: inline-flex;
  }}
  .act svg {{ width: 26px; height: 26px; }}
  .act.liked, .act.saved {{ color: var(--like); }}
  .act.liked svg, .act.saved svg {{ fill: var(--like); }}

  .likes {{ padding: 0 14px; font-size: .86rem; font-weight: 700; }}
  .caption {{
    padding: 4px 14px 2px; font-size: .9rem; line-height: 1.45;
  }}
  .caption b {{ font-weight: 700; margin-right: 6px; }}
  .caption .more-link {{ color: var(--muted); cursor: pointer; font-weight: 500; }}
  .caption .full-desc {{ display: none; }}
  .caption.expanded .short-desc {{ display: none; }}
  .caption.expanded .full-desc {{ display: inline; }}
  .why-line {{
    padding: 0 14px 4px; font-size: .78rem; color: var(--muted);
  }}
  .time {{
    padding: 2px 14px 14px; font-size: .68rem; color: var(--muted);
    letter-spacing: .04em; text-transform: uppercase;
  }}
  .open-row {{ padding: 0 14px 14px; }}
  .open-gh {{
    display: block; text-align: center; text-decoration: none;
    border-radius: 10px; padding: 10px 12px;
    background: var(--ink); color: #fff; font-weight: 700; font-size: .88rem;
  }}

  .sentinel {{ text-align: center; padding: 22px 12px; color: var(--muted); font-size: .8rem; }}
  .empty {{ text-align: center; padding: 64px 20px; color: var(--muted); }}
  .empty h2 {{ color: var(--ink); font-size: 1.1rem; }}
  .empty p {{ font-size: .85rem; line-height: 1.5; }}

  .bottom {{
    position: sticky; bottom: 0; z-index: 40;
    display: flex; justify-content: space-around; align-items: center;
    padding: 10px 4px calc(10px + env(safe-area-inset-bottom));
    background: rgba(255,255,255,.96);
    border-top: 1px solid var(--line);
  }}
  .nav {{
    border: 0; background: transparent; color: var(--ink); cursor: pointer;
    display: grid; place-items: center; gap: 2px; font-size: .58rem; font-weight: 600;
    min-width: 52px;
  }}
  .nav svg {{ width: 24px; height: 24px; }}
  .nav.on {{ color: var(--like); }}
  .me-panel {{ padding: 18px 16px 28px; }}
  .me-panel h2 {{ margin: 0 0 6px; font-size: 1.2rem; }}
  .me-panel .lead {{ color: var(--muted); font-size: .88rem; line-height: 1.45; margin: 0 0 16px; }}
  .me-card {{
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 12px 14px; margin-bottom: 10px;
  }}
  .me-card strong {{ display: block; margin-bottom: 4px; }}
  .me-card p {{ margin: 0; font-size: .82rem; color: var(--muted); line-height: 1.4; }}
  .me-actions {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
  .me-actions a, .me-actions button {{
    appearance: none; border: 1px solid var(--line); background: #fff; color: var(--ink);
    border-radius: 999px; padding: 7px 12px; font: inherit; font-size: .78rem; font-weight: 600;
    cursor: pointer; text-decoration: none;
  }}
  .me-actions a.primary, .me-actions button.primary {{
    background: var(--ink); color: #fff; border-color: var(--ink);
  }}

  .demo-bar {{
    position: fixed; left: 50%; bottom: 72px; transform: translateX(-50%);
    z-index: 60; display: none; align-items: center; gap: 10px;
    background: rgba(38,38,38,.92); color: #fff;
    padding: 10px 14px; border-radius: 999px;
    font-size: .78rem; font-weight: 600; max-width: calc(var(--phone) - 24px);
    width: max-content;
  }}
  .demo-bar.show {{ display: flex; }}
  .demo-bar .dot {{
    width: 8px; height: 8px; border-radius: 50%; background: var(--like);
    animation: pulse 1s ease infinite;
  }}
  @keyframes pulse {{
    0%,100% {{ opacity: .4; transform: scale(.9); }}
    50% {{ opacity: 1; transform: scale(1.15); }}
  }}
  .demo-bar button {{
    border: 0; border-radius: 999px; padding: 5px 10px;
    background: #fff; color: var(--ink); font: inherit; font-size: .72rem; font-weight: 700; cursor: pointer;
  }}

  .toast {{
    position: fixed; left: 50%; top: 64px; transform: translateX(-50%);
    background: rgba(38,38,38,.92); color: #fff;
    padding: 10px 14px; border-radius: 10px; font-size: .8rem;
    opacity: 0; transition: opacity .2s; z-index: 80; pointer-events: none;
    max-width: calc(var(--phone) - 32px); text-align: center;
  }}
  .toast.show {{ opacity: 1; }}

  /* —— Fullscreen story viewer（场景色底 + 完整封面卡，禁止 cover 裁切） —— */
  .story-viewer {{
    position: fixed; inset: 0; z-index: 100;
    background: #111; display: none; flex-direction: column;
    max-width: var(--phone); margin: 0 auto;
    left: 50%; transform: translateX(-50%);
    width: 100%;
  }}
  .story-viewer.open {{ display: flex; }}
  .sv-progress {{
    display: flex; gap: 4px; padding: 10px 10px 6px;
    position: absolute; top: 0; left: 0; right: 0; z-index: 2;
  }}
  .sv-bar {{
    flex: 1; height: 2px; background: rgba(255,255,255,.35); border-radius: 2px; overflow: hidden;
  }}
  .sv-bar i {{
    display: block; height: 100%; width: 0; background: #fff;
    transition: width .1s linear;
  }}
  .sv-bar.done i {{ width: 100%; }}
  .sv-bar.active i {{ animation: svFill 3.5s linear forwards; }}
  @keyframes svFill {{ from {{ width: 0; }} to {{ width: 100%; }} }}
  .sv-head {{
    position: absolute; top: 18px; left: 0; right: 0; z-index: 3;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 14px; color: #fff;
    text-shadow: 0 1px 8px rgba(0,0,0,.35);
  }}
  .sv-head .who {{ font-size: .85rem; font-weight: 700; }}
  .sv-close {{
    border: 0; background: rgba(0,0,0,.35); color: #fff;
    width: 32px; height: 32px; border-radius: 50%; cursor: pointer; font-size: 1.2rem;
  }}
  .sv-body {{
    flex: 1; position: relative;
    display: flex; flex-direction: column;
    touch-action: pan-y;
    padding: 56px 14px 96px;
    overflow: hidden;
  }}
  .sv-slide {{
    position: absolute; inset: 0;
    background: linear-gradient(160deg, #7c3aed 0%, #db2777 45%, #f59e0b 100%);
    transition: background .35s ease;
  }}
  .sv-slide::after {{
    content: ""; position: absolute; inset: 0; pointer-events: none;
    background:
      radial-gradient(circle at 12% 18%, rgba(255,255,255,.28), transparent 42%),
      radial-gradient(circle at 88% 12%, rgba(255,255,255,.18), transparent 36%),
      linear-gradient(180deg, rgba(0,0,0,.08) 0%, rgba(0,0,0,.18) 40%, rgba(0,0,0,.55) 100%);
  }}
  .sv-shade {{ display: none; }}
  .sv-stage {{
    position: relative; z-index: 1;
    display: flex; flex-direction: column; gap: 14px;
    height: 100%; min-height: 0;
  }}
  .sv-cover-wrap {{
    flex: 0 0 auto;
    border-radius: 14px; overflow: hidden;
    background: rgba(255,255,255,.12);
    border: 1px solid rgba(255,255,255,.22);
    box-shadow: 0 12px 36px rgba(0,0,0,.28);
  }}
  .sv-cover {{
    display: block; width: 100%;
    aspect-ratio: 2 / 1;
    object-fit: contain; object-position: center;
    background: rgba(0,0,0,.2);
  }}
  .sv-cover.hidden {{ display: none; }}
  .sv-content {{
    position: relative; z-index: 1;
    color: #fff; flex: 1; min-height: 0;
    display: flex; flex-direction: column; gap: 8px;
    overflow: auto;
  }}
  .sv-content .chips {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .sv-content .chip {{
    font-size: .68rem; font-weight: 700; padding: 4px 8px; border-radius: 999px;
    background: rgba(255,255,255,.2); border: 1px solid rgba(255,255,255,.28);
    backdrop-filter: blur(6px);
  }}
  .sv-content h2 {{
    margin: 0; font-size: 1.45rem; line-height: 1.2;
    text-shadow: 0 2px 12px rgba(0,0,0,.25);
  }}
  .sv-content p {{
    margin: 0; font-size: .88rem; opacity: .95; line-height: 1.45;
    background: rgba(0,0,0,.22); border: 1px solid rgba(255,255,255,.14);
    border-radius: 12px; padding: 10px 12px;
    max-height: 38vh; overflow: auto;
    white-space: pre-wrap; word-break: break-word;
  }}
  .sv-content .meta {{ font-size: .75rem; opacity: .88; }}
  .sv-foot {{
    position: absolute; bottom: 0; left: 0; right: 0; z-index: 2;
    padding: 16px 16px calc(16px + env(safe-area-inset-bottom));
  }}
  .sv-cta {{
    display: block; text-align: center; text-decoration: none;
    border-radius: 10px; padding: 12px; background: #fff; color: var(--ink);
    font-weight: 700; font-size: .9rem;
    box-shadow: 0 8px 24px rgba(0,0,0,.25);
  }}
  .sv-tap-left, .sv-tap-right {{
    position: absolute; top: 60px; bottom: 80px; width: 28%; z-index: 1;
  }}
  .sv-tap-left {{ left: 0; }}
  .sv-tap-right {{ right: 0; }}

  /* lite：skill-picker 发现子页 — 无 Stories/关注/发布/我的 */
  body.variant-lite .stories-wrap,
  body.variant-lite #followSheet,
  body.variant-lite .nav[data-action="publish"],
  body.variant-lite .nav[data-mode="me"],
  body.variant-lite .follow-mini,
  body.variant-lite #btnDemo {{ display: none !important; }}
  body.variant-lite .bottom {{ justify-content: center; }}
  body.variant-lite .bottom .nav[data-mode="all"] {{ min-width: 120px; }}
  body.variant-lite .feed {{ padding-bottom: 24px; }}
  body.variant-lite .lite-banner {{
    display: block; padding: 10px 14px; font-size: .78rem; line-height: 1.45;
    color: var(--muted); background: #fff; border-bottom: 1px solid var(--line);
  }}
  body.variant-lite .lite-banner b {{ color: var(--ink); }}
  .lite-banner {{ display: none; }}

  @media (max-width: 520px) {{
    .shell {{ border: 0; }}
    .story-viewer {{ max-width: 100%; left: 0; transform: none; }}
  }}
</style>
</head>
<body class="variant-{variant}">
  <div class="shell">
    <header class="topbar">
      <div class="top-left">
        <div class="logo">skill<span>feed</span></div>
        <div class="status" id="genStatus">更新 —</div>
      </div>
      <div class="top-actions">
        <button class="icon-btn" id="btnDemo" type="button" title="自动 Demo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="6,4 20,12 6,20"/></svg>
        </button>
        <span class="demo-badge" id="demoBadge" hidden>DEMO</span>
        <button class="icon-btn" id="btnHeart" type="button" title="反馈说明">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>
        </button>
      </div>
    </header>
    <div class="lite-banner" id="liteBanner">
      <b>本机没有合适 skill 时</b>，在这里按意图浏览远程线索，点「打开 GitHub」自行安装；装好后回 skill-picker 再扫一遍。
    </div>

    <div class="search-wrap" id="searchWrap">
      <input class="search" id="intent" type="search" placeholder="短关键词更好，如：去AI味 / 周报 / 剪视频" maxlength="40" />
      <div class="intent-keys" id="intentKeys" hidden></div>
    </div>

    <div class="stories-wrap" id="storiesWrap">
      <div class="stories-hint" id="storiesHint">
        <span><b>顶部圆环 = 你关注的最新动态</b>：关注 Builder 或行业后，新内容会出现在这里优先观看。</span>
        <button type="button" class="hint-close" id="storiesHintClose" aria-label="关闭提示">×</button>
      </div>
      <div class="stories" id="stories" aria-label="关注动态 Stories"></div>
    </div>
    <div class="sr-only" id="sceneLabel">一级场景</div>
    <div class="sr-only" id="sceneL2Label">二级场景</div>
    <div class="filter-strip" id="sceneStrip" aria-label="行业筛选"></div>
    <div class="filter-strip" id="l2Strip" aria-label="二级场景"></div>
    <div class="filter-strip" id="sectionStrip" aria-label="栏目"></div>

    <main class="feed" id="feed"></main>

    <nav class="bottom">
      <button class="nav on" type="button" data-mode="all" title="发现">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
        发现
      </button>
      <button class="nav" type="button" data-action="publish" title="发布">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
        发布
      </button>
      <button class="nav" type="button" data-mode="me" title="我的">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"/></svg>
        我的
      </button>
    </nav>
  </div>

  <div class="story-viewer" id="storyViewer" aria-hidden="true">
    <div class="sv-progress" id="svProgress"></div>
    <div class="sv-head">
      <div class="who" id="svWho">内容创作</div>
      <button type="button" class="sv-close" id="svClose" aria-label="关闭">&times;</button>
    </div>
    <div class="sv-body" id="svBody">
      <div class="sv-tap-left" id="svPrev" aria-label="上一条"></div>
      <div class="sv-tap-right" id="svNext" aria-label="下一条"></div>
      <div class="sv-slide" id="svSlide"></div>
      <div class="sv-stage">
        <div class="sv-cover-wrap" id="svCoverWrap">
          <img class="sv-cover" id="svCover" alt="" loading="lazy" referrerpolicy="no-referrer" />
        </div>
        <div class="sv-content" id="svContent"></div>
      </div>
    </div>
    <div class="sv-foot">
      <a class="sv-cta" id="svCta" href="#" target="_blank" rel="noopener">打开 GitHub</a>
    </div>
  </div>

  <div class="demo-bar" id="demoBar">
    <span class="dot"></span>
    <span id="demoText">Demo 巡演中</span>
    <button type="button" id="demoStop">停止</button>
  </div>
  <div class="toast" id="toast"></div>
  <div class="sheet" id="followSheet" aria-hidden="true">
    <div class="sheet-panel" id="followSheetPanel"></div>
  </div>

<script>
const FEED = {payload};
const SCENES = {scenes};
const SCENES_L2 = {scenes_l2};
const VARIANT = ((FEED.ui && FEED.ui.variant) || 'full');
const IS_LITE = VARIANT === 'lite';
const PAGE = 6;
const STORY_MS = 3500;
const API_BASE = IS_LITE ? '' : (((FEED.ui && FEED.ui.api_base) || '').replace(/\\/$/, ''));
const state = {{ mode: 'all', scene: 'all', scene_l2: 'all', section: 'all', shown: 0, intent: '', publisher: '' }};
const demo = {{ on: false, step: 0, timer: null, focus: -1 }};
const sv = {{ open: false, scene: '', items: [], idx: 0, timer: null }};
const publisherCache = {{}};

const PALETTES = [
  ['#ff6a3d','#c32bad','#7028e4'],
  ['#00c6ff','#0072ff','#7b2ff7'],
  ['#f7971e','#ffd200','#f53844'],
  ['#11998e','#38ef7d','#0f766e'],
  ['#ee0979','#ff6a00','#f9d423'],
  ['#396afc','#2948ff','#00d2ff'],
  ['#232526','#414345','#757F9A'],
  ['#fc466b','#3f5efb','#00f2fe'],
];

function loadSet(key) {{
  try {{
    const raw = localStorage.getItem(key);
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr : []);
  }} catch (e) {{
    return new Set();
  }}
}}

function persistSet(key, set) {{
  try {{ localStorage.setItem(key, JSON.stringify([...set])); }} catch (e) {{}}
}}

const liked = loadSet('sf_liked');
const saved = loadSet('sf_saved');
const followBuilders = loadSet('sf_follow_builders');
const followIndustries = loadSet('sf_follow_industries');

function toast(msg, ms) {{
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), ms || 2600);
}}

function flashStoriesHint() {{
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
  const hint = document.getElementById('storiesHint');
  if (!hint) return;
  if (hint.hidden) {{
    hint.hidden = false;
    try {{ localStorage.removeItem('sf_stories_hint_dismissed'); }} catch (e) {{}}
  }}
  hint.classList.remove('flash');
  void hint.offsetWidth;
  hint.classList.add('flash');
}}

function followToast(kind, name) {{
  const who = kind === 'builder' ? ('@' + name) : name;
  toast('已关注 ' + who + ' · 最新动态会出现在顶部 Stories 圆环', 3200);
  flashStoriesHint();
}}

function escapeHtml(s) {{
  return String(s ?? '').replace(/[&<>"']/g, c => ({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }})[c]);
}}

function sourceLabel(src) {{
  if (!src) return 'unknown';
  if (src === 'github.com/trending') return 'trending';
  if (src === 'hellogithub') return 'HelloGitHub';
  if (src === 'github-search') return 'GitHub Search';
  if (src === 'corpus') return '知识库';
  return src;
}}

function hashHue(s) {{
  let h = 0;
  for (let i = 0; i < (s||'').length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
}}

function paletteFor(key) {{
  return PALETTES[hashHue(key) % PALETTES.length];
}}

function initials(name) {{
  const s = (name || '?').replace(/[^A-Za-z0-9\\u4e00-\\u9fff]/g, '');
  return (s.slice(0, 2) || '?').toUpperCase();
}}

function fmtGeneratedAt() {{
  const g = FEED.generated_at;
  const host = (FEED.ui && FEED.ui.hosting === 'pages') ? ' · 网站' : '';
  if (!g) return '更新 —' + host;
  try {{
    const d = new Date(g);
    if (Number.isNaN(d.getTime())) return '更新 ' + String(g).slice(0, 16) + host;
    const s = d.toLocaleString('zh-CN', {{ month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }});
    return '更新 ' + s + host;
  }} catch (e) {{
    return '更新 ' + String(g).slice(0, 16) + host;
  }}
}}

function allPool() {{
  const live = FEED.items || [];
  const backup = FEED.corpus || [];
  const seen = new Set();
  const out = [];
  for (const it of live.concat(backup)) {{
    const k = it.full_name || it.id;
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(it);
  }}
  return out;
}}

function kindOf(it) {{
  return it.kind || (it.skill_path ? 'skill' : 'oss');
}}

function matchModeValue(it, mode) {{
  const kind = kindOf(it);
  const sec = it.hg_section || '';
  if (mode === 'all' || mode === 'me' || mode === 'saved') return true;
  if (mode === 'skills') return kind === 'skill' || !!it.skill_path || sec === 'Skills';
  if (mode === 'ai') return kind === 'ai' || sec === '人工智能';
  if (mode === 'oss') return kind !== 'skill' && !it.skill_path && sec !== 'Skills';
  return true;
}}

function matchMode(it) {{
  return matchModeValue(it, state.mode);
}}

function countMode(mode) {{
  return allPool().filter(it => matchModeValue(it, mode)).length;
}}

function countScene(sceneId) {{
  return allPool().filter(it => matchMode(it) && (it.scene || 'other') === sceneId).length;
}}

function countSection(secId) {{
  if (secId === 'all') return allPool().filter(it => matchMode(it)).length;
  return allPool().filter(it => {{
    if (!matchMode(it)) return false;
    const sec = it.hg_section || '';
    return !!sec && (sec === secId || sec.includes(secId));
  }}).length;
}}

function countL2(l2Id) {{
  if (l2Id === 'all') return countScene(state.scene);
  return allPool().filter(it =>
    matchMode(it) && (it.scene || 'other') === state.scene && (it.scene_l2 || '') === l2Id
  ).length;
}}

function ownerOf(it) {{
  return it.owner || (it.full_name || '').split('/')[0] || '';
}}

function sceneLabelOf(sceneId) {{
  return (SCENES.find(s => s.id === sceneId) || {{}}).label || sceneId;
}}

function isFollowingBuilder(owner) {{
  return !!owner && followBuilders.has(owner);
}}

function isFollowingIndustry(sceneId) {{
  return !!sceneId && followIndustries.has(sceneId);
}}

function toggleFollowBuilder(owner, opts) {{
  if (!owner) return false;
  const now = !followBuilders.has(owner);
  if (now) followBuilders.add(owner); else followBuilders.delete(owner);
  persistSet('sf_follow_builders', followBuilders);
  if (opts && opts.silent) return now;
  if (now) followToast('builder', owner);
  else toast('已取消关注 @' + owner);
  render(false);
  return now;
}}

function toggleFollowIndustry(sceneId, opts) {{
  if (!sceneId || sceneId === 'all') return false;
  const now = !followIndustries.has(sceneId);
  if (now) followIndustries.add(sceneId); else followIndustries.delete(sceneId);
  persistSet('sf_follow_industries', followIndustries);
  if (opts && opts.silent) return now;
  if (now) followToast('industry', sceneLabelOf(sceneId));
  else toast('已取消关注「' + sceneLabelOf(sceneId) + '」');
  render(false);
  return now;
}}

function builderItems(owner, limit) {{
  const q = state.intent.trim().toLowerCase();
  return allPool()
    .filter(it => ownerOf(it) === owner)
    .sort((a, b) => scoreRow(b, q) - scoreRow(a, q))
    .slice(0, limit || 5);
}}

function industryItems(sceneId, limit) {{
  const q = state.intent.trim().toLowerCase();
  return allPool()
    .filter(it => (it.scene || 'other') === sceneId)
    .sort((a, b) => scoreRow(b, q) - scoreRow(a, q))
    .slice(0, limit || 5);
}}

function followingItems(limit) {{
  const q = state.intent.trim().toLowerCase();
  return allPool()
    .filter(it => isFollowingBuilder(ownerOf(it)) || isFollowingIndustry(it.scene || 'other'))
    .sort((a, b) => scoreRow(b, q) - scoreRow(a, q))
    .slice(0, limit || 8);
}}

function topBuilders(limit) {{
  const counts = new Map();
  for (const it of allPool()) {{
    const o = ownerOf(it);
    if (!o) continue;
    counts.set(o, (counts.get(o) || 0) + 1);
  }}
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit || 12)
    .map(([owner, n]) => ({{ owner, n }}));
}}

function closeFollowSheet() {{
  const el = document.getElementById('followSheet');
  el.classList.remove('open');
  el.setAttribute('aria-hidden', 'true');
}}

function openFollowSheet(kind) {{
  if (IS_LITE) return;
  const panel = document.getElementById('followSheetPanel');
  if (kind === 'builder') {{
    const rows = topBuilders(16);
    panel.innerHTML = `<h3>发现 Builder</h3>
      <p class="lead">关注后，Ta 的最新 skill 会出现在<strong>顶部 Stories 圆环</strong>，方便优先观看。</p>` +
      rows.map(r => {{
        const on = isFollowingBuilder(r.owner);
        const pal = paletteFor(r.owner);
        return `<button type="button" class="sheet-row js-sheet-follow-builder" data-owner="${{escapeHtml(r.owner)}}">
          <div class="ava" style="background:${{pal[1]}}">${{escapeHtml(initials(r.owner))}}</div>
          <div class="meta"><b>@${{escapeHtml(r.owner)}}</b><span>Feed 内 ${{r.n}} 条</span></div>
          <span class="act-label">${{on ? '已关注 · 点按取消' : '关注'}}</span>
        </button>`;
      }}).join('') +
      `<button type="button" class="sheet-close js-sheet-close">关闭</button>`;
  }} else {{
    const rows = SCENES.filter(s => countScene(s.id) > 0);
    panel.innerHTML = `<h3>发现行业</h3>
      <p class="lead">关注行业后，该领域最新内容会出现在<strong>顶部 Stories 圆环</strong>。</p>` +
      rows.map(s => {{
        const on = isFollowingIndustry(s.id);
        const pal = paletteFor('scene:' + s.id);
        const n = countScene(s.id);
        return `<button type="button" class="sheet-row js-sheet-follow-industry" data-scene="${{escapeHtml(s.id)}}">
          <div class="ava" style="background:linear-gradient(135deg,${{pal[0]}},${{pal[2]}})">${{escapeHtml(initials(s.label))}}</div>
          <div class="meta"><b>${{escapeHtml(s.label)}}</b><span>Feed 内 ${{n}} 条</span></div>
          <span class="act-label">${{on ? '已关注 · 点按取消' : '关注'}}</span>
        </button>`;
      }}).join('') +
      `<button type="button" class="sheet-close js-sheet-close">关闭</button>`;
  }}
  const el = document.getElementById('followSheet');
  el.classList.add('open');
  el.setAttribute('aria-hidden', 'false');
}}

function openIndustrySheet(sceneId) {{
  if (IS_LITE || !sceneId) return;
  const label = sceneLabelOf(sceneId);
  const on = isFollowingIndustry(sceneId);
  const panel = document.getElementById('followSheetPanel');
  panel.innerHTML = `<h3>${{escapeHtml(label)}}</h3>
    <p class="lead">关注后，该行业最新动态会出现在<strong>顶部 Stories 圆环</strong>；也可只筛选发现流。</p>
    <button type="button" class="sheet-row js-sheet-follow-industry" data-scene="${{escapeHtml(sceneId)}}">
      <div class="meta"><b>${{on ? '取消关注行业' : '关注行业'}}</b>
      <span>${{on ? '圆环将不再优先展示该行业' : '最新内容进顶部圆环'}}</span></div>
      <span class="act-label">${{on ? '已关注' : '关注'}}</span>
    </button>
    <button type="button" class="sheet-row js-sheet-filter-scene" data-scene="${{escapeHtml(sceneId)}}">
      <div class="meta"><b>只看该行业 Feed</b><span>用下方 pills 筛选发现流</span></div>
      <span class="act-label">筛选</span>
    </button>
    <button type="button" class="sheet-close js-sheet-close">关闭</button>`;
  const el = document.getElementById('followSheet');
  el.classList.add('open');
  el.setAttribute('aria-hidden', 'false');
}}

function apiUrl(path) {{
  if (!API_BASE) return '';
  return API_BASE + (path.startsWith('/') ? path : ('/' + path));
}}

function openPublish() {{
  if (IS_LITE) {{
    toast('发现子页不支持发布 · 请打开完整 skill-feed 网站');
    return;
  }}
  const url = apiUrl('/publish');
  if (url) {{
    window.open(url, '_blank', 'noopener');
    return;
  }}
  toast('请先启动 API：python skillfeed.py api（或配置 ui.api_base）');
}}

const INTENT_STOP = new Set(
  '的了呢吗啊把被在是有我要帮做一份一个能否可以怎么如何请帮忙去掉删除去除一下帮我给我用到进行进行中以及还有就是这个那个什么哪些为了把它给'.split('')
);
const INTENT_PHRASES = [
  '去ai味', 'ai味', 'stop-slop', '周报复盘', '周报', '复盘', '剪视频', '短视频',
  '去ai', '文案', '写作', '润色', '飞书', 'figma', '图表', 'ppt', '演示',
  'cad', '知识图谱', '代码审查', '架构图', '网页推荐',
];

/** 长意图 → 短关键词（便于匹配与结果展示） */
function compressIntent(raw) {{
  const src = String(raw || '').trim();
  if (!src) return {{ keys: [], query: '', shortened: false }};
  const lower = src.toLowerCase().replace(/\\s+/g, ' ');
  const compact = lower.replace(/\\s+/g, '');
  const keys = [];
  const push = (k) => {{
    const t = String(k || '').trim();
    if (!t || t.length < 2) return;
    // 更长短语优先：若新词覆盖旧词则替换
    for (let i = 0; i < keys.length; i++) {{
      const x = keys[i];
      if (x === t) return;
      if (t.includes(x) && t.length > x.length) {{ keys[i] = t; return; }}
      if (x.includes(t)) return;
    }}
    keys.push(t);
  }};

  // 0) 场景特判先写入（短且准）
  let cjk = '';
  for (const ch of compact) {{
    if (/[\\u4e00-\\u9fff]/.test(ch) && !INTENT_STOP.has(ch)) cjk += ch;
  }}
  if (/ai味|去ai|ai写作|stop-slop|slop/.test(compact) || (cjk.includes('文案') && (compact.includes('ai') || cjk.includes('味')))) {{
    push('去AI味');
    if (cjk.includes('文案')) push('文案');
  }}
  if (/周报|复盘/.test(compact)) push(compact.includes('复盘') && compact.includes('周报') ? '周报复盘' : (compact.includes('周报') ? '周报' : '复盘'));
  if (/剪视频|短视频|口播/.test(compact)) push('剪视频');

  // 1) 短语库
  for (const p of INTENT_PHRASES) {{
    if (compact.includes(p) || lower.includes(p)) {{
      if (p === 'ai味' || p === '去ai' || p === '去ai味') push('去AI味');
      else push(p);
    }}
  }}
  // 2) 英文词
  for (const w of lower.match(/[a-z][a-z0-9\\-]{{1,24}}/g) || []) {{
    if (!['the', 'and', 'for', 'with', 'from', 'this', 'that', 'skill', 'skills'].includes(w)) push(w);
  }}
  // 3) 中文补足
  if (keys.length < 3) {{
    for (let len = 3; len >= 2 && keys.length < 3; len--) {{
      for (let i = 0; i + len <= cjk.length && keys.length < 3; i++) {{
        const slice = cjk.slice(i, i + len);
        if (/^[的了呢吗啊把被在是有我要帮]+$/.test(slice)) continue;
        push(slice);
      }}
    }}
  }}

  // 已经很短：原样（最多 12 字）
  const alreadyShort = compact.length <= 12 && src.split(/\\s+/).length <= 3;
  if (alreadyShort && !keys.length) {{
    return {{ keys: [src], query: src, shortened: false }};
  }}
  const picked = keys.slice(0, 3);
  if (!picked.length) {{
    const fallback = (cjk || compact).slice(0, 8);
    return {{ keys: fallback ? [fallback] : [src.slice(0, 12)], query: fallback || src.slice(0, 12), shortened: src.length > 12 }};
  }}
  const query = picked.join(' ');
  return {{ keys: picked, query, shortened: query !== src && compact.length > 8 }};
}}

function effectiveIntent() {{
  return compressIntent(state.intent).query.toLowerCase();
}}

function renderIntentKeys() {{
  const el = document.getElementById('intentKeys');
  if (!el) return;
  const {{ keys, shortened }} = compressIntent(state.intent);
  if (!state.intent.trim() || !keys.length) {{
    el.hidden = true;
    el.innerHTML = '';
    return;
  }}
  el.hidden = false;
  el.innerHTML = (shortened ? '<span>已提炼</span>' : '<span>关键词</span>') +
    keys.map(k => `<span class="ik">${{escapeHtml(k)}}</span>`).join('') +
    (shortened ? '<b>· 用短词结果更准</b>' : '');
}}

function applyIntentInput(raw, {{ forceCompress = false, silent = false }} = {{}}) {{
  const src = String(raw || '');
  const packed = compressIntent(src);
  const el = document.getElementById('intent');
  const tooLong = src.replace(/\\s+/g, '').length > 10 || src.length > 16;
  const use = (forceCompress || tooLong) ? packed.query : src.trim();
  state.intent = use;
  if (el && el.value !== use) el.value = use;
  if (!silent && packed.shortened && use && use !== src.trim()) {{
    toast('已提炼短关键词：' + use, 2200);
  }}
  renderIntentKeys();
}}

function intentHay(it) {{
  const tips = (typeof extractHighlightsClient === 'function') ? extractHighlightsClient(it) : {{}};
  const hl = Array.isArray(tips.highlights) ? tips.highlights.join(' ') : '';
  return (
    (it.name || '') + ' ' + (it.description || '') + ' ' + (it.full_name || '') + ' ' +
    (it.one_liner || '') + ' ' + (it.problem || '') + ' ' + (it.body_preview || '') + ' ' +
    (it.scene_label || '') + ' ' + (it.scene_l2_label || '') + ' ' + hl + ' ' +
    ((it.highlights || []).join ? (it.highlights || []).join(' ') : '')
  ).toLowerCase();
}}

function intentTokens(q) {{
  const packed = compressIntent(q);
  const raw = (packed.query || q || '').trim().toLowerCase();
  if (!raw) return [];
  const out = new Set(packed.keys.map(k => k.toLowerCase()));
  for (const part of raw.split(/\\s+/).filter(Boolean)) out.add(part);
  const compact = raw.replace(/\\s+/g, '');
  for (let i = 0; i < compact.length - 1; i++) {{
    const a = compact[i], b = compact[i + 1];
    if (/[\\u4e00-\\u9fff]/.test(a) || /[\\u4e00-\\u9fff]/.test(b)) out.add(a + b);
  }}
  if (/ai\\s*味|去\\s*ai|slop|人味|润色|去ai|去ai味/.test(raw) || (/文案/.test(raw) && /ai|味/.test(raw))) {{
    ['slop', 'stop-slop', 'ai writing', 'ai味', '去ai', '去ai味', '写作', '文案', '润色', 'human'].forEach(t => out.add(t));
  }}
  return [...out].filter(t => t.length >= 2);
}}

function intentMatch(it, q) {{
  if (!q) return true;
  const query = compressIntent(q).query.toLowerCase() || q;
  const hay = intentHay(it);
  if (hay.includes(query)) return true;
  const toks = intentTokens(query);
  if (!toks.length) return hay.includes(query);
  let hits = 0;
  for (const t of toks) if (hay.includes(t)) hits += 1;
  if (hits >= 1 && toks.length <= 2) return true;
  if (hits >= 2) return true;
  const strong = ['stop-slop', 'slop', 'ai味', '去ai', '去ai味', 'hallmark'];
  return strong.some(s => toks.includes(s) && hay.includes(s));
}}

function liveIntentBoost(it, q) {{
  if (!q) return 0;
  const hay = intentHay(it);
  let n = 0;
  for (const part of intentTokens(q)) {{
    if (hay.includes(part)) n += 1;
  }}
  return n * 0.08;
}}

function scoreRow(it, q) {{
  return (Number(it.personal_score) || Number(it.rel_score) || 0) + liveIntentBoost(it, q);
}}

function filtered() {{
  const q = effectiveIntent();

  if (state.mode === 'saved') {{
    const keep = new Set([...liked, ...saved]);
    const rows = allPool().filter(it => {{
      const fn = it.full_name || '';
      if (!fn || !keep.has(fn)) return false;
      if (q && !intentMatch(it, q)) return false;
      return true;
    }});
    rows.sort((a, b) => scoreRow(b, q) - scoreRow(a, q));
    return rows;
  }}

  const rows = allPool().filter(it => {{
    if (!matchMode(it)) return false;
    if (state.scene !== 'all' && (it.scene || 'other') !== state.scene) {{
      if (state.mode === 'skills' || state.mode === 'all') return false;
    }}
    if (state.scene_l2 !== 'all' && (it.scene_l2 || '') !== state.scene_l2) return false;
    if (state.section !== 'all') {{
      const sec = it.hg_section || '';
      if (!sec || (!sec.includes(state.section) && sec !== state.section)) return false;
    }}
    if (q && !intentMatch(it, q)) return false;
    return true;
  }});
  rows.sort((a, b) => scoreRow(b, q) - scoreRow(a, q));
  return rows;
}}

function sceneItems(sceneId, limit) {{
  const q = state.intent.trim().toLowerCase();
  return allPool()
    .filter(it => matchMode(it) && (it.scene || 'other') === sceneId)
    .sort((a, b) => scoreRow(b, q) - scoreRow(a, q))
    .slice(0, limit || 5);
}}

function l2Options() {{
  if (state.scene === 'all') return [];
  const kids = (SCENES_L2[state.scene] || [])
    .filter(k => countL2(k[0]) > 0)
    .map(([id, label]) => ({{ id, label }}));
  if (!kids.length) return [];
  return [{{ id: 'all', label: '全部二级' }}].concat(kids);
}}

function sectionOptions() {{
  const set = new Map();
  for (const it of allPool()) {{
    if (!matchMode(it)) continue;
    const sec = it.hg_section;
    if (sec) set.set(sec, sec.replace(/ 项目$/, ''));
  }}
  const preferred = ['Skills','人工智能','Python 项目','JavaScript 项目','Go 项目','Rust 项目','开源书籍','其它'];
  const rest = [...set.keys()].filter(k => !preferred.includes(k)).sort();
  const ids = preferred.filter(k => set.has(k) && countSection(k) > 0)
    .concat(rest.filter(k => countSection(k) > 0));
  if (!ids.length) return [];
  return [{{ id: 'all', label: '全部栏目' }}].concat(ids.map(id => ({{ id, label: set.get(id) }})));
}}

async function sendFeedback(action, it) {{
  const body = {{
    action,
    full_name: it.full_name || '',
    source: it.source || '',
    scene: it.scene || '',
    scene_l2: it.scene_l2 || '',
    from_corpus: !!it.from_corpus,
  }};
  try {{
    const resp = await fetch('/api/feedback', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    const data = await resp.json();
    if (!demo.on) toast(data.ok ? ('已记录 · ' + action) : (data.error || '反馈失败'));
  }} catch (e) {{
    if (!demo.on) toast('serve 模式下可写 feedback.jsonl');
  }}
}}

function heartSvg(filled) {{
  if (filled) return `<svg viewBox="0 0 24 24"><path d="M12 21s-7.2-4.5-9.5-8.2C.7 9.6 2.2 6 5.5 6c1.9 0 3.1 1.1 3.8 2.1C10 7.1 11.2 6 13.1 6c3.3 0 4.8 3.6 3 6.8C19.2 16.5 12 21 12 21z"/></svg>`;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>`;
}}

function bookmarkSvg(filled) {{
  if (filled) return `<svg viewBox="0 0 24 24"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>`;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>`;
}}

function friendlyWhy(it) {{
  const bits = [];
  if (it.scene_label) bits.push(it.scene_label);
  if (it.scene_l2_label) bits.push(it.scene_l2_label);
  if (it.soft) bits.push('知识库线索');
  else if (it.from_corpus) bits.push('知识库');
  if (it.source) bits.push(sourceLabel(it.source));
  return bits.length ? ('因为 · ' + bits.join(' · ')) : '';
}}

function extractHighlightsClient(it) {{
  if (Array.isArray(it.highlights) && it.highlights.length && it.problem) {{
    return {{ problem: it.problem, highlights: it.highlights.slice(0, 4) }};
  }}
  const desc = (it.description || it.one_liner || '').trim();
  const body = (it.body_preview || '').trim();
  const bullets = [];
  const headings = [];
  const paras = [];
  for (const raw of body.split('\\n')) {{
    const line = raw.trim();
    if (!line || line === '---' || line.startsWith('```')) continue;
    const hm = line.match(/^#{{1,3}}\\s+(.+)$/);
    if (hm) {{ const h = hm[1].replace(/[`*_]/g,'').trim(); if (h.length >= 8 && h.length <= 120) headings.push(h); continue; }}
    const bm = line.match(/^(?:[-*]|\\d+\\.)\\s+(.+)$/);
    if (bm) {{ const b = bm[1].replace(/[`*_]/g,'').replace(/\\[[^\\]]+\\]\\([^)]+\\)/g, '$1').trim(); if (b.length >= 8 && b.length <= 120) bullets.push(b); continue; }}
    if (line.startsWith('#') || line.startsWith('<')) continue;
    const p = line.replace(/[`*_]/g,'').trim();
    if (p.length >= 8 && p.length <= 120) paras.push(p);
  }}
  let problem = desc || paras[0] || headings[0] || (it.name || 'Skill');
  if (problem.length > 110) problem = problem.slice(0, 109) + '…';
  const highlights = [];
  const seen = new Set();
  for (const x of bullets.concat(headings).concat(paras.slice(1))) {{
    const k = x.toLowerCase();
    if (seen.has(k) || k === problem.toLowerCase()) continue;
    seen.add(k);
    highlights.push(x);
    if (highlights.length >= 4) break;
  }}
  if (!highlights.length) highlights.push('打开 GitHub 查看完整 SKILL.md 与用法');
  return {{ problem, highlights }};
}}

function cardHtml(it, idx) {{
  const url = it.url || ('https://github.com/' + it.full_name);
  const fn = it.full_name || '';
  const pal = paletteFor(fn || it.name || String(idx));
  const stars = (it.stars == null) ? '—' : Number(it.stars).toLocaleString();
  const score = it.personal_score != null ? Number(it.personal_score).toFixed(2)
    : (it.rel_score != null ? Number(it.rel_score).toFixed(2) : '—');
  const why = friendlyWhy(it);
  const tips = extractHighlightsClient(it);
  const cover = it.cover_url || (fn ? ('https://opengraph.githubassets.com/1/' + fn) : '');
  const skillUrl = it.skill_url || (it.skill_path ? ('https://github.com/' + fn + '/blob/HEAD/' + it.skill_path) : url);
  const isLiked = liked.has(fn);
  const isSaved = saved.has(fn);
  const focus = demo.focus === idx ? 'focus' : '';
  const owner = it.owner || (fn.split('/')[0] || 'skill');
  const softCls = it.soft ? ' soft' : '';
  const noCoverCls = cover ? '' : ' no-cover';
  const followed = isFollowingBuilder(owner);
  const sceneId = it.scene || '';
  const hl = tips.highlights.map(h => `<li>${{escapeHtml(h)}}</li>`).join('');
  return `<article class="post ${{it.from_corpus ? 'corpus' : ''}}${{softCls}} ${{focus}}" id="post-${{idx}}"
      data-fn="${{escapeHtml(fn)}}" data-src="${{escapeHtml(it.source || '')}}"
      data-scene="${{escapeHtml(sceneId)}}" data-l2="${{escapeHtml(it.scene_l2 || '')}}"
      data-owner="${{escapeHtml(owner)}}"
      data-fc="${{it.from_corpus ? '1' : '0'}}">
    <div class="post-head">
      <div class="avatar clickable js-publisher" data-owner="${{escapeHtml(owner)}}" title="查看发布者"><span><b style="background:${{pal[1]}}">${{escapeHtml(initials(owner))}}</b></span></div>
      <div class="who clickable js-publisher" data-owner="${{escapeHtml(owner)}}" title="查看发布者">
        <div class="name">${{escapeHtml(it.name || fn)}}</div>
        <div class="sub">@${{escapeHtml(owner)}} · ${{escapeHtml(sourceLabel(it.source))}} · ★ ${{stars}}</div>
      </div>
      ${{IS_LITE ? '' : `<button type="button" class="follow-mini js-follow-builder ${{followed ? 'on' : ''}}" data-owner="${{escapeHtml(owner)}}" title="关注后最新动态出现在顶部 Stories">${{followed ? '已关注' : '关注'}}</button>`}}
    </div>
    <div class="media js-media${{noCoverCls}}" data-idx="${{idx}}">
      ${{cover ? `<img class="cover" src="${{escapeHtml(cover)}}" alt="${{escapeHtml(it.name || fn)}}" loading="lazy" referrerpolicy="no-referrer" onerror="this.closest('.media').classList.add('no-cover')" />` : ''}}
      <div class="cover-fallback">
        <div class="t">${{escapeHtml(it.name || fn)}}</div>
        <div class="d">${{escapeHtml((tips.problem || '').slice(0, 120))}}</div>
      </div>
      <div class="badges">
        <span class="badge ${{IS_LITE ? 'clickable js-scene-filter' : 'clickable js-scene-tag'}}" data-scene="${{escapeHtml(sceneId)}}" title="${{IS_LITE ? '按行业筛选' : '关注行业 · 最新进顶部圆环'}}">${{escapeHtml(it.scene_label || it.scene || '其他')}}</span>
        ${{it.scene_l2_label ? `<span class="badge">${{escapeHtml(it.scene_l2_label)}}</span>` : ''}}
        ${{it.from_corpus ? `<span class="badge kb">知识库</span>` : ''}}
        ${{it.soft ? `<span class="badge soft">线索</span>` : ''}}
      </div>
      <div class="heart-burst" id="burst-${{idx}}">${{heartSvg(true)}}</div>
    </div>
    <div class="pitch">
      <div class="problem"><em>解决</em>${{escapeHtml(tips.problem || it.name || '')}}</div>
      <ul class="highlights">${{hl}}</ul>
      <a class="doc-link" href="${{escapeHtml(skillUrl)}}" target="_blank" rel="noopener">在 GitHub 看 SKILL.md 全文 →</a>
    </div>
    <div class="actions">
      <div class="actions-left">
        <button class="act js-like ${{isLiked ? 'liked' : ''}}" type="button" data-fn="${{escapeHtml(fn)}}" aria-label="like">${{heartSvg(isLiked)}}</button>
        <button class="act js-comment" type="button" aria-label="not useful">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        </button>
        <a class="act js-open" href="${{escapeHtml(url)}}" target="_blank" rel="noopener" aria-label="open github">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
        </a>
      </div>
      <button class="act js-save ${{isSaved ? 'saved' : ''}}" type="button" aria-label="save">${{bookmarkSvg(isSaved)}}</button>
    </div>
    <div class="likes">★ ${{stars}} · score ${{score}}</div>
    ${{why ? `<div class="why-line">${{escapeHtml(why)}}</div>` : ''}}
    <div class="time">${{it.soft ? 'Soft skill · 打开 GitHub 查看' : (it.from_corpus ? 'From corpus' : 'Suggested for you')}}</div>
    <div class="open-row"><a class="open-gh js-open" href="${{escapeHtml(url)}}" target="_blank" rel="noopener">打开 GitHub</a></div>
  </article>`;
}}

function publisherLocalItems(owner) {{
  return allPool().filter(it => (it.owner || (it.full_name || '').split('/')[0]) === owner);
}}

async function fetchGithubRepos(owner) {{
  if (Object.prototype.hasOwnProperty.call(publisherCache, owner) && publisherCache[owner] !== null) {{
    return publisherCache[owner];
  }}
  try {{
    const resp = await fetch('https://api.github.com/users/' + encodeURIComponent(owner) + '/repos?sort=updated&per_page=8', {{
      headers: {{ 'Accept': 'application/vnd.github+json' }},
    }});
    if (!resp.ok) {{
      publisherCache[owner] = [];
      return [];
    }}
    const rows = await resp.json();
    const localFns = new Set(publisherLocalItems(owner).map(it => it.full_name));
    publisherCache[owner] = (rows || [])
      .filter(r => !r.fork && !localFns.has(r.full_name))
      .map(r => ({{
        full_name: r.full_name,
        name: r.name,
        description: r.description || '',
        stars: r.stargazers_count,
        url: r.html_url,
        language: r.language || '',
      }}));
    return publisherCache[owner];
  }} catch (e) {{
    publisherCache[owner] = [];
    return [];
  }}
}}

function publisherPanelHtml(owner, ghRepos) {{
  const local = publisherLocalItems(owner);
  const pal = paletteFor(owner);
  const localHtml = local.length
    ? local.map(it => {{
        const tips = extractHighlightsClient(it);
        const stars = (it.stars == null) ? '—' : Number(it.stars).toLocaleString();
        return `<div class="pub-item js-pub-skill" data-fn="${{escapeHtml(it.full_name || '')}}" data-name="${{escapeHtml(it.name || '')}}">
          <strong>${{escapeHtml(it.name || it.full_name || '')}}</strong>
          <p>${{escapeHtml(tips.problem || it.description || '')}}</p>
          <div class="meta">${{escapeHtml(it.scene_label || '')}} · ★ ${{stars}} · Feed 内</div>
        </div>`;
      }}).join('')
    : `<p class="lead" style="color:var(--muted);font-size:.85rem">信息流里暂无 Ta 的其他 skill 卡。</p>`;
  let ghHtml = '';
  if (ghRepos === undefined || ghRepos === null) {{
    ghHtml = `<p class="lead" style="color:var(--muted);font-size:.85rem">正在拉取 GitHub 仓库…</p>`;
  }} else if (!ghRepos.length) {{
    ghHtml = `<p class="lead" style="color:var(--muted);font-size:.85rem">暂无更多公开仓库，或 GitHub API 限流。</p>`;
  }} else {{
    ghHtml = ghRepos.map(r => `<a class="pub-item" href="${{escapeHtml(r.url)}}" target="_blank" rel="noopener" style="display:block;text-decoration:none;color:inherit">
      <strong>${{escapeHtml(r.name)}}</strong>
      <p>${{escapeHtml((r.description || '暂无描述').slice(0, 140))}}</p>
      <div class="meta">★ ${{Number(r.stars || 0).toLocaleString()}}${{r.language ? ' · ' + escapeHtml(r.language) : ''}} · GitHub</div>
    </a>`).join('');
  }}
  const followed = isFollowingBuilder(owner);
  return `<div class="pub-panel">
    <div class="pub-head">
      <div class="ava" style="background:${{pal[1]}}">${{escapeHtml(initials(owner))}}</div>
      <div>
        <h2>@${{escapeHtml(owner)}}</h2>
        <p>发布者主页 · Feed 内 ${{local.length}} 条 · GitHub 整合</p>
        ${{IS_LITE ? '' : '<p style="margin-top:6px;color:var(--ink)">关注后，最新动态会出现在<strong>顶部 Stories 圆环</strong></p>'}}
      </div>
    </div>
    <div class="pub-actions">
      ${{IS_LITE ? '' : `<button type="button" class="js-follow-builder ${{followed ? 'following' : 'primary'}}" data-owner="${{escapeHtml(owner)}}">${{followed ? '已关注 · 点按取消' : '关注 Builder'}}</button>`}}
      <button type="button" class="js-pub-back">← 返回发现</button>
      <a href="https://github.com/${{escapeHtml(owner)}}" target="_blank" rel="noopener">打开 GitHub 主页</a>
      <a href="https://github.com/${{escapeHtml(owner)}}?tab=repositories" target="_blank" rel="noopener">全部仓库</a>
    </div>
    <div class="pub-sec">在 skill-feed 中</div>
    ${{localHtml}}
    <div class="pub-sec">GitHub 上的其他内容</div>
    ${{ghHtml}}
  </div>`;
}}

function openPublisher(owner) {{
  if (!owner) return;
  state.mode = 'publisher';
  state.publisher = owner;
  state.shown = 0;
  render(true);
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
  if (!Object.prototype.hasOwnProperty.call(publisherCache, owner)) {{
    publisherCache[owner] = null;
    fetchGithubRepos(owner).then(() => {{
      if (state.mode === 'publisher' && state.publisher === owner) render(false);
    }});
  }}
}}

function renderStories() {{
  const wrap = document.getElementById('storiesWrap');
  const el = document.getElementById('stories');
  if (IS_LITE) {{
    wrap.classList.add('hidden');
    el.innerHTML = '';
    return;
  }}
  const hide = state.mode === 'me' || state.mode === 'saved' || state.mode === 'publisher';
  wrap.classList.toggle('hidden', hide);
  if (hide) {{ el.innerHTML = ''; return; }}

  const rings = [];
  const nFollow = followBuilders.size + followIndustries.size;
  if (nFollow > 0) {{
    rings.push({{
      kind: 'following', value: 'all', label: '关注', face: '★',
      hot: followingItems(1).length > 0, cls: 'has-new',
    }});
  }}
  for (const owner of [...followBuilders]) {{
    const n = builderItems(owner, 1).length;
    rings.push({{
      kind: 'builder', value: owner, label: owner,
      face: initials(owner), hot: n > 0, cls: n ? 'has-new' : '',
    }});
  }}
  for (const sceneId of [...followIndustries]) {{
    const label = sceneLabelOf(sceneId);
    const n = industryItems(sceneId, 1).length;
    rings.push({{
      kind: 'industry', value: sceneId, label,
      face: initials(label), hot: n > 0, cls: n ? 'has-new' : '',
    }});
  }}
  rings.push({{ kind: 'guide', value: 'builder', label: '+ Builder', face: '+', cls: 'guide' }});
  rings.push({{ kind: 'guide', value: 'industry', label: '+ 行业', face: '+', cls: 'guide' }});

  el.innerHTML = rings.map(st => {{
    const pal = paletteFor(st.kind + ':' + st.value);
    const faceBg = st.cls === 'guide'
      ? ''
      : `style="background:linear-gradient(135deg,${{pal[0]}},${{pal[2]}})"`;
    return `<button type="button" class="story ${{st.cls || ''}} ${{st.hot ? 'hot' : ''}}" data-kind="${{st.kind}}" data-value="${{escapeHtml(st.value)}}" title="${{st.kind === 'guide' ? '去关注，最新动态会出现在这里' : '查看关注的最新动态'}}">
      <div class="ring"><div class="face"><i ${{faceBg}}>${{escapeHtml(st.face)}}</i></div></div>
      <span class="label">${{escapeHtml(st.label)}}</span>
    </button>`;
  }}).join('');
}}

function sceneOptions() {{
  const rows = SCENES.filter(s => countScene(s.id) > 0)
    .map(s => ({{ id: s.id, label: s.label }}));
  if (!rows.length) return [];
  return [{{ id: 'all', label: '全部行业' }}].concat(rows);
}}

function renderPills(el, items, key, show) {{
  el.classList.toggle('show', !!show);
  if (!show) {{ el.innerHTML = ''; return; }}
  el.innerHTML = items.map(it =>
    `<button type="button" class="pill ${{state[key]===it.id?'on':''}}" data-key="${{key}}" data-id="${{it.id}}">${{escapeHtml(it.label)}}</button>`
  ).join('');
}}

function githubSearchUrls(intent) {{
  const q = compressIntent(intent).query || (intent || '').trim();
  const enc = encodeURIComponent;
  // 空结果兜底：GitHub 代码搜索请用 path:**/SKILL.md
  // filename: 已不被识别，会把整串当正文搜出「提到 filename:SKILL.md」的无关笔记
  const codeQ = q
    ? `path:**/SKILL.md ${{q}}`
    : 'path:**/SKILL.md';
  const repoQ = q
    ? `${{q}} SKILL.md in:name,description,readme`
    : 'SKILL.md in:name,description,readme';
  return {{
    code: 'https://github.com/search?type=code&q=' + enc(codeQ),
    repos: 'https://github.com/search?type=repositories&q=' + enc(repoQ),
  }};
}}

function emptyHtml(items) {{
  const funnel = FEED.funnel || {{}};
  const rejected = FEED.rejected_counts || (FEED.gates && FEED.gates.rejected) || {{}};
  if (state.mode === 'saved') {{
    return `<div class="empty">
      <h2>还没有收藏</h2>
      <p>双击帖子点赞，或点书签收藏。可在「我的」里查看。</p>
    </div>`;
  }}
  const packed = compressIntent(state.intent);
  const intent = packed.query || (state.intent || '').trim();
  const gh = githubSearchUrls(intent);
  const intentLine = intent
    ? `<p>关键词：<b>${{escapeHtml(intent)}}</b> — Feed 内暂无匹配，可到 GitHub 继续搜。</p>`
    : `<p>Feed 内暂无结果。试短关键词（如「去AI味」），或直接去 GitHub 搜 SKILL.md。</p>`;
  return `<div class="empty">
    <h2>没有匹配帖子</h2>
    ${{intentLine}}
    <p style="margin:14px 0 10px;display:flex;flex-wrap:wrap;gap:8px;justify-content:center">
      <a class="open-gh" style="display:inline-block;padding:10px 16px;width:auto;min-width:180px" href="${{escapeHtml(gh.code)}}" target="_blank" rel="noopener">在 GitHub 搜 SKILL.md（代码）</a>
      <a class="open-gh" style="display:inline-block;padding:10px 16px;width:auto;min-width:180px;background:#fff;color:var(--ink);border:1px solid var(--line)" href="${{escapeHtml(gh.repos)}}" target="_blank" rel="noopener">在 GitHub 搜仓库</a>
    </p>
    <p style="font-size:.78rem;color:var(--muted)">不代装：在 GitHub 选中仓库后自行安装，再回 skill-picker 跑 scan。</p>
    <p style="font-size:.72rem;color:var(--muted);margin-top:12px">漏斗：trending ${{funnel.trending_repos ?? '—'}} · search ${{funnel.search_candidates ?? '—'}} ·
      过门禁 ${{funnel.passed ?? (FEED.gates && FEED.gates.passed) ?? 0}}
      · rejected ${{escapeHtml(JSON.stringify(rejected))}}</p>
  </div>`;
}}

function mePanelHtml() {{
  const nLiked = liked.size;
  const nSaved = saved.size;
  const pub = apiUrl('/publish') || '';
  const docs = apiUrl('/docs') || '';
  const home = apiUrl('/') || '';
  const builders = [...followBuilders];
  const industries = [...followIndustries];
  const builderChips = builders.length
    ? builders.map(o => `<span class="follow-chip">@${{escapeHtml(o)}} <button type="button" class="js-unfollow-builder" data-owner="${{escapeHtml(o)}}" aria-label="取消关注">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">还没关注 Builder。在卡片点「关注」，最新动态会出现在顶部 Stories。</p>`;
  const industryChips = industries.length
    ? industries.map(id => `<span class="follow-chip">${{escapeHtml(sceneLabelOf(id))}} <button type="button" class="js-unfollow-industry" data-scene="${{escapeHtml(id)}}" aria-label="取消关注">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">还没关注行业。点卡片上的场景标签即可关注。</p>`;
  return `<div class="me-panel">
    <h2>我的</h2>
    <p class="lead">关注的 Builder / 行业，其<strong>最新内容会出现在发现页顶部 Stories 圆环</strong>。赞/藏仍保存在此浏览器。</p>
    <div class="me-card">
      <strong>我关注的 Builder</strong>
      <div style="margin-top:8px">${{builderChips}}</div>
      <div class="me-actions">
        <button type="button" class="primary js-me-find-builder">发现 Builder</button>
      </div>
    </div>
    <div class="me-card">
      <strong>我关注的行业</strong>
      <div style="margin-top:8px">${{industryChips}}</div>
      <div class="me-actions">
        <button type="button" class="primary js-me-find-industry">发现行业</button>
      </div>
    </div>
    <div class="me-card">
      <strong>本机收藏</strong>
      <p>点赞 ${{nLiked}} · 书签 ${{nSaved}}</p>
      <div class="me-actions">
        <button type="button" class="primary js-me-saved">查看收藏</button>
      </div>
    </div>
    <div class="me-card">
      <strong>发布与后台</strong>
      <p>${{API_BASE ? ('API：' + escapeHtml(API_BASE)) : '尚未配置云端 API（ui.api_base / skillfeed.py api）'}}</p>
      <div class="me-actions">
        ${{pub ? `<a class="primary" href="${{escapeHtml(pub)}}" target="_blank" rel="noopener">去发布 Skill</a>` :
          `<button type="button" class="primary js-me-publish">去发布 Skill</button>`}}
        ${{docs ? `<a href="${{escapeHtml(docs)}}" target="_blank" rel="noopener">API 文档</a>` : ''}}
        ${{home ? `<a href="${{escapeHtml(home)}}" target="_blank" rel="noopener">API 首页</a>` : ''}}
        ${{API_BASE ? `<a href="${{escapeHtml(apiUrl('/auth/github'))}}" target="_blank" rel="noopener">GitHub 登录</a>` : ''}}
      </div>
    </div>
    <div class="me-card">
      <strong>发现站</strong>
      <p>Stories = 关注动态；下方 pills = 逛发现时的行业/栏目筛选。两者不再重复。</p>
    </div>
  </div>`;
}}

function render(reset) {{
  // 当前模式若已无内容，回退到发现
  if (['skills', 'ai', 'oss'].includes(state.mode) && countMode(state.mode) === 0) {{
    state.mode = 'all';
  }}
  if (state.scene !== 'all' && countScene(state.scene) === 0) {{
    state.scene = 'all';
    state.scene_l2 = 'all';
  }}
  if (state.section !== 'all' && countSection(state.section) === 0) {{
    state.section = 'all';
  }}

  const feed = document.getElementById('feed');
  document.getElementById('genStatus').textContent = fmtGeneratedAt();
  renderIntentKeys();
  renderStories();

  const hideChrome = state.mode === 'me' || state.mode === 'publisher';
  const scenes = sceneOptions();
  const secs = sectionOptions();
  const l2s = l2Options();
  renderPills(document.getElementById('sceneStrip'), scenes, 'scene', !hideChrome && scenes.length > 0);
  renderPills(document.getElementById('l2Strip'), l2s, 'scene_l2', !hideChrome && l2s.length > 0);
  renderPills(document.getElementById('sectionStrip'), secs, 'section', !hideChrome && secs.length > 0);

  document.querySelectorAll('.bottom .nav').forEach(n => {{
    const mode = n.dataset.mode;
    n.classList.toggle('on', !!mode && mode === state.mode);
  }});

  document.getElementById('searchWrap').style.display = hideChrome ? 'none' : '';

  if (state.mode === 'me') {{
    feed.innerHTML = mePanelHtml();
    return;
  }}
  if (state.mode === 'publisher') {{
    feed.innerHTML = publisherPanelHtml(state.publisher, publisherCache[state.publisher]);
    return;
  }}

  const items = filtered();
  if (!items.length) {{
    feed.innerHTML = emptyHtml(items);
    return;
  }}

  if (reset) state.shown = Math.min(PAGE, items.length);
  else state.shown = Math.max(state.shown, Math.min(PAGE, items.length));

  const slice = items.slice(0, state.shown);
  feed.innerHTML = slice.map((it, idx) => cardHtml(it, idx)).join('') +
    `<div class="sentinel" id="sentinel">${{
      state.shown < items.length
        ? '下滑加载更多 · 已显 <b>' + state.shown + '</b> / ' + items.length
        : '你已看完 · 共 <b>' + items.length + '</b> 条（含知识库 backup）'
    }}</div>`;
}}

function maybeLoadMore() {{
  const items = filtered();
  if (state.shown >= items.length) return;
  const sent = document.getElementById('sentinel');
  if (!sent) return;
  if (sent.getBoundingClientRect().top < window.innerHeight + 140) {{
    state.shown = Math.min(items.length, state.shown + PAGE);
    render(false);
  }}
}}

function burstAt(idx) {{
  const el = document.getElementById('burst-' + idx);
  if (!el) return;
  el.classList.remove('go');
  void el.offsetWidth;
  el.classList.add('go');
}}

function itemPayload(card) {{
  return {{
    full_name: card.dataset.fn || '',
    source: card.dataset.src || '',
    scene: card.dataset.scene || '',
    scene_l2: card.dataset.l2 || '',
    from_corpus: card.dataset.fc === '1',
  }};
}}

function toggleLike(fn, idx, postEl, feedback) {{
  if (!fn) return;
  const now = !liked.has(fn);
  if (now) liked.add(fn); else liked.delete(fn);
  persistSet('sf_liked', liked);
  const btn = postEl.querySelector('.js-like');
  if (btn) {{
    btn.classList.toggle('liked', now);
    btn.innerHTML = heartSvg(now);
  }}
  if (now) {{
    burstAt(idx);
    if (feedback !== false) sendFeedback('useful', itemPayload(postEl));
  }}
}}

function toggleSave(fn, postEl) {{
  if (!fn) return;
  const now = !saved.has(fn);
  if (now) saved.add(fn); else saved.delete(fn);
  persistSet('sf_saved', saved);
  const btn = postEl.querySelector('.js-save');
  if (btn) {{
    btn.classList.toggle('saved', now);
    btn.innerHTML = bookmarkSvg(now);
  }}
  if (now) sendFeedback('useful', itemPayload(postEl));
}}

/* —— Story viewer —— */
function stopSvTimer() {{
  if (sv.timer) clearTimeout(sv.timer);
  sv.timer = null;
}}

function sceneGradient(it) {{
  const key = it.scene || it.full_name || it.name || 'x';
  const pal = paletteFor(key);
  return `linear-gradient(160deg, ${{pal[0]}} 0%, ${{pal[1]}} 48%, ${{pal[2]}} 100%)`;
}}

function renderSvSlide() {{
  const it = sv.items[sv.idx];
  if (!it) return;
  const fn = it.full_name || '';
  const cover = it.cover_url || (fn ? ('https://opengraph.githubassets.com/1/' + fn) : '');
  const stars = (it.stars == null) ? '—' : Number(it.stars).toLocaleString();
  const slide = document.getElementById('svSlide');
  slide.style.background = sceneGradient(it);
  slide.style.backgroundImage = '';
  slide.innerHTML = '';

  const img = document.getElementById('svCover');
  const wrap = document.getElementById('svCoverWrap');
  if (cover) {{
    wrap.style.display = '';
    img.classList.remove('hidden');
    img.alt = it.name || fn;
    img.onerror = () => {{ wrap.style.display = 'none'; }};
    img.onload = () => {{ wrap.style.display = ''; }};
    img.src = cover;
  }} else {{
    wrap.style.display = 'none';
  }}

  const excerpt = (it.body_preview || it.one_liner || it.description || '').trim().slice(0, 280);
  const chips = [
    it.scene_label || it.scene,
    it.scene_l2_label,
    it.from_corpus ? '知识库' : '',
    it.soft ? '线索' : '',
  ].filter(Boolean).map(c => `<span class="chip">${{escapeHtml(c)}}</span>`).join('');
  document.getElementById('svContent').innerHTML =
    `<div class="chips">${{chips}}</div>` +
    `<h2>${{escapeHtml(it.name || fn)}}</h2>` +
    `<p>${{escapeHtml(excerpt)}}</p>` +
    `<div class="meta">★ ${{stars}} · ${{escapeHtml(sourceLabel(it.source))}} · ${{escapeHtml(fn)}}</div>`;
  const url = it.url || ('https://github.com/' + fn);
  const cta = document.getElementById('svCta');
  cta.href = url;
  cta.onclick = () => sendFeedback('opened_github', it);

  const bars = document.getElementById('svProgress');
  bars.innerHTML = sv.items.map((_, i) =>
    `<div class="sv-bar ${{i < sv.idx ? 'done' : ''}} ${{i === sv.idx ? 'active' : ''}}"><i></i></div>`
  ).join('');
}}

function svAdvance(delta) {{
  stopSvTimer();
  const next = sv.idx + delta;
  if (next >= sv.items.length) {{ closeStoryViewer(); return; }}
  if (next < 0) {{ sv.idx = 0; }} else {{ sv.idx = next; }}
  renderSvSlide();
  sv.timer = setTimeout(() => svAdvance(1), STORY_MS);
}}

function openStoryViewer(kind, value) {{
  let label = '';
  let items = [];
  if (kind === 'following') {{
    label = '关注动态';
    items = followingItems(8);
  }} else if (kind === 'builder') {{
    label = '@' + value;
    items = builderItems(value, 5);
  }} else if (kind === 'industry' || kind === 'scene') {{
    label = sceneLabelOf(value);
    items = industryItems(value, 5);
  }}
  if (!items.length) {{
    toast(kind === 'guide' ? '先去关注一位 Builder 或一个行业' : '暂无最新动态 · 试试换个关注或 refresh');
    return;
  }}
  sv.open = true;
  sv.scene = value || kind;
  sv.items = items;
  sv.idx = 0;
  document.getElementById('svWho').textContent = label + ' · 关注最新';
  document.getElementById('storyViewer').classList.add('open');
  document.getElementById('storyViewer').setAttribute('aria-hidden', 'false');
  renderSvSlide();
  stopSvTimer();
  sv.timer = setTimeout(() => svAdvance(1), STORY_MS);
}}

function closeStoryViewer() {{
  stopSvTimer();
  sv.open = false;
  document.getElementById('storyViewer').classList.remove('open');
  document.getElementById('storyViewer').setAttribute('aria-hidden', 'true');
}}

/* —— Demo —— */
const DEMO_INTENTS = ['写作 去AI味', '周报复盘', 'Figma', ''];

function setDemoUi(on) {{
  demo.on = on;
  document.getElementById('demoBar').classList.toggle('show', on);
  document.getElementById('btnDemo').classList.toggle('demo-on', on);
  document.getElementById('demoBadge').hidden = !on;
}}

function stopDemo() {{
  if (demo.timer) clearTimeout(demo.timer);
  demo.timer = null;
  demo.focus = -1;
  setDemoUi(false);
  document.getElementById('demoText').textContent = 'Demo 已停止';
}}

function demoTick() {{
  if (!demo.on) return;
  const steps = [
    () => {{
      document.getElementById('demoText').textContent = 'Demo：关注行业 → 顶部 Stories';
      state.mode = 'all';
      state.scene = 'all';
      state.scene_l2 = 'all';
      if (!isFollowingIndustry('content')) toggleFollowIndustry('content', {{ silent: true }});
      persistSet('sf_follow_industries', followIndustries);
      state.shown = 0;
      render(true);
      flashStoriesHint();
      toast('关注后最新动态出现在顶部圆环', 2800);
    }},
    () => {{
      document.getElementById('demoText').textContent = 'Demo：点 Stories 看关注最新';
      openStoryViewer('industry', 'content');
    }},
    () => {{
      closeStoryViewer();
      document.getElementById('demoText').textContent = 'Demo：pills 筛选行业（非 Stories）';
      state.scene = 'content';
      state.scene_l2 = 'writing';
      state.shown = 0;
      render(true);
    }},
    () => {{
      document.getElementById('demoText').textContent = 'Demo：意图搜索「写作 去AI味」';
      state.intent = DEMO_INTENTS[0];
      document.getElementById('intent').value = state.intent;
      state.scene = 'all';
      state.scene_l2 = 'all';
      state.shown = 0;
      render(true);
    }},
    () => {{
      const list = filtered();
      if (!list.length) return;
      demo.focus = 0;
      render(false);
      const el = document.getElementById('post-0');
      if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
      document.getElementById('demoText').textContent = 'Demo：双击点赞 · ' + (list[0].name || '');
      setTimeout(() => {{ if (demo.on && el) toggleLike(list[0].full_name, 0, el); }}, 600);
    }},
    () => {{
      document.getElementById('demoText').textContent = 'Demo：收藏书签';
      const list = filtered();
      if (list.length && document.getElementById('post-0')) {{
        toggleSave(list[0].full_name, document.getElementById('post-0'));
      }}
    }},
    () => {{
      document.getElementById('demoText').textContent = 'Demo：打开「我的」';
      state.mode = 'me';
      demo.focus = -1;
      state.shown = 0;
      render(true);
      window.scrollTo({{ top: 0, behavior: 'smooth' }});
    }},
    () => {{
      document.getElementById('demoText').textContent = 'Demo 循环 · 回发现';
      state.mode = 'all';
      state.scene = 'all';
      state.scene_l2 = 'all';
      state.section = 'all';
      state.intent = '';
      document.getElementById('intent').value = '';
      demo.focus = -1;
      state.shown = 0;
      render(true);
      window.scrollTo({{ top: 0, behavior: 'smooth' }});
    }},
  ];
  steps[demo.step % steps.length]();
  demo.step += 1;
  demo.timer = setTimeout(demoTick, 3200);
}}

function startDemo() {{
  if (demo.on) {{ stopDemo(); return; }}
  setDemoUi(true);
  demo.step = 0;
  document.getElementById('demoText').textContent = 'Demo 巡演开始';
  demoTick();
}}

/* —— Events —— */
document.getElementById('stories').addEventListener('click', (e) => {{
  const btn = e.target.closest('.story');
  if (!btn) return;
  const kind = btn.dataset.kind;
  const value = btn.dataset.value;
  if (kind === 'guide') {{
    openFollowSheet(value === 'industry' ? 'industry' : 'builder');
    return;
  }}
  if (kind === 'following' || kind === 'builder' || kind === 'industry') {{
    openStoryViewer(kind, value);
  }}
}});

document.getElementById('sceneStrip').addEventListener('click', (e) => {{
  const btn = e.target.closest('.pill');
  if (!btn) return;
  state.scene = btn.dataset.id;
  state.scene_l2 = 'all';
  state.shown = 0;
  render(true);
}});

document.getElementById('l2Strip').addEventListener('click', (e) => {{
  const btn = e.target.closest('.pill');
  if (!btn) return;
  state[btn.dataset.key] = btn.dataset.id;
  state.shown = 0;
  render(true);
}});

document.getElementById('sectionStrip').addEventListener('click', (e) => {{
  const btn = e.target.closest('.pill');
  if (!btn) return;
  state.section = btn.dataset.id;
  state.shown = 0;
  render(true);
}});

document.getElementById('followSheet').addEventListener('click', (e) => {{
  const t = e.target;
  if (!(t instanceof Element)) return;
  if (t === e.currentTarget || t.closest('.js-sheet-close')) {{
    closeFollowSheet();
    return;
  }}
  const b = t.closest('.js-sheet-follow-builder');
  if (b) {{
    toggleFollowBuilder(b.dataset.owner || '');
    openFollowSheet('builder');
    return;
  }}
  const ind = t.closest('.js-sheet-follow-industry');
  if (ind) {{
    const sceneId = ind.dataset.scene || '';
    toggleFollowIndustry(sceneId);
    const title = (document.querySelector('#followSheetPanel h3') || {{}}).textContent || '';
    if (title === '发现行业') openFollowSheet('industry');
    else if (sceneId) openIndustrySheet(sceneId);
    return;
  }}
  const fil = t.closest('.js-sheet-filter-scene');
  if (fil) {{
    state.mode = 'all';
    state.scene = fil.dataset.scene || 'all';
    state.scene_l2 = 'all';
    state.shown = 0;
    closeFollowSheet();
    render(true);
    window.scrollTo({{ top: 0, behavior: 'smooth' }});
  }}
}});

document.getElementById('storiesHintClose').addEventListener('click', () => {{
  const hint = document.getElementById('storiesHint');
  hint.hidden = true;
  try {{ localStorage.setItem('sf_stories_hint_dismissed', '1'); }} catch (e) {{}}
}});

document.querySelector('.bottom').addEventListener('click', (e) => {{
  const nav = e.target.closest('.nav');
  if (!nav) return;
  if (nav.dataset.action === 'publish') {{
    if (IS_LITE) return;
    openPublish();
    return;
  }}
  if (IS_LITE && nav.dataset.mode === 'me') return;
  state.mode = nav.dataset.mode || 'all';
  if (state.mode === 'all') {{
    state.section = 'all';
  }}
  state.shown = 0;
  render(true);
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
}});

const intentEl = document.getElementById('intent');
intentEl.addEventListener('input', (e) => {{
  state.intent = e.target.value || '';
  renderIntentKeys();
  state.shown = 0;
  render(true);
}});
intentEl.addEventListener('paste', () => {{
  setTimeout(() => {{
    applyIntentInput(intentEl.value, {{ forceCompress: true }});
    state.shown = 0;
    render(true);
  }}, 0);
}});
intentEl.addEventListener('blur', () => {{
  const v = intentEl.value || '';
  if (v.replace(/\\s+/g, '').length > 10 || v.length > 16) {{
    applyIntentInput(v, {{ forceCompress: true }});
    state.shown = 0;
    render(true);
  }}
}});
intentEl.addEventListener('keydown', (e) => {{
  if (e.key === 'Enter') {{
    applyIntentInput(intentEl.value, {{ forceCompress: true }});
    state.shown = 0;
    render(true);
  }}
}});

document.getElementById('feed').addEventListener('click', (e) => {{
  const t = e.target;
  if (!(t instanceof Element)) return;

  if (t.closest('.js-me-saved')) {{
    state.mode = 'saved';
    state.shown = 0;
    render(true);
    return;
  }}
  if (t.closest('.js-me-publish')) {{
    openPublish();
    return;
  }}
  if (t.closest('.js-me-find-builder')) {{
    state.mode = 'all';
    render(true);
    openFollowSheet('builder');
    return;
  }}
  if (t.closest('.js-me-find-industry')) {{
    state.mode = 'all';
    render(true);
    openFollowSheet('industry');
    return;
  }}
  const unB = t.closest('.js-unfollow-builder');
  if (unB) {{
    toggleFollowBuilder(unB.dataset.owner || '');
    return;
  }}
  const unI = t.closest('.js-unfollow-industry');
  if (unI) {{
    toggleFollowIndustry(unI.dataset.scene || '');
    return;
  }}
  if (t.closest('.js-pub-back')) {{
    state.mode = 'all';
    state.publisher = '';
    state.shown = 0;
    render(true);
    return;
  }}
  const followBtn = t.closest('.js-follow-builder');
  if (followBtn) {{
    e.stopPropagation();
    toggleFollowBuilder(followBtn.dataset.owner || '');
    return;
  }}
  const sceneFilter = t.closest('.js-scene-filter');
  if (sceneFilter) {{
    e.stopPropagation();
    state.scene = sceneFilter.dataset.scene || 'all';
    state.scene_l2 = 'all';
    state.shown = 0;
    render(true);
    return;
  }}
  const sceneTag = t.closest('.js-scene-tag');
  if (sceneTag) {{
    e.stopPropagation();
    openIndustrySheet(sceneTag.dataset.scene || '');
    return;
  }}
  const pubSkill = t.closest('.js-pub-skill');
  if (pubSkill) {{
    state.mode = 'all';
    state.publisher = '';
    state.intent = pubSkill.dataset.name || '';
    document.getElementById('intent').value = state.intent;
    state.shown = 0;
    render(true);
    return;
  }}
  const pub = t.closest('.js-publisher');
  if (pub) {{
    openPublisher(pub.dataset.owner || '');
    return;
  }}

  const card = t.closest('.post');
  if (!card) return;
  const idx = Number(card.id.replace('post-', '') || 0);

  if (t.closest('.js-like')) {{
    toggleLike(card.dataset.fn, idx, card, false);
    return;
  }}
  if (t.closest('.js-save')) {{
    toggleSave(card.dataset.fn, card);
    return;
  }}
  if (t.closest('.js-comment')) {{
    sendFeedback('bad', itemPayload(card));
    return;
  }}
  if (t.closest('.js-open')) {{
    sendFeedback('opened_github', itemPayload(card));
    return;
  }}
}});

let lastTap = 0;
document.getElementById('feed').addEventListener('click', (e) => {{
  const media = e.target.closest('.js-media');
  if (!media) return;
  const now = Date.now();
  if (now - lastTap < 320) {{
    const card = media.closest('.post');
    const idx = Number(media.dataset.idx || 0);
    if (card) toggleLike(card.dataset.fn, idx, card);
  }}
  lastTap = now;
}});

document.getElementById('svClose').addEventListener('click', closeStoryViewer);
document.getElementById('svPrev').addEventListener('click', () => svAdvance(-1));
document.getElementById('svNext').addEventListener('click', () => svAdvance(1));
document.getElementById('storyViewer').addEventListener('keydown', (e) => {{
  if (!sv.open) return;
  if (e.key === 'Escape') closeStoryViewer();
  if (e.key === 'ArrowRight') svAdvance(1);
  if (e.key === 'ArrowLeft') svAdvance(-1);
}});

let svTouchX = 0;
document.getElementById('svBody').addEventListener('touchstart', (e) => {{
  svTouchX = e.changedTouches[0].clientX;
}}, {{ passive: true }});
document.getElementById('svBody').addEventListener('touchend', (e) => {{
  const dx = e.changedTouches[0].clientX - svTouchX;
  if (Math.abs(dx) > 40) svAdvance(dx < 0 ? 1 : -1);
}}, {{ passive: true }});

window.addEventListener('scroll', () => maybeLoadMore(), {{ passive: true }});
document.getElementById('btnDemo').addEventListener('click', startDemo);
document.getElementById('demoStop').addEventListener('click', stopDemo);
document.getElementById('btnHeart').addEventListener('click', () =>
  toast('关注后最新进顶部 Stories · 双击点赞 · 书签收藏'));

try {{
  if (!IS_LITE && localStorage.getItem('sf_stories_hint_dismissed') === '1') {{
    document.getElementById('storiesHint').hidden = true;
  }}
}} catch (e) {{}}

(function prefillIntentFromQuery() {{
  const q = new URLSearchParams(location.search).get('q') || new URLSearchParams(location.search).get('intent') || '';
  if (!q) return;
  applyIntentInput(q, {{ forceCompress: true, silent: true }});
}})();

renderIntentKeys();
render(true);

if (!IS_LITE && new URLSearchParams(location.search).get('demo') === '1') {{
  setTimeout(startDemo, 400);
}}
</script>
</body>
</html>
"""


def write_feed_html(feed: dict, path: Path, *, variant: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_feed_html(feed, variant=variant), encoding="utf-8")


def write_feed_variants(feed: dict, *, full_path: Path, lite_path: Path) -> None:
    """同时写出独立站 full 页与 picker 用 lite 页。"""
    write_feed_html(feed, full_path, variant="full")
    write_feed_html(feed, lite_path, variant="lite")
