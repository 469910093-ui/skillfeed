"""生成 Instagram 风格无限下滑 Feed HTML（只推荐到 GitHub）。"""

from __future__ import annotations

import json
from pathlib import Path

import scene


def build_feed_html(feed: dict) -> str:
    payload = json.dumps(feed, ensure_ascii=False)
    scenes = json.dumps(feed.get("scenes") or scene.scene_chips(), ensure_ascii=False)
    scenes_l2 = json.dumps(feed.get("scenes_l2") or scene.scene_l2_tree(), ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>skill-feed</title>
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

  .stories {{
    display: flex; gap: 14px; overflow-x: auto; padding: 14px 12px 12px;
    border-bottom: 1px solid var(--line); background: var(--card);
    scrollbar-width: none;
  }}
  .stories::-webkit-scrollbar {{ display: none; }}
  .stories.hidden {{ display: none; }}
  .story {{
    flex: 0 0 auto; width: 72px; text-align: center; cursor: pointer;
    background: transparent; border: 0; padding: 0; font: inherit; color: inherit;
  }}
  .story .ring {{
    width: 66px; height: 66px; margin: 0 auto 6px; padding: 2px;
    border-radius: 50%; background: #dbdbdb;
  }}
  .story.on .ring, .story.hot .ring {{ background: var(--ring); }}
  .story .face {{
    width: 100%; height: 100%; border-radius: 50%;
    background: #fff; padding: 2px; display: grid; place-items: center;
  }}
  .story .face i {{
    width: 100%; height: 100%; border-radius: 50%;
    display: grid; place-items: center;
    font-style: normal; font-weight: 700; font-size: .85rem; color: #fff;
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

  .doc {{
    margin: 0; padding: 12px 14px 4px;
    background: #fff;
  }}
  .doc-head {{
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    margin-bottom: 8px;
  }}
  .doc-label {{
    font-size: .68rem; font-weight: 700; letter-spacing: .04em;
    color: var(--muted); text-transform: uppercase;
  }}
  .doc-link {{
    font-size: .72rem; font-weight: 600; color: var(--link); text-decoration: none;
  }}
  .doc-body {{
    margin: 0; padding: 12px 12px 14px;
    background: #f6f8fa; border: 1px solid #eaeef2; border-radius: 10px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .78rem; line-height: 1.5; color: #24292f;
    white-space: pre-wrap; word-break: break-word;
    max-height: 168px; overflow: hidden;
    display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 8;
  }}
  .doc.expanded .doc-body {{
    max-height: none; -webkit-line-clamp: unset; display: block;
  }}
  .doc-more {{
    display: inline-block; margin-top: 6px; margin-bottom: 2px;
    border: 0; background: transparent; color: var(--muted);
    font: inherit; font-size: .78rem; font-weight: 600; cursor: pointer; padding: 0;
  }}

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

  @media (max-width: 520px) {{
    .shell {{ border: 0; }}
    .story-viewer {{ max-width: 100%; left: 0; transform: none; }}
  }}
</style>
</head>
<body>
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

    <div class="search-wrap" id="searchWrap">
      <input class="search" id="intent" type="search" placeholder="搜索意图，如：去 AI 味写作 / 周报复盘" />
    </div>

    <div class="stories" id="stories" aria-label="场景 Stories"></div>
    <div class="sr-only" id="sceneLabel">一级场景</div>
    <div class="sr-only" id="sceneL2Label">二级场景</div>
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

<script>
const FEED = {payload};
const SCENES = {scenes};
const SCENES_L2 = {scenes_l2};
const PAGE = 6;
const STORY_MS = 3500;
const API_BASE = ((FEED.ui && FEED.ui.api_base) || '').replace(/\\/$/, '');
const state = {{ mode: 'all', scene: 'all', scene_l2: 'all', section: 'all', shown: 0, intent: '' }};
const demo = {{ on: false, step: 0, timer: null, focus: -1 }};
const sv = {{ open: false, scene: '', items: [], idx: 0, timer: null }};

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

function toast(msg) {{
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2200);
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

function apiUrl(path) {{
  if (!API_BASE) return '';
  return API_BASE + (path.startsWith('/') ? path : ('/' + path));
}}

function openPublish() {{
  const url = apiUrl('/publish');
  if (url) {{
    window.open(url, '_blank', 'noopener');
    return;
  }}
  toast('请先启动 API：python skillfeed.py api（或配置 ui.api_base）');
}}

function liveIntentBoost(it, q) {{
  if (!q) return 0;
  const hay = ((it.name||'') + ' ' + (it.description||'') + ' ' + (it.scene_label||'') + ' ' + (it.scene_l2_label||'')).toLowerCase();
  let n = 0;
  for (const part of q.split(/\\s+/).filter(Boolean)) {{
    if (hay.includes(part)) n += 1;
  }}
  return n * 0.08;
}}

function scoreRow(it, q) {{
  return (Number(it.personal_score) || Number(it.rel_score) || 0) + liveIntentBoost(it, q);
}}

function filtered() {{
  const q = state.intent.trim().toLowerCase();

  if (state.mode === 'saved') {{
    const keep = new Set([...liked, ...saved]);
    const rows = allPool().filter(it => {{
      const fn = it.full_name || '';
      if (!fn || !keep.has(fn)) return false;
      if (q) {{
        const hay = ((it.name||'') + ' ' + (it.description||'') + ' ' + (it.full_name||'') + ' ' + (it.one_liner||'')).toLowerCase();
        if (!hay.includes(q) && !q.split(/\\s+/).some(p => p && hay.includes(p))) return false;
      }}
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
    if (q) {{
      const hay = ((it.name||'') + ' ' + (it.description||'') + ' ' + (it.full_name||'') + ' ' + (it.scene_l2_label||'') + ' ' + (it.one_liner||'')).toLowerCase();
      if (!hay.includes(q) && !q.split(/\\s+/).some(p => p && hay.includes(p))) return false;
    }}
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

function cardHtml(it, idx) {{
  const url = it.url || ('https://github.com/' + it.full_name);
  const fn = it.full_name || '';
  const pal = paletteFor(fn || it.name || String(idx));
  const stars = (it.stars == null) ? '—' : Number(it.stars).toLocaleString();
  const score = it.personal_score != null ? Number(it.personal_score).toFixed(2)
    : (it.rel_score != null ? Number(it.rel_score).toFixed(2) : '—');
  const why = friendlyWhy(it);
  const desc = it.description || '';
  const body = (it.body_preview || '').trim();
  const cover = it.cover_url || (fn ? ('https://opengraph.githubassets.com/1/' + fn) : '');
  const skillUrl = it.skill_url || (it.skill_path ? ('https://github.com/' + fn + '/blob/HEAD/' + it.skill_path) : url);
  const docText = body || desc;
  const docLong = docText.length > 320;
  const isLiked = liked.has(fn);
  const isSaved = saved.has(fn);
  const focus = demo.focus === idx ? 'focus' : '';
  const owner = (fn.split('/')[0] || 'skill');
  const softCls = it.soft ? ' soft' : '';
  const noCoverCls = cover ? '' : ' no-cover';
  return `<article class="post ${{it.from_corpus ? 'corpus' : ''}}${{softCls}} ${{focus}}" id="post-${{idx}}"
      data-fn="${{escapeHtml(fn)}}" data-src="${{escapeHtml(it.source || '')}}"
      data-scene="${{escapeHtml(it.scene || '')}}" data-l2="${{escapeHtml(it.scene_l2 || '')}}"
      data-fc="${{it.from_corpus ? '1' : '0'}}">
    <div class="post-head">
      <div class="avatar"><span><b style="background:${{pal[1]}}">${{escapeHtml(initials(owner))}}</b></span></div>
      <div class="who">
        <div class="name">${{escapeHtml(it.name || fn)}}</div>
        <div class="sub">${{escapeHtml(fn)}} · ${{escapeHtml(sourceLabel(it.source))}} · ★ ${{stars}}</div>
      </div>
      <button class="more" type="button" aria-label="more">···</button>
    </div>
    <div class="media js-media${{noCoverCls}}" data-idx="${{idx}}">
      ${{cover ? `<img class="cover" src="${{escapeHtml(cover)}}" alt="${{escapeHtml(it.name || fn)}}" loading="lazy" referrerpolicy="no-referrer" onerror="this.closest('.media').classList.add('no-cover')" />` : ''}}
      <div class="cover-fallback">
        <div class="t">${{escapeHtml(it.name || fn)}}</div>
        <div class="d">${{escapeHtml(desc.slice(0, 120))}}</div>
      </div>
      <div class="badges">
        <span class="badge">${{escapeHtml(it.scene_label || it.scene || '其他')}}</span>
        ${{it.scene_l2_label ? `<span class="badge">${{escapeHtml(it.scene_l2_label)}}</span>` : ''}}
        ${{it.from_corpus ? `<span class="badge kb">知识库</span>` : ''}}
        ${{it.soft ? `<span class="badge soft">线索</span>` : ''}}
      </div>
      <div class="heart-burst" id="burst-${{idx}}">${{heartSvg(true)}}</div>
    </div>
    ${{docText ? `<div class="doc" id="doc-${{idx}}">
      <div class="doc-head">
        <span class="doc-label">${{body ? 'SKILL.md 预览' : '简介'}}</span>
        <a class="doc-link" href="${{escapeHtml(skillUrl)}}" target="_blank" rel="noopener">在 GitHub 看全文</a>
      </div>
      <pre class="doc-body">${{escapeHtml(docText)}}</pre>
      ${{docLong ? `<button type="button" class="doc-more js-doc-more" data-idx="${{idx}}">展开全文摘要</button>` : ''}}
    </div>` : ''}}
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

function renderStories() {{
  const el = document.getElementById('stories');
  const hide = state.mode === 'me' || state.mode === 'saved';
  el.classList.toggle('hidden', hide);
  if (hide) {{ el.innerHTML = ''; return; }}

  const modes = [
    {{ id: 'mode:all', label: '全部', kind: 'mode', value: 'all' }},
    {{ id: 'mode:skills', label: 'Skills', kind: 'mode', value: 'skills' }},
    {{ id: 'mode:ai', label: 'AI', kind: 'mode', value: 'ai' }},
    {{ id: 'mode:oss', label: '开源', kind: 'mode', value: 'oss' }},
  ].filter(m => m.value === 'all' || countMode(m.value) > 0);

  const sceneStories = [{{ id: 'scene:all', label: '全部', kind: 'scene', value: 'all', text: '全部' }}]
    .concat(SCENES
      .filter(s => countScene(s.id) > 0)
      .map(s => ({{ id: 'scene:' + s.id, label: s.label, kind: 'scene', value: s.id, text: s.label }})));

  const items = modes.concat(sceneStories);
  el.innerHTML = items.map(st => {{
    const on = (st.kind === 'mode' && state.mode === st.value) ||
               (st.kind === 'scene' && state.scene === st.value && st.value !== 'all') ||
               (st.kind === 'scene' && st.value === 'all' && state.scene === 'all' && state.mode === 'all');
    const pal = paletteFor(st.id);
    const label = st.text || st.label;
    return `<button type="button" class="story ${{on ? 'on' : 'hot'}}" data-kind="${{st.kind}}" data-value="${{st.value}}">
      <div class="ring"><div class="face"><i style="background:linear-gradient(135deg,${{pal[0]}},${{pal[2]}})">${{escapeHtml(initials(label))}}</i></div></div>
      <span class="label">${{escapeHtml(label)}}</span>
    </button>`;
  }}).join('');
}}

function renderPills(el, items, key, show) {{
  el.classList.toggle('show', !!show);
  if (!show) {{ el.innerHTML = ''; return; }}
  el.innerHTML = items.map(it =>
    `<button type="button" class="pill ${{state[key]===it.id?'on':''}}" data-key="${{key}}" data-id="${{it.id}}">${{escapeHtml(it.label)}}</button>`
  ).join('');
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
  return `<div class="empty">
    <h2>没有匹配帖子</h2>
    <p>漏斗：trending ${{funnel.trending_repos ?? '—'}} · search ${{funnel.search_candidates ?? '—'}} ·
      过门禁 ${{funnel.passed ?? (FEED.gates && FEED.gates.passed) ?? 0}}</p>
    <p>rejected ${{escapeHtml(JSON.stringify(rejected))}}</p>
    <p>换个 Story / 二级场景，或跑 refresh 更新 corpus；配 GITHUB_TOKEN 可开 GitHub Search。</p>
  </div>`;
}}

function mePanelHtml() {{
  const nLiked = liked.size;
  const nSaved = saved.size;
  const pub = apiUrl('/publish') || '';
  const docs = apiUrl('/docs') || '';
  const home = apiUrl('/') || '';
  return `<div class="me-panel">
    <h2>我的</h2>
    <p class="lead">个人账户、本机收藏，以及发布后台入口。赞/藏仍保存在此浏览器。</p>
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
      <p>底部仅保留「发现 / 发布 / 我的」。Skills、AI、开源筛选在顶部 Stories，无内容的已自动隐藏。</p>
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
  renderStories();

  const hideChrome = state.mode === 'me';
  const secs = sectionOptions();
  const l2s = l2Options();
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

function openStoryViewer(sceneId) {{
  const label = (SCENES.find(s => s.id === sceneId) || {{}}).label || sceneId;
  const items = sceneItems(sceneId, 5);
  if (!items.length) {{
    toast('该场景暂无内容 · 试试 refresh 或 corpus');
    return;
  }}
  sv.open = true;
  sv.scene = sceneId;
  sv.items = items;
  sv.idx = 0;
  document.getElementById('svWho').textContent = label;
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
      document.getElementById('demoText').textContent = 'Demo：点场景 Story → 内容创作';
      state.mode = 'all';
      state.scene = 'content';
      state.scene_l2 = 'all';
      state.shown = 0;
      render(true);
      openStoryViewer('content');
    }},
    () => {{
      closeStoryViewer();
      document.getElementById('demoText').textContent = 'Demo：二级场景 → 写作润色';
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
  if (kind === 'mode') {{
    state.mode = value;
    state.scene_l2 = 'all';
    if (value === 'oss') state.scene = 'all';
    state.shown = 0;
    render(true);
    return;
  }}
  if (kind === 'scene') {{
    if (value === 'all') {{
      state.scene = 'all';
      state.scene_l2 = 'all';
      state.shown = 0;
      render(true);
    }} else {{
      state.scene = value;
      state.scene_l2 = 'all';
      if (state.mode === 'oss') state.mode = 'all';
      state.shown = 0;
      render(true);
      openStoryViewer(value);
    }}
  }}
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

document.querySelector('.bottom').addEventListener('click', (e) => {{
  const nav = e.target.closest('.nav');
  if (!nav) return;
  if (nav.dataset.action === 'publish') {{
    openPublish();
    return;
  }}
  state.mode = nav.dataset.mode || 'all';
  if (state.mode === 'all') {{
    state.section = 'all';
  }}
  state.shown = 0;
  render(true);
  window.scrollTo({{ top: 0, behavior: 'smooth' }});
}});

document.getElementById('intent').addEventListener('input', (e) => {{
  state.intent = e.target.value || '';
  state.shown = 0;
  render(true);
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

  if (t.closest('.js-doc-more')) {{
    const idx = t.closest('.js-doc-more').dataset.idx;
    const doc = document.getElementById('doc-' + idx);
    const btn = t.closest('.js-doc-more');
    if (doc) {{
      const on = doc.classList.toggle('expanded');
      btn.textContent = on ? '收起' : '展开全文摘要';
    }}
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
  toast('双击点赞 · 书签收藏 · 反馈写入 personal_score 排序'));

render(true);

if (new URLSearchParams(location.search).get('demo') === '1') {{
  setTimeout(startDemo, 400);
}}
</script>
</body>
</html>
"""


def write_feed_html(feed: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_feed_html(feed), encoding="utf-8")
