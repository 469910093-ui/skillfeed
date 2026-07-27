"""抓取并解析 https://github.com/trending（标准库 urllib + html.parser）。"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

TRENDING_URL = "https://github.com/trending"


@dataclass
class TrendingRepo:
    full_name: str  # owner/repo
    url: str
    description: str
    language: str
    stars: int
    stars_today: int
    source: str = "github.com/trending"

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]


def _parse_int(text: str) -> int:
    if not text:
        return 0
    cleaned = re.sub(r"[^\d]", "", text.replace(",", ""))
    return int(cleaned) if cleaned else 0


class TrendingHTMLParser(HTMLParser):
    """解析 GitHub trending 页面上的 article.Box-row 卡片。"""

    def __init__(self) -> None:
        super().__init__()
        self.repos: list[TrendingRepo] = []
        self._in_article = False
        self._article_depth = 0
        self._capture: Optional[str] = None
        self._buf: list[str] = []
        self._href: str = ""
        self._cur: dict = {}
        self._class_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        ad = dict(attrs)
        cls = ad.get("class") or ""
        self._class_stack.append(cls)

        if tag == "article" and "Box-row" in cls:
            self._in_article = True
            self._article_depth = 1
            self._cur = {
                "full_name": "",
                "url": "",
                "description": "",
                "language": "",
                "stars": 0,
                "stars_today": 0,
            }
            return

        if not self._in_article:
            return

        if tag == "article":
            self._article_depth += 1

        if tag == "a":
            href = ad.get("href") or ""
            # 仓库链接：/owner/repo（排除更深路径）
            if re.fullmatch(r"/[^/]+/[^/]+", href):
                # h2 内的主标题链接优先
                parent_cls = self._class_stack[-2] if len(self._class_stack) >= 2 else ""
                if "h3" in parent_cls or "lh-condensed" in parent_cls or not self._cur["full_name"]:
                    self._cur["url"] = "https://github.com" + href
                    self._cur["full_name"] = href.lstrip("/")
            if href.endswith("/stargazers") and self._cur["full_name"]:
                self._capture = "stars"
                self._buf = []
            return

        if tag == "p" and "col-9" in cls:
            self._capture = "description"
            self._buf = []
            return

        if tag == "span" and ad.get("itemprop") == "programmingLanguage":
            self._capture = "language"
            self._buf = []
            return

        # stars today: often in a span with float-sm-right
        if tag in ("span", "div") and ("float-sm-right" in cls or "d-inline-block" in cls):
            self._capture = "stars_today_block"
            self._buf = []

    def handle_endtag(self, tag: str) -> None:
        if self._in_article and tag == "article":
            self._article_depth -= 1
            if self._article_depth <= 0:
                self._in_article = False
                if self._cur.get("full_name"):
                    self.repos.append(TrendingRepo(
                        full_name=self._cur["full_name"],
                        url=self._cur["url"] or f"https://github.com/{self._cur['full_name']}",
                        description=(self._cur.get("description") or "").strip(),
                        language=(self._cur.get("language") or "").strip(),
                        stars=int(self._cur.get("stars") or 0),
                        stars_today=int(self._cur.get("stars_today") or 0),
                    ))
                self._cur = {}
            if self._class_stack:
                self._class_stack.pop()
            return

        if self._capture and tag in ("a", "p", "span", "div"):
            text = "".join(self._buf).strip()
            if self._capture == "stars":
                self._cur["stars"] = _parse_int(text)
            elif self._capture == "description":
                self._cur["description"] = text
            elif self._capture == "language":
                self._cur["language"] = text
            elif self._capture == "stars_today_block":
                m = re.search(r"([\d,]+)\s*stars?\s*today", text, re.I)
                if m:
                    self._cur["stars_today"] = _parse_int(m.group(1))
            self._capture = None
            self._buf = []

        if self._class_stack:
            self._class_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._capture is not None:
            self._buf.append(data)


def parse_trending_html(html: str) -> list[TrendingRepo]:
    parser = TrendingHTMLParser()
    parser.feed(html)
    # 去重保序
    seen: set[str] = set()
    out: list[TrendingRepo] = []
    for r in parser.repos:
        if r.full_name in seen:
            continue
        seen.add(r.full_name)
        out.append(r)
    return out


def trending_url(since: str = "daily", spoken_language: str = "") -> str:
    q = []
    if since and since != "daily":
        q.append(f"since={since}")
    if spoken_language:
        q.append(f"spoken_language_code={spoken_language}")
    return TRENDING_URL + (("?" + "&".join(q)) if q else "")


def fetch_url(url: str, user_agent: str, timeout: int = 30) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


def cache_paths(data_dir: Path, since: str) -> tuple[Path, Path]:
    return data_dir / f"trending_{since}.html", data_dir / f"trending_{since}.json"


def load_cached_repos(data_dir: Path, since: str, ttl_hours: float) -> Optional[list[TrendingRepo]]:
    html_path, json_path = cache_paths(data_dir, since)
    if not json_path.exists():
        return None
    age = time.time() - json_path.stat().st_mtime
    if age > ttl_hours * 3600:
        return None
    try:
        rows = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return [TrendingRepo(**row) for row in rows]


def save_cache(data_dir: Path, since: str, html: str, repos: list[TrendingRepo]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    html_path, json_path = cache_paths(data_dir, since)
    html_path.write_text(html, encoding="utf-8")
    payload = [asdict(r) for r in repos]
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def fetch_trending(
    data_dir: Path,
    since: str = "daily",
    ttl_hours: float = 6,
    user_agent: str = "skill-feed/0.1",
    force: bool = False,
) -> tuple[list[TrendingRepo], dict]:
    """返回 (repos, meta)。meta 含 from_cache / warn / fetched_at。"""
    meta = {
        "source": "github.com/trending",
        "since": since,
        "from_cache": False,
        "warn": "",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "url": trending_url(since),
    }
    if not force:
        cached = load_cached_repos(data_dir, since, ttl_hours)
        if cached is not None:
            meta["from_cache"] = True
            meta["fetched_at"] = datetime.fromtimestamp(
                cache_paths(data_dir, since)[1].stat().st_mtime, tz=timezone.utc
            ).isoformat()
            return cached, meta

    try:
        html = fetch_url(meta["url"], user_agent=user_agent)
        repos = parse_trending_html(html)
        if not repos:
            raise ValueError("parsed 0 repos from trending HTML (layout may have changed)")
        save_cache(data_dir, since, html, repos)
        return repos, meta
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as e:
        # 失败回退任意年龄的缓存
        _, json_path = cache_paths(data_dir, since)
        if json_path.exists():
            rows = json.loads(json_path.read_text(encoding="utf-8"))
            repos = [TrendingRepo(**row) for row in rows]
            meta["from_cache"] = True
            meta["warn"] = f"fetch failed ({e}); using stale cache"
            return repos, meta
        meta["warn"] = f"fetch failed ({e}); no cache"
        return [], meta
