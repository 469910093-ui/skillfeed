import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

import feed_dashboard
import scene

# 分类色按 scene.py 的权威清单逐一核对：新增一个一级场景而忘了配色，
# 这里会直接红，而不是上线后静静落到 other 的灰蓝
SCENE_IDS = [sid for sid, _label in scene.SCENES]


NODE = shutil.which("node")


def _script_source(html: str) -> str:
    """取出内联 <script> 里的 JS。"""
    blocks = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    return max(blocks, key=len)


def _top_level_functions(js: str) -> str:
    """把顶层 function 声明整块抠出来。

    模板里所有顶层函数都是 `function x(` 顶格开始、`}` 顶格结束，
    所以按行首大括号切最省事，也不用真写个 JS parser。
    """
    out = []
    lines = js.split("\n")
    i = 0
    while i < len(lines):
        if re.match(r"^(?:async\s+)?function\s+[A-Za-z0-9_$]+\s*\(", lines[i]):
            start = i
            i += 1
            while i < len(lines) and lines[i] != "}":
                i += 1
            out.append("\n".join(lines[start:i + 1]))
        i += 1
    return "\n\n".join(out)


def _grab(js: str, pattern: str) -> str:
    m = re.search(pattern, js, flags=re.S | re.M)
    if not m:
        raise AssertionError("模板里找不到：" + pattern)
    return m.group(0)


# 够跑面板函数的最小 DOM：只记录写进去的东西，好让 openFollowSheet 这类
# 直接操作 document 的函数能在 node 里真跑一遍，而不是把它的 HTML 抄一份来断言。
DOM_STUB = """
class StubEl {
  constructor(id) {
    this.id = id; this.innerHTML = ''; this.textContent = ''; this.value = '';
    this.hidden = false; this.dataset = {}; this.style = {}; this.attrs = {};
    this.title = ''; this.placeholder = ''; this.children = [];
    this.classList = {
      _s: new Set(),
      add(...c) { c.forEach(x => this._s.add(x)); },
      remove(...c) { c.forEach(x => this._s.delete(x)); },
      toggle(c, on) { if (on === undefined) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); } else if (on) { this._s.add(c); } else { this._s.delete(c); } },
      contains(c) { return this._s.has(c); },
    };
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  scrollIntoView() {}
  closest() { return null; }
  addEventListener() {}
}
const __els = {};
const document = {
  documentElement: new StubEl('html'),
  title: '',
  // safeUrl 拿 baseURI 当相对地址的解析基准；给个 http 基准，模拟线上而不是 file://
  baseURI: 'https://skillfeeder.cn/feed.html',
  getElementById(id) { return (__els[id] = __els[id] || new StubEl(id)); },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  addEventListener() {},
};
// scrollY / innerHeight 给「回到顶部」的阈值判定用。
// 刻意不在这里声明 location：test_install_button 复用本 stub 并自己声明一份
// （它要按地址栏切换 live/copy/off 三种形态），这里再声明一次会重复定义。
const window = { scrollTo() {}, addEventListener() {}, scrollY: 0, innerHeight: 800 };
const history = { replaceState() {} };
function setTimeout() { return 0; }
function clearTimeout() {}
const __store = {};
const localStorage = {
  getItem(k) { return Object.prototype.hasOwnProperty.call(__store, k) ? __store[k] : null; },
  setItem(k, v) { __store[k] = String(v); },
  removeItem(k) { delete __store[k]; },
};
const __sess = {};
const sessionStorage = {
  getItem(k) { return Object.prototype.hasOwnProperty.call(__sess, k) ? __sess[k] : null; },
  setItem(k, v) { __sess[k] = String(v); },
  removeItem(k) { delete __sess[k]; },
};
"""


class JsHarness:
    """在 node 里跑模板生成的真 JS，避免把去重规则在 Python 里抄第二份。"""

    def __init__(
        self,
        html: str,
        lang: str = "zh",
        *,
        scenes=None,
        scenes_l2=None,
        feed=None,
        follow_builders=(),
        follow_industries=(),
        local_block=None,
    ):
        js = _script_source(html)
        # skill-picker 注入的本机索引：把数据块的原文塞进 DOM stub，再跑模板里真正那段
        # 解析 IIFE。传 None 就是公开站的形态（数据块不存在）。
        seed_local = (
            "document.getElementById('skillpicker-local').textContent = "
            + json.dumps(local_block) + ";"
        ) if local_block is not None else ""
        self.prelude = "\n".join([
            DOM_STUB,
            seed_local,
            _grab(js, r"const LOCAL_SKILLS = \(function \(\) \{.*?\n\}\)\(\);"),
            _grab(js, r"const LOCAL_FRESH = \{\};"),
            _grab(js, r"const I18N = \{.*?\n\};"),
            "let LANG = " + json.dumps(lang) + ";",
            "const SCENES = %s; const SCENES_L2 = %s;" % (
                json.dumps(scenes or []), json.dumps(scenes_l2 or {}),
            ),
            "const FEED = %s;" % json.dumps(feed or {"ui": {}}),
            "const IS_LITE = false;",
            "const liked = new Set(); const saved = new Set(); const hidden = new Set(); const batchSkip = new Set();",
            "const followBuilders = new Set(%s); const followIndustries = new Set(%s);" % (
                json.dumps(list(follow_builders)), json.dumps(list(follow_industries)),
            ),
            "const demo = { on: false, step: 0, timer: null, focus: -1 };",
            # API_BASE 在模板里由 FEED.ui.api_base 推出来，这里固定成「没配云端」那一支
            "const API_BASE = ''; const PAGE = 6; const STORY_MS = 3500;",
            _grab(js, r"const SCENE_PAL = \{.*?\n\};"),
            _grab(js, r"const PAL_POOL = [^\n]*;"),
            _grab(js, r"const INK_HEX = '[^']*';"),
            _grab(js, r"const SECTION_EN = \{.*?\n\};"),
            _grab(js, r"const SECTION_AI = '[^']*';"),
            _grab(js, r"const SECTION_SKILLS = '[^']*';"),
            _grab(js, r"const SECTION_ORDER = \[.*?\n\];"),
            _grab(js, r"const DUP_PREFIX_MIN = \d+;"),
            _grab(js, r"const PITCH_MAX = \d+;"),
            _grab(js, r"const INTENT_STOP = new Set\(.*?\n\);"),
            _grab(js, r"const INTENT_PHRASES = \[.*?\n\];"),
            _grab(js, r"const MAX_INTENT_KEYS = \d+;"),
            _grab(js, r"const INTENT_CANON = \{.*?\n\};"),
            _grab(js, r"const DESLOP_ALIASES = new Set\(\[[^\n]*\]\);"),
            _grab(js, r"^const state = \{[^\n]*\};"),
            _grab(js, r"^const sv = \{[^\n]*\};"),
            _grab(js, r"^const publisherCache = \{[^\n]*\};"),
            _grab(js, r"^const ACCT = \{[^\n]*\};"),
            _grab(js, r"^const LOGIN_PATH = '[^']*';"),
            _grab(js, r"^const TAB_QUERY = \{[^\n]*\};"),
            # 空货架 `[];`、单行 JSON、或多行 indent 都能收口在第一个 `];`。
            # 旧写法要求 `\n]`，空 `[]` 会一路吞到后面的 PACK_HOWTO_LOCKED。
            _grab(js, r"^const PACK_SHELF = \[[\s\S]*?\];"),
            _grab(js, r"^const PACK_HOWTO_LOCKED = \[[\s\S]*?\n\];"),
            _top_level_functions(js),
        ])

    def eval(self, expr: str):
        src = self.prelude + "\nprocess.stdout.write(JSON.stringify(" + expr + "));\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.mjs"
            path.write_text(src, encoding="utf-8")
            proc = subprocess.run(
                [NODE, str(path)], capture_output=True, text=True, encoding="utf-8",
            )
        if proc.returncode != 0:
            raise AssertionError("node 执行失败：" + (proc.stderr or ""))
        return json.loads(proc.stdout)


CLOUD_MAIL = {
    "full_name": "maillab/cloud-mail",
    "name": "cloud-mail",
    "owner": "maillab",
    "description": (
        "基于 Cloudflare 的轻量级邮箱服务。这是一款基于 Cloudflare 的轻量级、响应式邮箱服务，"
        "只需一个域名即可在 Cloudflare Workers 上低成本快速搭建邮件服务平台，"
        "支持群发、收发附件和人机验证等功能。"
    ),
    "one_liner": (
        "基于 Cloudflare 的轻量级邮箱服务。这是一款基于 Cloudflare 的轻量级、响应式邮箱服务，"
        "只需一个域名即可在 Cloudflare Workers 上低成本快速搭建邮件服务平台，"
        "支持群发、收发附件和人机验证等功能。"
    ),
    "problem": (
        "基于 Cloudflare 的轻量级邮箱服务。这是一款基于 Cloudflare 的轻量级、响应式邮箱服务，"
        "只需一个域名即可在 Cloudflare Workers 上低成本快速搭建邮件服务平台，支持群发、收发附件和人…"
    ),
    "highlights": ["打开 GitHub 查看完整 SKILL.md 与用法"],
    "cover_url": "https://opengraph.githubassets.com/1/maillab/cloud-mail",
    "skill_url": "https://github.com/maillab/cloud-mail/blob/HEAD/SKILL.md",
    "url": "https://github.com/maillab/cloud-mail",
    "source": "hellogithub",
    "hg_section": "JavaScript 项目",
    "scene": "content",
    "scene_label": "内容创作",
    "from_corpus": True,
    "soft": False,
    "stars": None,
    "personal_score": 0.25,
}

REAL_SKILL = {
    "full_name": "hardikpandya/stop-slop",
    "name": "stop-slop",
    "owner": "hardikpandya",
    "description": "Remove AI writing patterns from prose.",
    "one_liner_zh": "一键删掉 AI 腔，让文字读起来像人写的。",
    "one_liner_en": "Remove AI-sounding patterns to make prose sound human.",
    "highlights_zh": ["删掉填充词和冗余副词", "打散刻板句式与虚假节奏"],
    "highlights_en": ["Cuts filler phrases and redundant adverbs", "Breaks rigid sentence patterns"],
    "who_for_zh": "编辑、作者、内容审核员",
    "who_for_en": "Editors, writers, content reviewers",
    "highlights": ["Cut filler phrases."],
    "problem": "Remove AI writing patterns from prose.",
    "skill_path": "SKILL.md",
    "skill_url": "https://github.com/hardikpandya/stop-slop/blob/HEAD/SKILL.md",
    "url": "https://github.com/hardikpandya/stop-slop",
    "source": "hellogithub",
    "scene": "content",
    "scene_label": "内容创作",
    "kind": "skill",
    "stars": 16729,
    "from_corpus": False,
    "soft": False,
}

FILLER_ZH = "打开 GitHub 查看完整 SKILL.md 与用法"
FILLER_EN = "Open GitHub for the full SKILL.md and usage"
DOC_LINK_ZH = "在 GitHub 看 SKILL.md 全文"
DOC_LINK_EN = "Read the full SKILL.md on GitHub"


class TestFeedDashboard(unittest.TestCase):
    def test_build_contains_items_and_open_github(self):
        feed = {
            "meta": {"source": "github.com/trending", "since": "daily"},
            "config": {"min_stars": 20},
            "funnel": {"trending_repos": 25, "probed": 3, "passed": 1},
            "items": [{
                "full_name": "acme/agent-skills",
                "name": "agent-skills",
                "description": "demo skill description long enough",
                "body_preview": "# Agent Skills\n\nUse this skill to automate weekly reviews.",
                "cover_url": "https://opengraph.githubassets.com/1/acme/agent-skills",
                "stars": 100,
                "stars_today": 5,
                "rel_score": 0.4,
                "rel_why": "domain:skill",
                "language": "Python",
                "url": "https://github.com/acme/agent-skills",
                "source": "github.com/trending",
                "scene": "agent-tooling",
                "scene_label": "Agent工具链",
                "kind": "skill",
            }],
            "corpus": [{
                "full_name": "hardikpandya/stop-slop",
                "name": "stop-slop",
                "description": "去 AI 味写作技能包",
                "source": "hellogithub",
                "hg_section": "Skills",
                "scene": "content",
                "scene_label": "内容创作",
                "kind": "skill",
                "from_corpus": True,
                "url": "https://github.com/hardikpandya/stop-slop",
            }],
        }
        html = feed_dashboard.build_feed_html(feed)
        self.assertIn("skill-feed", html)
        self.assertIn("acme/agent-skills", html)
        self.assertIn("打开 GitHub", html)
        self.assertIn("/api/feedback", html)
        self.assertNotIn("/api/install", html)
        self.assertNotIn("安装到本机", html)
        self.assertIn("下滑加载更多", html)
        self.assertIn("内容创作", html)
        self.assertIn("opengraph.githubassets.com", html)
        self.assertIn("class=\"zone-read pitch\"", html)
        self.assertIn("extractHighlightsClient", html)
        self.assertIn("js-publisher", html)
        self.assertIn("openPublisher", html)
        self.assertNotIn("aria-label=\"more\"", html)
        self.assertIn("sv-cover", html)
        self.assertIn("object-fit: contain", html)
        self.assertRegex(html, r"\.media \.cover \{[^}]*object-fit: cover;")
        self.assertNotIn("background-size: cover; background-position: center;", html)
        self.assertIn("发现", html)
        self.assertIn("发布", html)
        self.assertIn("我的", html)
        self.assertIn("variant-full", html)
        self.assertIn("IS_LITE", html)
        self.assertIn("githubSearchUrls", html)
        self.assertIn("path:**/SKILL.md", html)
        self.assertNotIn("filename:SKILL.md ${", html)
        self.assertIn("countMode", html)
        self.assertNotIn('data-mode="skills"', html)
        self.assertIn('"full_name": "acme/agent-skills"', json.dumps(feed))

    def test_lite_variant_strips_social_chrome(self):
        feed = {
            "items": [{
                "full_name": "acme/agent-skills",
                "name": "agent-skills",
                "description": "demo",
                "url": "https://github.com/acme/agent-skills",
                "source": "github.com/trending",
                "scene": "content",
                "scene_label": "内容创作",
            }],
            "corpus": [],
            "ui": {"variant": "lite"},
        }
        html = feed_dashboard.build_feed_html(feed, variant="lite")
        self.assertIn("variant-lite", html)
        self.assertIn("去 GitHub 发现", html)
        self.assertIn("本机没有合适 skill", html)
        self.assertIn("打开 GitHub", html)
        self.assertIn("const IS_LITE = VARIANT === 'lite'", html)
        # lite 仍含 DOM（CSS/JS 门控），但标记为 lite 且默认隐藏社交模块
        self.assertIn("body.variant-lite .stories-wrap", html)

    def test_dedupe_helpers_shipped(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        self.assertIn("function normDup", html)
        self.assertIn("function dupText", html)
        self.assertIn("function hasSkillDoc", html)
        self.assertIn("function isFillerHighlight", html)
        self.assertIn(".media.no-cover.bare", html)
        # 亮点为空时整块不渲染；真文档并进唯一的「打开 GitHub」，不再另挂一条文链
        self.assertIn("${hl ? `<ul class=\"highlights\">", html)
        self.assertNotIn('class="doc-link"', html)
        self.assertIn("hasSkillDoc(it) ? skillUrl : url", html)


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的卡片 JS")
class TestCardDedupeJs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, lang="zh"):
        return JsHarness(self.html, lang=lang)

    def test_normalized_dup_detection(self):
        js = self.harness()
        full = CLOUD_MAIL["description"]
        cut = CLOUD_MAIL["problem"]
        got = js.eval("[" + ",".join([
            # 截断版是全量版的前缀，裸字符串相等抓不到
            f"dupText({json.dumps(cut)}, {json.dumps(full)})",
            f"{json.dumps(cut)} === {json.dumps(full)}",
            # 归一化：折叠空白、去尾部省略号与句号、统一大小写
            "dupText('Stop  Slop 去AI味...', '  stop slop 去AI味  ')",
            "sameText('Cloud-Mail', 'cloud-mail')",
            "sameText('去 AI 味。', '去 AI 味')",
            # 短串不吃前缀规则，长串无关文本也不误判
            "dupText('AI', 'AI 写作助手')",
            "dupText('基于 Cloudflare 的轻量级邮箱服务', '一个跑在浏览器里的向量数据库演示')",
            "dupText('', '任何东西')",
            # 截断/全量二选一时留全量
            f"preferFuller({json.dumps(cut)}, {json.dumps(full)}) === {json.dumps(full)}",
        ]) + "]")
        self.assertEqual(
            got,
            [True, False, True, True, True, False, False, False, True],
        )

    def test_corpus_card_drops_skill_md_and_filler(self):
        for lang, doc_link, filler in (("zh", DOC_LINK_ZH, FILLER_ZH), ("en", DOC_LINK_EN, FILLER_EN)):
            with self.subTest(lang=lang):
                card = self.harness(lang).eval(
                    "cardHtml(" + json.dumps(CLOUD_MAIL) + ", 0)")
                self.assertNotIn(doc_link, card)
                self.assertNotIn("blob/HEAD/SKILL.md", card)
                self.assertNotIn(filler, card)
                self.assertNotIn(FILLER_ZH, card)
                self.assertNotIn(FILLER_EN, card)
                # 亮点没内容就整块不渲染，不留空壳
                self.assertNotIn("<ul class=\"highlights\">", card)
                # 唯一诚实的 CTA 留着
                self.assertIn("open-gh", card)
                self.assertIn(CLOUD_MAIL["url"], card)

    def test_corpus_card_shows_each_line_once(self):
        card = self.harness().eval("cardHtml(" + json.dumps(CLOUD_MAIL) + ", 0)")
        head = "基于 Cloudflare 的轻量级邮箱服务"
        self.assertEqual(card.count(head), 1, card)
        # 封面兜底层的大字与作者行同名，删掉后 media 缩成窄条
        self.assertEqual(card.count("cloud-mail<"), 1, card)
        self.assertNotIn("cover-fallback", card)
        # bare 要在渲染时就打上：no-cover 是封面图 onerror 时才动态加的
        self.assertIn('class="zone-media media js-media bare"', card)
        # 只剩一份时留全量文案，不留「和人…」这种断句
        self.assertIn("人机验证", card)

    def test_real_skill_card_opens_skill_md_via_single_cta(self):
        for lang, doc_link in (("zh", DOC_LINK_ZH), ("en", DOC_LINK_EN)):
            with self.subTest(lang=lang):
                card = self.harness(lang).eval(
                    "cardHtml(" + json.dumps(REAL_SKILL) + ", 0)")
                self.assertNotIn(doc_link, card)
                self.assertNotIn("doc-link", card)
                self.assertNotIn("follow-mini", card)
                self.assertNotIn("why-line", card)
                self.assertNotIn("score ", card)
                self.assertIn("blob/HEAD/SKILL.md", card)
                self.assertIn("open-gh", card)
                self.assertIn("<ul class=\"highlights\">", card)
                self.assertIn("who-for", card)

    def test_real_skill_without_highlights_keeps_truthful_fallback(self):
        item = dict(REAL_SKILL)
        for key in ("highlights_zh", "highlights_en", "highlights"):
            item.pop(key, None)
        item["body_preview"] = ""
        tips = self.harness().eval("extractHighlightsClient(" + json.dumps(item) + ")")
        self.assertEqual(tips["highlights"], [FILLER_ZH])

    def test_highlights_never_repeat_the_problem_line(self):
        item = dict(REAL_SKILL)
        item["highlights_zh"] = [
            item["one_liner_zh"],
            item["one_liner_zh"][:-1],
            "删掉填充词和冗余副词",
            "删掉填充词和冗余副词…",
        ]
        tips = self.harness().eval("extractHighlightsClient(" + json.dumps(item) + ")")
        self.assertEqual(tips["highlights"], ["删掉填充词和冗余副词"])

    def test_who_for_dropped_when_it_repeats_problem(self):
        item = dict(REAL_SKILL)
        item["who_for_zh"] = item["one_liner_zh"]
        tips = self.harness().eval("extractHighlightsClient(" + json.dumps(item) + ")")
        self.assertEqual(tips["whoFor"], "")


class TestFirstScreenChrome(unittest.TestCase):
    """七个角色对「门口是空壳」的共识：没关注就不放圆环，Demo/反馈默认藏。"""

    def test_template_hides_empty_rings_and_demo_chrome(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        self.assertIn("aspect-ratio: 16 / 7", html)
        self.assertIn("nFollow === 0", html)
        self.assertIn("body.show-demo-tools .icon-btn", html)
        self.assertRegex(html, r"\.icon-btn \{[^}]*display: none;")
        self.assertNotIn('id="genStatus"', html)
        self.assertIn('id="btnRefresh"', html)
        header = re.search(r'<header class="topbar">.*?</header>', html, flags=re.S).group(0)
        self.assertIn('id="searchWrap"', header, "搜索必须吸在顶栏里，不能再掉到顶栏下面")
        self.assertIn('id="btnRefresh"', header)
        self.assertIn('id="productLine"', header)
        self.assertIn("每刷一下，就快人一步", header)
        self.assertIn('data-i18n="valueLine"', header)
        self.assertIn('id="coach"', html)
        self.assertIn('id="coachSkip"', html)
        self.assertIn("target: '#storiesWrap'", html)
        self.assertIn("target: '#feed .coach-react'", html)
        self.assertIn("target: '#feed .coach-github'", html)
        self.assertIn("target: '#tab-publish'", html)

    @unittest.skipIf(NODE is None, "需要 node 才能跑 renderStories")
    def test_empty_follows_hide_story_rings(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        hidden = JsHarness(html).eval(
            "(renderStories(), document.getElementById('storiesWrap').classList.contains('hidden'))")
        self.assertTrue(hidden)

    @unittest.skipIf(NODE is None, "需要 node 才能跑 renderStories")
    def test_followed_builder_shows_story_rings(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        h = JsHarness(html, follow_builders=("acme",))
        got = h.eval(
            "(renderStories(), {"
            "hidden: document.getElementById('storiesWrap').classList.contains('hidden'),"
            "html: document.getElementById('stories').innerHTML"
            "})")
        self.assertFalse(got["hidden"])
        self.assertIn('class="story', got["html"])


CJK = re.compile(r"[\u4e00-\u9fff]")

# 只有这两个钩子会换文本内容；-aria / -title 换的是属性，不管文本
TEXT_HOOKS = {"data-i18n", "data-i18n-html"}


class _ChineseTextFinder(HTMLParser):
    """收集所有「自己和祖先都没挂 i18n 钩子」的中文文本节点。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[bool] = []
        self.leaks: list[str] = []

    VOID = ("br", "img", "input", "meta", "link", "hr")

    def _inherited(self) -> bool:
        # 必须显式转 bool：空 stack 时 `self.stack and self.stack[-1]` 会把
        # stack 自己返回来，append 进去就成了自引用列表，之后每一层都判成真
        return bool(self.stack) and bool(self.stack[-1])

    def handle_starttag(self, tag, attrs):
        hooked = bool({k for k, _ in attrs} & TEXT_HOOKS)
        if tag not in self.VOID:
            self.stack.append(hooked or self._inherited())

    def handle_endtag(self, tag):
        if tag not in self.VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        text = data.strip()
        if text and CJK.search(text) and not self._inherited():
            self.leaks.append(text)


def _static_chinese_without_i18n(html: str) -> list[str]:
    p = _ChineseTextFinder()
    p.feed(html)
    return p.leaks


SCENES_FIX = [
    {"id": "content", "label": "内容创作", "label_en": "Content"},
    {"id": "design", "label": "产品设计", "label_en": "Design"},
]

FEED_FIX = {
    "ui": {},
    "funnel": {"trending_repos": 25, "search_candidates": 9, "passed": 3},
    "items": [dict(REAL_SKILL, owner="acme", full_name="acme/stop-slop")],
    "corpus": [],
}


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的面板 JS")
class TestPanelI18n(unittest.TestCase):
    """EN 模式下这些块一个汉字都不能出现，zh 模式下必须还是中文。

    两边都断言，是为了防止「EN 无中文」因为函数根本没渲染出东西而空过。
    """

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, lang, **kw):
        kw.setdefault("scenes", SCENES_FIX)
        kw.setdefault("feed", FEED_FIX)
        return JsHarness(self.html, lang=lang, **kw)

    # 每条是 (用例名, JS 表达式)；表达式要返回一段 HTML 或文本
    BLOCKS = (
        ("mePanelHtml", "mePanelHtml()"),
        ("mePanelHtml/followed", "mePanelHtml()"),
        ("topicsPanelHtml", "topicsPanelHtml()"),
        ("topicsPanelHtml/section", "(state.topicsView = 'section', topicsPanelHtml())"),
        # API_BASE 在 harness 里固定成空串，所以这里走的是「无后端」那一支
        ("publishPanelHtml/no-api", "publishPanelHtml()"),
        ("emptyHtml/no-intent", "emptyHtml([])"),
        ("emptyHtml/saved", "(state.mode = 'saved', emptyHtml([]))"),
        ("emptyHtml/intent", "(state.mode = 'all', state.intent = 'stop-slop', emptyHtml([]))"),
        ("followSheet/builder", "followSheetHtml('builder')"),
        ("followSheet/industry", "followSheetHtml('industry')"),
        ("industrySheet", "industrySheetHtml('content')"),
        ("publisherPanel/repos", "publisherPanelHtml('acme', [{name:'r',url:'u',stars:1,description:''}])"),
        ("publisherPanel/empty", "publisherPanelHtml('acme', [])"),
        ("publisherPanel/loading", "publisherPanelHtml('acme', null)"),
        ("openFollowSheet/industry",
         "(openFollowSheet('industry'), document.getElementById('followSheetPanel').innerHTML)"),
        ("openFollowSheet/builder",
         "(openFollowSheet('builder'), document.getElementById('followSheetPanel').innerHTML)"),
        ("storyViewer/slide",
         "(sv.items = FEED.items, sv.idx = 0, renderSvSlide(),"
         " document.getElementById('svContent').innerHTML)"),
        ("storyViewer/who",
         "(openStoryViewer('industry', 'content'),"
         " document.getElementById('svWho').textContent)"),
        ("sentinel", "(render(true), document.getElementById('feed').innerHTML)"),
    )

    def test_no_chinese_in_en_mode(self):
        js = self.harness("en", follow_builders=["acme"], follow_industries=["content"])
        for name, expr in self.BLOCKS:
            with self.subTest(block=name):
                got = js.eval(expr)
                self.assertTrue(got, "块渲染成空，断言会假过：" + name)
                self.assertEqual([], CJK.findall(got), name + " 漏中文：" + got[:400])

    def test_same_blocks_are_chinese_in_zh_mode(self):
        js = self.harness("zh", follow_builders=["acme"], follow_industries=["content"])
        for name, expr in self.BLOCKS:
            with self.subTest(block=name):
                got = js.eval(expr)
                self.assertTrue(CJK.search(got), name + " 中文模式下没中文：" + got[:400])

    def test_story_chips_follow_language(self):
        item = dict(REAL_SKILL, scene="content", from_corpus=True, soft=True)
        expr = ("(sv.items = [" + json.dumps(item) + "], sv.idx = 0, renderSvSlide(),"
                " document.getElementById('svContent').innerHTML)")
        zh = self.harness("zh").eval(expr)
        en = self.harness("en").eval(expr)
        # 行业徽标按 SCENES 里的 label/label_en 走，「知识库」「线索」走 I18N
        self.assertIn("内容创作", zh)
        self.assertIn("知识库", zh)
        self.assertIn("线索", zh)
        self.assertIn("Content", en)
        self.assertIn("Library", en)
        self.assertIn("Lead", en)
        self.assertEqual([], CJK.findall(en), en[:400])


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的面板 JS")
class TestLogicNotKeyedOnDisplayText(unittest.TestCase):
    """分支判断必须基于稳定标识，不能拿展示文案比字符串。

    原来是 `title === '发现行业'`：切到 EN 后 <h3> 变成 'Discover industries'，
    这个等号永远不成立，「发现行业」列表点关注后会被换成单行业详情页。
    """

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, lang):
        return JsHarness(self.html, lang=lang, scenes=SCENES_FIX, feed=FEED_FIX)

    def test_open_sheet_stamps_stable_identifier(self):
        for lang in ("zh", "en"):
            with self.subTest(lang=lang):
                got = self.harness(lang).eval(
                    "[(openFollowSheet('industry'), document.getElementById('followSheetPanel').dataset.sheet),"
                    " (openFollowSheet('builder'), document.getElementById('followSheetPanel').dataset.sheet),"
                    " (openIndustrySheet('content'), document.getElementById('followSheetPanel').dataset.sheet)]")
                self.assertEqual(got, ["industry-list", "builder-list", "industry-detail"])

    def test_reopen_branch_is_language_stable(self):
        """两种语言下，重渲染分支的走向必须完全一样。"""
        expr = ("[reopenSheetAfterIndustryToggle('industry-list', 'content'),"
                " reopenSheetAfterIndustryToggle('industry-detail', 'content'),"
                " reopenSheetAfterIndustryToggle('builder-list', ''),"
                " reopenSheetAfterIndustryToggle('', 'content')]")
        zh = self.harness("zh").eval(expr)
        en = self.harness("en").eval(expr)
        self.assertEqual(zh, ["industry-list", "industry-detail", "", "industry-detail"])
        self.assertEqual(zh, en)

    def test_industry_list_stays_a_list_after_following(self):
        """点「发现行业」列表里的关注，重渲染出来的还得是那张列表。

        EN 下旧代码会掉到 openIndustrySheet 分支，列表被换成单行业详情页，
        用户想连着关注第二个行业就得退出来重开。
        """
        expr = ("(openFollowSheet('industry'),"
                " reopenSheetAfterIndustryToggle("
                "   document.getElementById('followSheetPanel').dataset.sheet, 'content'),"
                " document.getElementById('followSheetPanel').dataset.sheet)")
        for lang in ("zh", "en"):
            with self.subTest(lang=lang):
                self.assertEqual(self.harness(lang).eval(expr), "industry-list")

    def test_ascii_intent_never_compresses_into_chinese(self):
        """EN 界面里输 ASCII，搜索框和关键词条不能被改写成中文。"""
        exprs = [
            "compressIntent('stop-slop')",
            "compressIntent('de-slop my writing')",
            "compressIntent('slop')",
            "demoIntent()",
        ]
        en = self.harness("en").eval("[" + ",".join(exprs) + "]")
        self.assertEqual([], CJK.findall(json.dumps(en, ensure_ascii=False)), str(en))
        # zh 下仍规范化成中文短词，改动没把中文侧压平
        zh = self.harness("zh").eval("compressIntent('stop-slop')")
        self.assertIn("去AI味", zh["keys"])

    def test_section_matching_uses_upstream_data_values(self):
        """hg_section 里的中文是 HelloGitHub 上游数据值，不能跟着界面语言翻。"""
        expr = ("[matchModeValue({hg_section:'人工智能'}, 'ai'),"
                " matchModeValue({hg_section:'Skills'}, 'skills'),"
                " sectionLabelOf('人工智能'),"
                " sectionLabelOf('Python 项目')]")
        zh = self.harness("zh").eval(expr)
        en = self.harness("en").eval(expr)
        self.assertEqual(zh[:2], [True, True])
        self.assertEqual(en[:2], [True, True], "按数据值匹配的分支不该受语言影响")
        self.assertEqual(zh[2:], ["人工智能", "Python"])
        self.assertEqual(en[2:], ["AI", "Python"])


class TestNoChineseLiteralsInLogic(unittest.TestCase):
    """源码级护栏：拦住「拿中文展示文案做判断」这一类写法再长回来。"""

    def setUp(self):
        js = _script_source(
            feed_dashboard.build_feed_html({"items": [], "corpus": []}))
        # 注释里会引用旧写法当反面教材，扫之前先去掉，否则自己的注释会把测试打红
        js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
        self.js = re.sub(r"(?m)//.*$", "", js)

    def test_no_equality_check_against_chinese_display_text(self):
        # 只拦 ===/!== 和 switch-case 上的中文字面量：
        # 这类写法一换语言就静默失效。includes()/正则/Set.has() 那些是拿来匹配
        # 用户输入和上游数据值的，中文是数据不是文案，不在此列。
        leaked = re.findall(
            r"(?:===|!==)\s*'[^']*[\u4e00-\u9fff][^']*'"
            r"|'[^']*[\u4e00-\u9fff][^']*'\s*(?:===|!==)"
            r"|case\s*'[^']*[\u4e00-\u9fff][^']*'",
            self.js,
        )
        self.assertEqual([], leaked, "别拿中文文案做相等判断：" + str(leaked))

    def _skeleton(self, variant):
        html = feed_dashboard.build_feed_html(
            {"items": [], "corpus": []}, variant=variant)
        # 含 type=ld+json 的 script、以及给爬虫看的 noscript GEO 块，都不是
        # applyLang 要换的 UI 文案；只剥「无属性 script」会把 JSON-LD 漏进来。
        html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.S | re.I)
        html = re.sub(r"<style\b[^>]*>.*?</style>", "", html, flags=re.S | re.I)
        html = re.sub(r"<noscript\b[^>]*>.*?</noscript>", "", html, flags=re.S | re.I)
        return html

    def test_static_chinese_aria_labels_are_i18n_hooked(self):
        # 骨架里带中文的 aria-label / title 必须挂 data-i18n-aria / data-i18n-title，
        # 否则切到 EN 后这些无障碍文案还是中文
        for variant in ("full", "lite"):
            skeleton = self._skeleton(variant)
            for tag in re.findall(r"<[a-zA-Z][^>]*>", skeleton):
                for attr, hook in (("aria-label", "data-i18n-aria"),
                                   ("title", "data-i18n-title")):
                    m = re.search(attr + r'="([^"]*)"', tag)
                    if m and CJK.search(m.group(1)) and hook not in tag:
                        self.fail("%s 变体里 %s 的中文没挂 %s：%s" % (
                            variant, attr, hook, tag[:160]))

    def test_static_chinese_text_nodes_are_i18n_hooked(self):
        """骨架里每处中文文本都得挂 i18n 钩子，否则切 EN 后它还是中文。

        用真 parser 而不是按标签切串，因为 liteBanner 这类文案里裹着 <b>，
        钩子挂在外层元素上，只看同一段文本判断不出来。
        """
        import geo as _geo
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                leaks = _static_chinese_without_i18n(self._skeleton(variant))
                # 语言开关自己的「中文」按钮按惯例用本语言书写，不跟随开关；
                # <title> 由服务端渲染中文默认值（full=GEO 标题，lite=发现子页），
                # applyLang 里另有一刀；JSON-LD / noscript 已在 _skeleton 剥掉。
                if variant == "full":
                    expected = [_geo.PAGE_TITLE, "中文"]
                else:
                    expected = ["去 GitHub 发现", "中文"]
                self.assertEqual(expected, leaks,
                                 variant + " 骨架里有没挂 i18n 钩子的中文：" + str(leaks))

EVIL_CLOSE = "</script><script>window.__PWNED__=1;</script>"

# 能让浏览器提前结束脚本块 / 进入注释状态的序列。`<` `>` 一被转义这些就都不成立了，
# 但断言写全是为了让「只挡了 </script>」这种半吊子修法直接把测试打红。
SCRIPT_BREAKOUTS = ("</script", "<script", "<!--", "-->", "]]>", "\u2028", "\u2029")


def _script_blocks(html: str) -> list[str]:
    return re.findall(r"<script>(.*?)</script>", html, flags=re.S)


def _wcag_ratio(fg: str, bg: str) -> float:
    """算 WCAG 2.x 相对亮度对比，接受 #rrggbb。"""
    def lum(hexstr):
        h = hexstr.lstrip("#")
        parts = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    a, b = lum(fg), lum(bg)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def _css_token(html: str, name: str) -> str:
    m = re.search(r"--" + re.escape(name) + r":\s*(#[0-9a-fA-F]{6})\s*;", html)
    if not m:
        raise AssertionError("找不到 CSS 令牌 --" + name)
    return m.group(1).lower()


MALICIOUS_ITEM = {
    "full_name": "attacker/evil-skill",
    "name": "evil-skill",
    "owner": "attacker",
    "description": "A normal looking skill. " + EVIL_CLOSE,
    "one_liner_zh": "看起来正常的一句话。" + EVIL_CLOSE,
    # U+2028/U+2029 在 JSON 里合法，在 JS 源码里却是行终止符
    "problem": "line1\u2028line2\u2029line3",
    "highlights": ["<!--", "<script", "</SCRIPT >", "]]>", "-->"],
    "who_for_zh": "所有人",
    "url": "javascript:window.__PWNED_HREF__=1",
    "skill_url": "javascript:window.__PWNED_SKILL__=1",
    "cover_url": "javascript:window.__PWNED_IMG__=1",
    "skill_path": "SKILL.md",
    "source": "hellogithub",
    "scene": "content",
    "scene_label": "内容创作",
    "kind": "skill",
    "stars": 999,
}


def _malicious_feed() -> dict:
    return {
        "items": [dict(MALICIOUS_ITEM)],
        "corpus": [],
        # scenes / scenes_l2 是另外两个被塞进 <script> 的插值点
        "scenes": [{"id": "content", "label": "内容创作" + EVIL_CLOSE, "label_en": "C"}],
        "scenes_l2": {"content": [{"id": "x", "label": "sub" + EVIL_CLOSE}]},
    }


class TestScriptInjection(unittest.TestCase):
    """存储型 XSS：任何人在自己的 SKILL.md 里写 </script> 都不能提前结束脚本块。

    数据源就是「从 GitHub 抓陌生人写的 SKILL.md」，所以不可信输入是常态不是边缘情况。
    """

    def test_json_for_script_roundtrips_every_escaped_char(self):
        """转义只动序列化后的文本，数据本身必须一个字节都不丢。"""
        for value in (
            EVIL_CLOSE,
            "<!-- --> ]]> <script",
            "a\u2028b\u2029c",
            "反斜杠 \\ 与 <> & 混在一起",
            {"k": ["<", ">", "&", "\u2028"]},
            "emoji 🚀 与 <b>",
        ):
            with self.subTest(value=value):
                dumped = feed_dashboard._json_for_script(value)
                self.assertEqual(value, json.loads(dumped))
                for ch in ("<", ">", "&", "\u2028", "\u2029"):
                    self.assertNotIn(ch, dumped, "序列化结果里还留着裸 " + repr(ch))

    def test_malicious_item_cannot_close_the_script_block(self):
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                html = feed_dashboard.build_feed_html(_malicious_feed(), variant=variant)
                # 允许两块：GEO 的 application/ld+json + 页面主脚本。
                # 多出来的裸 <script> 才是被恶意数据劈开的。
                tags = re.findall(r"<script\b([^>]*)>", html, flags=re.I)
                self.assertEqual(2, len(tags), tags)
                self.assertEqual(
                    1, sum(1 for a in tags if "ld+json" in a.lower()),
                    "缺 JSON-LD 或被劈成多块")
                self.assertEqual(
                    1, sum(1 for a in tags if "ld+json" not in a.lower()),
                    "主脚本被劈开或消失：" + str(tags))
                self.assertEqual(2, len(re.findall(r"</script\s*>", html, flags=re.I)))
                bodies = _script_blocks(html)
                self.assertEqual(1, len(bodies), "主脚本（无 type）应恰好一块")
                body = bodies[0].lower()
                for seq in SCRIPT_BREAKOUTS:
                    self.assertNotIn(seq.lower(), body,
                                     "脚本块里出现可提前闭合/注释的序列：" + repr(seq))

    def test_build_path_never_uses_bare_json_dumps(self):
        """源码级护栏：进 <script> 的插值必须走 _json_for_script。

        逐个注入点手写 replace 一定会漏，所以这里直接禁掉裸 json.dumps。
        """
        src = Path(feed_dashboard.__file__).read_text(encoding="utf-8")
        body = src[src.index("def build_feed_html"):src.index("def write_feed_html")]
        self.assertNotIn("json.dumps", body,
                         "build_feed_html 里不该再出现裸 json.dumps，请用 _json_for_script")


@unittest.skipIf(NODE is None, "需要 node 才能验证生成的 JS 真能读到数据")
class TestMaliciousDataStillUsable(unittest.TestCase):
    """修安全不能把数据弄坏：恶意 item 的正常字段仍要被 JS 原样读到。"""

    def _feed_from_page(self, variant):
        html = feed_dashboard.build_feed_html(_malicious_feed(), variant=variant)
        js = max(_script_blocks(html), key=len)
        # 只取到 VARIANT 之前：后面的代码会碰 document
        head = js.split("const VARIANT")[0]
        src = head + (
            "\nprocess.stdout.write(JSON.stringify({"
            " item: FEED.items[0], scene: SCENES[0].label,"
            " l2: SCENES_L2.content[0].label }));\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.mjs"
            path.write_text(src, encoding="utf-8")
            proc = subprocess.run([NODE, str(path)], capture_output=True,
                                  text=True, encoding="utf-8")
        if proc.returncode != 0:
            raise AssertionError("生成的 JS 跑不起来：" + (proc.stderr or ""))
        return json.loads(proc.stdout)

    def test_every_field_survives_serialization(self):
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                got = self._feed_from_page(variant)
                for key in ("description", "one_liner_zh", "problem", "highlights", "url"):
                    self.assertEqual(MALICIOUS_ITEM[key], got["item"][key],
                                     key + " 在往返中被改坏了")
                self.assertEqual("内容创作" + EVIL_CLOSE, got["scene"])
                self.assertEqual("sub" + EVIL_CLOSE, got["l2"])


@unittest.skipIf(NODE is None, "需要 node 才能跑 safeUrl / cardHtml")
class TestUrlSchemeAllowlist(unittest.TestCase):
    """escapeHtml 挡属性逸出，挡不住协议：href="javascript:..." 一个引号都不用。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def test_safe_url_keeps_http_and_blocks_the_rest(self):
        cases = [
            ("https://github.com/a/b", "https://github.com/a/b"),
            ("http://example.com/x?y=1#z", "http://example.com/x?y=1#z"),
            ("/api/feedback", "/api/feedback"),          # 相对地址解析到 https 基准
            ("", ""),                                     # 空值保持空，调用方的条件分支不变
            ("javascript:alert(1)", "about:blank"),
            ("JaVaScRiPt:alert(1)", "about:blank"),       # 大小写混淆
            ("  \t javascript:alert(1)", "about:blank"),  # 前导空白
            ("data:text/html,<script>alert(1)</script>", "about:blank"),
            ("vbscript:msgbox(1)", "about:blank"),
            ("file:///etc/passwd", "about:blank"),
        ]
        got = JsHarness(self.html).eval(
            "[" + ",".join("safeUrl(%s)" % json.dumps(u) for u, _ in cases) + "]")
        self.assertEqual([want for _, want in cases], got)

    def test_card_never_emits_a_javascript_url(self):
        card = JsHarness(self.html).eval(
            "cardHtml(" + json.dumps(MALICIOUS_ITEM) + ", 0)")
        self.assertNotIn("javascript:", card)
        # CTA 仍然渲染出来，只是指向惰性地址，不会静默消失
        self.assertIn('href="about:blank"', card)
        self.assertIn("open-gh", card)

    def test_every_url_attribute_in_template_goes_through_safe_url(self):
        """源码级护栏：href / src 的插值必须套 safeUrl，只 escapeHtml 是不够的。"""
        js = max(_script_blocks(self.html), key=len)
        # 前置排除 -/\w：否则 data-src="${…}"（存的是 catalog/trending 这种来源名，
        # 从不当 URL 用）会被当成 src 属性误报。
        bare = [m.group(0) for m in re.finditer(r'(?<![-\w])(?:href|src)="\$\{[^"]*\}"', js)
                if "safeUrl(" not in m.group(0)]
        self.assertEqual([], bare, "这些 URL 属性没过协议白名单：" + str(bare))


class TestViewportAndFocusVisible(unittest.TestCase):
    def test_zoom_is_not_disabled(self):
        """maximum-scale=1 / user-scalable=no 违反 WCAG 1.4.4。

        这个产品次级文本只有 9.9–12.8px，主要在手机上看，
        「放大看清楚」是用户最后的自救手段，不能拿掉。
        """
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                html = feed_dashboard.build_feed_html(
                    {"items": [], "corpus": []}, variant=variant)
                meta = re.search(r'<meta name="viewport" content="([^"]*)"', html).group(1)
                self.assertNotIn("maximum-scale", meta)
                self.assertNotIn("user-scalable", meta)
                self.assertIn("width=device-width", meta)

    def test_focus_visible_ring_exists_and_is_not_suppressed(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        style = re.search(r"<style>(.*?)</style>", html, flags=re.S).group(1)
        self.assertIn(":focus-visible", style)
        # 键盘用户唯一的定位手段，别再被 outline:none 抹掉
        self.assertNotRegex(style, r"outline:\s*(none|0)")


class TestContrastTokens(unittest.TestCase):
    """对比度用真实数值断言，不看颜色字符串——换个「看起来更深」的值也可能仍不达标。"""

    AA_TEXT = 4.5
    NON_TEXT_MIN = 3.0

    # highlights 面板的底色。它不是令牌，是写死在 `.pitch .highlights li` 里的，
    # 所以这里也只能写死；用处一变就会静默变松，由
    # test_the_panel_background_is_still_only_used_where_we_think 盯着。
    PANEL = "#f6f8fa"

    # token → (它在哪儿当文本用, 它实际会落在哪些背景上)
    #
    # 背景要逐 token 列，不能一律套三种：PANEL 只铺在 `.pitch .highlights li` 上，
    # 那个元素里唯一着色的是 `::before` 的 ✦（走 --accent）。--muted 在
    # `.who-for`、--like-ink 在卡上的操作按钮，都是白卡背景 —— 它俩在 PANEL 上
    # 分别只有 4.45 / 4.43，一律套宽了会逼着下次有人去动根本没这个问题的取值。
    TEXT_TOKENS = {
        "ink": ("正文", ("card", "bg", PANEL)),
        "muted": ("「适合谁 / 为什么推荐」这类决策文案", ("card", "bg")),
        "accent": ("链接 / .act-label / .nav.on / highlights 的 ✦",
                   ("card", "bg", PANEL)),
        "accent-strong": ("链接的 hover / press", ("card", "bg")),
        "like-ink": ("「已赞」的文字态", ("card", "bg")),
    }

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        # 底色从令牌里读，不写死：写死的话，换了 --bg 就没人再验这两条了
        cls.BACKGROUNDS = (_css_token(cls.html, "card"), _css_token(cls.html, "bg"))

    def bg_value(self, ref):
        """背景既可以写令牌名（跟着 --bg 走），也可以直接写 hex（写死在规则里的）。"""
        return ref if ref.startswith("#") else _css_token(self.html, ref)

    def test_every_text_token_clears_aa_on_every_background_it_lands_on(self):
        """所有当文本用的令牌一次过完。

        这条补的是一个真实缺口：色板注释里写满了实测值，但在它出现之前只有
        --muted 和 --like-ink 有断言，--accent / --accent-strong 是裸的。
        变异测试证实过：把 --accent 提到 #059669（3.77，掉出 AA）全套测试照样绿。
        """
        for name, (where, backgrounds) in self.TEXT_TOKENS.items():
            value = _css_token(self.html, name)
            for ref in backgrounds:
                bg = self.bg_value(ref)
                with self.subTest(token=name, bg=bg):
                    got = _wcag_ratio(value, bg)
                    self.assertGreaterEqual(
                        got, self.AA_TEXT,
                        f"--{name} = {value}（用在{where}）在 {bg} 上只有 "
                        f"{got:.2f}:1，要 {self.AA_TEXT}。想更鲜就提饱和别提亮："
                        f"同一明度段里饱和度有大把空间")

    def test_hover_is_darker_than_rest(self):
        """hover / press 要比常态更暗，否则「按下去」这个反馈是反的。"""
        card = _css_token(self.html, "card")
        self.assertGreater(
            _wcag_ratio(_css_token(self.html, "accent-strong"), card),
            _wcag_ratio(_css_token(self.html, "accent"), card),
            "--accent-strong 没比 --accent 更暗")

    def test_fill_only_tokens_are_not_held_to_the_text_rule(self):
        """--like 只需过非文本的 3:1，--like-ink 才是当文字用的那个。

        这条原来断言 --like **低于** 4.5，理由是当时的玫红 #e0364f 只有 4.37，
        当文字必掉 AA。换成纯红 #b91c1c 后它顺带过了 4.5，那句反向断言就变成
        「不许把填充色选深」，是纯粹的伪要求，所以改掉。

        真正要守的是这两个令牌不许被合并：谁把 --like-ink 往亮处调到比 --like
        还浅，「已赞」的文字态就会先掉出 AA——而 TEXT_TOKENS 那条只逐个量
        对比度，量不出两者的先后关系。
        """
        like = _css_token(self.html, "like")
        like_ink = _css_token(self.html, "like-ink")
        bg = _css_token(self.html, "bg")
        self.assertGreaterEqual(
            _wcag_ratio(like, bg), self.NON_TEXT_MIN,
            f"--like = {like} 连非文本的 {self.NON_TEXT_MIN}:1 都不过了")
        self.assertNotEqual(
            like, like_ink,
            "--like 与 --like-ink 被合成同一个值了；填充与文字的门槛不同，"
            "合并之后必然是其中一边将就另一边")
        self.assertGreaterEqual(
            _wcag_ratio(like_ink, bg), _wcag_ratio(like, bg),
            f"--like-ink = {like_ink} 比填充色 {like} 还浅，"
            f"两个令牌的深浅关系反了")

    def test_the_panel_background_is_still_only_used_where_we_think(self):
        """TEXT_TOKENS 里的背景清单是照着当时的用法列的，用法一变它就静默变松。

        PANEL 现在铺在 highlights、货架流水线 pill、商详 HOWTO 骨架上。
        哪天有人拿它去铺别的块，那块里的 --muted（在它上面只有 4.45，掉出 AA）
        就会悄悄不合格。
        """
        # 只扫 <style>：整页 HTML 里 JS 花括号太多，[^{}]* 会扫成超线性。
        # 先剥 CSS 注释：这个色板的注释里写满了实测色值
        # （`/* 在 #f6f8fa 上 5.15:1 */`），不剥会把提到它的规则一起算进来。
        style = "".join(re.findall(r"<style>(.*?)</style>", self.html, flags=re.S))
        css = re.sub(r"/\*.*?\*/", "", style, flags=re.S)
        rules = [m.group(1).strip() for m in re.finditer(
            r"([^{}]+)\{[^{}]*" + re.escape(self.PANEL) + r"[^{}]*\}", css)]
        self.assertEqual(
            [".pitch .highlights li", ".pack-flow li", ".pack-detail .howto-skel li"],
            rules,
            f"{self.PANEL} 的用处变了（现在铺在 {rules}）；"
            f"回去核对 TEXT_TOKENS 里各令牌的背景清单")

    def test_like_ink_keeps_the_brand_hue(self):
        """--like-ink 只准调明度/饱和度，色相不许动（换品牌色是产品决策）。

        AA 那半边已经由 test_every_text_token_... 一并覆盖。
        """
        like = _css_token(self.html, "like")
        like_ink = _css_token(self.html, "like-ink")

        def hue(hexstr):
            import colorsys
            h = hexstr.lstrip("#")
            rgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            return colorsys.rgb_to_hsv(*rgb)[0] * 360

        # 本次只准调明度/饱和度，色相不许动（换品牌色是产品决策）
        self.assertLess(abs(hue(like_ink) - hue(like)), 2.0,
                        f"--like-ink 的色相 {hue(like_ink):.1f}° 偏离了 --like 的 {hue(like):.1f}°")

    @unittest.skipIf(NODE is None, "需要 node 才能跑模板里的 readableOn")
    def test_avatar_letter_passes_aa_for_every_palette(self):
        """pal[1] 是头像与分类徽章的纯色底，字压在上面必须过 AA。

        readableOn 按底色亮度挑前景，这里逐套板验，别让新增一类场景悄悄掉队。
        """
        got = JsHarness(self.html).eval(
            "Object.keys(SCENE_PAL).map(k => {"
            "  const bg = SCENE_PAL[k][1];"
            "  const fg = readableOn(bg);"
            "  return [k, bg, fg, contrastRatio(relLum(fg), relLum(bg))];"
            "})")
        self.assertEqual(len(SCENE_IDS), len(got))
        for scene_id, bg, fg, ratio in got:
            with self.subTest(scene=scene_id):
                self.assertGreaterEqual(
                    ratio, self.AA_TEXT,
                    f"{scene_id} 的 {fg} on {bg} 只有 {ratio:.2f}:1")


class TestBrandIdentityIsOurOwn(unittest.TestCase):
    """页面外壳的品牌要素必须是我们自己的，不得使用第三方品牌标识。

    断言范围是**页面外壳**（`<style>` + head + 静态 markup），刻意剔掉 `<script>`
    里的内容数据。因为 feed 里正当存在提到第三方产品的条目
    （`instagram-curator`、"TikTok and Instagram carousel" 之类的第三方 skill），
    指名提及真实产品是正当使用，不是我们的品牌表述。对整页 HTML 做字符串断言
    会在有真实内容时误报——空 feed 下还是绿的、一上线就炸，属于最难查的那种假绿，
    所以夹具里专门放了一条这样的条目来证明不会误报。

    中性灰不在禁用名单里：浅灰是几千个站点
    共用的通用值，不构成任何人的品牌识别，理由见 docs/brand-tokens.md。
    """

    # 禁用清单：这些取值属于第三方的品牌标识，我们的外观里不得出现。
    # 这是一份合规控制清单，保留具体归属是为了让人能核对与维护，别把它删成
    # 「禁用 #ed4956」这种查无实据的规矩——那样下次就会有人换个相邻值绕过去。
    BANNED = {
        "billabong": "Instagram 字标所用字体",
        "#f09433": "Instagram 品牌渐变起点",
        "#e6683c": "Instagram 品牌渐变",
        "#dc2743": "Instagram 品牌渐变",
        "#cc2366": "Instagram 品牌渐变",
        "#bc1888": "Instagram 品牌渐变终点",
        "#ed4956": "Instagram 的点赞红",
        "#00376b": "Instagram 的链接蓝",
    }

    # 到禁用值的最小 RGB 距离。低于这个值就当成「照着清单微调一档绕过去」。
    MIN_DISTANCE = 40
    # 豁免清单现在是空的，这是刻意留空而不是删掉：它曾经装着 --like / --like-ink
    # （距禁用红 20 / 17），后来两者都挪到纯红一路、距离升到 54 / 79，豁免就没了
    # 存在理由。留着这个空集合是为了让「又要加豁免」这件事必须显式写进来被看见——
    # 每加一个近似色就顺手加一条豁免，清单会被蚕食成一张白名单。
    GRANDFATHERED = frozenset()

    # 我们的外观描述里不得把自己说成某个第三方产品的同款。
    # 自称仿版是「意图」的书面证据，在侵权纠纷里比色值本身更难解释。
    THIRD_PARTY_APPS = ("instagram", "tiktok", "douyin", "xiaohongshu",
                        "twitter", "pinterest", "snapchat")

    # 内容里正当提到第三方产品的条目：用来证明下面的断言不会对它误报
    ITEM_NAMING_A_THIRD_PARTY_PRODUCT = {
        "full_name": "someone/instagram-curator",
        "name": "instagram-curator",
        "owner": "someone",
        "description": "Instagram marketing specialist for visual storytelling.",
        "one_liner_zh": "帮你做 Instagram 视觉运营的 skill。",
        "url": "https://github.com/someone/instagram-curator",
        "source": "corpus",
        "kind": "skill",
        "stars": 12,
    }

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html(
            {"items": [cls.ITEM_NAMING_A_THIRD_PARTY_PRODUCT], "corpus": []})
        # 剔掉 <script>：那里面是内容数据和模板，不是我们的品牌外观
        cls.chrome = re.sub(r"<script>.*?</script>", "", cls.html, flags=re.S).lower()
        # Twitter Card 的 <meta name="twitter:*"> 是行业标准分享标签，不是自称 Twitter。
        # 从「第三方名字」扫描面里剔掉，避免把 og/twitter meta 误判成仿版意图。
        cls.chrome_for_names = re.sub(
            r'<meta\s+name="twitter:[^"]*"\s+content="[^"]*"\s*/?>',
            "",
            cls.chrome,
            flags=re.I,
        )
        # 再剔掉 CSS 注释，得到「真正会被画出来的东西」。
        #
        # 两个范围是有意分开的，判定标准不同：
        #   - 颜色取值按**渲不渲染**判。注释里的值没有任何外观，写在那儿通常正是
        #     为了记录「这个值被否掉了、别再用」——`--like-ink` 上面那条就是这样，
        #     记着 #d7344c 掉出 AA。把它算成违规，等于逼着后人删掉决策记录。
        #   - 第三方**名字**按出不出现判，仍然扫 chrome（含注释）。自称某产品同款
        #     是意图的书面证据，注释里也不能有；归属说明该放 docs/brand-tokens.md。
        cls.painted = re.sub(r"/\*.*?\*/", "", cls.chrome, flags=re.S)
        cls.script_code = _script_code(cls.html)
        # 颜色要扫的完整表面 = CSS + JS 里的外观常量。
        #
        # 只扫 CSS 曾经漏掉一整类东西：卡片头像底、story 环面、全屏 story 背景的
        # 颜色都由 <script>_里的调色板数组驱动，一个都不在 CSS 里。那批值在门外
        # 待了很久，其中几组贴着禁用清单。范围之所以当初画错，是因为「script 里
        # 是内容数据」对**数据**成立、对**外观常量**不成立——所以现在按这条界线
        # 切：剔掉注入的 FEED / SCENES / SCENES_L2 三条数据声明，剩下的代码全扫。
        cls.painted_all = cls.painted + "\n" + cls.script_code

    def test_third_party_product_name_in_content_is_present_so_the_fixture_is_meaningful(self):
        """先确认夹具真的把第三方产品名写进了页面，否则下面两条断言是空过。"""
        self.assertIn("instagram", self.html.lower())

    def test_the_comment_stripper_does_not_eat_live_css(self):
        """先证明 painted 没被剪坏，否则下面三条断言可能是在一个空串上空过。

        `/\\*.*?\\*/` 配 DOTALL 在含 `/*` 的字符串上会吃掉整段，这类假绿最难查。
        """
        self.assertIn("--accent:", self.painted, "剪注释把令牌声明也剪掉了")
        self.assertIn(".media .badge", self.painted, "剪注释把规则也剪掉了")
        self.assertLess(len(self.painted), len(self.chrome), "一条注释都没剪掉")

    def test_no_banned_brand_values_reach_the_page_chrome(self):
        for token, why in self.BANNED.items():
            with self.subTest(token=token):
                haystack = self.painted if token.startswith("#") else self.chrome
                self.assertNotIn(
                    token, haystack,
                    f"{token}（{why}）出现在页面外壳里；品牌要素要用我们自己的取值")

    def test_banned_values_are_also_caught_when_written_as_rgb(self):
        """同一个颜色写成 rgb()/rgba() 时上面那条完全看不见。

        这不是假想的：`.badge.kb` / `.badge.local.drift` / `hintFlash` 三处曾经写的是
        `rgba(237,73,86,.85)`，而 `237,73,86` 就是 `#ed4956`——禁用清单里的第一条。
        只比对 hex 字符串的断言在这三处上一路是绿的。所以这里把外壳里所有
        rgb/rgba 折算回 hex 再比一遍。
        """
        for hexval, where in _rgb_functions(self.painted_all):
            with self.subTest(value=hexval, at=where):
                self.assertNotIn(
                    hexval, self.BANNED,
                    f"{where} 写的 {hexval} 是禁用值"
                    f"（{self.BANNED.get(hexval, '')}）的十进制写法")

    def test_chrome_colours_keep_their_distance_from_the_banned_ones(self):
        """挡「换个相邻值绕过去」：逐色算到禁用值的 RGB 欧氏距离。

        清单本身挡不住这个——把 `#ed4956` 改成 `#ed4957` 就能过。文档里明写了这是
        预期的失效模式，所以这里改成量距离。

        阈值 40 是按现状定的：现在离禁用值最近的自有色是 scene 板里工程开发那套
        的 `#075985`，距禁用的链接蓝 43，刚好在门内。`--like` 从 `#e0364f` 挪到
        `#b91c1c` 之后距离从 20 升到 54，豁免清单因此清空。
        """
        near = _too_close_to_banned(
            _all_colours(self.painted_all), self.BANNED,
            self.MIN_DISTANCE, self.GRANDFATHERED)
        self.assertEqual(
            near, [],
            "外壳里有颜色贴着禁用值：\n  " + "\n  ".join(near))

    def test_the_script_scan_sees_the_palettes(self):
        """反向证明 painted_all 真的覆盖了 <script> 里的调色板。

        这条不是形式主义。上面两条断言之前一路是绿的，恰恰因为扫描范围看不到
        调色板——门在、断言在、拦不住任何东西。所以这里直接点名要求：调色板的
        色值必须出现在被扫的文本里，而注入的内容数据必须不在。

        同时兜住 `_script_code` 剔注释剔坏的情况：`/\\*.*?\\*/` 配 DOTALL 或那条
        行注释规则一旦吃掉真实代码，这里会先红。
        """
        self.assertIn("scene_pal", self.script_code, "剔注释把调色板声明剪掉了")
        for scene_id, pal in (("engineering", "#0369a1"),
                              ("design", "#9333ea"),
                              ("other", "#475569")):
            with self.subTest(scene=scene_id):
                self.assertIn(
                    pal, self.painted_all,
                    f"{scene_id} 的 {pal} 不在被扫范围里，这道门对调色板是瞎的")
        # 注入的内容数据必须留在范围外，否则夹具里那条正当提到第三方产品的
        # 条目会把名字检查打红——那是假红，比假绿更容易让人去关掉断言
        self.assertNotIn("instagram-curator", self.script_code,
                         "注入的 FEED 没被剔掉，内容数据被当成品牌外观扫了")

    def test_the_distance_gate_is_actually_sensitive(self):
        """检验上面那道门自己的灵敏度。

        变异测试里唯一活下来的改动就是把阈值从 40 调到 0——门还在、断言还绿，
        但什么都不拦了。上一条断言查的是「有没有违规色」，查不出「门是不是被
        拆了」，因为没有违规色时两种情况的结果都是空列表。

        所以这里塞一个合成色进同一条代码路径：`#ea4a58` 距 `#ed4956` 只有 5，
        必须被报出来。阈值一旦降到 5 以下，这条就炸。
        """
        planted = [("#ea4a58", "合成夹具")]
        near = _too_close_to_banned(
            planted, self.BANNED, self.MIN_DISTANCE, self.GRANDFATHERED)
        self.assertTrue(
            near,
            f"阈值 {self.MIN_DISTANCE} 连距禁用值 5 的颜色都放过了，这道门是空的")
        self.assertGreaterEqual(
            self.MIN_DISTANCE, 30,
            "阈值低于 30 就挡不住肉眼看不出差别的改动")

    def test_chrome_does_not_describe_itself_as_another_product(self):
        """外壳里不许出现自称某第三方产品同款的字样。

        挡的是往后有人把这类描述写进 title / meta description / tagline。
        Twitter Card meta（name="twitter:*"）不算自称，已从扫描面剔除。
        """
        for app in self.THIRD_PARTY_APPS:
            with self.subTest(app=app):
                self.assertNotIn(app, self.chrome_for_names)

    def test_wordmark_keeps_skill_solid_and_paints_feeder_with_logo_grad(self):
        """Skill 实心海军蓝；Feeder 才走 logo 的紫→薄荷。clip 不许挂到整个 .logo。"""
        m = re.search(r"\.logo\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(m, "找不到 .logo 规则")
        self.assertNotIn("background-clip", m.group(1),
                         "clip 挂到了整个 .logo，Skill 也会变成透明字")
        feeder = re.search(
            r"\.logo\s+\.feeder\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(feeder, "找不到 .logo .feeder")
        self.assertIn("background-clip", feeder.group(1))
        self.assertIn("var(--brand-grad)", feeder.group(1))
        self.assertIn('Skill<span class="feeder">Feeder</span>', self.html)
        self.assertIn('class="site-foot"', self.html)

    def test_feide_logo_is_the_brand_asset_file(self):
        """顶栏/页脚/空态都用完整透明团子，不用带底图缺口的残缺磁贴。"""
        uri = feed_dashboard.brand_png_data_uri()
        self.assertTrue(uri.startswith("data:image/png;base64,"))
        self.assertGreaterEqual(self.html.count(uri), 3)  # 顶栏 + 页脚 + 空态
        # 残缺磁贴（140×160 带蓝底缺口）不得进空态
        empty_bad = feed_dashboard._BRAND_ASSETS / "logo-feide-empty.png"
        if empty_bad.exists():
            bad_uri = feed_dashboard.brand_png_data_uri("logo-feide-empty.png")
            self.assertNotIn(bad_uri, self.html)

    def test_feide_empty_mascot_keeps_source_aspect_ratio(self):
        """空态肥嘚跟透明源图同比例（512×393 → 156×120），禁止正方形硬框。"""
        m = re.search(r"\.feide\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(m, "找不到 .feide 规则")
        body = m.group(1)
        self.assertIn("object-fit: contain", body)
        self.assertRegex(body, r"width:\s*156px")
        self.assertRegex(body, r"height:\s*120px")
        wh = re.search(r"width:\s*(\d+)px", body)
        hh = re.search(r"height:\s*(\d+)px", body)
        self.assertIsNotNone(wh)
        self.assertIsNotNone(hh)
        self.assertNotEqual(wh.group(1), hh.group(1), "肥嘚被塞进正方形会变形")
        self.assertIn(
            'src="' + feed_dashboard.brand_png_data_uri("logo-feide-transparent.png"),
            self.html)

    def test_ring_gradient_stays_in_the_accent_family(self):
        """头像环是渐变最大的曝光面：每张卡片一个。"""
        m = re.search(r"--ring:\s*([^;]+);", self.html)
        self.assertIsNotNone(m, "找不到 --ring")
        self.assertIn("var(--accent)", m.group(1))

    def test_ring_gradient_is_one_hue_family(self):
        """含 var(--accent) 还不够：另外那些写死的色站也得留在同一色族里。

        上一条只查了「有没有引用 accent」，光靠它挡不住
        `var(--accent) 0%, <一个完全不同色相的值> 100%` 这种写法 —— 而那正好
        就是要避开的那个结构（圆形头像环 + 鲜艳多色渐变）。这里改查实际色相跨度。
        """
        stops = _ring_stops(self.html)
        self.assertGreaterEqual(len(stops), 2, f"--ring 里没解出色站：{stops}")
        hues = [_hsl(s)[0] for s in stops]
        span = max(hues) - min(hues)
        self.assertLessEqual(
            span, 30,
            f"--ring 的色相跨度 {span:.0f}°（色站 {stops}，色相 "
            f"{[f'{h:.0f}°' for h in hues]}）。渐变要留在 accent 的单一色族内，"
            f"多色扫掠 + 圆形头像环是别人的识别要素")


def _script_code(html):
    """`<script>` 里属于「我们写的代码」的那部分，去掉注入的数据与注释。

    切法：整块取出后剔掉 `const FEED / SCENES / SCENES_L2 = ...` 三条注入声明。
    它们是内容数据，里面正当地含第三方产品名（`instagram-curator` 这类条目），
    不该被当成我们的品牌表述。剩下的全是模板自己的代码，含调色板这类外观常量。

    注释按 CSS 与 JS 两种写法剔。行注释的 `//` 用 `(?<![:/])` 排除 `https://`：
    第一个斜杠前是冒号故跳过，第二个前是斜杠也跳过。剔坏了会静默削掉真实色值，
    所以另有 test_the_script_scan_sees_the_palettes 反向证明它没削掉。
    """
    bodies = "\n".join(re.findall(r"<script>(.*?)</script>", html, flags=re.S))
    code = re.sub(r"^const (?:FEED|SCENES|SCENES_L2) = .*$", "", bodies,
                  flags=re.M)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"(?<![:/])//[^\n]*", "", code)
    return code.lower()


def _rgb_functions(css):
    """外壳里所有 rgb()/rgba() 折算成 hex，附带出现位置（行号 + 该行片段）。

    只认十进制三元组。`rgba(var(--like-rgb), .85)` 这种走令牌的写法解不出数字，
    这里就直接跳过——它指向的值会在 `_all_colours` 里以 hex 形式被查到。
    """
    out = []
    for m in re.finditer(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", css):
        r, g, b = (int(x) for x in m.groups())
        line = css[:m.start()].count("\n") + 1
        out.append(("#%02x%02x%02x" % (r, g, b), f"第 {line} 行"))
    return out


def _all_colours(css):
    """外壳里所有颜色，hex 与 rgb() 两种写法都算进来，用于距离检查。"""
    out = list(_rgb_functions(css))
    for m in re.finditer(r"#([0-9a-f]{6})\b", css):
        line = css[:m.start()].count("\n") + 1
        out.append(("#" + m.group(1), f"第 {line} 行"))
    return out


def _too_close_to_banned(colours, banned_map, threshold, exempt=()):
    """挑出贴着禁用值的颜色，返回人能读的说明列表。

    抽成函数是为了让「真实页面」和「合成夹具」走同一条代码路径——不然那条检验
    灵敏度的测试就成了另写一遍逻辑，改了阈值它照样绿。
    """
    out = []
    for hexval, where in colours:
        if hexval in exempt:
            continue
        for banned, why in banned_map.items():
            if not banned.startswith("#"):
                continue
            d = _rgb_distance(hexval, banned)
            if d < threshold:
                out.append(f"{where} 的 {hexval} 距 {banned}（{why}）只有 {d:.0f}")
    return out


def _rgb_distance(a, b):
    """RGB 空间欧氏距离。

    刻意不用 CIEDE2000 之类的感知色差：这道门要挡的是「照着一个值微调一档绕过
    清单」，不是判断两个颜色人眼能否分辨。RGB 距离对这个目的够用，而且不引依赖、
    读代码的人一眼能复算。
    """
    pa = tuple(int(a.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    pb = tuple(int(b.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    return sum((x - y) ** 2 for x, y in zip(pa, pb, strict=True)) ** 0.5


def _hsl(hexstr):
    h = hexstr.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    mx, mn = max(r, g, b), min(r, g, b)
    d = mx - mn
    if d == 0:
        hue = 0.0
    elif mx == r:
        hue = ((g - b) / d) % 6
    elif mx == g:
        hue = (b - r) / d + 2
    else:
        hue = (r - g) / d + 4
    light = (mx + mn) / 2
    sat = 0 if d == 0 else d / (1 - abs(2 * light - 1))
    return hue * 60, sat * 100, light * 100


def _ring_stops(html):
    """把 --ring 里的色站解成 hex 列表，var(--accent) 展开成实际取值。"""
    ring = re.search(r"--ring:\s*([^;]+);", html).group(1)
    ring = ring.replace("var(--accent)", _css_token(html, "accent"))
    return re.findall(r"#[0-9a-fA-F]{6}", ring)


class TestRingStillSignalsNewContent(unittest.TestCase):
    """环的着色是「有新内容」的唯一提示，得和未激活的灰环拉开 3:1。

    `.story.hot .ring` / `.has-new .ring` 上渐变，普通 story 上一片灰，两者之差
    就是这个状态的全部表达 —— 环本身 `aria-hidden`，label 只写名字不带数量，
    所以读屏用户拿不到，视觉用户只能靠颜色。落进 WCAG 1.4.11，门槛 3:1。

    这条拦的是「为了好看把环调亮」：调亮 → 和灰环越来越近 → 状态提示静默失效，
    页面看着更漂亮，功能悄悄没了。上一版最弱段只有 2.12，就是这么来的。
    """

    NON_TEXT_MIN = 3.0

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def inactive_grey(self):
        m = re.search(r"\.story\s+\.ring\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(m, "找不到 .story .ring 规则")
        g = re.search(r"background:\s*(#[0-9a-fA-F]{6})", m.group(1))
        self.assertIsNotNone(g, f"没解出未激活底色：{m.group(1)}")
        return g.group(1)

    def test_every_gradient_stop_clears_the_inactive_ring(self):
        grey = self.inactive_grey()
        for stop in _ring_stops(self.html):
            with self.subTest(stop=stop):
                got = _wcag_ratio(stop, grey)
                self.assertGreaterEqual(
                    got, self.NON_TEXT_MIN,
                    f"色站 {stop} 对未激活环 {grey} 只有 {got:.2f}:1"
                    f"（要 {self.NON_TEXT_MIN}）—— 环再亮就分不出有没有新内容了")

    def test_the_guide_ring_stays_fainter_than_the_inactive_one(self):
        """引导环（那个 "+"）是提示不是内容，刻意比未激活环更淡。

        这个层级很容易在调灰阶时被压平成同一个值。
        """
        m = re.search(r"\.story\.guide\s+\.ring\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(m, "找不到 .story.guide .ring")
        guide = re.search(r"background:\s*(#[0-9a-fA-F]{6})", m.group(1)).group(1)
        inactive = self.inactive_grey()
        self.assertGreater(
            _hsl(guide)[2], _hsl(inactive)[2],
            f"引导环 {guide} 没比未激活环 {inactive} 更淡，两级压平了")


# 分类色的三道门都抽成函数，让「真实调色板」和「合成夹具」走同一条代码路径。
# 不抽的话，那几条检验灵敏度的测试就是另写一遍逻辑——阈值被放宽了它照样绿，
# 这不是假想：色族门、撞色门、accent 保护带三道，最初都是这么放过变异的。


def _hue_span_offenders(palettes, limit):
    """挑出跨色相超限的板：跨色相的三段扇推正是要避开的那种外观。"""
    out = []
    for scene_id, stops in sorted(palettes.items()):
        hues = [_hsl(s)[0] for s in stops]
        span = max(hues) - min(hues)
        if span > limit:
            out.append(f"{scene_id} 的色相跨了 {span:.0f}°（{stops}）")
    return out


def _clashing_pairs(palettes, threshold):
    """挑出 pal[1] 互相贴太近的两类：撞色了颜色就不再能区分分类。"""
    out = []
    keys = sorted(palettes)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            d = _rgb_distance(palettes[a][1], palettes[b][1])
            if d < threshold:
                out.append(
                    f"{a} {palettes[a][1]} 与 {b} {palettes[b][1]} 只差 {d:.0f}")
    return out


def _accent_squatters(palettes, band):
    """挑出落在品牌 accent 色族里的分类色：那一段的含义是「被强调」。"""
    lo, hi = band
    out = []
    for scene_id, stops in sorted(palettes.items()):
        for s in stops:
            hue = _hsl(s)[0]
            if lo <= hue <= hi:
                out.append(
                    f"{scene_id} 的 {s} 落在 accent 色族 "
                    f"{lo:.0f}-{hi:.0f}°（实测 {hue:.0f}°）")
    return out


def _scene_palettes(html):
    """从模板里解出 SCENE_PAL，返回 {scene_id: [深, 中, 浅]}。"""
    block = re.search(r"const SCENE_PAL = \{(.*?)\n\}\;", html, flags=re.S)
    assert block, "模板里找不到 SCENE_PAL"
    out = {}
    for m in re.finditer(
            r"'([a-z0-9\-]+)':\s*\[([^\]]+)\]", block.group(1)):
        out[m.group(1)] = re.findall(r"#[0-9a-fA-F]{6}", m.group(2))
    return out


class TestSceneColoursCarryInformation(unittest.TestCase):
    """分类色是十套「一场景一色族」的板，替掉了原来八套随机哈希渐变。

    换的原因有两条，测试也分两半守：

    1. 信息着色。原来的颜色按名字哈希，同一分类的卡每张一个色，颜色对读者恒等
       于噪声——页面「丑」的真因不是取值不好看，是满屏灰字加 2% 的强调色。现在
       颜色键入 scene，蓝=工程、紫=Agent 工具链，扫一眼就能筛。
    2. 合规。原来那八套里有三套是暖色的紫→洋红→橙扇推，和被禁的那家商标外观
       结构相似；而它们全写在 `<script>` 里，当时的品牌门刻意剔掉 script，一个
       都没看见。现在单色族的深→浅斜推凑不出多色相扇推。

    这里只管板自己的性质（覆盖、单色族、互相可分、不占 accent 色族）。到禁用值
    的距离由 TestBrandIdentityIsOurOwn 那道门统一量，扫描范围已经含 script。
    """

    AA_TEXT = 4.5
    # 色族宽度上限。超过就不再是「一个色族的深浅三档」，而是一段跨色相扇推——
    # 正是要避开的那种外观。30° 是留给同色族深浅档位的正常漂移。
    HUE_SPAN_MAX = 30.0
    # 品牌 accent 的色相邻域。分类色进这一段，读者会把「某个分类」误读成
    # 「被强调/被选中」——accent 在页面上就是这个含义。
    # 品牌 accent 现是薄荷青 #0d7377（约 183°）。保护带覆盖旧青绿和新青，
    # 上沿停在 198°，以免吃掉 engineering 的 201°。
    ACCENT_BAND = (150.0, 198.0)
    # pal[1] 是头像与徽章的纯色底，两类撞色就没法靠颜色区分。40 与品牌门的
    # MIN_DISTANCE 同值，取的是同一个「人眼能不能当成两个颜色」的量级。
    PAIR_MIN_DISTANCE = 40.0

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        cls.pal = _scene_palettes(cls.html)

    def test_every_scene_in_the_taxonomy_has_a_palette(self):
        """漏一个的表现是那一类静默落进 other 的灰蓝，看起来像分类没分好。

        清单从 scene.py 取，不在测试里抄一份——抄一份就会在加分类时一起忘。
        """
        self.assertEqual(
            sorted(SCENE_IDS), sorted(self.pal),
            "SCENE_PAL 和 scene.py 的一级场景对不上")
        self.assertIn("other", self.pal, "缺 other，未知分类就没有兜底色了")

    def test_each_palette_is_three_shades_of_one_hue(self):
        """单色族是合规约束，不是审美偏好：跨色相的三段扇推才是要避开的外观。"""
        for scene_id, stops in self.pal.items():
            with self.subTest(scene=scene_id):
                self.assertEqual(3, len(stops), f"{scene_id} 不是三档：{stops}")
        offenders = _hue_span_offenders(self.pal, self.HUE_SPAN_MAX)
        self.assertEqual(
            offenders, [],
            "这些板已经是跨色相的扇推，不是一个色族的深浅：\n  "
            + "\n  ".join(offenders))

    def test_every_threshold_gate_is_actually_sensitive(self):
        """逐个检验上面那几道门自己的灵敏度。

        这条补的是一整类失效，不是某一处笔误。变异测试证实过：把 HUE_SPAN_MAX
        放宽到 360、把 PAIR_MIN_DISTANCE 放到 0、把 ACCENT_BAND 收成空区间，
        三个改动都让对应的门什么都不拦，而整套测试照样绿。原因是上面那几条查的
        都是「真实调色板里有没有违规」，查不出「门是不是被拆了」——真实取值本来
        就合规，放宽阈值当然还是绿。

        所以这里给每道门塞一个已知坏样本，走同一个判定函数，要求必须被拎出来。
        夹具都用真实来源而不是随便编：扇推那组是旧调色板里真实存在过的
        紫→洋红→橙，accent 那个取的是品牌 accent 邻域的正中间。
        """
        cases = [
            (
                "色族宽度",
                lambda: _hue_span_offenders(
                    {"synthetic": ["#7028e4", "#c32bad", "#ff6a3d"]},
                    self.HUE_SPAN_MAX),
            ),
            (
                "分类色互相可分",
                lambda: _clashing_pairs(
                    {"a": ["#075985", "#0369a1", "#0284c7"],
                     "b": ["#075985", "#0369a1", "#0284c7"]},
                    self.PAIR_MIN_DISTANCE),
            ),
            (
                "accent 色族保护带",
                lambda: _accent_squatters(
                    {"synthetic": ["#0f766e", "#10a37f", "#34d399"]},
                    self.ACCENT_BAND),
            ),
        ]
        for gate, probe in cases:
            with self.subTest(gate=gate):
                hits = probe()
                self.assertNotEqual(
                    [], hits,
                    f"「{gate}」这道门没拦住已知的坏样本，它当前是装饰品")

    def test_each_palette_goes_from_dark_to_light(self):
        """pal[0] 深、pal[1] 中、pal[2] 浅。顺序错了渐变会从浅走到深，

        而 pal[1] 也就不再是那个「压白字刚好够对比度」的中间档。
        """
        for scene_id, stops in self.pal.items():
            with self.subTest(scene=scene_id):
                lights = [_hsl(s)[2] for s in stops]
                self.assertEqual(
                    lights, sorted(lights),
                    f"{scene_id} 的明度不是递增：{list(zip(stops, lights, strict=True))}")

    def test_no_palette_squats_on_the_accent_hue(self):
        """accent 色族在页面上的含义是「被强调」，分类色占进去就是语义串台。"""
        squatters = _accent_squatters(self.pal, self.ACCENT_BAND)
        self.assertEqual(
            squatters, [],
            "这些分类色占了强调色的色族：\n  " + "\n  ".join(squatters))

    def test_the_avatar_shades_stay_apart_from_each_other(self):
        """两类的 pal[1] 撞在一起，颜色就不再能区分分类，信息着色白做。"""
        clashes = _clashing_pairs(self.pal, self.PAIR_MIN_DISTANCE)
        self.assertEqual(
            clashes, [], "分类色互相撞了：\n  " + "\n  ".join(clashes))

    def test_the_badge_colour_is_derived_from_the_scene_not_the_name(self):
        """徽章的颜色必须由 scene 推出来，不能退回按 repo 名哈希。

        这条补的是变异测试里唯一活下来的那个改动：把
        `paletteForScene(sceneId)` 换回 `paletteFor(fn || it.name || ...)`，
        整套测试照样绿——因为别处只断言「徽章上了 scenePal[1]」，而变量名没变，
        变的是它从哪来。颜色于是重新变成按名字散开的噪声，这次改动的全部意义
        就没了，而门一声不响。

        断言落在源码的数据流上，而不是渲染结果上：卡片是客户端渲的，要观察到
        真实徽章颜色得起整个 JS 环境，而那只能证明 `paletteForScene` 这个纯函数
        对不对，证明不了徽章接的是它。接线这件事只有源码看得见。
        """
        src = Path(feed_dashboard.__file__).read_text(encoding="utf-8")
        m = re.search(r"^\s*const scenePal = ([^\n;]+);", src, flags=re.M)
        self.assertIsNotNone(m, "找不到 scenePal 的赋值")
        rhs = m.group(1).strip()
        self.assertEqual(
            "paletteForScene(sceneId)", rhs,
            f"scenePal 现在取自 `{rhs}`；分类色只能由 scene 决定，"
            f"按名字/序号哈希会让同一分类的卡每张一个色")

    def test_colour_is_never_the_only_thing_saying_which_scene_it_is(self):
        """WCAG 1.4.1：颜色不能是唯一的信息载体。

        分类色是给视觉用户的加速器，不是载体本身——徽章里必须同时有分类名的
        文本。哪天有人为了「更干净」把文字去掉只留色块，读屏用户和色觉障碍用户
        就完全拿不到分类了，这条会先红。
        """
        src = Path(feed_dashboard.__file__).read_text(encoding="utf-8")
        m = re.search(r'class="badge scene [^\n]*?</button>', src)
        self.assertIsNotNone(m, "找不到分类徽章的模板")
        badge = m.group(0)
        self.assertIn("scenepal[1]", badge.lower().replace(" ", ""),
                      "分类徽章没上分类色")
        self.assertIn("itemSceneLabel(it)", badge,
                      "分类徽章里没有分类名文本——颜色成了唯一载体")


class TestAriaLabelsAreLocalized(unittest.TestCase):
    """aria-label 不许硬编码：中文用户开读屏时不该听到英文，反之亦然。

    静态标签靠 data-i18n-aria + applyLang() 换，模板里拼出来的靠 tr()。
    漏一个的表现是「切了语言但读屏还是旧语言」，肉眼完全看不出来，只能靠这条拦。
    """

    @classmethod
    def setUpClass(cls):
        cls.src = Path(feed_dashboard.__file__).read_text(encoding="utf-8")

    def test_every_aria_label_is_wired_to_i18n(self):
        offenders = []
        for lineno, line in enumerate(self.src.splitlines(), 1):
            for m in re.finditer(r'aria-label=(["\'])(.*?)\1', line):
                val = m.group(2)
                if "${" in val:
                    # 模板插值：值本身或同函数内的变量必须过 tr()
                    if "tr(" not in val and "Aria}" not in val:
                        offenders.append((lineno, val, "插值但没走 tr()"))
                elif "data-i18n-aria" not in line:
                    offenders.append((lineno, val, "静态且没挂 data-i18n-aria"))
        self.assertEqual([], offenders, f"这些 aria-label 没接 i18n：{offenders}")

    def test_applylang_actually_rewrites_aria_labels(self):
        """光挂 data-i18n-aria 不够，还得真有代码去读它。"""
        self.assertRegex(
            self.src,
            r"setAttribute\(\s*['\"]aria-label['\"]\s*,\s*tr\(")


@unittest.skipIf(NODE is None, "需要 node 才能跑 cardHtml / renderStories")
class TestKeyboardReachableControls(unittest.TestCase):
    """带点击行为的元素必须是原生 <button>，否则键盘用户完全用不了。

    这个页面的点击全靠容器上的 closest() 委派，所以 div→button 不影响事件路由；
    换成原生 button 才能白拿聚焦、Enter/Space 和正确的 role。
    """

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def card(self, lang="zh", lite=False):
        h = JsHarness(self.html, lang=lang)
        if lite:
            h.prelude = h.prelude.replace("const IS_LITE = false;", "const IS_LITE = true;")
        return h.eval("cardHtml(" + json.dumps(REAL_SKILL) + ", 0)")

    def test_publisher_and_scene_hooks_are_buttons(self):
        for lite in (False, True):
            with self.subTest(lite=lite):
                card = self.card(lite=lite)
                hook = "js-scene-filter" if lite else "js-scene-tag"
                for cls in ("js-publisher", hook):
                    self.assertRegex(
                        card, r'<button type="button" class="[^"]*' + cls,
                        cls + " 不是 <button>，键盘到不了")
                self.assertNotRegex(card, r'<div class="who clickable')
                self.assertNotRegex(card, r'<span class="badge [^"]*clickable')

    def test_card_splits_media_summary_and_actions(self):
        card = self.card()
        self.assertIn("zone-media", card)
        self.assertIn("zone-read", card)
        self.assertIn("zone-engage", card)
        self.assertLess(card.find("zone-media"), card.find("zone-read"))
        self.assertLess(card.find("zone-read"), card.find("zone-engage"))
        self.assertIn(".zone-read.pitch", self.html)
        self.assertIn("background: #eef2fb", self.html)

    def test_avatar_stays_clickable_but_out_of_the_a11y_tree(self):
        """头像和作者行点的是同一个功能，头像重复占 Tab 序只会让键盘更难用。"""
        card = self.card()
        avatar = re.search(r'<button[^>]*class="avatar[^>]*>', card).group(0)
        self.assertIn('aria-hidden="true"', avatar)
        self.assertIn('tabindex="-1"', avatar)
        self.assertIn("js-publisher", avatar)   # 鼠标热区还在

    def test_story_ring_face_does_not_duplicate_the_label(self):
        """face 是 '+'，label 是 '+ Builder'，都进无障碍树就读成「+ + Builder」。"""
        js = max(_script_blocks(self.html), key=len)
        ring = _grab(js, r'return `<button type="button" class="story .*?</button>`;')
        self.assertIn('<div class="ring" aria-hidden="true">', ring)
        # 只在渲染处禁裸字面量：I18N 表本身必须存着这个值，拿整个 js 断言等于
        # 要求译文既存在又不存在，永远红。
        self.assertNotIn("'+ Builder'", ring)
        self.assertIn("tr('addBuilder')", js)

    def test_story_tap_zones_are_buttons(self):
        """原来是带 aria-label 的 div：读屏播报「上一条」却无法聚焦触发。"""
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                html = feed_dashboard.build_feed_html(
                    {"items": [], "corpus": []}, variant=variant)
                for eid in ("svPrev", "svNext"):
                    tag = re.search(r'<[a-z]+[^>]*id="' + eid + r'"[^>]*>', html).group(0)
                    self.assertTrue(tag.startswith("<button"),
                                    eid + " 还是 " + tag[:40])


@unittest.skipIf(NODE is None, "需要 node 才能跑 cardHtml")
class TestActionLabelsAreLocalised(unittest.TestCase):
    """卡片操作按钮原来硬编码 aria-label="like"/"not useful"/"save"。

    中文用户用读屏听到的是英文，英文用户听到的是中文——两个方向都错。
    """

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    EXPECT = {
        "zh": {"js-like": "点赞", "js-bad": "不感兴趣", "js-save": "收藏"},
        "en": {"js-like": "Like", "js-bad": "Not interested", "js-save": "Save"},
    }

    def _labels(self, lang):
        card = JsHarness(self.html, lang=lang).eval(
            "cardHtml(" + json.dumps(REAL_SKILL) + ", 0)")
        out = {}
        for cls in ("js-like", "js-bad", "js-save"):
            tag = re.search(r'<button[^>]*' + cls + r'[^>]*>', card).group(0)
            out[cls] = re.search(r'aria-label="([^"]*)"', tag).group(1)
        return out

    def test_labels_follow_the_language_switch(self):
        for lang, want in self.EXPECT.items():
            with self.subTest(lang=lang):
                self.assertEqual(want, self._labels(lang))

    def test_no_hardcoded_english_aria_labels_left(self):
        js = max(_script_blocks(self.html), key=len)
        for dead in ('aria-label="like"', 'aria-label="not useful"', 'aria-label="save"'):
            self.assertNotIn(dead, js, "aria-label 又被写死成英文：" + dead)

    def test_skeleton_buttons_all_have_an_accessible_name(self):
        """title 在 accname 里是最后兜底，靠它给名字太脆；显式补 aria-label。"""
        for variant in ("full", "lite"):
            skeleton = re.sub(r"<script>.*?</script>", "",
                              feed_dashboard.build_feed_html(
                                  {"items": [], "corpus": []}, variant=variant), flags=re.S)
            for m in re.finditer(r"<button[^>]*>(.*?)</button>", skeleton, flags=re.S):
                tag, inner = m.group(0), m.group(1)
                text = re.sub(r"<[^>]*>", "", inner).strip()
                if text or 'aria-hidden="true"' in tag:
                    continue
                self.assertIn("aria-label=", tag,
                              variant + " 变体里有个按钮既无文本也无 aria-label：" + tag[:120])


class TestContentSecurityPolicy(unittest.TestCase):
    """CSP 的失效模式全都是静默的，所以每一条都得锁住。

    这条策略靠内联块的 sha256 哈希生效。它有两种坏法，都不会在生成时报错：

    - 哈希对不上 → 浏览器拒绝执行那一整块 script → **整页白屏**。改任何
      会影响内联内容的东西（包括加一个空格）都会换哈希，所以真正要锁的是
      「算哈希的代码和最终产物始终一致」，而不是某个具体的哈希值。
    - 有人加了内联事件处理器（onclick / onerror 之类）→ 哈希覆盖不到属性，
      script-src 用了哈希之后 'unsafe-inline' 会被忽略 → 那个交互静默失效。

    所以这里从最终 HTML 里重新抠出内联块自己算一遍，跟 meta 里的比 —— 用的是
    浏览器的视角，而不是复用被测代码的中间变量（那样两边一起错也照样绿）。
    """

    ITEM = dict(REAL_SKILL, url="https://github.com/hardikpandya/stop-slop")

    @classmethod
    def setUpClass(cls):
        cls.pages = {
            v: feed_dashboard.build_feed_html(
                {"items": [cls.ITEM], "corpus": []}, variant=v)
            for v in ("full", "lite")
        }

    @staticmethod
    def _policy(html: str) -> dict[str, list[str]]:
        m = re.search(
            r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        assert m, "页面里没有 CSP meta"
        out = {}
        for chunk in m.group(1).split("; "):
            name, _, rest = chunk.partition(" ")
            out[name] = rest.split()
        return out

    @staticmethod
    def _sha256_source(text: str) -> str:
        return "'sha256-" + base64.b64encode(
            hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"

    def test_every_inline_block_hash_matches_what_a_browser_would_compute(self):
        """哈希错一个字节，线上就是白屏；这条是整套 CSP 的命门。"""
        for variant, html in self.pages.items():
            policy = self._policy(html)
            scripts = re.findall(
                r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.S)
            styles = re.findall(r"<style[^>]*>(.*?)</style>", html, flags=re.S)
            self.assertTrue(scripts, variant + "：没有内联 script，抽取规则已失效")
            self.assertTrue(styles, variant + "：没有内联 style，抽取规则已失效")
            for block in scripts:
                with self.subTest(variant=variant, kind="script"):
                    self.assertIn(self._sha256_source(block), policy["script-src"],
                                  "内联 script 的哈希不在 script-src 里 —— 线上会白屏")
            for block in styles:
                with self.subTest(variant=variant, kind="style"):
                    self.assertIn(self._sha256_source(block),
                                  policy["style-src-elem"],
                                  "内联 style 的哈希不在 style-src-elem 里")

    def test_script_src_never_falls_back_to_unsafe(self):
        """script-src 里一旦出现 unsafe-inline / unsafe-eval，这条策略就白写了。"""
        for variant, html in self.pages.items():
            with self.subTest(variant=variant):
                src = self._policy(html)["script-src"]
                for token in ("'unsafe-inline'", "'unsafe-eval'", "'none'", "*"):
                    self.assertNotIn(token, src)
                self.assertTrue(all(s.startswith("'sha256-") for s in src),
                                "script-src 里混进了非哈希来源：" + str(src))

    def test_no_inline_event_handlers_anywhere(self):
        """内联处理器在哈希式 CSP 下不执行，加进来就是静默坏掉一个交互。

        故意连注释里的字样一起挡：注释会随页面发给访客，任何安全扫描器看到
        `onerror="` 都会报，与其日后逐个解释，不如换个说法。
        """
        for variant, html in self.pages.items():
            with self.subTest(variant=variant):
                hits = re.findall(r"\bon[a-z]+\s*=\s*[\"']", html)
                self.assertEqual([], hits,
                                 "出现内联事件处理器，改用 addEventListener："
                                 + str(hits[:5]))

    def test_cover_failure_uses_a_delegated_listener(self):
        """封面兜底不能依赖内联 onerror。

        GitHub 的 OG 图有相当比例 404，这条路径是常态。error 事件不冒泡，
        所以监听必须在捕获阶段注册 —— 写成冒泡阶段收不到，页面上会留一个
        2:1 的空黑盒。
        """
        js = max(_script_blocks(self.pages["full"]), key=len)
        m = re.search(r"document\.addEventListener\(\s*'error'[\s\S]{0,400}?\}\s*,\s*(\w+)\s*\)", js)
        self.assertIsNotNone(m, "找不到 error 事件的委托监听")
        self.assertEqual("true", m.group(1),
                         "error 事件不冒泡，addEventListener 必须传 true 走捕获阶段")
        self.assertIn("no-cover", m.group(0))

    def test_policy_is_declared_before_anything_it_governs(self):
        """CSP 只管它被解析到之后声明的资源，插晚了前面的字体和样式就在策略之外。"""
        for variant, html in self.pages.items():
            with self.subTest(variant=variant):
                meta = html.index("Content-Security-Policy")
                self.assertLess(meta, html.index("<link"))
                self.assertLess(meta, html.index("<style"))
                # charset 必须仍在最前，否则编码嗅探要出问题
                self.assertLess(html.index('<meta charset="utf-8">'), meta)

    def test_default_src_is_closed_and_each_opening_is_deliberate(self):
        """默认全关、逐项开口。开口的清单本身就是这条策略的可审计部分。"""
        for variant, html in self.pages.items():
            with self.subTest(variant=variant):
                policy = self._policy(html)
                self.assertEqual(["'none'"], policy["default-src"])
                self.assertEqual(["'none'"], policy["base-uri"])
                self.assertEqual(["'none'"], policy["form-action"])
                self.assertEqual(["https://fonts.gstatic.com"], policy["font-src"])
                self.assertIn("https://api.github.com", policy["connect-src"])
                self.assertIn("'self'", policy["connect-src"])

    def test_old_browsers_still_get_styles(self):
        """style-src-elem / -attr 是 Chrome 75+ / Firefox 111+ / Safari 15.4+ 才有的。

        不支持的浏览器会回退到 style-src；那里如果不留 'unsafe-inline'，
        内联 <style> 会被一起拦掉，整页变成无样式的裸 HTML。宁可在老浏览器上
        少一层 CSS 防护，也不能让页面在那里彻底不可读。
        """
        for variant, html in self.pages.items():
            with self.subTest(variant=variant):
                policy = self._policy(html)
                self.assertIn("'unsafe-inline'", policy["style-src"])
                self.assertIn("'unsafe-inline'", policy["style-src-attr"])

    def test_homepage_recovers_api_base_when_built_without_it(self):
        """定时发布若漏写 SKILLFEED_PUBLIC_URL，主站仍应认出自己。"""
        html = feed_dashboard.build_feed_html({
            "items": [self.ITEM], "corpus": [], "ui": {},
        }, variant="full")
        self.assertIn("function resolveApiBase()", html)
        self.assertIn("https://skillfeeder.cn", html)

    def test_api_base_is_allowed_through_connect_src_when_configured(self):
        """配了后端地址就得放行，否则反馈回传会被 connect-src 静默拦掉。"""
        html = feed_dashboard.build_feed_html({
            "items": [self.ITEM], "corpus": [],
            "ui": {"api_base": "https://feed.example.com/"},
        }, variant="full")
        self.assertIn("https://feed.example.com",
                      self._policy(html)["connect-src"])

    def test_a_bogus_api_base_is_not_pasted_into_the_policy(self):
        """api_base 会进 CSP 文本，不是绝对 http(s) URL 就不许拼进去。"""
        for junk in ("javascript:alert(1)", "'; script-src *; '", "not-a-url"):
            with self.subTest(api_base=junk):
                policy = self._policy(feed_dashboard.build_feed_html({
                    "items": [], "corpus": [], "ui": {"api_base": junk},
                }, variant="full"))
                self.assertEqual(["'self'", "https://api.github.com"],
                                 policy["connect-src"])
                self.assertTrue(all(s.startswith("'sha256-")
                                    for s in policy["script-src"]))


@unittest.skipUnless(NODE, "需要 node")
class TestLocalInstalledBadge(unittest.TestCase):
    """「本机已有同名」徽标。

    数据由 skill-picker 的 discover.py 注入，本仓库只负责读。三条必须锁住：

    - 公开站上数据块不存在 → 整套标记静默关闭，不能报错也不能留空壳
    - 对上的键只能是 skill 名（本机 catalog 里没有任何 GitHub 坐标），
      所以 skill_path 推目录名这一步不能错
    - 文案只能说「同名」。实测 feed 里有 17 个名字对应多个仓库，说「你装的就是这个」
      会有 8% 左右的条目在骗人
    """

    ITEM = dict(
        REAL_SKILL,
        name="stop-slop",
        skill_path="skills/stop-slop/SKILL.md",
        url="https://github.com/hardikpandya/stop-slop",
    )

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, index=None, lang="zh"):
        block = None if index is None else json.dumps(index, ensure_ascii=False)
        return JsHarness(self.html, lang=lang, local_block=block)

    # ---------- 缺数据块时的降级 ----------

    def test_public_site_has_no_block_and_degrades_silently(self):
        js = self.harness()
        self.assertIsNone(js.eval("LOCAL_SKILLS"))
        self.assertIsNone(js.eval("localHit(" + json.dumps(self.ITEM) + ")"))
        self.assertEqual("", js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")"))

    def test_malformed_block_is_not_fatal(self):
        """数据块是外部写进来的文件内容，坏了也不能让整页 JS 崩掉。"""
        for junk in ("", "{", "null", "[]", '{"names": 3}', '{"nope": {}}'):
            with self.subTest(block=junk):
                js = JsHarness(self.html, local_block=junk)
                self.assertIsNone(js.eval("LOCAL_SKILLS"))
                self.assertEqual(
                    "", js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")"))

    # ---------- 键推导 ----------

    def test_matches_on_item_name(self):
        js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        hit = js.eval("localHit(" + json.dumps(self.ITEM) + ")")
        self.assertEqual("stop-slop", hit["key"])
        self.assertEqual(1, hit["copies"])

    def test_matches_on_dir_derived_from_skill_path(self):
        """feed 的 name 和目录名不一致时（实测 546 条里有 73 条），要能靠路径兜上。"""
        item = dict(self.ITEM, name="Stop Slop 去AI味", skill_path="skills/stop-slop/SKILL.md")
        js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        hit = js.eval("localHit(" + json.dumps(item) + ")")
        self.assertEqual("stop-slop", hit["key"])

    def test_nested_skill_path_uses_the_last_directory(self):
        """真实数据里有 skills/public/find-skills/SKILL.md 这种多层路径。"""
        item = dict(self.ITEM, name="x", skill_path="skills/public/find-skills/SKILL.md")
        js = self.harness({"names": {"find-skills": {"copies": 1, "hosts": ["codex"], "drifted": False}}})
        self.assertEqual("find-skills", js.eval("localHit(" + json.dumps(item) + ")")["key"])

    def test_repo_root_skill_path_yields_no_dir_key(self):
        """skill_path 就是 SKILL.md 时（实测 8 条）没有目录名可推，不能把 'skill' 当键。"""
        item = dict(self.ITEM, name="ruflo", skill_path="SKILL.md")
        js = self.harness({"names": {"skill": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        self.assertIsNone(js.eval("localHit(" + json.dumps(item) + ")"))
        self.assertEqual(["ruflo"], js.eval("localSkillKeys(" + json.dumps(item) + ")"))

    def test_case_and_leading_slash_are_normalized(self):
        item = dict(self.ITEM, name="STOP-SLOP", skill_path="/skills/Stop-Slop/SKILL.md")
        js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        self.assertEqual("stop-slop", js.eval("localHit(" + json.dumps(item) + ")")["key"])

    def test_unrelated_name_does_not_match(self):
        js = self.harness({"names": {"work-report": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        self.assertIsNone(js.eval("localHit(" + json.dumps(self.ITEM) + ")"))

    def test_prototype_keys_do_not_produce_phantom_hits(self):
        """localHit 用 hasOwnProperty 而不是 in / 取值判真，否则 name 叫 constructor
        的条目会凭空命中。"""
        for poison in ("constructor", "toString", "__proto__", "hasOwnProperty"):
            with self.subTest(name=poison):
                item = dict(self.ITEM, name=poison, skill_path="skills/" + poison + "/SKILL.md")
                js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": [], "drifted": False}}})
                self.assertIsNone(js.eval("localHit(" + json.dumps(item) + ")"))

    # ---------- 文案 ----------

    def test_single_copy_says_same_name_not_installed(self):
        """不能说「已装」：同一个名字在 feed 里可能来自另一个仓库。"""
        js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        badge = js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")")
        self.assertIn("本机已有同名", badge)
        self.assertNotIn("已装", badge)

    def test_copy_count_is_shown(self):
        js = self.harness({"names": {"stop-slop": {"copies": 6, "hosts": ["cursor", "codex"], "drifted": False}}})
        badge = js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")")
        self.assertIn("6", badge)
        self.assertNotIn("{n}", badge)

    def test_drift_wins_over_the_plain_count(self):
        """漂移是 picker 的核心价值，不能被「本机 N 份」这句盖掉。"""
        js = self.harness({"names": {"stop-slop": {"copies": 2, "hosts": ["cursor", "codex"], "drifted": True}}})
        badge = js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")")
        self.assertIn("不一致", badge)
        self.assertIn("drift", badge)

    def test_hosts_land_in_the_tooltip(self):
        js = self.harness({"names": {"stop-slop": {"copies": 2, "hosts": ["codex", "cursor"], "drifted": False}}})
        badge = js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")")
        self.assertIn("codex / cursor", badge)
        self.assertNotIn("{hosts}", badge)
        self.assertNotIn("{name}", badge)

    def test_english_has_no_chinese_left(self):
        js = self.harness(
            {"names": {"stop-slop": {"copies": 2, "hosts": ["cursor"], "drifted": True}}},
            lang="en",
        )
        badge = js.eval("localBadgeHtml(" + json.dumps(self.ITEM) + ")")
        self.assertFalse(
            re.search(r"[\u4e00-\u9fff]", badge), "EN 模式漏了中文：" + badge)
        self.assertIn("differ", badge)

    def test_a_hostile_local_name_is_escaped(self):
        """索引来自本机 frontmatter，注入方不做 HTML 转义，渲染这一侧必须做。"""
        item = dict(self.ITEM, name='<img src=x onerror=alert(1)>', skill_path="SKILL.md")
        js = self.harness({
            "names": {'<img src=x onerror=alert(1)>': {"copies": 1, "hosts": ["cursor"], "drifted": False}},
        })
        badge = js.eval("localBadgeHtml(" + json.dumps(item) + ")")
        self.assertNotIn("<img", badge)
        self.assertIn("&lt;img", badge)

    # ---------- 接进卡片 ----------

    def test_badge_reaches_the_card(self):
        js = self.harness({"names": {"stop-slop": {"copies": 2, "hosts": ["cursor"], "drifted": False}}})
        card = js.eval("cardHtml(" + json.dumps(self.ITEM) + ", 0)")
        self.assertIn("badge local", card)
        self.assertIn("本机 2 份同名", card)

    def test_card_is_unchanged_without_the_block(self):
        """公开站的卡片一个字节都不该因为这个功能变样。"""
        plain = self.harness().eval("cardHtml(" + json.dumps(self.ITEM) + ", 0)")
        self.assertNotIn("badge local", plain)
        self.assertNotIn("本机", plain)

    def test_badge_does_not_add_a_row_above_the_cta(self):
        """CTA 已经在折叠线下了，徽标必须待在封面 badges 里，不许再撑高卡片。"""
        js = self.harness({"names": {"stop-slop": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        card = js.eval("cardHtml(" + json.dumps(self.ITEM) + ", 0)")
        badges = re.search(r'<div class="badges">(.*?)</div>', card, flags=re.S)
        self.assertIsNotNone(badges, "badges 容器没了")
        self.assertIn("badge local", badges.group(1))


class TestLocalBlockDoesNotBreakCsp(unittest.TestCase):
    """注入的数据块必须不需要 CSP 配合。

    script-src 用了哈希之后 'unsafe-inline' 会被忽略，所以往成品页里塞任何**可执行**
    脚本都会被拦掉。选 type="application/json" 就是为了绕开这一点——浏览器实测确认
    数据块不走脚本执行路径。这条测试锁的是：注入不会改动 CSP，也不会被算进哈希集。
    """

    @staticmethod
    def _csp(html: str) -> str:
        m = re.search(
            r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        assert m, "页面里没有 CSP meta"
        return m.group(1)

    def test_injecting_the_block_leaves_the_policy_untouched(self):
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []}, variant="lite")
        before = self._csp(html)
        block = ('<script type="application/json" id="skillpicker-local">'
                 '{"names": {"a": {"copies": 1, "hosts": [], "drifted": false}}}</script>\n')
        after = self._csp(html.replace("</head>", block + "</head>", 1))
        self.assertEqual(before, after)

    def test_the_data_block_is_not_a_hashed_inline_script(self):
        """数据块若被算进哈希集，说明抽取规则把它当可执行脚本了。"""
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []}, variant="lite")
        policy = self._csp(html)
        payload = '{"names": {}}'
        digest = "'sha256-" + base64.b64encode(
            hashlib.sha256(payload.encode("utf-8")).digest()).decode("ascii") + "'"
        self.assertNotIn(digest, policy)

    def test_script_src_still_refuses_inline(self):
        """这一条是上面那个设计的前提：可执行内联脚本确实被拦。"""
        html = feed_dashboard.build_feed_html({"items": [], "corpus": []}, variant="lite")
        script_src = [c for c in self._csp(html).split("; ") if c.startswith("script-src ")]
        self.assertEqual(1, len(script_src))
        self.assertNotIn("'unsafe-inline'", script_src[0])


TOPIC_SCENES = [
    {"id": "content", "label": "内容创作", "label_en": "Content"},
    {"id": "design", "label": "设计与视觉", "label_en": "Design"},
    {"id": "other", "label": "其他", "label_en": "Other"},
]

TOPIC_SCENES_L2 = {
    "content": [
        {"id": "writing", "label": "写作润色", "label_en": "Writing"},
        {"id": "podcast", "label": "播客音频", "label_en": "Podcast"},
    ],
    "design": [{"id": "figma", "label": "Figma/UI", "label_en": "Figma/UI"}],
}

TOPIC_FEED = {
    "ui": {},
    "items": [
        dict(REAL_SKILL, full_name="a/one", name="one", owner="a",
             scene="content", scene_l2="writing"),
        dict(REAL_SKILL, full_name="a/two", name="two", owner="a",
             scene="content", scene_l2="podcast"),
        dict(REAL_SKILL, full_name="b/three", name="three", owner="b",
             scene="design", scene_l2="figma", hg_section="Skills"),
    ],
    "corpus": [],
}

# 新增文案必须中英双份齐全。列出来而不是比整张表：老表里本来就有几处只在一侧
# 出现的历史键，全表比对会把这条测试变成一个待修的旧账，拦不住新的漏译。
NEW_I18N_KEYS = (
    "navTopics", "navPacks", "tabsAria", "backToTop",
    "topicsTitle", "topicsSecSection", "topicsSubScene", "topicsSubSection",
    "topicsViewAria", "topicsLead", "topicsLeadSection", "topicsCount",
    "topicsCountScenes", "topicsCountNoL2", "topicsBrowse", "topicsNoL2",
    "topicsEmpty", "topicsSectionEmpty", "topicsOther",
    "packsTitle", "packsLead", "packsGroupAll", "packsGroupEcom",
    "packsGroupMedia", "packsGroupOps", "packsBadgeShelf", "packsBadgeSoon",
    "packsPriceTbd", "packsOpen", "packsBuy", "packsBuyLocked", "packsBuySoon",
    "packsBuyNeedSite", "packsOwned", "packsBuyOk", "packsBuyFail",
    "packsSeatsFull", "packsEntryPrice", "packsMonthHint", "packsInstallHint",
    "packsUnlockedHint", "packsMine", "packsNoneOwned",
    "subPlanTitle", "subHero1", "subHero2", "subTrackCont", "subTrackOnce",
    "subMonthCont", "subQuarterCont", "subYearCont",
    "subMonthOnce", "subQuarterOnce", "subYearOnce",
    "subPlanActive", "subPlanFree",
    "subUpgradeQuarter", "subUpgradeYear",
    "packsBack", "packsSecFlow", "packsSecHowto",
    "packsSecWhy", "packsSecLocked",
    "packsLockedHint", "packsDeliverMd", "packsDeliverSkills",
    "packsDeliverApps", "packsDeliverKb", "packsCopyMd", "packsDeliverEmpty",
    "packsMetaNamed", "packsEmpty",
    "packsHighlightSafeTitle", "packsHighlightSafeBody",
    "packsHighlightFlowTitle", "packsHighlightFlowBody",
    "packsHighlightSpaceTitle", "packsHighlightSpaceBody",
    "packsHighlightTeachTitle", "packsHighlightTeachBody",
    "packsHowto1", "packsHowto2", "packsHowto3", "packsHowto4",
    "packsHowto5", "packsHowto6", "packsHowto7", "packsHowto8",
    "publishTitle", "publishLead", "publishFieldTitle", "publishFieldUrl",
    "publishFieldDesc", "publishFieldBody", "publishHint", "publishSubmit",
    "publishSubmitting", "publishOkMsg", "publishNeedLogin", "publishLoginBtn",
    "publishOpenPage", "publishNoBackendTitle", "publishNoBackend",
    "publishRemoteTitle", "publishRemote", "publishFailed",
    "acctTitle", "acctChecking", "acctSignedIn", "acctLogout", "acctLoggedOut",
    "acctAnonTitle", "acctAnon", "acctLocalTitle", "acctLocalOnly",
    "acctRemoteNote", "acctOpenSite", "acctMyPosts", "acctPostsLoading",
    "acctNoPosts", "acctPostsNeedLogin", "acctServerCounts", "acctLocalCounts",
    "acctReactionsPending",
    "acctKeysTitle", "acctKeysHint", "acctKeyGithub", "acctKeyWechat", "acctKeyPhone",
    "acctKeyOn", "acctKeyOff", "acctBindWechat", "acctBindPhone", "acctBindGithub",
    "acctExport", "acctBindTaken",
    "bindNudgeTitle", "bindNudgeBody", "bindNudgeLater",
    "bindNudgeEmailTitle", "bindNudgeEmailBody", "bindNudgeEmailCta",
    "recallSavedTitle", "recallSavedCta",
    "emailOptTitle", "emailOptBody", "emailOptPh", "emailOptCheck",
    "emailOptSave", "emailOptSaved", "emailOptBad", "emailOptOn",
    "previewClose", "acctPostPending", "acctPostLive",
    "cardPreviewPending", "cardPreviewRejected",
    "refreshAria", "refreshTitle", "reshuffleToast",
    "valueLine", "coachSkip", "coachNext", "coachDone", "coachStepOf",
    "coach1Title", "coach1Body", "coach2Title", "coach2Body",
    "coach3Title", "coach3Body", "coach4Title", "coach4Body",
    "coach5Title", "coach5Body",
)


class TestFourEntryPointsSkeleton(unittest.TestCase):
    """发现 / 主题分类 / 一站式配齐 / 发布 / 我的。"""

    @classmethod
    def setUpClass(cls):
        cls.full = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        cls.lite = feed_dashboard.build_feed_html(
            {"items": [], "corpus": []}, variant="lite")

    def test_my_posts_open_a_card_preview_or_feed_deep_link(self):
        self.assertIn('id="cardPreview"', self.full)
        self.assertIn('data-i18n="previewClose"', self.full)
        js = _script_source(self.full)
        self.assertIn("function openMyPostCard", js)
        self.assertIn("js-me-post", js)
        self.assertIn("hydrateSiteConfig", js)
        fn = js[js.index("function openMyPostCard"):js.index("async function hydrateSiteConfig")]
        self.assertNotIn("state.mode = 'all'", fn)
        self.assertNotIn("render(true)", fn)
        self.assertNotIn("meAboutTitle", _script_source(self.full).split("function mePanelHtml")[1][:2500])
        self.assertIn("function track", js)
        self.assertIn("function collectAttribution", js)
        self.assertIn("flushJourney", js)
        self.assertIn("function claimGuestDevice", js)
        self.assertIn("function bootGuestIdentity", js)
        self.assertIn("/api/events", js)

    def test_the_bottom_bar_is_a_real_tablist(self):
        """div + class 也能画出一样的东西，但读屏不会播报「5 个中的第 2 个」。"""
        bar = re.search(r'<nav class="bottom"[^>]*>', self.full).group(0)
        self.assertIn('role="tablist"', bar)
        self.assertIn('data-i18n-aria="tabsAria"', bar)
        tabs = re.findall(r'<button class="nav[^>]*role="tab"[^>]*>', self.full)
        self.assertEqual(5, len(tabs), "五个入口：发现 / 主题分类 / 一站式配齐 / 发布 / 我的")
        self.assertIn('id="tab-packs"', self.full)
        self.assertIn('id="tab-publish"', self.full)
        self.assertTrue(
            any('data-mode="packs"' in t for t in tabs),
            "一站式配齐 tab 必须出现在公开页")
        self.assertTrue(
            any('data-mode="publish"' in t for t in tabs),
            "发布 tab 必须出现在公开页，首访引导要指到它")
        for tag in tabs:
            self.assertRegex(tag, r'aria-selected="(true|false)"')
            self.assertIn('aria-controls="feed"', tag)
            self.assertRegex(tag, r'id="tab-[a-z]+"')
        panel = re.search(r'<main class="feed" id="feed"[^>]*>', self.full).group(0)
        self.assertIn('role="tabpanel"', panel)
        self.assertIn('aria-labelledby=', panel)

    def test_packs_shelf_framework_lists_first_wave(self):
        js = _script_source(self.full)
        self.assertIn("const PACK_SHELF = [", js)
        self.assertIn("function packsPanelHtml", js)
        self.assertIn("shelf-ecom", js)
        self.assertIn("cross-border", js)
        self.assertIn("short-drama", js)
        self.assertIn("marketing", js)
        self.assertIn("data-analytics", js)
        self.assertIn("一站式配齐", self.full)
        self.assertIn("持续扩充中", self.full)
        self.assertNotIn("发现流仍全量免费", self.full)
        self.assertIn("packs: 'packs'", js)
        self.assertNotIn('"priceFen"', js)
        self.assertIn("连续包月 ¥29 起", self.full)
        self.assertIn("按你电脑里已有的技能推荐", self.full)
        self.assertIn("function packsSubHeroHtml", js)
        self.assertIn("subscriber_month_cont", js)
        self.assertIn("/api/pay/checkout", js)
        self.assertIn("/api/me/seats/assign", js)
        self.assertIn("function packPriceText", js)
        # 商详卖成套亮点，不全文展开手册 / 核心能力
        self.assertIn("packsSecWhy", js)
        self.assertIn("packsHighlightSafeTitle", js)
        self.assertIn("PACK_HOWTO_LOCKED", js)
        self.assertNotIn("whyChooseZh", js)
        self.assertNotIn("coreSkills", js)
        self.assertIn("pack-flow-hero", js)
        self.assertIn("pack-flow-map", js)
        self.assertIn("flowHintZh", js)
        self.assertIn("包含哪些环节？", self.full)
        self.assertNotIn("可卖·材料齐", self.full)
        self.assertIn("竞品分析", js)
        self.assertIn("竞品追踪", js)
        self.assertIn("从选品做到利润复盘", js)
        self.assertIn("只上架已验证技能", self.full)
        self.assertNotIn("待定价", self.full)
        self.assertNotIn("首波上架", self.full)
        self.assertNotIn("收银台即将开通", self.full)

    def test_only_one_tab_starts_selected_and_the_rest_leave_the_tab_order(self):
        """roving tabindex：tablist 整体只占一个 Tab 位。"""
        tabs = re.findall(r'<button class="nav[^>]*role="tab"[^>]*>', self.full)
        selected = [t for t in tabs if 'aria-selected="true"' in t]
        self.assertEqual(1, len(selected))
        self.assertIn('data-mode="all"', selected[0])
        for tag in tabs:
            if 'aria-selected="true"' in tag:
                self.assertNotIn('tabindex="-1"', tag)
            else:
                self.assertIn('tabindex="-1"', tag, "未激活的 tab 还占着 Tab 序：" + tag[:80])

    def test_active_tab_is_not_signalled_by_colour_alone(self):
        """WCAG 1.4.1：`.nav.on { color: var(--accent) }` 单独一条不够。"""
        self.assertIn(".nav.on::before {", self.full)
        self.assertRegex(self.full, r"\.nav\.on \.nav-label \{ font-weight")

    def test_nav_labels_do_not_wrap_mid_word(self):
        """「一站式配齐」等标签不许拆到第二行。"""
        m = re.search(r"\.nav-label\s*\{(.*?)\}", self.full, flags=re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("white-space: nowrap", body)
        self.assertNotIn("max-width:", body)

    def test_lite_keeps_topics_but_drops_publish_account_and_packs(self):
        """lite 是 skill-picker 的发现子页，按产品约定不含发布/个人后台/付费货架。"""
        self.assertIn('body.variant-lite .nav[data-mode="publish"]', self.lite)
        self.assertIn('body.variant-lite .nav[data-mode="me"]', self.lite)
        self.assertIn('body.variant-lite .nav[data-mode="packs"]', self.lite)
        self.assertNotIn('body.variant-lite .nav[data-mode="topics"]', self.lite)
        # 旧的 data-action 钩子换成了 data-mode，别让隐藏规则指着一个不存在的属性
        self.assertNotIn('data-action="publish"', self.lite)

    def test_back_to_top_button_ships_in_both_variants_with_a_name(self):
        for variant, html in (("full", self.full), ("lite", self.lite)):
            with self.subTest(variant=variant):
                tag = re.search(r'<button class="to-top"[^>]*>', html).group(0)
                self.assertIn("hidden", tag, "初始就该是隐藏的")
                self.assertIn('aria-label="回到顶部"', tag)
                self.assertIn('data-i18n-aria="backToTop"', tag)

    def test_new_copy_exists_in_both_languages(self):
        js = _script_source(self.full)
        zh = _grab(js, r"  zh: \{.*?\n  \}\,")
        en = _grab(js, r"  en: \{.*?\n  \}\,")
        for key in NEW_I18N_KEYS:
            with self.subTest(key=key):
                self.assertIn(key + ":", zh, key + " 缺中文")
                self.assertIn(key + ":", en, key + " 缺英文")


class TestResponsiveShell(unittest.TestCase):
    """电脑 / 平板网页 / 手机共用一套壳，断点写在源码里而不是生成后的快照。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def test_viewport_asks_for_safe_area(self):
        self.assertIn("viewport-fit=cover", self.html)

    def test_stage_wraps_the_feed_so_desktop_can_grid(self):
        self.assertIn('class="stage"', self.html)
        self.assertLess(
            self.html.index('class="stage"'),
            self.html.index('id="feed"'),
            "stage 必须包住信息流，电脑端才能把导航甩到左侧")
        self.assertGreater(
            self.html.index("</div>", self.html.index('id="feed"')),
            self.html.index('id="feed"'))

    def test_three_widths_are_declared(self):
        self.assertIn("@media (max-width: 380px)", self.html)
        self.assertIn("@media (min-width: 720px)", self.html)
        self.assertIn("@media (min-width: 1100px)", self.html)
        self.assertIn("grid-template-areas", self.html)
        self.assertIn("safe-area-inset-top", self.html)
        self.assertNotIn("@media (max-width: 520px)", self.html)

    def test_phone_search_is_16px_to_avoid_ios_zoom(self):
        self.assertRegex(self.html, r"\.search \{[^}]*font-size: 16px")


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的 tab / 账户逻辑")
class TestTabRoutingAndRuntimeShapes(unittest.TestCase):
    """tab ↔ URL、三种运行形态下入口的显隐。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, lang="zh", api_base="", lite=False, extra=""):
        h = JsHarness(self.html, lang=lang,
                      scenes=TOPIC_SCENES, scenes_l2=TOPIC_SCENES_L2, feed=TOPIC_FEED)
        if api_base:
            h.prelude = h.prelude.replace(
                "const API_BASE = '';", "const API_BASE = %s;" % json.dumps(api_base))
        if lite:
            h.prelude = h.prelude.replace(
                "const IS_LITE = false;", "const IS_LITE = true;")
        if extra:
            h.prelude = h.prelude + "\n" + extra
        return h

    def test_every_tab_survives_a_url_roundtrip(self):
        """刷新/分享不能丢当前 tab，所以 query ↔ mode 必须是一对一的。"""
        got = self.harness().eval(
            "['all','topics','packs','publish','me'].map(m =>"
            " (state.mode = m, tabFromQuery(tabSearch('', m)) || 'all'))")
        self.assertEqual(["all", "topics", "packs", "publish", "me"], got)

    def test_publish_tab_is_addressable(self):
        got = self.harness().eval(
            "[tabAllowed('publish'), tabFromQuery('?tab=publish'), tabForMode('publish')]")
        self.assertEqual([True, "publish", "publish"], got)

    def test_discover_is_the_default_and_needs_no_parameter(self):
        got = self.harness().eval(
            "[tabSearch('', 'all'), tabFromQuery(''), tabFromQuery('?tab=discover')]")
        self.assertEqual(["", "", "all"], got)

    def test_an_unknown_tab_value_is_ignored(self):
        got = self.harness().eval(
            "[tabFromQuery('?tab=nope'), tabFromQuery('?tab='), tabFromQuery('?tab=ME')]")
        self.assertEqual(["", "", "me"], got, "大小写可以宽容，乱值不能猜")

    def test_the_tab_parameter_rides_along_with_the_existing_ones(self):
        """?q= 是既有约定，加 tab 不能把它挤掉。"""
        got = self.harness().eval("(state.mode = 'me', tabSearch('?q=weekly', 'me'))")
        self.assertIn("q=weekly", got)
        self.assertIn("tab=me", got)

    def test_a_filtered_discover_view_is_shareable(self):
        got = self.harness().eval(
            "(state.scene = 'content', state.scene_l2 = 'writing', tabSearch('', 'all'))")
        self.assertIn("scene=content", got)
        self.assertIn("l2=writing", got)

    def test_scene_parameters_are_dropped_on_the_other_tabs(self):
        """分享一个「我的」链接时带着 scene= 只会在切回发现时莫名筛上。"""
        got = self.harness().eval(
            "(state.scene = 'content', state.mode = 'me', tabSearch('?scene=design', 'me'))")
        self.assertNotIn("scene=", got)

    def test_lite_refuses_the_publish_and_account_tabs(self):
        got = self.harness(lite=True).eval(
            "[tabAllowed('all'), tabAllowed('topics'), tabAllowed('packs'),"
            " tabAllowed('publish'), tabAllowed('me'), tabFromQuery('?tab=me'),"
            " tabFromQuery('?tab=publish'), tabFromQuery('?tab=packs')]")
        self.assertEqual([True, True, False, False, False, "", "", ""], got,
                         "lite 下 ?tab=me / packs 不能把个人后台或付费货架逼出来")

    def test_subviews_keep_their_parent_tab_highlighted(self):
        """「查看收藏」和发布者主页不是独立 tab，但也不该让五个 tab 全灭。"""
        got = self.harness().eval(
            "['saved','publisher','topics','packs','nope'].map(tabForMode)")
        self.assertEqual(["me", "all", "topics", "packs", "all"], got)

    def test_packs_tab_is_shareable_with_pack_deep_link(self):
        got = self.harness().eval(
            "(state.packId = 'shelf-ecom', state.packGroup = 'ecom',"
            " tabSearch('', 'packs'))")
        self.assertIn("tab=packs", got)
        self.assertIn("pack=shelf-ecom", got)
        self.assertIn("pg=ecom", got)

    def test_account_mode_follows_the_runtime_shape(self):
        """三种形态的判据全部由 IS_LITE + API_BASE 推出来，没有第二套探测。"""
        cases = {
            "off": dict(lite=True, api_base="https://skillfeeder.cn"),
            "local": dict(),
            "live": dict(api_base="https://skillfeeder.cn"),
            "linked": dict(api_base="https://api.elsewhere.example"),
        }
        for want, kw in cases.items():
            with self.subTest(shape=want):
                self.assertEqual(want, self.harness(**kw).eval("accountMode()"))

    def test_a_shape_without_a_usable_api_never_paints_a_dead_control(self):
        """形态 2/3 不能出现「点了没反应」的入口。"""
        pub = self.harness(lite=True).eval("publishPanelHtml()")
        self.assertNotIn("<button", pub)
        self.assertNotIn("<form", pub)
        self.assertNotIn("href=", pub)
        lite_acct = self.harness(lite=True).eval("mePanelHtml()")
        self.assertNotIn("/publish", lite_acct)
        self.assertNotIn("/login", lite_acct)

        pub = self.harness().eval("publishPanelHtml()")
        self.assertNotIn("<button", pub)
        self.assertNotIn("<form", pub)
        self.assertNotIn("href=", pub)
        acct = self.harness().eval("mePanelHtml()")
        self.assertNotIn("/publish", acct)
        self.assertNotIn('href="/login"', acct)
        self.assertNotIn('type="password"', acct)

    def test_a_cross_origin_api_only_offers_a_full_page_hop(self):
        """跨站请求带不上 SameSite=Lax 的会话 Cookie，所以不在页内做表单。"""
        js = self.harness(api_base="https://api.elsewhere.example")
        pub = js.eval("publishPanelHtml()")
        self.assertNotIn("<form", pub)
        self.assertIn("https://api.elsewhere.example/publish", pub)
        acct = js.eval("mePanelHtml()")
        self.assertIn("https://api.elsewhere.example/", acct)
        self.assertNotIn("acctChecking", acct)

    def test_a_same_origin_api_gets_the_in_page_form(self):
        js = self.harness(api_base="https://skillfeeder.cn")
        pub = js.eval("publishPanelHtml()")
        self.assertIn('id="pubForm"', pub)
        for field in ("title", "github_url", "description"):
            self.assertIn('name="%s"' % field, pub, field + " 是 /api/posts 的契约字段")
        self.assertNotIn('name="body_md"', pub)
        self.assertIn("https://skillfeeder.cn/login", pub)
        self.assertNotIn("粘 <strong>SKILL.md</strong>", pub)
        self.assertIn("cTitle", pub)
        self.assertIn("pubPreview", pub)

    def test_the_account_panel_shows_the_real_signed_in_user(self):
        js = self.harness(
            api_base="https://skillfeeder.cn",
            extra="Object.assign(ACCT, { loaded: true,"
                  " user: { login: 'kai', name: 'Kai L' },"
                  " posts: [{ title: 'my-skill', description: 'd', status: 'published',"
                  " public_id: 'ugc:kai/my-skill::SKILL.md',"
                  " scene_label: '内容创作', created_at: '2026-09-09T10:00:00' }] });")
        html = js.eval("mePanelHtml()")
        self.assertIn("@kai", html)
        self.assertIn("Kai L", html)
        self.assertIn("js-acct-logout", html)
        self.assertIn("我发布的", html)
        self.assertIn("js-me-post", html)
        self.assertNotIn("acctAnonTitle", html)
        self.assertNotIn("发现站", html)
        posts = js.eval("mePanelHtml()")
        self.assertIn("my-skill", posts)

    def test_bind_nudge_offers_wechat_or_phone_when_github_only(self):
        """只登了 GitHub、且通道已开时，发现流要出绑定召回条。"""
        js = self.harness(
            api_base="https://skillfeeder.cn",
            extra=(
                "Object.assign(ACCT, { loaded: true, wechat: true, sms: true,"
                " user: { login: 'kai', name: 'Kai', providers: ['github'] } });"
                "try { localStorage.removeItem('sf_bind_nudge'); } catch (e) {}"
            ),
        )
        html = js.eval("bindNudgeHtml()")
        self.assertIn("绑定手机或微信", html)
        self.assertIn("/auth/wechat", html)
        self.assertIn("js-bind-nudge-later", html)
        gone = js.eval(
            "(localStorage.setItem('sf_bind_nudge', '1'), bindNudgeHtml())")
        self.assertEqual("", gone)

    def test_bind_nudge_falls_back_to_email_when_channels_off(self):
        """生产未开微信/短信时，引导去「我的」填邮箱（可落地的外联通道）。"""
        js = self.harness(
            api_base="https://skillfeeder.cn",
            extra=(
                "Object.assign(ACCT, { loaded: true, wechat: false, sms: false,"
                " user: { login: 'kai', name: 'Kai', providers: ['github'],"
                " email_opt_in: false } });"
                "try { localStorage.removeItem('sf_bind_nudge'); } catch (e) {}"
            ),
        )
        html = js.eval("bindNudgeHtml()")
        self.assertIn("留下邮箱", html)
        self.assertIn("js-bind-nudge-email", html)
        self.assertNotIn("/auth/wechat", html)
        opted = js.eval(
            "(ACCT.user.email_opt_in = true, bindNudgeHtml())")
        self.assertEqual("", opted)

    def test_recall_saved_strip_points_at_bookmarks(self):
        js = self.harness(
            extra=(
                "saved.add('acme/stop-slop');"
                "try { sessionStorage.removeItem('sf_recall_saved'); } catch (e) {}"
            ),
        )
        html = js.eval("recallSavedHtml()")
        self.assertIn("你收藏了 1 条", html)
        self.assertIn("js-recall-saved", html)

    def test_email_opt_form_is_on_me_when_signed_in(self):
        js = self.harness(
            api_base="https://skillfeeder.cn",
            extra=(
                "Object.assign(ACCT, { loaded: true,"
                " user: { login: 'kai', name: 'Kai', providers: ['github'],"
                " email_opt_in: false, email_masked: '' } });"
            ),
        )
        html = js.eval("mePanelHtml()")
        self.assertIn("meEmailForm", html)
        self.assertIn("邮件提醒", html)
        self.assertNotIn("acctBindNeedWx", html)
        self.assertNotIn("配好服务号", html)

    def test_the_account_page_drops_the_discover_explainer(self):
        html = self.harness().eval("mePanelHtml()")
        self.assertNotIn("发现站", html)
        self.assertNotIn("meAboutTitle", html)
        self.assertIn("本机收藏", html)
        self.assertIn("我关注的 Builder", html)
        live = self.harness(api_base="https://skillfeeder.cn",
                            extra="Object.assign(ACCT, { loaded: true });").eval(
            "mePanelHtml()")
        self.assertIn("我发布的", live)
        self.assertNotIn("发现站", live)
        follow = self.harness(extra="followBuilders.add('acme');").eval(
            "mePanelHtml()")
        self.assertIn("@acme", follow)

    def test_a_signed_out_visitor_is_pointed_at_the_real_login(self):
        js = self.harness(api_base="https://skillfeeder.cn",
                          extra="Object.assign(ACCT, { loaded: true, user: null });")
        html = js.eval("mePanelHtml()")
        self.assertIn("https://skillfeeder.cn/login", html)
        self.assertIn("https://skillfeeder.cn/auth/github", html)
        # 假登录框：静态页自己收账号密码，一个字段都不该有
        self.assertNotIn('type="password"', html)

    def test_server_side_counts_win_once_they_are_readable(self):
        local = self.harness(api_base="https://skillfeeder.cn",
                             extra="Object.assign(ACCT, { loaded: true });")
        # 云端读到了账号收藏/点赞数组（/auth/me 返 saved/liked）就以它为准；
        # 计数与「查看收藏」列表同源（effectiveSavedSet/effectiveLikedSet）。
        remote = self.harness(api_base="https://skillfeeder.cn",
                              extra="Object.assign(ACCT, { loaded: true, remote: true,"
                                    " likedNames: ['a/x::SKILL.md','b/y::SKILL.md',"
                                    " 'c/z::SKILL.md','d/w::SKILL.md','e/v::SKILL.md',"
                                    " 'f/u::SKILL.md','g/t::SKILL.md'],"
                                    " savedNames: ['a/x::SKILL.md','b/y::SKILL.md',"
                                    " 'c/z::SKILL.md'] });")
        self.assertIn("本机记录", local.eval("mePanelHtml()"))
        got = remote.eval("mePanelHtml()")
        self.assertIn("云端记录", got)
        self.assertIn("7", got)
        self.assertNotIn("本机记录", got)

    def test_the_english_panels_have_no_chinese_left(self):
        for kw in (dict(), dict(api_base="https://skillfeeder.cn"),
                   dict(api_base="https://api.elsewhere.example")):
            with self.subTest(**kw):
                js = self.harness(lang="en", extra="Object.assign(ACCT, { loaded: true });", **kw)
                for expr in ("publishPanelHtml()", "mePanelHtml()", "topicsPanelHtml()"):
                    got = js.eval(expr)
                    self.assertTrue(got, expr + " 渲染成空，断言会假过")
                    self.assertEqual([], CJK.findall(got), expr + "：" + got[:300])


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的分类页与滚动逻辑")
class TestTopicsPanelAndFirstScreen(unittest.TestCase):
    """主题分类页，以及它换来的首屏空间。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, lang="zh"):
        return JsHarness(self.html, lang=lang, scenes=TOPIC_SCENES,
                         scenes_l2=TOPIC_SCENES_L2, feed=TOPIC_FEED)

    def test_every_populated_scene_becomes_a_block_with_a_count(self):
        rows = self.harness().eval("topicRows()")
        self.assertEqual(["content", "design"], [r["id"] for r in rows],
                         "空场景不该占一整块，其他/other 在这份夹具里是 0 条")
        self.assertEqual([2, 1], [r["n"] for r in rows], "按条目数排，多的在前")
        self.assertEqual(["writing", "podcast"], [k["id"] for k in rows[0]["kids"]])

    def test_the_uncategorised_topic_block_uses_the_interesting_finds_name(self):
        """主题分类里 other 改叫「有意思的发现」；发现流 chips / 栏目仍用「其他」。"""
        feed = {
            "ui": {},
            "items": [dict(REAL_SKILL, full_name="z/odd", name="odd", owner="z",
                           scene="other", scene_l2="")],
            "corpus": [],
        }
        js = JsHarness(self.html, lang="zh", scenes=TOPIC_SCENES,
                       scenes_l2=TOPIC_SCENES_L2, feed=feed)
        rows = js.eval("topicRows()")
        other = [r for r in rows if r["id"] == "other"]
        self.assertEqual(1, len(other))
        self.assertEqual("有意思的发现", other[0]["label"])
        html = js.eval("topicsPanelHtml()")
        self.assertIn("有意思的发现", html)
        self.assertEqual("其他", js.eval("chipLabel(SCENES.find(s => s.id === 'other'))"),
                         "发现流 chips 仍走 scene 原名，不能跟着主题分类改")
        en = JsHarness(self.html, lang="en", scenes=TOPIC_SCENES,
                       scenes_l2=TOPIC_SCENES_L2, feed=feed)
        self.assertEqual("Interesting finds",
                         en.eval("topicRows().find(r => r.id === 'other').label"))
        self.assertEqual("Other",
                         en.eval("chipLabel(SCENES.find(s => s.id === 'other'))"))

    def test_the_block_says_how_many_in_words_not_just_in_colour(self):
        """分类色是卡片徽章那套色的复述，条目数必须是文字。"""
        html = self.harness().eval("topicsPanelHtml()")
        self.assertIn("2 条 · 2 个二级场景", html)
        self.assertIn('class="dot" aria-hidden="true"', html,
                      "色块是纯装饰，不该被读屏念出来")
        self.assertIn('role="tablist"', html)
        self.assertIn("按主题分类", html)
        self.assertIn("按栏目", html)
        self.assertNotIn("js-topic-section", html,
                         "主题子 tab 不该再把栏目画成底下一排 pill")

    def test_section_view_uses_the_same_card_chrome(self):
        html = self.harness().eval(
            "(state.topicsView = 'section', topicsPanelHtml())")
        self.assertIn('class="topic-card"', html)
        self.assertIn('class="topic-head js-topic-section"', html)
        self.assertIn("Skills", html)
        self.assertIn("1 条 · 1 个主题", html)
        self.assertIn("设计与视觉", html)
        self.assertNotIn('class="topic-head js-topic"', html)
        self.assertIn('aria-selected="true"', html)

    def test_switching_the_subtab_is_shareable(self):
        got = self.harness().eval(
            "(state.mode = 'topics', state.topicsView = 'section',"
            " [topicsViewFromQuery('?tab=topics&view=section'),"
            "  topicsViewFromQuery('?tab=topics'),"
            "  tabSearch('', 'topics')])")
        self.assertEqual(["section", "scene"], got[:2])
        self.assertIn("tab=topics", got[2])
        self.assertIn("view=section", got[2])

    def test_a_subcategory_chip_lands_on_the_narrower_filter(self):
        got = self.harness().eval(
            "(goTopic('content', 'writing'), [state.mode, state.scene, state.scene_l2])")
        self.assertEqual(["all", "content", "writing"], got)

    def test_the_heading_lands_on_the_whole_scene(self):
        got = self.harness().eval(
            "(goTopic('content', 'all'), [state.mode, state.scene, state.scene_l2])")
        self.assertEqual(["all", "content", "all"], got)

    def test_a_section_card_lands_on_that_section(self):
        got = self.harness().eval(
            "(goSection('Skills', 'all'),"
            " [state.mode, state.section, state.scene, state.scene_l2])")
        self.assertEqual(["all", "Skills", "all", "all"], got)

    def test_a_section_topic_chip_keeps_both_filters(self):
        got = self.harness().eval(
            "(goSection('Skills', 'design'),"
            " [state.mode, state.section, state.scene])")
        self.assertEqual(["all", "Skills", "design"], got)

    def test_an_empty_feed_says_so_instead_of_rendering_nothing(self):
        js = JsHarness(self.html, scenes=TOPIC_SCENES,
                       scenes_l2=TOPIC_SCENES_L2, feed={"ui": {}, "items": [], "corpus": []})
        html = js.eval("topicsPanelHtml()")
        self.assertIn("refresh", html)
        self.assertNotIn("topic-card", html)

    def test_discover_shows_no_filter_strips_until_something_is_filtered(self):
        """这是「当前非常难用」那条：不筛的时候三排 chips 一排都不长。"""
        js = self.harness()
        clean = js.eval(
            "(state.mode = 'all', state.scene = 'all', state.section = 'all', render(true),"
            " ['sceneStrip','l2Strip','sectionStrip']"
            "   .map(id => document.getElementById(id).classList.contains('show')))")
        self.assertEqual([False, False, False], clean)
        filtered_ = js.eval(
            "(state.mode = 'all', state.scene = 'content', state.scene_l2 = 'all',"
            " render(true), ['sceneStrip','l2Strip']"
            "   .map(id => document.getElementById(id).classList.contains('show')))")
        self.assertEqual([True, True], filtered_,
                         "筛着的时候必须看得见在筛什么、并且能清掉")

    def test_the_panel_tabs_hide_the_search_box_and_the_strips(self):
        for mode in ("topics", "me"):
            with self.subTest(mode=mode):
                got = self.harness().eval(
                    "(state.mode = '%s', state.scene = 'content', render(true),"
                    " [document.getElementById('searchWrap').style.display,"
                    "  document.getElementById('sceneStrip').classList.contains('show')])" % mode)
                self.assertEqual(["none", False], got)


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的滚动逻辑")
class TestBackToTop(unittest.TestCase):
    """一键回到顶部。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, extra=""):
        h = JsHarness(self.html)
        if extra:
            h.prelude = h.prelude + "\n" + extra
        return h

    def test_it_appears_only_after_a_full_screen_of_scrolling(self):
        got = self.harness().eval(
            "[shouldShowToTop(0, 800), shouldShowToTop(799, 800),"
            " shouldShowToTop(801, 800), shouldShowToTop(2000, 800)]")
        self.assertEqual([False, False, True, True], got)

    def test_a_very_short_viewport_still_needs_real_scrolling(self):
        """内嵌在小 iframe 里时 innerHeight 可能只有一两百 px。"""
        got = self.harness().eval("[shouldShowToTop(100, 120), shouldShowToTop(300, 120)]")
        self.assertEqual([False, True], got)

    def test_the_button_leaves_the_tab_order_while_hidden(self):
        got = self.harness().eval(
            "[(window.scrollY = 0, syncToTop(), document.getElementById('toTop').hidden),"
            " (window.scrollY = 3000, syncToTop(), document.getElementById('toTop').hidden)]")
        self.assertEqual([True, False], got)

    def test_smooth_by_default(self):
        self.assertEqual("smooth", self.harness().eval("scrollTopBehavior()"))

    def test_reduced_motion_gets_an_instant_jump(self):
        js = self.harness(
            extra="window.matchMedia = (q) => ({ matches: q.indexOf('reduced-motion') >= 0 });")
        self.assertEqual("auto", js.eval("scrollTopBehavior()"))

    def test_a_browser_without_matchmedia_does_not_break_the_button(self):
        self.assertEqual("smooth", self.harness().eval(
            "(window.matchMedia = undefined, scrollTopBehavior())"))

    def test_the_scroll_listener_also_drives_the_button(self):
        """按钮的显隐必须挂在既有的 scroll 监听上，不能自己再加一个。"""
        js = _script_source(self.html)
        self.assertRegex(
            js, r"window\.addEventListener\('scroll',[^\n]*syncToTop\(\)")


RANK_FEED = {
    "ui": {},
    "items": [
        {"full_name": "a/one", "name": "one", "owner": "a", "scene": "content",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "a/two", "name": "two", "owner": "a", "scene": "content",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "b/one", "name": "one", "owner": "b", "scene": "design",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "b/two", "name": "two", "owner": "b", "scene": "design",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "c/one", "name": "one", "owner": "c", "scene": "engineering",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "c/two", "name": "two", "owner": "c", "scene": "engineering",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "d/one", "name": "one", "owner": "d", "scene": "data-review",
         "personal_score": 0.50, "kind": "skill"},
        {"full_name": "d/two", "name": "two", "owner": "d", "scene": "data-review",
         "personal_score": 0.50, "kind": "skill"},
    ],
    "corpus": [],
}


@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的面板 JS")
class TestHideAndSessionRank(unittest.TestCase):
    """👎 立刻永滤 + 静态页补上会话级排序（后端 rank_feed 静态站用不上）。"""

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})

    def harness(self, feed=None, **kw):
        return JsHarness(self.html, feed=feed or FEED_FIX, **kw)

    def test_hide_drops_the_card_from_the_pool_and_remembers_it(self):
        got = self.harness().eval(
            "(hideItem('acme/stop-slop'), {"
            " pool: allPool().map(x => x.full_name),"
            " stored: [...loadSet('sf_hidden')],"
            " toast: document.getElementById('toast').textContent"
            "})")
        self.assertEqual([], got["pool"])
        self.assertEqual(["acme/stop-slop"], got["stored"])
        self.assertIn("不再推荐", got["toast"])

    def test_hide_also_clears_like_and_save(self):
        got = self.harness().eval(
            "(liked.add('acme/stop-slop'), saved.add('acme/stop-slop'),"
            " hideItem('acme/stop-slop'),"
            " [liked.has('acme/stop-slop'), saved.has('acme/stop-slop'),"
            "  JSON.parse(localStorage.getItem('sf_liked') || '[]'),"
            "  JSON.parse(localStorage.getItem('sf_saved') || '[]')])")
        self.assertEqual([False, False, [], []], got)

    def test_hidden_items_stay_out_of_filtered(self):
        js = self.harness()
        before = js.eval("filtered().map(x => x.full_name)")
        self.assertIn("acme/stop-slop", before)
        after = js.eval("(hideItem('acme/stop-slop'), filtered().map(x => x.full_name))")
        self.assertNotIn("acme/stop-slop", after)

    def test_session_jitter_is_stable_for_one_seed(self):
        got = self.harness().eval(
            "[sessionJitter('acme/x', 'seed-a', 0.12),"
            " sessionJitter('acme/x', 'seed-a', 0.12),"
            " sessionJitter('acme/x', 'seed-b', 0.12)]")
        self.assertEqual(got[0], got[1])
        self.assertNotEqual(got[0], got[2])

    def test_two_sessions_reshuffle_a_tied_cluster(self):
        js = self.harness(feed=RANK_FEED)
        a = js.eval("rankRows(FEED.items, '', 'seed-alpha').map(x => x.full_name)")
        b = js.eval("rankRows(FEED.items, '', 'seed-beta').map(x => x.full_name)")
        self.assertEqual(sorted(a), sorted(b))
        self.assertNotEqual(a, b, "同分簇换会话必须换序，不能每天同一张领跑")

    def test_search_turns_jitter_off(self):
        js = self.harness(feed=RANK_FEED)
        a = js.eval("rankRows(FEED.items, 'skill', 'seed-alpha').map(x => x.full_name)")
        b = js.eval("rankRows(FEED.items, 'skill', 'seed-beta').map(x => x.full_name)")
        self.assertEqual(a, b)

    def test_diversity_breaks_a_same_scene_run(self):
        feed = {
            "ui": {},
            "items": [
                {"full_name": "a/%d" % i, "name": str(i), "owner": "o%d" % i,
                 "scene": "content", "personal_score": 0.9 - i * 0.01, "kind": "skill"}
                for i in range(5)
            ] + [
                {"full_name": "b/1", "name": "1", "owner": "bx",
                 "scene": "design", "personal_score": 0.40, "kind": "skill"},
                {"full_name": "b/2", "name": "2", "owner": "by",
                 "scene": "design", "personal_score": 0.39, "kind": "skill"},
            ],
            "corpus": [],
        }
        names = self.harness(feed=feed).eval(
            "rankRows(FEED.items, '', 'fixed').map(x => x.scene)")
        run = 1
        worst = 1
        for i in range(1, len(names)):
            if names[i] == names[i - 1]:
                run += 1
                worst = max(worst, run)
            else:
                run = 1
        self.assertLessEqual(worst, 2, "闲逛态同 scene 不能连坐超过 2：" + str(names))

    def test_explore_pulls_a_tail_item_into_slot_five(self):
        items = [
            {"full_name": chr(97 + i), "name": chr(97 + i), "owner": chr(97 + i),
             "scene": "content" if i % 2 == 0 else "design",
             "personal_score": 1.0 - i * 0.01, "kind": "skill"}
            for i in range(12)
        ]
        got = self.harness().eval(
            "injectExplore(" + json.dumps(items) + ", false)[4].full_name")
        self.assertGreaterEqual(got, "f", "第 5 位应从后半段抽一条上来，不能永远是第 5 高分")

    def _lead_feed(self):
        return {
            "ui": {},
            "items": [
                {"full_name": "lead/x", "name": "lead", "owner": "lead",
                 "scene": "content", "personal_score": 0.99, "kind": "skill"},
                {"full_name": "alt/x", "name": "alt", "owner": "alt",
                 "scene": "design", "personal_score": 0.50, "kind": "skill"},
                {"full_name": "alt/y", "name": "alt2", "owner": "alt2",
                 "scene": "engineering", "personal_score": 0.40, "kind": "skill"},
            ],
            "corpus": [],
        }

    def test_two_hits_this_week_still_allow_the_same_slot(self):
        now = 1_700_000_000_000
        hist = {"lead/x": {"0": [now - 1000]}}
        first = self.harness(feed=self._lead_feed()).eval(
            "rankRows(FEED.items, '', 'fixed', %s, %d)[0].full_name"
            % (json.dumps(hist), now))
        self.assertEqual("lead/x", first)

    def test_a_third_hit_this_week_must_leave_the_slot(self):
        now = 1_700_000_000_000
        hist = {"lead/x": {"0": [now - 2000, now - 1000]}}
        first = self.harness(feed=self._lead_feed()).eval(
            "rankRows(FEED.items, '', 'fixed', %s, %d)[0].full_name"
            % (json.dumps(hist), now))
        self.assertNotEqual("lead/x", first, "一周内同一位次第 3 次必须换卡")

    def test_hits_older_than_a_week_do_not_count(self):
        now = 1_700_000_000_000
        week = 7 * 24 * 60 * 60 * 1000
        hist = {"lead/x": {"0": [now - week - 1000, now - week - 2000]}}
        first = self.harness(feed=self._lead_feed()).eval(
            "rankRows(FEED.items, '', 'fixed', %s, %d)[0].full_name"
            % (json.dumps(hist), now))
        self.assertEqual("lead/x", first)

    def test_shown_positions_are_remembered_once_per_view(self):
        got = self.harness().eval(
            "("
            "noteShownPositions([{full_name:'lead/x'}], true, 1000),"
            "noteShownPositions([{full_name:'lead/x'}], false, 1001),"
            "noteShownPositions([{full_name:'lead/x'}], true, 1002),"
            "JSON.parse(localStorage.getItem('sf_pos_hist'))['lead/x']['0']"
            ")")
        self.assertEqual([1000, 1002], got)

    def test_reshuffle_swaps_in_a_fresh_batch(self):
        items = [
            {"full_name": "n/%d" % i, "name": str(i), "owner": "o%d" % i,
             "scene": "content" if i % 2 == 0 else "design",
             "personal_score": 0.90 - i * 0.01, "kind": "skill"}
            for i in range(18)
        ]
        js = self.harness(feed={"ui": {}, "items": items, "corpus": []})
        got = js.eval(
            "(() => {"
            "  state.shown = 6;"
            "  const first = filtered().slice(0, 6).map(x => x.full_name);"
            "  reshuffleFeed();"
            "  const second = filtered().slice(0, 6).map(x => x.full_name);"
            "  return {first, second, toast: document.getElementById('toast').textContent};"
            "})()")
        self.assertTrue(set(got["first"]).isdisjoint(got["second"]),
                        "换一批必须换掉当前这屏，不能还是同一批："
                        + str(got))
        self.assertIn("换一批", got["toast"])


if __name__ == "__main__":
    unittest.main()
