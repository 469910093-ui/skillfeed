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
const window = { scrollTo() {}, addEventListener() {} };
function setTimeout() { return 0; }
function clearTimeout() {}
const localStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
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
            "const liked = new Set(); const saved = new Set();",
            "const followBuilders = new Set(%s); const followIndustries = new Set(%s);" % (
                json.dumps(list(follow_builders)), json.dumps(list(follow_industries)),
            ),
            "const demo = { on: false, step: 0, timer: null, focus: -1 };",
            # API_BASE 在模板里由 FEED.ui.api_base 推出来，这里固定成「没配云端」那一支
            "const API_BASE = ''; const PAGE = 6; const STORY_MS = 3500;",
            _grab(js, r"const PALETTES = \[.*?\n\];"),
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
        self.assertIn("class=\"pitch\"", html)
        self.assertIn("extractHighlightsClient", html)
        self.assertIn("js-publisher", html)
        self.assertIn("openPublisher", html)
        self.assertNotIn("aria-label=\"more\"", html)
        self.assertIn("sv-cover", html)
        self.assertIn("object-fit: contain", html)
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
        # 亮点为空时整块不渲染，SKILL.md 链接只跟着真文档出
        self.assertIn("${hl ? `<ul class=\"highlights\">", html)
        self.assertIn("${hasSkillDoc(it) ? `<a class=\"doc-link\"", html)


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
        self.assertIn('class="media js-media bare"', card)
        # 只剩一份时留全量文案，不留「和人…」这种断句
        self.assertIn("人机验证", card)

    def test_real_skill_card_keeps_skill_md_link(self):
        for lang, doc_link in (("zh", DOC_LINK_ZH), ("en", DOC_LINK_EN)):
            with self.subTest(lang=lang):
                card = self.harness(lang).eval(
                    "cardHtml(" + json.dumps(REAL_SKILL) + ", 0)")
                self.assertIn(doc_link, card)
                self.assertIn("blob/HEAD/SKILL.md", card)
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
        html = re.sub(r"<script>.*?</script>", "", html, flags=re.S)
        return re.sub(r"<style>.*?</style>", "", html, flags=re.S)

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
        for variant in ("full", "lite"):
            with self.subTest(variant=variant):
                leaks = _static_chinese_without_i18n(self._skeleton(variant))
                # 语言开关自己的「中文」按钮按惯例用本语言书写，不跟随开关；
                # lite 的 <title> 由服务端渲染，applyLang 里另有一刀补上
                expected = ["中文"] if variant == "full" else ["去 GitHub 发现", "中文"]
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
                # 模板本来只有一个内联脚本块；多出来的就是被恶意数据劈开的
                self.assertEqual(1, len(re.findall(r"<script\b", html, flags=re.I)))
                self.assertEqual(1, len(re.findall(r"</script\s*>", html, flags=re.I)))
                self.assertEqual(1, len(_script_blocks(html)))
                body = _script_blocks(html)[0].lower()
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

    @classmethod
    def setUpClass(cls):
        cls.html = feed_dashboard.build_feed_html({"items": [], "corpus": []})
        # 底色从令牌里读，不写死：写死的话，换了 --bg 就没人再验这两条了
        cls.BACKGROUNDS = (_css_token(cls.html, "card"), _css_token(cls.html, "bg"))

    def test_muted_passes_aa_on_both_page_backgrounds(self):
        muted = _css_token(self.html, "muted")
        # --muted 同时落在卡片底和页面底上
        for bg in self.BACKGROUNDS:
            with self.subTest(bg=bg):
                self.assertGreaterEqual(
                    _wcag_ratio(muted, bg), self.AA_TEXT,
                    f"--muted {muted} 在 {bg} 上只有 {_wcag_ratio(muted, bg):.2f}:1")

    def test_like_ink_passes_aa_and_keeps_the_brand_hue(self):
        like = _css_token(self.html, "like")
        like_ink = _css_token(self.html, "like-ink")
        for bg in self.BACKGROUNDS:
            with self.subTest(bg=bg):
                self.assertGreaterEqual(_wcag_ratio(like_ink, bg), self.AA_TEXT)

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
        """头像字母原来恒为白色，落在 #ffd200 上只有 1.45:1。

        readableOn 按底色亮度挑前景，这里逐个调色板验，别让新增一组颜色悄悄掉队。
        """
        got = JsHarness(self.html).eval(
            "PALETTES.map(p => {"
            "  const fg = readableOn(p[1]);"
            "  return [p[1], fg, contrastRatio(relLum(fg), relLum(p[1]))];"
            "})")
        self.assertEqual(8, len(got))
        for bg, fg, ratio in got:
            with self.subTest(bg=bg):
                self.assertGreaterEqual(
                    ratio, self.AA_TEXT,
                    f"头像字母 {fg} on {bg} 只有 {ratio:.2f}:1")


class TestBrandIdentityIsOurOwn(unittest.TestCase):
    """页面外壳的品牌要素必须是我们自己的，不得使用第三方品牌标识。

    断言范围是**页面外壳**（`<style>` + head + 静态 markup），刻意剔掉 `<script>`
    里的内容数据。因为 feed 里正当存在提到第三方产品的条目
    （`instagram-curator`、"TikTok and Instagram carousel" 之类的第三方 skill），
    指名提及真实产品是正当使用，不是我们的品牌表述。对整页 HTML 做字符串断言
    会在有真实内容时误报——空 feed 下还是绿的、一上线就炸，属于最难查的那种假绿，
    所以夹具里专门放了一条这样的条目来证明不会误报。

    中性灰（`#fafafa` / `#262626` / `#dbdbdb`）不在禁用名单里：浅灰是几千个站点
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

    def test_third_party_product_name_in_content_is_present_so_the_fixture_is_meaningful(self):
        """先确认夹具真的把第三方产品名写进了页面，否则下面两条断言是空过。"""
        self.assertIn("instagram", self.html.lower())

    def test_no_banned_brand_values_reach_the_page_chrome(self):
        for token, why in self.BANNED.items():
            with self.subTest(token=token):
                self.assertNotIn(
                    token, self.chrome,
                    f"{token}（{why}）出现在页面外壳里；品牌要素要用我们自己的取值")

    def test_chrome_does_not_describe_itself_as_another_product(self):
        """外壳里不许出现自称某第三方产品同款的字样。

        挡的是往后有人把这类描述写进 title / meta description / tagline。
        """
        for app in self.THIRD_PARTY_APPS:
            with self.subTest(app=app):
                self.assertNotIn(app, self.chrome)

    def test_wordmark_is_solid_accent_not_a_gradient_fill(self):
        """辨识度来自「手写体字标 + 渐变填充」这个组合，不是单一元素，所以两样都不用。"""
        m = re.search(r"\.logo\s*\{(.*?)\}", self.html, flags=re.S)
        self.assertIsNotNone(m, "找不到 .logo 规则")
        self.assertNotIn("background-clip", m.group(1),
                         ".logo 变成渐变填充的字了")
        self.assertIn("var(--accent)", re.search(
            r"\.logo\s+span\s*\{(.*?)\}", self.html, flags=re.S).group(1))

    def test_ring_gradient_stays_in_the_accent_family(self):
        """头像环是渐变最大的曝光面：每张卡片一个。"""
        m = re.search(r"--ring:\s*([^;]+);", self.html)
        self.assertIsNotNone(m, "找不到 --ring")
        self.assertIn("var(--accent)", m.group(1))


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


if __name__ == "__main__":
    unittest.main()
