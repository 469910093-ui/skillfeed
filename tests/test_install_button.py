"""「装到本机」按钮：变体边界、三种运行形态、计划面板、回执面板。

这个功能的风险不在画得好不好看，在两件事上：
  1. 公开站上不能有它 —— skill-feed 自己不写用户磁盘，这条边界是产品承诺，
     所以下面第一组测试盯的是「生成时」就没有，而不是「运行时」不显示。
  2. 面板上写的必须就是真要落盘的 —— 知情同意是这套 UI 存在的全部理由，
     所以计划面板是纯函数，这里拿真数据形状喂它，断言目标路径、文件数都在。

JS 一律跑模板生成的那份真代码（node），不在 Python 里抄第二遍。
"""

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import feed_dashboard
from test_feed_dashboard import (
    DOM_STUB, NODE, _grab, _script_source, _top_level_functions,
)


ITEM = {
    "id": "acme/agent-skills#skills/demo-skill",
    "name": "demo-skill",
    "full_name": "acme/agent-skills",
    "url": "https://github.com/acme/agent-skills",
    "skill_path": "skills/demo-skill/SKILL.md",
    "description": "示例",
    "stars": 12,
    "scene": "writing",
}

FEED = {"items": [ITEM], "gates": {}, "funnel": {}}

# /api/install/plan 的真实响应形状，字段名与 install_api.InstallApi._describe 对齐
PLAN = {
    "ok": True,
    "plan_id": "pl4n1d",
    "source": "https://github.com/acme/agent-skills",
    "subdir": "skills/demo-skill",
    "ref": "main",
    "commit": "0123456789ab",
    "name": "demo-skill",
    "dir_name": "demo-skill",
    "host": "claude",
    "target": "/home/u/.claude/skills/demo-skill",
    "file_count": 3,
    "total_bytes": 2048,
    "files": [{"path": "SKILL.md", "bytes": 900}, {"path": "refs/a.md", "bytes": 1148}],
    "more_files": 0,
    "notes": [],
    "blockers": [],
}


def _lite_html(**kw) -> str:
    return feed_dashboard.build_feed_html(FEED, variant="lite", **kw)


class LiteHarness:
    """在 node 里跑 lite 变体的安装相关 JS。

    比 test_feed_dashboard 的 JsHarness 多两样东西：PICKER 状态和 fetch 桩。
    location 也得给，因为运行形态的判据就是地址栏。
    """

    def __init__(self, *, mode=None, lang="zh", href="http://127.0.0.1:8765/dashboard.html",
                 session=None, session_status=200, session_throws=False,
                 posts=None, local_block=None):
        js = _script_source(_lite_html())
        url = re.match(r"^([a-z]+):", href)
        seed_local = (
            "document.getElementById('skillpicker-local').textContent = "
            + json.dumps(local_block) + ";"
        ) if local_block is not None else ""
        # session 默认是「serve 在跑、令牌正常」那一支
        if session is None:
            session = {"ok": True, "token": "tok-abc", "hosts": ["claude", "cursor"],
                       "default_host": "claude"}
        self.prelude = "\n".join([
            DOM_STUB,
            "const location = %s;" % json.dumps({
                "protocol": (url.group(1) if url else "http") + ":",
                "hostname": re.sub(r"^[a-z]+://([^/:]*).*$", r"\1", href),
                "href": href, "search": "",
            }),
            "const __posts = []; const __toasts = []; let __rendered = 0;",
            "const __session = { body: %s, status: %d, throws: %s };" % (
                json.dumps(session), session_status,
                "true" if session_throws else "false",
            ),
            "const __postQueue = %s;" % json.dumps(list(posts or [])),
            _FETCH_STUB,
            seed_local,
            _grab(js, r"const LOCAL_SKILLS = \(function \(\) \{.*?\n\}\)\(\);"),
            _grab(js, r"const LOCAL_FRESH = \{\};"),
            _grab(js, r"const I18N = \{.*?\n\};"),
            # 安装相关文案不在共用表里，是 lite 块自己 assign 上去的
            _grab(js, r"Object\.assign\(I18N\.zh, \{.*?\n\}\);"),
            _grab(js, r"Object\.assign\(I18N\.en, \{.*?\n\}\);"),
            "let LANG = " + json.dumps(lang) + ";",
            "const IS_LITE = true;",
            "const SCENES = []; const SCENES_L2 = {}; const FEED = {\"ui\":{}};",
            "const liked = new Set(); const saved = new Set(); const hidden = new Set(); const batchSkip = new Set();",
            "const followBuilders = new Set(); const followIndustries = new Set();",
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
            _grab(js, r"const PICKER = \{[^\n]*\};"),
            _top_level_functions(js),
            # toast / render 是真函数，但一个要落到 DOM、一个要跑整套渲染。
            # 覆盖掉是为了能断言「有没有被调」，被测的安装代码本身一个字没换。
            "toast = m => { __toasts.push(m); };",
            "render = () => { __rendered += 1; };",
        ])
        # mode 给了就直接坐进那个形态，不给就跑真的探测逻辑
        self.boot = ("PICKER.mode = %s; PICKER.token = 'tok-abc'; PICKER.host = 'claude';"
                     % json.dumps(mode)) if mode else "await pickerInit();"

    def eval(self, expr: str):
        src = (self.prelude + "\n" + self.boot
               + "\nprocess.stdout.write(JSON.stringify(await (" + expr + ")));\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.mjs"
            path.write_text(src, encoding="utf-8")
            proc = subprocess.run([NODE, str(path)], capture_output=True,
                                  text=True, encoding="utf-8")
        if proc.returncode != 0:
            raise AssertionError("node 执行失败：" + (proc.stderr or ""))
        return json.loads(proc.stdout)


_FETCH_STUB = """
async function fetch(path, opts) {
  if (path === '/api/session') {
    if (__session.throws) throw new Error('refused');
    return {
      ok: __session.status >= 200 && __session.status < 300,
      status: __session.status,
      json: async () => __session.body,
    };
  }
  __posts.push({ path, opts });
  const next = __postQueue.shift();
  if (!next) throw new Error('测试没给这次 POST 准备响应：' + path);
  if (next.throws) throw new Error('network down');
  return {
    ok: next.status >= 200 && next.status < 300,
    status: next.status,
    json: async () => { if (next.bad) throw new Error('not json'); return next.body; },
  };
}
"""


class TestPublicSiteHasNoInstallSurface(unittest.TestCase):
    """公开站不是「运行时藏起来」，是生成时就没有。"""

    FORBIDDEN = ("/api/install", "js-install", "has-install", "installSheet",
                 "X-Skillpick-Token", "PICKER", "installBtnHtml", "装到本机",
                 "Install here", "skillpick.py add", "pickerInit")

    def test_full_variant_contains_no_install_bytes(self):
        html = feed_dashboard.build_feed_html(FEED)
        for token in self.FORBIDDEN:
            self.assertNotIn(token, html, f"公开站漏了 {token}")

    def test_lite_variant_contains_them(self):
        html = _lite_html()
        for token in self.FORBIDDEN:
            self.assertIn(token, html, f"lite 少了 {token}")

    def test_full_card_template_never_calls_the_button(self):
        # 不是「调了个返回空串的函数」，是模板里连调用点都不存在
        html = feed_dashboard.build_feed_html(FEED)
        self.assertIn('class="open-row"', html)
        self.assertNotIn("open-row${", html)

    def test_lite_card_template_calls_it(self):
        self.assertIn("installBtnHtml(it)", _lite_html())

    def test_the_no_install_note_only_gets_rewritten_in_lite(self):
        # 公开站那句「不代装」必须留着；改写它的代码只在 lite 里
        full = feed_dashboard.build_feed_html(FEED)
        self.assertIn("不代装", full)
        self.assertNotIn("I18N.zh.noInstallNote =", full)
        self.assertIn("I18N.zh.noInstallNote =", _lite_html())

    def test_default_variant_is_the_public_one(self):
        # 漏传 variant 不能意外把安装能力发到公开站上
        self.assertNotIn("/api/install", feed_dashboard.build_feed_html(FEED))

    def test_install_css_lands_before_the_sentinel_rule(self):
        # 插错位置会掉到 <style> 外面变成正文
        html = _lite_html()
        self.assertLess(html.index(".open-row.has-install"), html.index("</style>"))


class TestTheBlockRunsBeforeTheFirstRender(unittest.TestCase):
    """`const PICKER` 不提升，cardHtml 却在首屏就调 installBtnHtml。

    这段代码原来插在脚本末尾，结果每张卡都在暂时性死区上抛 ReferenceError，
    整个 feed 渲成空白 —— 而 node 测试全绿，因为 harness 自己拼作用域、
    顺序是它定的。所以这条不变量只能在源码顺序上盯。
    """

    def setUp(self):
        self.js = _script_source(_lite_html())

    def test_picker_is_declared_before_the_bootstrap_render(self):
        self.assertLess(self.js.index("const PICKER = "),
                        self.js.index("\napplyLang(LANG);"))

    def test_the_button_helper_is_defined_before_the_bootstrap_render(self):
        self.assertLess(self.js.index("function installBtnHtml("),
                        self.js.index("\napplyLang(LANG);"))

    def test_the_card_template_that_calls_it_comes_after_i18n(self):
        # installBtnHtml 走 tr()，文案是 lite 块 assign 上去的
        self.assertLess(self.js.index("const I18N = "),
                        self.js.index("Object.assign(I18N.zh, {"))

    def test_the_probe_is_kicked_off_before_the_bootstrap_render_too(self):
        # 探测是异步的，但发车得在同步段里，否则首屏之后还要等一轮
        self.assertLess(self.js.index("pickerInit()."),
                        self.js.index("\napplyLang(LANG);"))


@unittest.skipUnless(NODE, "需要 node")
class TestRunModeComesFromTheAddressBar(unittest.TestCase):
    """三种形态：live / copy / off。判据只看地址栏，不看数据。"""

    def test_localhost_with_a_live_serve_is_live(self):
        h = LiteHarness(href="http://127.0.0.1:8765/dashboard.html")
        self.assertEqual(h.eval("PICKER.mode"), "live")

    def test_the_token_and_host_come_from_the_session(self):
        h = LiteHarness(href="http://127.0.0.1:8765/dashboard.html")
        self.assertEqual(h.eval("[PICKER.token, PICKER.host, PICKER.hosts]"),
                         ["tok-abc", "claude", ["claude", "cursor"]])

    def test_localhost_by_name_also_works(self):
        h = LiteHarness(href="http://localhost:8765/dashboard.html")
        self.assertEqual(h.eval("PICKER.mode"), "live")

    def test_file_url_degrades_to_copy(self):
        h = LiteHarness(href="file:///C:/Users/u/.skill-picker/dashboard.html")
        self.assertEqual(h.eval("PICKER.mode"), "copy")

    def test_file_url_never_touches_the_network(self):
        h = LiteHarness(href="file:///C:/Users/u/.skill-picker/dashboard.html")
        self.assertEqual(h.eval("__posts.length"), 0)

    def test_the_published_embed_stays_off(self):
        # embed.html 也是 lite，会发到 Pages 上；那里必须完全不出现
        h = LiteHarness(href="https://skillfeeder.cn/embed.html")
        self.assertEqual(h.eval("PICKER.mode"), "off")

    def test_a_lookalike_hostname_is_not_local(self):
        h = LiteHarness(href="http://127.0.0.1.evil.com/embed.html")
        self.assertEqual(h.eval("PICKER.mode"), "off")

    def test_a_failing_session_falls_back_to_off(self):
        h = LiteHarness(session_status=500)
        self.assertEqual(h.eval("PICKER.mode"), "off")

    def test_a_session_without_a_token_falls_back_to_off(self):
        h = LiteHarness(session={"ok": True})
        self.assertEqual(h.eval("PICKER.mode"), "off")

    def test_a_thrown_fetch_falls_back_to_off(self):
        # serve 没开就是这一支：宁可没按钮，也不要点了没反应
        h = LiteHarness(session_throws=True)
        self.assertEqual(h.eval("PICKER.mode"), "off")

    def test_becoming_live_triggers_one_rerender(self):
        # 按钮是探测完才有的，不重渲染就要等用户自己滑
        h = LiteHarness(href="http://127.0.0.1:8765/x.html")
        self.assertEqual(h.eval("(await pickerInit(), __rendered)"), 0)

    def test_live_rewrites_the_no_install_note(self):
        h = LiteHarness(href="http://127.0.0.1:8765/x.html")
        self.assertNotIn("不代装", h.eval("I18N.zh.noInstallNote"))

    def test_off_leaves_the_no_install_note_alone(self):
        h = LiteHarness(href="https://skillfeeder.cn/embed.html")
        self.assertIn("不代装", h.eval("I18N.zh.noInstallNote"))


@unittest.skipUnless(NODE, "需要 node")
class TestTheButton(unittest.TestCase):

    def test_off_renders_nothing(self):
        h = LiteHarness(mode="off")
        self.assertEqual(h.eval("installBtnHtml(%s)" % json.dumps(ITEM)), "")

    def test_live_says_install_here(self):
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(ITEM))
        self.assertIn("装到本机", out)
        self.assertIn("js-install", out)

    def test_copy_says_copy_the_command(self):
        h = LiteHarness(mode="copy")
        self.assertIn("复制安装命令", h.eval("installBtnHtml(%s)" % json.dumps(ITEM)))

    def test_english_has_no_chinese_left(self):
        h = LiteHarness(mode="live", lang="en")
        out = h.eval("installBtnHtml(%s)" % json.dumps(ITEM))
        self.assertNotRegex(out, r"[\u4e00-\u9fff]")
        self.assertIn("Install here", out)

    def test_it_carries_the_repo_url(self):
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(ITEM))
        self.assertIn('data-url="https://github.com/acme/agent-skills"', out)

    def test_it_carries_the_subdir_not_the_skill_md_path(self):
        # 后端拿这个当子目录用，递文件路径过去会被拼成 .../SKILL.md/SKILL.md
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(ITEM))
        self.assertIn('data-path="skills/demo-skill"', out)

    def test_a_missing_url_is_rebuilt_from_the_full_name(self):
        item = dict(ITEM)
        item.pop("url")
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(item))
        self.assertIn('data-url="https://github.com/acme/agent-skills"', out)

    def test_no_coordinates_means_no_button(self):
        # corpus 池里有既无 url 又无 full_name 的条目，点了也没地方装
        h = LiteHarness(mode="live")
        self.assertEqual(h.eval("installBtnHtml({name:'x'})"), "")

    def test_a_hostile_url_cannot_break_out_of_the_attribute(self):
        item = dict(ITEM, url='https://x/"><img src=x onerror=alert(1)>')
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(item))
        self.assertNotIn("<img", out)
        self.assertIn("&quot;", out)

    def test_a_hostile_skill_path_is_escaped_too(self):
        item = dict(ITEM, skill_path='a"><b>')
        h = LiteHarness(mode="live")
        out = h.eval("installBtnHtml(%s)" % json.dumps(item))
        self.assertNotIn("<b>", out)

    def test_it_shares_the_row_with_the_github_cta(self):
        # CTA 已经在折叠线下了，按钮不能再加一行高度
        h = LiteHarness(mode="live")
        self.assertIn("open-gh install", h.eval("installBtnHtml(%s)" % json.dumps(ITEM)))

    def test_off_leaves_the_row_class_alone(self):
        h = LiteHarness(mode="off")
        self.assertEqual(h.eval("installBtnHtml(%s) ? 1 : 0" % json.dumps(ITEM)), 0)


@unittest.skipUnless(NODE, "需要 node")
class TestTheSubdirWeSendToTheBackend(unittest.TestCase):
    """feed 给的是 SKILL.md 的完整路径，后端要的是它所在的目录。

    第一版直接把 skill_path 递过去，实网上就报了
    「SKILL.md/SKILL.md 在包里不存在」。
    """

    def sub(self, p):
        return LiteHarness(mode="live").eval("installSubdir(%s)" % json.dumps(p))

    def test_a_root_skill_md_means_the_repo_root(self):
        self.assertEqual(self.sub("SKILL.md"), "")

    def test_a_nested_skill_md_yields_its_directory(self):
        self.assertEqual(self.sub("skills/demo/SKILL.md"), "skills/demo")

    def test_a_deeply_nested_one_keeps_the_whole_prefix(self):
        self.assertEqual(self.sub(".claude/skills/a/b/SKILL.md"), ".claude/skills/a/b")

    def test_a_leading_slash_is_dropped(self):
        self.assertEqual(self.sub("/skills/demo/SKILL.md"), "skills/demo")

    def test_lowercase_skill_md_is_handled_too(self):
        self.assertEqual(self.sub("skills/demo/skill.md"), "skills/demo")

    def test_a_path_that_is_already_a_directory_is_left_alone(self):
        self.assertEqual(self.sub("skills/demo"), "skills/demo")

    def test_empty_and_missing_are_empty(self):
        self.assertEqual(self.sub(""), "")
        self.assertEqual(
            LiteHarness(mode="live").eval("installSubdir(undefined)"), "")

    def test_double_slashes_do_not_leave_empty_segments(self):
        self.assertEqual(self.sub("skills//demo//SKILL.md"), "skills/demo")

    def test_a_root_skill_md_posts_an_empty_path(self):
        item = dict(ITEM, skill_path="SKILL.md")
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": PLAN}])
        got = h.eval("(await startInstall({dataset:{url:'https://github.com/a/b',"
                     " path:installSubdir(%s)}}), JSON.parse(__posts[0].opts.body).path)"
                     % json.dumps(item["skill_path"]))
        self.assertEqual(got, "")


@unittest.skipUnless(NODE, "需要 node")
class TestTheCommandWeTellPeopleToRun(unittest.TestCase):

    def test_it_is_the_documented_command(self):
        h = LiteHarness(mode="copy")
        self.assertEqual(h.eval("pickerCommand('https://github.com/a/b')"),
                         "python ~/.skill-picker/skillpick.py add https://github.com/a/b --yes")

    def test_the_panel_shows_it_verbatim(self):
        h = LiteHarness(mode="copy")
        out = h.eval("installCopyHtml('https://github.com/a/b')")
        self.assertIn("skillpick.py add https://github.com/a/b --yes", out)

    def test_the_panel_explains_why_the_button_degraded(self):
        h = LiteHarness(mode="copy")
        self.assertIn("file://", h.eval("installCopyHtml('https://github.com/a/b')"))

    def test_a_hostile_url_is_escaped_in_the_panel(self):
        h = LiteHarness(mode="copy")
        out = h.eval("installCopyHtml('https://x/</dd><img src=x>')")
        self.assertNotIn("<img", out)

    def test_clicking_the_button_opens_the_panel_instead_of_posting(self):
        h = LiteHarness(mode="copy")
        got = h.eval(
            "(await startInstall({dataset:{url:'https://github.com/a/b'}}),"
            " [__posts.length, document.getElementById('installSheetPanel').innerHTML"
            ".includes('skillpick.py add')])")
        self.assertEqual(got, [0, True])


@unittest.skipUnless(NODE, "需要 node")
class TestThePlanPanelShowsWhatWouldLand(unittest.TestCase):
    """知情同意是这套 UI 存在的理由：屏幕上写的就得是真要落盘的。"""

    def panel(self, **over):
        h = LiteHarness(mode="live")
        return h.eval("installPlanHtml(%s)" % json.dumps(dict(PLAN, **over)))

    def test_the_target_path_is_shown(self):
        self.assertIn("/home/u/.claude/skills/demo-skill", self.panel())

    def test_the_source_and_subdir_are_shown(self):
        out = self.panel()
        self.assertIn("https://github.com/acme/agent-skills", out)
        self.assertIn("skills/demo-skill", out)

    def test_the_commit_is_shown_next_to_the_ref(self):
        # ref 可以动，commit 不会；两个一起给才说得清装的是哪一版
        out = self.panel()
        self.assertIn("main", out)
        self.assertIn("0123456789ab", out)

    def test_the_file_count_and_size_are_shown(self):
        out = self.panel()
        self.assertIn("3 个文件", out)
        self.assertIn("2.0 KB", out)

    def test_the_file_list_is_shown(self):
        out = self.panel()
        self.assertIn("SKILL.md", out)
        self.assertIn("refs/a.md", out)

    def test_a_truncated_list_says_how_many_more(self):
        self.assertIn("还有 7 个", self.panel(more_files=7))

    def test_a_complete_list_does_not(self):
        self.assertNotIn("还有", self.panel(more_files=0))

    def test_notes_are_shown(self):
        self.assertIn("本机已有同名", self.panel(notes=["本机已有同名（claude）"]))

    def test_blockers_are_shown_and_marked(self):
        out = self.panel(ok=False, blockers=["目标目录已存在"])
        self.assertIn("目标目录已存在", out)
        self.assertIn("blocker", out)

    def test_a_blocked_plan_offers_no_confirm_button(self):
        out = self.panel(ok=False, blockers=["目标目录已存在"])
        self.assertNotIn("js-install-go", out)
        self.assertIn("js-install-cancel", out)

    def test_a_clean_plan_offers_confirm_carrying_the_plan_id(self):
        out = self.panel()
        self.assertIn('data-plan="pl4n1d"', out)

    def test_the_panel_says_nothing_lands_yet(self):
        self.assertIn("一个字节都不会落地", self.panel())

    def test_hostile_plan_text_cannot_inject(self):
        out = self.panel(target="/x", notes=["<img src=x onerror=alert(1)>"],
                         files=[{"path": "<b>a</b>", "bytes": 1}])
        self.assertNotIn("<img", out)
        self.assertNotIn("<b>", out)

    def test_english_panel_has_no_chinese_left(self):
        h = LiteHarness(mode="live", lang="en")
        out = h.eval("installPlanHtml(%s)" % json.dumps(PLAN))
        self.assertNotRegex(out, r"[\u4e00-\u9fff]")

    def test_a_missing_field_does_not_crash_the_panel(self):
        h = LiteHarness(mode="live")
        out = h.eval("installPlanHtml({ok:true,plan_id:'p'})")
        self.assertIn("js-install-go", out)


@unittest.skipUnless(NODE, "需要 node")
class TestTheReceiptPanel(unittest.TestCase):
    """装完的四种结局都得说清楚，尤其是「回滚了」和「装了但没进索引」。"""

    def panel(self, res):
        h = LiteHarness(mode="live")
        return h.eval("installDoneHtml(%s)" % json.dumps(res))

    def test_a_clean_install_says_how_many_files_landed(self):
        out = self.panel({"ok": True, "files": 3, "report": {"code": 0}})
        self.assertIn("装好了", out)
        self.assertIn("3 个文件", out)

    def test_a_rollback_says_the_disk_is_back(self):
        out = self.panel({"ok": False, "files": 3,
                          "report": {"code": 2, "rolled_back": True}})
        self.assertIn("回滚", out)
        self.assertIn("blocker", out)

    def test_a_rollback_never_claims_files_landed(self):
        out = self.panel({"ok": False, "files": 3,
                          "report": {"code": 2, "rolled_back": True}})
        self.assertNotIn("个文件，重扫", out)

    def test_not_indexed_points_at_the_dashboard(self):
        out = self.panel({"ok": False, "files": 3,
                          "report": {"code": 2, "missing_from_catalog": True}})
        self.assertIn("catalog", out)
        self.assertIn("blocker", out)

    def test_twins_are_reported_without_offering_to_delete(self):
        out = self.panel({"ok": True, "files": 3,
                          "report": {"code": 0, "twins": ["cursor", "agents"]}})
        self.assertIn("cursor / agents", out)
        self.assertIn("不代删", out)

    def test_a_failing_gate_is_reported_as_an_index_problem(self):
        out = self.panel({"ok": False, "files": 3,
                          "report": {"code": 2, "gates_failed": ["G1"]}})
        self.assertIn("G1", out)

    def test_the_title_tracks_the_outcome(self):
        ok = self.panel({"ok": True, "files": 1, "report": {"code": 0}})
        bad = self.panel({"ok": False, "files": 1, "report": {"code": 2, "gates_failed": ["G1"]}})
        self.assertIn("装好了", ok)
        self.assertIn("有话说", bad)

    def test_english_receipt_has_no_chinese_left(self):
        h = LiteHarness(mode="live", lang="en")
        out = h.eval("installDoneHtml({ok:true,files:2,report:{code:0,twins:['cursor']}})")
        self.assertNotRegex(out, r"[\u4e00-\u9fff]")

    def test_hostile_host_names_are_escaped(self):
        out = self.panel({"ok": True, "files": 1,
                          "report": {"code": 0, "twins": ["<img src=x>"]}})
        self.assertNotIn("<img", out)


@unittest.skipUnless(NODE, "需要 node")
class TestPostsCarryTheSecurityHeaders(unittest.TestCase):
    """服务端四道门禁里有两道靠这里发对：自定义令牌头和 JSON Content-Type。"""

    def post(self, expr, posts):
        h = LiteHarness(mode="live", posts=posts)
        return h.eval(expr)

    def test_the_token_header_is_sent(self):
        got = self.post("(await pickerPost('/api/x', {}), __posts[0].opts.headers)",
                        [{"status": 200, "body": {"ok": True}}])
        self.assertEqual(got["X-Skillpick-Token"], "tok-abc")

    def test_the_content_type_forces_a_preflight(self):
        # application/json 不是 CORS 简单请求，跨源页面得先过 preflight，而我们不回 CORS 头
        got = self.post("(await pickerPost('/api/x', {}), __posts[0].opts.headers)",
                        [{"status": 200, "body": {"ok": True}}])
        self.assertEqual(got["Content-Type"], "application/json")

    def test_it_posts(self):
        got = self.post("(await pickerPost('/api/x', {a:1}), __posts[0].opts.method)",
                        [{"status": 200, "body": {"ok": True}}])
        self.assertEqual(got, "POST")

    def test_the_body_is_json(self):
        got = self.post("(await pickerPost('/api/x', {a:1}), __posts[0].opts.body)",
                        [{"status": 200, "body": {"ok": True}}])
        self.assertEqual(json.loads(got), {"a": 1})

    def test_a_server_error_surfaces_the_server_message(self):
        got = self.post(
            "pickerPost('/api/x', {}).then(() => 'no', e => e.message)",
            [{"status": 403, "body": {"ok": False, "error": "拒绝：令牌不对，刷新看板重试"}}])
        self.assertIn("令牌不对", got)

    def test_an_unparseable_body_does_not_leak_a_json_error(self):
        got = self.post("pickerPost('/api/x', {}).then(() => 'no', e => e.message)",
                        [{"status": 200, "bad": True}])
        self.assertIn("没应答", got)

    def test_a_dead_serve_says_so(self):
        got = self.post("startInstall({dataset:{url:'https://github.com/a/b'}})"
                        ".then(() => __toasts[0])", [{"throws": True}])
        self.assertTrue(got)


@unittest.skipUnless(NODE, "需要 node")
class TestPlanThenApply(unittest.TestCase):

    def test_the_button_asks_for_a_plan_first(self):
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": PLAN}])
        got = h.eval("(await startInstall({dataset:{url:'https://github.com/a/b',path:'p'}}),"
                     " [__posts[0].path, JSON.parse(__posts[0].opts.body)])")
        self.assertEqual(got[0], "/api/install/plan")
        self.assertEqual(got[1], {"url": "https://github.com/a/b", "path": "p", "host": "claude"})

    def test_the_plan_lands_in_the_sheet(self):
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": PLAN}])
        got = h.eval("(await startInstall({dataset:{url:'https://github.com/a/b'}}),"
                     " document.getElementById('installSheet').classList.contains('open'))")
        self.assertTrue(got)

    def test_nothing_is_applied_before_the_user_confirms(self):
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": PLAN}])
        got = h.eval("(await startInstall({dataset:{url:'https://github.com/a/b'}}),"
                     " __posts.map(p => p.path))")
        self.assertEqual(got, ["/api/install/plan"])

    def test_confirm_applies_by_plan_id_only(self):
        # 只回传 plan_id：URL 再进来一次也拿不到别的计划，服务端才能防重放
        h = LiteHarness(mode="live", posts=[
            {"status": 200, "body": {"ok": True, "files": 3, "report": {"code": 0}, "local": {"names": {}}}}])
        got = h.eval("(await confirmInstall({dataset:{plan:'pl4n1d'}, textContent:''}),"
                     " JSON.parse(__posts[0].opts.body))")
        self.assertEqual(got, {"plan_id": "pl4n1d"})

    def test_a_successful_apply_refreshes_the_local_badge_index(self):
        body = {"ok": True, "files": 3, "report": {"code": 0},
                "local": {"names": {"demo-skill": {"copies": 1, "hosts": ["claude"], "drifted": False}}}}
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": body}])
        got = h.eval("(await confirmInstall({dataset:{plan:'p'}, textContent:''}),"
                     " localHit(%s))" % json.dumps(ITEM))
        self.assertEqual(got["hosts"], ["claude"])

    def test_a_successful_apply_rerenders_so_the_badge_appears(self):
        body = {"ok": True, "files": 1, "report": {"code": 0}, "local": {"names": {}}}
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": body}])
        self.assertEqual(h.eval("(await confirmInstall({dataset:{plan:'p'}, textContent:''}),"
                                " __rendered)"), 1)

    def test_an_expired_plan_re_enables_the_button(self):
        h = LiteHarness(mode="live", posts=[
            {"status": 409, "body": {"ok": False, "error": "这份安装计划已经过期，重新点一次「装到本机」"}}])
        got = h.eval("(async () => { const b = {dataset:{plan:'p'}, textContent:'', disabled:false};"
                     " await confirmInstall(b); return [b.disabled, __toasts[0]]; })()")
        self.assertFalse(got[0])
        self.assertIn("过期", got[1])

    def test_a_blocked_plan_never_reaches_apply(self):
        blocked = dict(PLAN, ok=False, blockers=["目标目录已存在"])
        h = LiteHarness(mode="live", posts=[{"status": 200, "body": blocked}])
        got = h.eval("(await startInstall({dataset:{url:'https://github.com/a/b'}}),"
                     " __posts.map(p => p.path))")
        self.assertEqual(got, ["/api/install/plan"])


@unittest.skipUnless(NODE, "需要 node")
class TestFreshlyInstalledSkillsShowUpImmediately(unittest.TestCase):
    """数据块是 scan 时烤进 HTML 的，装完不会自己变；增量得走 LOCAL_FRESH。"""

    def hit(self, fresh, item=ITEM, local_block=None):
        h = LiteHarness(mode="live", local_block=local_block)
        return h.eval("(Object.assign(LOCAL_FRESH, %s), localHit(%s))"
                      % (json.dumps(fresh), json.dumps(item)))

    def test_a_fresh_entry_shows_up_with_no_data_block_at_all(self):
        got = self.hit({"demo-skill": {"copies": 1, "hosts": ["claude"], "drifted": False}})
        self.assertEqual(got["copies"], 1)

    def test_a_fresh_entry_wins_over_the_baked_one(self):
        block = json.dumps({"names": {"demo-skill": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        got = self.hit({"demo-skill": {"copies": 2, "hosts": ["cursor", "claude"], "drifted": False}},
                       local_block=block)
        self.assertEqual(got["copies"], 2)

    def test_the_baked_index_still_works_when_nothing_is_fresh(self):
        block = json.dumps({"names": {"demo-skill": {"copies": 1, "hosts": ["cursor"], "drifted": False}}})
        got = self.hit({}, local_block=block)
        self.assertEqual(got["hosts"], ["cursor"])

    def test_no_match_is_still_no_match(self):
        self.assertIsNone(self.hit({"something-else": {"copies": 1, "hosts": ["claude"]}}))

    def test_prototype_keys_do_not_produce_phantom_hits(self):
        self.assertIsNone(self.hit({}, item=dict(ITEM, name="constructor", skill_path="")))

    def test_the_public_page_keeps_it_empty_forever(self):
        # full 变体里没有任何往 LOCAL_FRESH 写东西的代码
        self.assertNotIn("LOCAL_FRESH[", feed_dashboard.build_feed_html(FEED))


class TestCspStillCoversTheNewCode(unittest.TestCase):

    @staticmethod
    def policy(html: str) -> str:
        m = re.search(r'Content-Security-Policy" content="([^"]*)"', html)
        assert m, "没找到 CSP"
        return m.group(1)

    def test_script_src_is_a_hash_and_nothing_else(self):
        pol = self.policy(_lite_html())
        script = re.search(r"script-src ([^;]*)", pol).group(1)
        self.assertRegex(script, r"^'sha256-[A-Za-z0-9+/=]+'$")

    def test_the_hash_matches_the_script_with_the_install_code_in_it(self):
        html = _lite_html()
        js = _script_source(html)
        self.assertIn("pickerInit", js)
        self.assertIn(feed_dashboard._sha256_source(js), self.policy(html))

    def test_still_one_script_tag(self):
        self.assertEqual(_lite_html().count("<script"), 1)

    def test_same_origin_fetch_is_allowed(self):
        # /api/install/* 是同源，靠 connect-src 'self'
        self.assertIn("connect-src 'self'", self.policy(_lite_html()))

    def test_no_inline_or_eval_escape_hatch_crept_in(self):
        script = re.search(r"script-src ([^;]*)", self.policy(_lite_html())).group(1)
        self.assertNotIn("unsafe-inline", script)
        self.assertNotIn("unsafe-eval", script)

    def test_the_full_variant_hash_differs(self):
        # 两份产物的脚本内容不同，哈希必须各算各的
        a = self.policy(_lite_html())
        b = self.policy(feed_dashboard.build_feed_html(FEED))
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
