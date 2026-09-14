"""生成竖向无限下滑 skill 发现 Feed 的 HTML（只推荐到 GitHub）。

版式沿用移动信息流的通用惯例：单列窄壳、卡片、story 横条、双击点赞、红心=已赞、
书签=收藏、底部 tab 导航。这些是功能性的行业通用交互，不构成任何人的品牌识别。

品牌要素——字标字体、强调色、头像环渐变——一律是我们自己的。取值、实测对比度、
以及一份**禁用清单**（不得使用的第三方品牌标识）都在 docs/brand-tokens.md，
由 `tests/test_feed_dashboard.py::TestBrandIdentityIsOurOwn` 把门。

改下面 `:root` 里的令牌前请先看那份文档：`--muted` / `--link` / `--like-ink`
是在各自色相与饱和度上逐档搜出来的「刚好过 WCAG AA 的最亮值」，
往亮的方向动一档就会掉出 AA。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import scene


def _resolve_variant(feed: dict, variant: str | None = None) -> str:
    v = (variant or (feed.get("ui") or {}).get("variant") or "full").strip().lower()
    return v if v in ("full", "lite") else "full"


# HTML 解析器在 <script> 里只认标签边界，不认 JS 语法：一旦正文出现 `</script>`
# 浏览器就在那里结束脚本块，后面的内容当新 HTML/脚本解析。数据全部来自陌生人的
# SKILL.md，所以每个进 <script> 的插值都必须走 _json_for_script，不能裸 json.dumps。
_SCRIPT_UNSAFE = (
    # `<` `>` 一起转，既挡 `</script`、`<script`、`<!--`，也挡 `-->` 和 `]]>` 那类
    # 结束序列；JSON 里这三个字符只会出现在字符串字面量内，全局替换不会破坏结构
    ("&", "\\u0026"),
    ("<", "\\u003c"),
    (">", "\\u003e"),
    # U+2028/2029 在 JSON 里合法，但在 JS 源码里是行终止符，会把字符串字面量截断
    ("\u2028", "\\u2028"),
    ("\u2029", "\\u2029"),
)


def _json_for_script(value: object) -> str:
    """序列化成可安全内嵌进 <script> 的 JS 字面量。

    替换的是 json.dumps 的输出文本而不是原始数据：`\\u003c` 是合法 JSON 转义，
    JSON.parse 后仍还原成 `<`，所以数据一个字节都不会丢。
    """
    out = json.dumps(value, ensure_ascii=False)
    for raw, esc in _SCRIPT_UNSAFE:
        out = out.replace(raw, esc)
    return out


_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_INLINE_STYLE = re.compile(r"<style[^>]*>(.*?)</style>", re.S)
_CHARSET_META = '<meta charset="utf-8">'


def _sha256_source(text: str) -> str:
    """CSP 的 sha256-base64 源表达式。"""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _with_csp(html: str, *, api_base: str = "") -> str:
    """给页面加上按实际内联内容算出哈希的 CSP。

    用哈希而不是 nonce：这些产物是静态文件（GitHub Pages / 本地 file://），
    每次响应给的是同一份字节，写死的 nonce 对攻击者和对我们一样可见，
    等价于 'unsafe-inline'。哈希在静态托管下才是唯一有效的写法。

    `script-src` 是这条策略真正的价值所在：全站只有一块内联 script、没有外链
    脚本、没有 eval / new Function / 字符串式 setTimeout（改动前核查过），
    所以能收到「只允许这一段字节执行」，注入进来的 <script> 与 onX= 处理器
    一律不执行。为此把封面图的 onerror 改成了捕获阶段的委托监听。

    style 那边刻意留了退路。`style-src-elem` 用哈希、`style-src-attr` 放行
    inline，是想要的效果；但这两个指令是 Chrome 75 / Firefox 111 / Safari 15.4
    以后才有的，不支持的浏览器会回退到 `style-src`——如果那里不写
    'unsafe-inline'，它们就会连内联 <style> 一起拦掉，整页变成无样式的裸 HTML。
    宁可在老浏览器上少一层 CSS 防护，也不能让页面在那里彻底不可读。

    `img-src` 放到 https: 这么宽，是因为封面图地址来自陌生人的仓库元数据
    （`opengraph.githubassets.com` 只是最常见的一个，不是唯一），
    收窄到白名单会让相当一部分卡片没有封面。
    """
    sources = {
        "default-src": ["'none'"],
        "script-src": [_sha256_source(s) for s in _INLINE_SCRIPT.findall(html)],
        # 老浏览器的回退档：见 docstring，这里必须留 'unsafe-inline'
        "style-src": ["'unsafe-inline'", "https://fonts.googleapis.com"],
        "style-src-elem": ([_sha256_source(s) for s in _INLINE_STYLE.findall(html)]
                           + ["https://fonts.googleapis.com"]),
        # 模板里 19 处 style=""（场景色板 + 排版微调），哈希覆盖不到属性
        "style-src-attr": ["'unsafe-inline'"],
        "font-src": ["https://fonts.gstatic.com"],
        "img-src": ["'self'", "https:", "data:"],
        "connect-src": ["'self'", "https://api.github.com"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
    }
    if api_base.startswith(("http://", "https://")):
        sources["connect-src"].append(api_base.rstrip("/"))

    if not sources["script-src"]:
        raise RuntimeError(
            "没找到内联 <script>，CSP 会把页面锁死。"
            "改过 <script> 标签的写法就要同步改 _INLINE_SCRIPT。")

    policy = "; ".join(f"{k} {' '.join(v)}" for k, v in sources.items())
    meta = f'<meta http-equiv="Content-Security-Policy" content="{policy}">'

    # 必须插在 charset 之后、任何 <link>/<style> 之前：CSP 只管它被解析到
    # 之后声明的资源，插晚了前面的字体样式表就是策略外的。
    if _CHARSET_META not in html:
        raise RuntimeError("没找到 charset meta，无法确定 CSP 的插入位置")
    return html.replace(_CHARSET_META, _CHARSET_META + "\n" + meta, 1)


# ---------------------------------------------------------------- 装到本机
# 「不代装」这条产品边界没有变，只是说得更准了：**skill-feed 自己一个字节都不写你的
# 磁盘**。下面这套 UI 只出现在 lite 变体里，而 lite 就是 skill-picker 拷进
# ~/.skill-picker/discover.html 的那份；点下去调的是 skill-picker 的本地 serve
# （它自己的安装引擎、它自己的存证与回滚），本仓库只是把按钮画出来。
#
# 因此这三块按变体在**生成时**决定要不要写进去：公开的 index.html 里连一个相关字节
# 都没有，不靠运行时判断。tests 里有一条在盯这件事。
#
# 位置有硬要求：这段必须插在 applyLang(LANG) 那次首屏渲染之前。cardHtml 会调
# installBtnHtml，而它读 PICKER —— 函数声明会提升，`const PICKER` 不会。插晚了每张卡
# 都在暂时性死区上抛 ReferenceError，整个 feed 渲成空白（踩过一次）。
#
# lite 也会作为 embed.html 发到 Pages 上，所以运行时还有第二道：只有
# 127.0.0.1 / localhost 才去探端点，file:// 降级成复制命令，其余一律不显示。

INSTALL_CSS = """
  .open-row.has-install { display: flex; gap: 8px; }
  .open-row.has-install .open-gh { flex: 1 1 0; min-width: 0; }
  .open-gh.install {
    appearance: none; border: 1px solid var(--ink); cursor: pointer;
    background: #fff; color: var(--ink); font: inherit; font-weight: 700;
    font-size: .88rem; border-radius: 10px; padding: 10px 12px;
  }
  .open-gh.install[disabled] { opacity: .55; cursor: progress; }
  .install-plan { font-size: .8rem; line-height: 1.5; }
  .install-plan dl { display: grid; grid-template-columns: auto 1fr; gap: 4px 10px; margin: 0 0 10px; }
  .install-plan dt { color: var(--muted); white-space: nowrap; }
  .install-plan dd { margin: 0; word-break: break-all; }
  .install-plan ul { margin: 0 0 10px; padding-left: 18px; color: var(--muted); }
  /* 计划里的提示是后端逐字给的，带换行和缩进（同一份文案也要在终端里读）。
     pre-line 让换行留住、把缩进的空白吃掉，不然在页面上糊成一长条。 */
  .install-plan .note, .install-plan .blocker { white-space: pre-line; }
  .install-plan .note { color: var(--muted); margin: 0 0 6px; }
  .install-plan .blocker { color: #b42318; font-weight: 600; margin: 0 0 6px; }
  .install-act { display: flex; gap: 8px; margin-top: 12px; }
  .install-act button {
    flex: 1 1 0; border-radius: 10px; padding: 10px 12px; font: inherit;
    font-weight: 700; cursor: pointer; border: 1px solid var(--line); background: #fff;
  }
  .install-act button.primary { background: var(--ink); color: #fff; border-color: var(--ink); }
  .install-act button[disabled] { opacity: .55; cursor: not-allowed; }
"""

INSTALL_SHEET_HTML = """  <div class="sheet" id="installSheet" aria-hidden="true">
    <div class="sheet-panel" id="installSheetPanel"></div>
  </div>
"""

INSTALL_JS = """
/* ---------- 装到本机（只在 lite 变体里存在） ---------- */
/* 文案也塞在这个块里、不进共用的 I18N 表：公开产物里连「装到本机」这四个字都不该有。 */
Object.assign(I18N.zh, {
  installHere: '装到本机', installCopy: '复制安装命令',
  installPlanning: '看一下…', installWorking: '安装中…',
  installTitle: '装到本机', installConfirm: '确认安装', installCancel: '不装',
  installLead: '下面这些是真要写进你磁盘的东西。确认前它一个字节都不会落地。',
  installFrom: '来源', installVersion: '版本', installTarget: '装到', installContent: '内容',
  installFiles: '{n} 个文件 · {kb} KB', installMoreFiles: '还有 {n} 个',
  installOkTitle: '装好了', installWarnTitle: '装了，但有话说',
  installOkToast: '装好了，已进 catalog',
  installWrote: '写了 {n} 个文件，重扫已收进 catalog。',
  installTwins: '本机现在有 {n} 份同名（{hosts}）。要不要留着由你定，工具不代删。',
  installGateFail: '门禁 {gates} 没过。装的东西没问题，是索引层面要你看一眼。',
  installRolledBack: '落盘校验没对上，已经回滚，磁盘回到装之前。',
  installNotIndexed: '文件写进去了，但重扫没把它收进 catalog。去看板「理技能」看看目录对不对。',
  installNoAnswer: '本机看板服务没应答。确认 skillpick serve 还在跑。',
  installCopyTitle: '复制这条命令', installCopyBtn: '复制',
  installCopyLead: '这个看板是用 file:// 打开的，浏览器不让页面连本机服务。'
    + '在终端跑下面这条，或者改用 python ~/.skill-picker/skillpick.py serve 打开看板。',
  installCopied: '已复制', installCopyFail: '浏览器不让复制，请手动选中',
});
Object.assign(I18N.en, {
  installHere: 'Install here', installCopy: 'Copy install command',
  installPlanning: 'Checking…', installWorking: 'Installing…',
  installTitle: 'Install on this machine', installConfirm: 'Install', installCancel: 'Not now',
  installLead: 'This is what would actually be written to your disk. Nothing lands until you confirm.',
  installFrom: 'Source', installVersion: 'Version', installTarget: 'Target', installContent: 'Contents',
  installFiles: '{n} files · {kb} KB', installMoreFiles: '{n} more',
  installOkTitle: 'Installed', installWarnTitle: 'Installed, with a caveat',
  installOkToast: 'Installed and indexed',
  installWrote: 'Wrote {n} files; the rescan picked it up.',
  installTwins: 'This machine now holds {n} copies of that name ({hosts}). '
    + 'Keeping them is your call — nothing is deleted for you.',
  installGateFail: 'Gate {gates} did not pass. The files are fine; the index wants a look.',
  installRolledBack: 'The on-disk check did not match, so it was rolled back. Your disk is as it was.',
  installNotIndexed: 'The files were written but the rescan did not index them. '
    + 'Check the directory in the dashboard.',
  installNoAnswer: 'The local dashboard service did not answer. '
    + 'Check that skillpick serve is still running.',
  installCopyTitle: 'Copy this command', installCopyBtn: 'Copy',
  installCopyLead: 'This dashboard was opened over file://, so the page is not allowed to reach '
    + 'the local service. Run the command below, or reopen the dashboard with '
    + 'python ~/.skill-picker/skillpick.py serve.',
  installCopied: 'Copied', installCopyFail: 'The browser refused; select it by hand',
});

/* 三种运行形态，判据只看地址栏，不看数据：
     live —— 127.0.0.1/localhost 且 /api/session 应答 → 真能装
     copy —— file:// 打开的看板，浏览器不让 fetch 本机服务 → 复制命令
     off  —— 其它任何地方（包括 Pages 上的 embed.html）→ 完全不出现
   探测失败一律退回 off：宁可没有按钮，也不要点了没反应。 */
const PICKER = { mode: 'off', token: '', hosts: [], host: '' };

function pickerIsLocalHost() {
  return location.hostname === '127.0.0.1' || location.hostname === 'localhost';
}

function pickerCommand(url) {
  return 'python ~/.skill-picker/skillpick.py add ' + url + ' --yes';
}

async function pickerInit() {
  if (location.protocol === 'file:') { PICKER.mode = 'copy'; return; }
  if (!pickerIsLocalHost()) return;
  try {
    const resp = await fetch('/api/session', { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data || !data.token) return;
    PICKER.mode = 'live';
    PICKER.token = data.token;
    PICKER.hosts = data.hosts || [];
    PICKER.host = data.default_host || PICKER.hosts[0] || '';
    // 空结果页那句「不代装」在这里就不成立了。改文案而不是改渲染点：
    // 这样公开站的 index.html 里连这条替换文案都不存在。
    I18N.zh.noInstallNote = '这台机器上可以直接装：卡片上点「装到本机」，'
      + '装前会先给你计划，装完自动重扫进 catalog。';
    I18N.en.noInstallNote = 'On this machine you can install directly: use “Install here” on a card. '
      + 'You see the plan first, and the rescan indexes it for you afterwards.';
  } catch (e) { /* serve 没开就当没这功能 */ }
}

/* 后端要的是「装哪个子目录」，而 skill_path 指到 SKILL.md 文件本身。
   直接把文件路径递过去，后端会去找 skills/x/SKILL.md/SKILL.md（踩过一次）。 */
function installSubdir(skillPath) {
  const parts = String(skillPath || '').replace(/^\\/+/, '').split('/').filter(Boolean);
  if (parts.length && /\\.md$/i.test(parts[parts.length - 1])) parts.pop();
  return parts.join('/');
}

function installBtnHtml(it) {
  if (PICKER.mode === 'off') return '';
  const url = it.url || (it.full_name ? ('https://github.com/' + it.full_name) : '');
  if (!url) return '';
  const label = PICKER.mode === 'copy' ? tr('installCopy') : tr('installHere');
  return '<button type="button" class="open-gh install js-install"'
    + ' data-url="' + escapeHtml(url) + '"'
    + ' data-path="' + escapeHtml(installSubdir(it.skill_path)) + '">'
    + escapeHtml(label) + '</button>';
}

async function pickerPost(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Skillpick-Token': PICKER.token },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await resp.json(); } catch (e) { data = null; }
  if (!data) throw new Error(tr('installNoAnswer'));
  if (!resp.ok) throw new Error(data.error || tr('installNoAnswer'));
  return data;
}

function closeInstallSheet() {
  const el = document.getElementById('installSheet');
  if (!el) return;
  el.classList.remove('open');
  el.setAttribute('aria-hidden', 'true');
}

function showInstallSheet(html) {
  const panel = document.getElementById('installSheetPanel');
  if (!panel) return;
  panel.innerHTML = html;
  const el = document.getElementById('installSheet');
  el.classList.add('open');
  el.setAttribute('aria-hidden', 'false');
}

/* 计划面板是纯函数，好测；也保证「屏幕上写的」和「等会儿真写盘的」是同一份数据 */
function installPlanHtml(plan) {
  const rows = [
    [tr('installFrom'), plan.source + (plan.subdir ? ('  ' + plan.subdir) : '')],
    [tr('installVersion'), plan.ref + (plan.commit ? ('  ' + plan.commit) : '')],
    [tr('installTarget'), plan.target],
    [tr('installContent'), trn('installFiles', { n: plan.file_count,
      kb: (Number(plan.total_bytes || 0) / 1024).toFixed(1) })],
  ];
  const dl = rows.map(r => '<dt>' + escapeHtml(r[0]) + '</dt><dd>'
    + escapeHtml(String(r[1] || '')) + '</dd>').join('');
  const files = (plan.files || []).map(f => '<li>' + escapeHtml(f.path) + '</li>').join('')
    + (plan.more_files ? ('<li>' + escapeHtml(trn('installMoreFiles', { n: plan.more_files })) + '</li>') : '');
  const notes = (plan.notes || []).map(n => '<p class="note">' + escapeHtml(n) + '</p>').join('');
  const blockers = (plan.blockers || []).map(b => '<p class="blocker">' + escapeHtml(b) + '</p>').join('');
  const act = plan.ok
    ? '<button type="button" class="primary js-install-go" data-plan="' + escapeHtml(plan.plan_id) + '">'
      + escapeHtml(tr('installConfirm')) + '</button>'
    : '';
  return '<h3>' + escapeHtml(tr('installTitle')) + '</h3>'
    + '<p class="lead">' + escapeHtml(tr('installLead')) + '</p>'
    + '<div class="install-plan"><dl>' + dl + '</dl>'
    + (files ? ('<ul>' + files + '</ul>') : '') + notes + blockers + '</div>'
    + '<div class="install-act">'
    + '<button type="button" class="js-install-cancel">' + escapeHtml(tr('installCancel')) + '</button>'
    + act + '</div>';
}

function installDoneHtml(res) {
  const rep = res.report || {};
  const lines = [];
  if (rep.rolled_back) {
    lines.push('<p class="blocker">' + escapeHtml(tr('installRolledBack')) + '</p>');
  } else if (rep.missing_from_catalog) {
    lines.push('<p class="blocker">' + escapeHtml(tr('installNotIndexed')) + '</p>');
  } else {
    lines.push('<p class="note">' + escapeHtml(trn('installWrote', { n: res.files })) + '</p>');
    if ((rep.twins || []).length) {
      lines.push('<p class="note">' + escapeHtml(trn('installTwins',
        { n: rep.twins.length, hosts: rep.twins.join(' / ') })) + '</p>');
    }
    if ((rep.gates_failed || []).length) {
      lines.push('<p class="blocker">' + escapeHtml(trn('installGateFail',
        { gates: rep.gates_failed.join(' / ') })) + '</p>');
    }
  }
  return '<h3>' + escapeHtml(res.ok ? tr('installOkTitle') : tr('installWarnTitle')) + '</h3>'
    + '<div class="install-plan">' + lines.join('') + '</div>'
    + '<div class="install-act">'
    + '<button type="button" class="primary js-install-cancel">' + escapeHtml(tr('close')) + '</button></div>';
}

/* file:// 打开时浏览器不让 fetch 本机服务，所以这里退成命令。
   不直接静默写剪贴板：file:// 和 iframe 下 clipboard 权限时有时无，
   静默失败会让人以为复制成功了。命令原文摊在面上，复制不成也能手选。 */
function installCopyHtml(url) {
  return '<h3>' + escapeHtml(tr('installCopyTitle')) + '</h3>'
    + '<p class="lead">' + escapeHtml(tr('installCopyLead')) + '</p>'
    + '<div class="install-plan"><dd id="installCmd">'
    + escapeHtml(pickerCommand(url)) + '</dd></div>'
    + '<div class="install-act">'
    + '<button type="button" class="js-install-cancel">' + escapeHtml(tr('close')) + '</button>'
    + '<button type="button" class="primary js-install-copy">' + escapeHtml(tr('installCopyBtn'))
    + '</button></div>';
}

async function pickerCopy(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) { /* 往下走兜底 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  } catch (e) {
    return false;
  }
}

async function startInstall(btn) {
  const url = btn.dataset.url || '';
  if (!url) return;
  if (PICKER.mode === 'copy') {
    showInstallSheet(installCopyHtml(url));
    return;
  }
  btn.disabled = true;
  btn.textContent = tr('installPlanning');
  try {
    const plan = await pickerPost('/api/install/plan',
      { url: url, path: btn.dataset.path || '', host: PICKER.host });
    showInstallSheet(installPlanHtml(plan));
  } catch (e) {
    toast(String(e.message || e));
  } finally {
    btn.disabled = false;
    btn.textContent = tr('installHere');
  }
}

async function confirmInstall(btn) {
  btn.disabled = true;
  btn.textContent = tr('installWorking');
  try {
    const res = await pickerPost('/api/install/apply', { plan_id: btn.dataset.plan || '' });
    // 装完立刻要能看出「已装」，不能等下一次 scan 重写数据块
    const names = (res.local && res.local.names) || {};
    Object.keys(names).forEach(k => { LOCAL_FRESH[k] = names[k]; });
    showInstallSheet(installDoneHtml(res));
    render(false);
    toast(res.ok ? tr('installOkToast') : tr('installWarnTitle'));
  } catch (e) {
    toast(String(e.message || e));
    btn.disabled = false;
    btn.textContent = tr('installConfirm');
  }
}

document.addEventListener('click', e => {
  const go = e.target.closest('.js-install-go');
  if (go) { confirmInstall(go); return; }
  if (e.target.closest('.js-install-cancel')) { closeInstallSheet(); return; }
  const cp = e.target.closest('.js-install-copy');
  if (cp) {
    const el = document.getElementById('installCmd');
    pickerCopy(el ? el.textContent : '').then(ok => toast(tr(ok ? 'installCopied' : 'installCopyFail')));
    return;
  }
  const btn = e.target.closest('.js-install');
  if (btn) { startInstall(btn); return; }
});

document.getElementById('installSheet').addEventListener('click', e => {
  if (e.target.id === 'installSheet') closeInstallSheet();
});

pickerInit().then(() => { if (PICKER.mode !== 'off') render(false); });
"""


def build_feed_html(feed: dict, *, variant: str | None = None) -> str:
    """生成 Feed HTML。

    variant:
      - full：独立网页产品（动态圆环/关注/发布/我的）
      - lite：给 skill-picker 嵌入的发现子页（无关注/发布/个人后台，含「装到本机」）
    """
    variant = _resolve_variant(feed, variant)
    lite = variant == "lite"
    install_css = INSTALL_CSS if lite else ""
    install_sheet = INSTALL_SHEET_HTML if lite else ""
    install_js = INSTALL_JS if lite else ""
    # 卡片模板里的调用点也按变体决定：full 里连调用都不存在，而不是调了个空函数
    install_slot = "${installBtnHtml(it)}" if lite else ""
    install_row_cls = "${installBtnHtml(it) ? ' has-install' : ''}" if lite else ""
    feed = dict(feed)
    ui = dict(feed.get("ui") or {})
    ui["variant"] = variant
    feed["ui"] = ui
    payload = _json_for_script(feed)
    scenes = _json_for_script(feed.get("scenes") or scene.scene_chips())
    scenes_l2 = _json_for_script(feed.get("scenes_l2") or scene.scene_l2_tree())
    page_title = "去 GitHub 发现" if variant == "lite" else "SkillFeeder"
    preview_banner = ""
    if ui.get("preview"):
        shown = len(feed.get("items") or [])
        total = int((feed.get("meta") or {}).get("full_item_count") or shown)
        daily = int(ui.get("free_daily") or 8)
        preview_banner = (
            f'<div class="lite-banner" id="previewBanner" style="display:block">'
            f'<b>登录后每天可看 {daily} 条</b>，订阅会员不限'
            f'（全库 {total} 条不随静态站发布）。'
            f'完整精选请本机 <code>python skillfeed.py refresh</code> 或登录主站。'
            f'</div>'
        )
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  /* 色板与字体的取值依据、以及哪些值不许搬回来，写在本文件模块 docstring
     和 docs/brand-tokens.md，不写在这里：这段 CSS 会随页面发给每个访客。 */
  :root {{
    /* 外框海军蓝 + 栏内冰紫：logo 磁贴的底，也是「年轻黑客」的底盘。 */
    --chassis: #0c1020;
    --bg: #f4f7ff;
    --ink: #0a1848;
    /* #717171 是纯灰里在 #fff / #f4f7ff 上都过 AA 的最亮值（4.88 / 4.55）。
       旧的 #737373 在冰紫底上只有 4.42，换底必须重搜。 */
    --muted: #717171;
    --line: #cfd6ea;
    --card: #ffffff;

    /* logo S 尾部的薄荷青绿压深一档，才能当链接/导航文本（5.62 / 5.25）。
       亮薄荷 #64e2d4 只有 1.57，只许出现在字标渐变里，不能进正文。 */
    --accent: #0d7377;
    --accent-strong: #115e59;

    /* 字标 Feeder 专用：从 logo S 头到尾的紫→青→薄荷。只涂在 .feeder 上，
       头像环不准复用——跨色相扫掠 + 圆环是别人的识别结构。 */
    --brand-purple: #9860e7;
    --brand-cyan: #49aaeb;
    --brand-mint: #64e2d4;
    --brand-grad: linear-gradient(90deg, var(--brand-purple) 0%, var(--brand-cyan) 52%, var(--brand-mint) 100%);

    /* 头像环仍留在 accent 单一色族。最亮档 #10948c 对灰环 #e8e8e8 是 3.04。 */
    --ring: linear-gradient(135deg, var(--accent) 0%, #0e8a82 50%, #10948c 100%);

    /* --like 只做图标填充与背景：非文本元素 3:1 即可，实测 6.47 / 6.20。
       上一版是 #e0364f，玫红一路，离禁用值只有 20——过得了「不相等」，过不了
       「不相似」。这版挪到纯红 0° 并压深一档，色距 54，代价是心形比原来沉。
       想更亮就必须往洋红走，那条路上 40 以上的余量不存在，测过 209 个候选。 */
    --like: #b91c1c;
    /* 同一个红的 RGB 三元组，只为让 rgba() 能带 alpha 复用它。
       任何要带透明度的红都必须走这个令牌：手写十进制三元组曾经绕过品牌合规
       检查（那道门当时只比对 hex 字符串），详见 docs/brand-tokens.md。 */
    --like-rgb: 185, 28, 28;
    /* --like-ink 当文本用，同色相同饱和再压一档明度，8.31 / 7.96，色距 79。 */
    --like-ink: #991b1b;
    /* 链接复用 accent，不引入第二个「差不多但不一样」的绿。 */
    --link: var(--accent);

    --font: "Outfit", "PingFang SC", "Microsoft YaHei", sans-serif;
    --logo: "Outfit", "PingFang SC", sans-serif;
    --phone: 448px;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: var(--font); }}
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
    display: flex; flex-direction: column;
    padding: 10px 14px 8px;
    background: rgba(244,247,255,.92);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }}
  .top-row {{
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
  }}
  .top-left {{ display: flex; flex-direction: column; gap: 2px; min-width: 0; }}
  /* Skill 实心海军蓝；Feeder 才是 logo 那道紫→薄荷。clip 只挂在 .feeder 上，
     .logo 本身仍是实心字，安卓 WebView 把 clip 弄丢时至少 Skill 还在。 */
  .logo {{
    display: flex;
    align-items: center;
    gap: 7px;
    font-family: var(--logo);
    font-size: 1.45rem;
    font-weight: 800;
    line-height: 1.1;
    letter-spacing: -.03em;
    color: var(--ink);
  }}
  .logo-mark {{
    width: 30px;
    height: 30px;
    flex-shrink: 0;
    object-fit: contain;
    display: inline-block;
  }}
  .foot-logo .logo-mark {{ width: 22px; height: 22px; }}
  .logo .feeder {{
    color: var(--brand-purple);
    background-image: var(--brand-grad);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .top-actions {{ display: flex; gap: 14px; align-items: center; flex-shrink: 0; }}
  .icon-btn {{
    appearance: none; border: 0; background: transparent; padding: 0;
    cursor: pointer; color: var(--ink); display: none;
  }}
  body.show-demo-tools .icon-btn {{ display: inline-flex; }}
  .icon-btn svg {{ width: 24px; height: 24px; }}
  .refresh-btn {{
    appearance: none; border: 0; background: transparent; padding: 2px;
    cursor: pointer; color: var(--ink); display: inline-flex;
  }}
  .refresh-btn svg {{ width: 22px; height: 22px; }}
  .refresh-btn.spin svg {{ animation: refreshSpin .45s ease; }}
  @keyframes refreshSpin {{
    from {{ transform: rotate(0deg); }}
    to {{ transform: rotate(360deg); }}
  }}
  /* Demo 相关的红（这里 + .demo-badge + .demo-bar .dot）是故意的：
     它表达「正在运行」这个瞬时状态，和录制指示灯同一类语义，不是强调色。
     别把它们一起改成 --accent。 */
  .icon-btn.demo-on {{ color: var(--like); }}

  .lang-toggle {{
    display: inline-flex; align-items: center;
    border: 1px solid var(--line); border-radius: 999px;
    background: #fff; overflow: hidden; flex-shrink: 0;
  }}
  .lang-toggle button {{
    appearance: none; border: 0; background: transparent;
    font: inherit; font-size: .68rem; font-weight: 700;
    color: var(--muted); padding: 3px 9px; cursor: pointer;
    line-height: 1.6; letter-spacing: .02em;
  }}
  .lang-toggle button.on {{ background: var(--ink); color: #fff; }}
  .demo-badge {{
    display: none;
    font-size: .65rem; font-weight: 700; color: #fff;
    background: var(--like); border-radius: 999px; padding: 2px 7px;
    margin-left: -6px; margin-top: -12px;
  }}
  body.show-demo-tools .demo-badge {{ display: inline; }}

  .search-wrap {{ padding: 8px 0 0; background: transparent; }}
  .search {{
    width: 100%; border: 0; border-radius: 10px;
    background: #efefef; padding: 9px 12px;
    font: inherit; font-size: .9rem; color: var(--ink);
  }}
  .search::placeholder {{ color: var(--muted); }}
  /* 原来是 #c7c7c7，对 #efefef 底只有 1.47:1，等于没有焦点提示（SC 1.4.11 要 3:1） */
  .search:focus {{ outline: 2px solid var(--ink); outline-offset: 0; background: #fff; }}

  /* 全站唯一的焦点样式。卡片上的头像/作者名/行业徽标都是 <button>，没有这条
     规则键盘用户看不出焦点落在哪；:focus-visible 只在键盘/辅助技术下亮，
     鼠标点击不会留下焦点环，所以不影响触屏与鼠标手感。 */
  :focus-visible {{
    outline: 2px solid var(--ink);
    outline-offset: 2px;
    border-radius: 4px;
  }}
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
    30% {{ background: rgba(var(--like-rgb), .08); }}
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
    /* 未激活底色。不用 var(--line)：这个值要和 --ring 渐变拉开 3:1（环的着色
       是「有新内容」的唯一提示），#dbdbdb 只能到 2.69，提到 #e8e8e8 才是 3.04。
       代价是无新内容的环对白底只剩 1.23，但环里还有 face 撑存在感。 */
    border-radius: 50%; background: #e8e8e8;
  }}
  .story.hot .ring, .story.has-new .ring {{ background: var(--ring); }}
  /* 引导环（那个 "+"）本来就刻意比未激活环更淡 —— 它是提示不是内容。
     未激活环提到 #e8e8e8 之后要再让一档，否则两者的层级就压平了。 */
  .story.guide .ring {{ background: #f0f0f0; }}
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
  .post.leaving {{
    animation: postOut .2s ease forwards;
    pointer-events: none;
  }}
  @keyframes postOut {{
    to {{ opacity: 0; transform: translateX(-36px); }}
  }}
  .post.focus {{ box-shadow: inset 3px 0 0 var(--accent); }}

  .post-head {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px;
  }}
  /* 头像和作者行都是 <button>（键盘可达），这里把浏览器默认按钮外观清掉，
     视觉与改造前的 div 完全一致 */
  .avatar {{
    width: 36px; height: 36px; border-radius: 50%;
    padding: 2px; background: var(--ring); flex: 0 0 auto;
    appearance: none; border: 0; font: inherit; color: inherit; display: block;
  }}
  .avatar span {{
    display: grid; place-items: center; width: 100%; height: 100%;
    border-radius: 50%; background: #fff; font-weight: 700; font-size: .75rem;
  }}
  .avatar span b {{
    display: grid; place-items: center; width: 100%; height: 100%;
    border-radius: 50%; color: #fff; font-weight: 700;
  }}
  .who {{
    flex: 1; min-width: 0;
    appearance: none; border: 0; background: transparent; padding: 0;
    font: inherit; color: inherit; text-align: left; display: block;
  }}
  .who .name {{ display: block; font-weight: 700; font-size: .9rem; }}
  .who .sub {{ display: block; font-size: .72rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .more {{ border: 0; background: transparent; font-size: 1.2rem; cursor: pointer; color: var(--ink); }}

  /* Real cover (GitHub OG) + SKILL.md document preview
     2:1 把决策文案顶到折线下；16/7 仍是横幅，但首屏能看见「解决」 */
  .media {{
    position: relative;
    width: 100%;
    aspect-ratio: 16 / 7;
    overflow: hidden;
    cursor: pointer;
    user-select: none;
    background: var(--bg);
  }}
  .media .cover {{
    position: absolute; inset: 0;
    width: 100%; height: 100%;
    object-fit: cover; object-position: center;
    display: block;
    background: var(--bg);
  }}
  .media.no-cover .cover {{ display: none; }}
  .media .cover-fallback {{
    display: none; position: absolute; inset: 0;
    padding: 16px; color: var(--ink);
    background: linear-gradient(145deg, #e8eefc, var(--bg));
  }}
  .media.no-cover .cover-fallback {{ display: flex; flex-direction: column; justify-content: flex-end; gap: 6px; }}
  /* 兜底层的字被去重清掉后，别留一个 2:1 的空黑盒，缩成只放徽标的窄条 */
  .media.no-cover.bare {{ aspect-ratio: auto; min-height: 46px; }}
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
  /* 场景徽章的底色由 JS 按 scene 内联；这里只去掉共用的半透明黑与描边，
     免得实心场景色被压在 rgba(0,0,0,.45) 底下看不出区别 */
  .media .badge.scene {{ background: none; border-color: transparent; }}
  .media .badge.kb {{ background: rgba(var(--like-rgb), .85); border-color: transparent; }}
  .media .badge.soft {{ background: rgba(255,193,7,.92); color: #262626; border-color: transparent; }}
  /* 「本机已有同名」只在 skill-picker 注入了本机索引时出现，公开站上不存在。
     用中性深色而不是绿色：它是一条装前提醒，不是「已装好」的成功态。 */
  .media .badge.local {{ background: rgba(17,17,17,.82); border-color: rgba(255,255,255,.3); cursor: help; }}
  .media .badge.local.drift {{ background: rgba(var(--like-rgb), .9); border-color: transparent; }}
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
    color: var(--accent); font-size: .75rem;   /* 在 #f6f8fa 上 5.15:1 */
  }}
  .pitch .who-for {{
    margin: 8px 0 0; font-size: .76rem; color: var(--muted); line-height: 1.4;
  }}
  .pitch .who-for em {{
    font-style: normal; font-weight: 700; color: #24292f; margin-right: 5px;
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
  .media .badge.clickable {{
    cursor: pointer; text-decoration: underline; text-underline-offset: 2px;
    appearance: none; font: inherit; font-size: .66rem; font-weight: 700; line-height: 1.35;
  }}
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
  .sheet-row .act-label {{ font-size: .72rem; font-weight: 700; color: var(--accent); white-space: nowrap; }}
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
{install_css}
  .sentinel {{ text-align: center; padding: 22px 12px; color: var(--muted); font-size: .8rem; }}
  .empty {{ text-align: center; padding: 64px 20px; color: var(--muted); }}
  .empty h2 {{ color: var(--ink); font-size: 1.1rem; }}
  .empty p {{ font-size: .85rem; line-height: 1.5; }}
  .feide-wrap {{ display: flex; justify-content: center; margin-bottom: 20px; }}
  .feide {{ width: 120px; height: 120px; animation: feideRoll 3s ease-in-out infinite; }}
  @keyframes feideRoll {{
    0%, 100% {{ transform: translateX(-15px) rotate(-8deg) translateY(0); }}
    25% {{ transform: translateX(0) rotate(0deg) translateY(-6px); }}
    50% {{ transform: translateX(15px) rotate(8deg) translateY(0); }}
    75% {{ transform: translateX(0) rotate(0deg) translateY(-6px); }}
  }}

  .bottom {{
    position: relative;
    display: flex; justify-content: space-around; align-items: center;
    padding: 10px 4px calc(10px + env(safe-area-inset-bottom));
    background: transparent;
    border-top: 0;
  }}
  .dock {{
    position: sticky; bottom: 0; z-index: 40;
    background: rgba(255,255,255,.96);
    backdrop-filter: blur(10px);
    border-top: 1px solid var(--line);
  }}
  .site-foot {{
    display: flex; justify-content: center;
    padding: 8px 12px 0;
  }}
  .foot-logo {{ font-size: 1.05rem; }}
  .nav {{
    border: 0; background: transparent; color: var(--ink); cursor: pointer;
    display: grid; place-items: center; gap: 2px; font-size: .58rem; font-weight: 600;
    min-width: 52px;
  }}
  .nav svg {{ width: 24px; height: 24px; }}
  /* 底部导航激活态走品牌色。红色只留给「已赞」这一个语义，
     否则页面上会同时存在绿和红两个强调色，谁是品牌就说不清了。 */
  .nav.on {{ color: var(--accent); }}
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

  /* —— 底部 tab（发现 / 主题分类 / 发布 / 我的） ——
     激活态原来只有一个颜色提示。WCAG 1.4.1 要求颜色不是唯一的视觉载体，所以再加
     一条顶端指示条和一档字重：位置与形状的变化在灰度和色觉障碍下同样读得出来。
     语义那一侧由 role=tab + aria-selected 承担，不靠这两条视觉提示。 */
  .nav {{ position: relative; }}
  .nav::before {{
    content: ""; position: absolute; top: -10px; left: 50%; transform: translateX(-50%);
    width: 22px; height: 3px; border-radius: 0 0 3px 3px;
    background: var(--accent); opacity: 0;
  }}
  .nav.on::before {{ opacity: 1; }}
  .nav.on .nav-label {{ font-weight: 800; }}

  /* —— 回到顶部 ——
     滚动容器是文档本身（.shell 只是限宽，没有自己的滚动条），所以监听 window、
     滚 window。横向位置贴住手机壳右缘：窄屏退回 14px，宽屏跟着壳走。 */
  .to-top {{
    position: fixed; z-index: 55;
    bottom: calc(108px + env(safe-area-inset-bottom));
    right: max(14px, calc(50% - (var(--phone) / 2) + 14px));
    width: 42px; height: 42px; border-radius: 50%;
    display: grid; place-items: center;
    appearance: none; border: 1px solid var(--line); background: #fff; color: var(--ink);
    cursor: pointer; box-shadow: 0 6px 18px rgba(0,0,0,.14);
  }}
  /* .to-top 自带 display:grid，会盖掉浏览器给 [hidden] 的 display:none */
  .to-top[hidden] {{ display: none; }}
  .to-top svg {{ width: 20px; height: 20px; }}

  /* —— 主题分类 —— */
  .topics-panel {{ padding: 14px 12px 28px; }}
  .topics-panel h2 {{ margin: 0 0 4px; font-size: 1.15rem; }}
  .topics-panel .lead {{ margin: 0 0 14px; font-size: .82rem; color: var(--muted); line-height: 1.45; }}
  .topics-panel .sec {{
    font-size: .72rem; font-weight: 700; color: var(--muted); letter-spacing: .04em;
    text-transform: uppercase; margin: 18px 0 8px;
  }}
  .topic-card {{
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 0 0 10px; margin-bottom: 10px;
  }}
  .topic-head {{
    appearance: none; width: 100%; border: 0; background: transparent; font: inherit;
    color: inherit; text-align: left; cursor: pointer;
    display: flex; align-items: center; gap: 10px; padding: 12px 12px 8px;
  }}
  /* 分类色只是同一分类在卡片徽章上那套色的复述，不承载任何独有信息：
     条目数和二级场景都写成文字了 */
  .topic-head .dot {{ width: 10px; height: 34px; border-radius: 4px; flex: 0 0 auto; }}
  .topic-head .meta {{ flex: 1; min-width: 0; }}
  .topic-head .meta b {{ display: block; font-size: .95rem; }}
  .topic-head .meta span {{ font-size: .72rem; color: var(--muted); }}
  .topic-head .go {{ font-size: .72rem; font-weight: 700; color: var(--accent); white-space: nowrap; }}
  .topic-l2 {{ display: flex; flex-wrap: wrap; gap: 6px; padding: 0 12px; }}
  .topic-none {{ font-size: .78rem; color: var(--muted); padding: 0 12px; margin: 0; }}

  /* —— 发布 / 我的（复用 .me-panel / .me-card / .me-actions 的壳） —— */
  .pub-form label {{
    display: block; font-size: .74rem; font-weight: 700; color: var(--muted); margin: 10px 0 4px;
  }}
  .pub-form input, .pub-form textarea {{
    width: 100%; border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px;
    font: inherit; font-size: .85rem; background: #fff; color: var(--ink);
  }}
  .pub-form textarea {{ min-height: 140px; font-size: .8rem; line-height: 1.5; }}
  .pub-form .hint {{ font-size: .72rem; color: var(--muted); margin: 4px 0 0; line-height: 1.45; }}
  .pub-msg {{ margin: 10px 0 0; font-size: .8rem; line-height: 1.45; }}
  .pub-msg.err {{ color: var(--like-ink); font-weight: 600; }}
  .pub-msg.ok {{ color: var(--accent); font-weight: 600; }}
  .acct-id {{ display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }}
  .acct-id .ava {{
    width: 44px; height: 44px; border-radius: 50%; flex: 0 0 auto;
    display: grid; place-items: center; font-weight: 700; font-size: .85rem;
  }}
  .acct-id .meta {{ min-width: 0; }}
  .acct-id .meta b {{ display: block; font-size: 1rem; }}
  .acct-id .meta span {{ font-size: .75rem; color: var(--muted); }}

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
    background: rgba(10,24,72,.92); color: #fff;
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
  /* 全屏 story 背景的兜底。JS 随后会用 sceneGradient() 覆盖，但兜底本身也得合规：
     这里原来是紫→洋红→橙的三段暖色扫掠，逐段 hex 都不是精确匹配所以躲过了禁用
     清单，可「竖屏全屏 story + 暖色洋红扫掠背景」正是要避开的那个整体印象。
     换成 accent 单一色族，和 --ring 同一条纪律。深度是按白字 + ::after 的暗压
     选的，不是随手取的。 */
  .sv-slide {{
    position: absolute; inset: 0;
    background: linear-gradient(160deg, var(--accent-strong) 0%, var(--accent) 55%, #05865c 100%);
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
  /* 动态全屏的翻页热区是 <button>：原来是带 aria-label 的 div，读屏会播报「上一条」
     却无法聚焦触发，等于告诉用户有这个控件又不给用 */
  .sv-tap-left, .sv-tap-right {{
    position: absolute; top: 60px; bottom: 80px; width: 28%; z-index: 1;
    appearance: none; border: 0; background: transparent; padding: 0;
    font: inherit; color: inherit; cursor: pointer;
  }}
  .sv-tap-left {{ left: 0; }}
  .sv-tap-right {{ right: 0; }}

  /* lite：skill-picker 发现子页 — 无动态圆环/关注/发布/我的
     「主题分类」留着：它是浏览辅助而不是社交/后台能力，而本机没有合适 skill 时
     按分类逛远程线索恰恰是这张子页存在的理由。 */
  body.variant-lite .stories-wrap,
  body.variant-lite #followSheet,
  body.variant-lite .nav[data-mode="publish"],
  body.variant-lite .nav[data-mode="me"],
  body.variant-lite .follow-mini,
  body.variant-lite #btnDemo {{ display: none !important; }}
  body.variant-lite .bottom {{ justify-content: space-evenly; }}
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
      <div class="top-row">
        <div class="top-left">
          <div class="logo">
            <img class="logo-mark" src="data:image/png;base64,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" alt="" />
            Skill<span class="feeder">Feeder</span>
          </div>
        </div>
        <div class="top-actions">
          <div class="lang-toggle" id="langToggle" role="group" aria-label="语言 / Language" data-i18n-aria="langGroup">
            <!-- 语言名一律用本语言书写（中文 / EN），这里的中文不跟随语言开关 -->
            <button type="button" data-lang="zh" class="on">中文</button>
            <button type="button" data-lang="en">EN</button>
          </div>
          <button class="refresh-btn" id="btnRefresh" type="button" title="换一批" data-i18n-title="refreshTitle" aria-label="换一批" data-i18n-aria="refreshAria">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.6-6.3"/><path d="M21 4v5h-5"/></svg>
          </button>
          <button class="icon-btn" id="btnDemo" type="button" title="自动 Demo" data-i18n-title="demoTitle" aria-label="播放自动 Demo" data-i18n-aria="demoAria">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="6,4 20,12 6,20"/></svg>
          </button>
          <span class="demo-badge" id="demoBadge" hidden>DEMO</span>
          <button class="icon-btn" id="btnHeart" type="button" title="反馈说明" data-i18n-title="feedbackTitle" aria-label="反馈说明" data-i18n-aria="feedbackAria">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>
          </button>
        </div>
      </div>
      <div class="search-wrap" id="searchWrap">
        <input class="search" id="intent" type="search" placeholder="短关键词更好，如：去AI味 / 周报 / 剪视频" maxlength="40" />
        <div class="intent-keys" id="intentKeys" hidden></div>
      </div>
    </header>
    <div class="lite-banner" id="liteBanner" data-i18n-html="liteBanner">
      <b>本机没有合适 skill 时</b>，在这里按意图浏览远程线索，点「打开 GitHub」自行安装；装好后回 skill-picker 再扫一遍。
    </div>
    {preview_banner}

    <div class="stories-wrap" id="storiesWrap">
      <div class="stories-hint" id="storiesHint">
        <span data-i18n-html="storiesHint"><b>顶部圆环 = 你关注的最新动态</b>：关注 Builder 或行业后，新内容会出现在这里优先观看。</span>
        <button type="button" class="hint-close" id="storiesHintClose" aria-label="关闭提示" data-i18n-aria="closeHint">×</button>
      </div>
      <div class="stories" id="stories" aria-label="关注动态圆环" data-i18n-aria="storiesAria"></div>
    </div>
    <div class="sr-only" id="sceneLabel" data-i18n="sceneSr">一级场景</div>
    <div class="sr-only" id="sceneL2Label" data-i18n="sceneL2Sr">二级场景</div>
    <div class="filter-strip" id="sceneStrip" aria-label="行业筛选" data-i18n-aria="sceneStripAria"></div>
    <div class="filter-strip" id="l2Strip" aria-label="二级场景" data-i18n-aria="sceneL2Sr"></div>
    <div class="filter-strip" id="sectionStrip" aria-label="栏目" data-i18n-aria="sectionStripAria"></div>

    <!-- 一个 tabpanel 配四个 tab：aria-labelledby 跟着激活的 tab 走（renderTabs）。
         切 tab 换的是同一块内容区，做四个常驻 panel 只会多出三块空 DOM。 -->
    <main class="feed" id="feed" role="tabpanel" aria-labelledby="tab-all"></main>

    <!-- 试用期只对外信息流：发现 + 主题分类 + 本机「我的」（赞藏/关注）。
         发布入口整颗拿掉——后端 /publish 还在，但公开页不能点到一个交不出去的表单。
         底部 tab 而不是顶部分段：顶部已经被 header + 圆环 + 搜索占满。 -->
    <div class="dock">
    <footer class="site-foot">
      <div class="logo foot-logo">
            <img class="logo-mark" src="data:image/png;base64,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" alt="" />
        Skill<span class="feeder">Feeder</span>
      </div>
    </footer>
    <nav class="bottom" id="tabBar" role="tablist" aria-label="主导航" data-i18n-aria="tabsAria">
      <button class="nav on" type="button" data-mode="all" role="tab" id="tab-all" aria-selected="true" aria-controls="feed">
        <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
        <span class="nav-label" data-i18n="navDiscover">发现</span>
      </button>
      <button class="nav" type="button" data-mode="topics" role="tab" id="tab-topics" aria-selected="false" aria-controls="feed" tabindex="-1">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        <span class="nav-label" data-i18n="navTopics">主题分类</span>
      </button>
      <button class="nav" type="button" data-mode="me" role="tab" id="tab-me" aria-selected="false" aria-controls="feed" tabindex="-1">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"/></svg>
        <span class="nav-label" data-i18n="navMe">我的</span>
      </button>
    </nav>
    </div>
  </div>

  <button class="to-top" id="toTop" type="button" hidden aria-label="回到顶部" data-i18n-aria="backToTop">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 19V6"/><path d="M6 12l6-6 6 6"/></svg>
  </button>

  <div class="story-viewer" id="storyViewer" aria-hidden="true">
    <div class="sv-progress" id="svProgress"></div>
    <div class="sv-head">
      <!-- 打开时由 openStoryViewer 写入，静态占位留空免得漏中文 -->
      <div class="who" id="svWho"></div>
      <button type="button" class="sv-close" id="svClose" aria-label="关闭" data-i18n-aria="close">&times;</button>
    </div>
    <div class="sv-body" id="svBody">
      <button type="button" class="sv-tap-left" id="svPrev" aria-label="上一条" data-i18n-aria="prevStory"></button>
      <button type="button" class="sv-tap-right" id="svNext" aria-label="下一条" data-i18n-aria="nextStory"></button>
      <div class="sv-slide" id="svSlide"></div>
      <div class="sv-stage">
        <div class="sv-cover-wrap" id="svCoverWrap">
          <img class="sv-cover" id="svCover" alt="" loading="lazy" referrerpolicy="no-referrer" />
        </div>
        <div class="sv-content" id="svContent"></div>
      </div>
    </div>
    <div class="sv-foot">
      <a class="sv-cta" id="svCta" href="#" target="_blank" rel="noopener" data-i18n="openGithub">打开 GitHub</a>
    </div>
  </div>

  <div class="demo-bar" id="demoBar">
    <span class="dot"></span>
    <span id="demoText" data-i18n="demoIdle">Demo 巡演中</span>
    <button type="button" id="demoStop" data-i18n="demoStopBtn">停止</button>
  </div>
  <div class="toast" id="toast"></div>
  <div class="sheet" id="followSheet" aria-hidden="true">
    <div class="sheet-panel" id="followSheetPanel"></div>
  </div>
{install_sheet}
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
/* 「我的」的服务端侧状态。loaded 分「没拉过」和「拉过但是空的」，
   否则每次 render 都会再打一轮请求。 */
const ACCT = {{ loading: false, loaded: false, user: null, posts: null, liked: 0, saved: 0, remote: false, quota: null, devAuth: false }};
/* 登录页路径。另一个 agent 正在给 server/ 加强制登录墙（认证服务号 + 短信兜底），
   落地后页面路径可能不是 /login；这里留成一个常量，改一行就能对齐。 */
const LOGIN_PATH = '/login';
/* 底部 tab ↔ URL 的映射。tab= 存稳定英文标识，不用展示文案（切语言会失效）。 */
const TAB_QUERY = {{ all: 'discover', topics: 'topics', publish: 'publish', me: 'me' }};

/* ---------- 本机已装索引（可选，由 skill-picker 注入） ---------- */
/* skill-picker 的 discover.py 把本页拷成 ~/.skill-picker/discover.html 时，会在 head
   末尾塞一个 id=skillpicker-local、type=application/json 的数据块。
   用数据块而不是可执行脚本，是因为本页 CSP 的 script-src 只认内联块哈希——新塞一段
   可执行脚本会被直接拦掉（实测拦住了），而 JSON 数据块不走执行路径。
   公开站上这个块不存在，整套标记静默关闭。
   （这段注释刻意不写出那个标签的字面量：页面内联块里出现该序列会破坏
     「全页只有一个 script 标签」这条不变量，tests 里有专门一条在盯。） */
const LOCAL_SKILLS = (function () {{
  try {{
    const el = document.getElementById('skillpicker-local');
    if (!el) return null;
    const data = JSON.parse(el.textContent || 'null');
    const names = data && data.names;
    if (!names || typeof names !== 'object') return null;
    return names;
  }} catch (e) {{
    return null;
  }}
}})();

/* 本机 catalog 里没有任何 GitHub 坐标（只有本机绝对路径和目录名），所以唯一能和
   feed 条目对上的键就是 skill 名。实测 483 个 feed 名对上本机 278 个名里的 50~62 个，
   其中 4 个名字在 feed 里对应多个仓库——所以文案只能说「同名」，不能说「你装的就是这个」。 */
function localSkillKeys(it) {{
  const keys = [];
  const nm = (it.name || '').trim().toLowerCase();
  if (nm) keys.push(nm);
  const sp = (it.skill_path || '').replace(/^\\/+/, '');
  if (sp) {{
    const parts = sp.split('/').filter(Boolean);
    if (parts.length && /\\.md$/i.test(parts[parts.length - 1])) parts.pop();
    if (parts.length) {{
      const dir = parts[parts.length - 1].toLowerCase();
      if (dir && keys.indexOf(dir) < 0) keys.push(dir);
    }}
  }}
  return keys;
}}

/* 刚装完的 skill 要立刻显示「已装」，而数据块是 scan 时烤进 HTML 的、这辈子不会自己更新。
   所以安装成功后把本机索引的增量写这里，查的时候先看它。公开站上它永远是空的。 */
const LOCAL_FRESH = {{}};

function localHit(it) {{
  const keys = localSkillKeys(it);
  for (let i = 0; i < keys.length; i++) {{
    const src = Object.prototype.hasOwnProperty.call(LOCAL_FRESH, keys[i])
      ? LOCAL_FRESH
      : (LOCAL_SKILLS && Object.prototype.hasOwnProperty.call(LOCAL_SKILLS, keys[i]) ? LOCAL_SKILLS : null);
    if (src) {{
      const hit = src[keys[i]];
      if (hit) return {{ key: keys[i], copies: Number(hit.copies) || 1, hosts: hit.hosts || [], drifted: !!hit.drifted }};
    }}
  }}
  return null;
}}

function localBadgeHtml(it) {{
  const hit = localHit(it);
  if (!hit) return '';
  const hosts = hit.hosts.length ? hit.hosts.join(' / ') : '—';
  const label = hit.drifted
    ? trn('localDrift', {{ n: hit.copies }})
    : (hit.copies > 1 ? trn('localMany', {{ n: hit.copies }}) : tr('localOne'));
  const tip = hit.drifted
    ? trn('localTipDrift', {{ hosts: hosts, name: hit.key }})
    : trn('localTip', {{ hosts: hosts, name: hit.key }});
  const cls = hit.drifted ? 'badge local drift' : 'badge local';
  return `<span class="${{cls}}" title="${{escapeHtml(tip)}}">${{escapeHtml(label)}}</span>`;
}}

/* ---------- 语言：默认中文，localStorage 记住，切换不发请求 ---------- */
/* 所有面向用户的文案都必须走这张表。JS 里留中文字面量 = EN 模式下漏中文，
   而且一旦被拿去做相等判断（title === '发现行业'），切语言后分支会静默失效。
   例外只有两类：I18N 表本身，和 HelloGitHub 栏目名那种「中文就是数据值」的场景。 */
const I18N = {{
  zh: {{
    updated: '更新', solves: '解决', forWho: '适合',
    openGithub: '打开 GitHub', openGithubHome: '打开 GitHub 主页',
    readSkillMd: '在 GitHub 看 SKILL.md 全文 →',
    fallbackHl: '打开 GitHub 查看完整 SKILL.md 与用法',
    kb: '知识库', lead: '线索', leadLong: '知识库线索', because: '因为',
    localOne: '本机已有同名', localMany: '本机 {{n}} 份同名',
    localDrift: '本机 {{n}} 份不一致',
    localTip: '本机 {{hosts}} 有同名 skill「{{name}}」。同名不等于同一个仓库，装前先比一比。',
    localTipDrift: '本机 {{hosts}} 各有一份「{{name}}」，内容已不一致。先去看板「理技能」处理漂移，再决定要不要动。',
    softTime: 'Soft skill · 打开 GitHub 查看',
    corpusTime: '来自知识库', suggestTime: '为你推荐',
    follow: '关注', following: '已关注',
    followTitle: '关注后最新动态出现在顶部动态圆环',
    viewPublisher: '查看发布者',
    filterByScene: '按行业筛选',
    followScene: '关注行业 · 最新进顶部圆环',
    searchPlaceholder: '短关键词更好，如：去AI味 / 周报 / 剪视频',
    navDiscover: '发现', navTopics: '主题分类', navPublish: '发布', navMe: '我的',
    tabsAria: '主导航', backToTop: '回到顶部',

    /* 主题分类 */
    topicsTitle: '主题分类', topicsSecSection: '按栏目浏览',
    topicsLead: '一级场景各自成块。点标题只看这一类，点二级场景直接落到更窄的一层。',
    topicsCount: '{{n}} 条 · {{k}} 个二级场景',
    topicsCountNoL2: '{{n}} 条',
    topicsBrowse: '只看这类 →',
    topicsNoL2: '这一类当前没有细分到二级场景。',
    topicsEmpty: 'Feed 里暂时没有任何分类条目，先 refresh 一次。',

    /* 发布 */
    publishTitle: '发布 Skill',
    publishLead: '把自己的 skill 交给这条 Feed：粘 <strong>SKILL.md</strong> 正文，或者给一个公开 GitHub 仓库地址。发布后进混排 Feed，<strong>不代装到任何人的机器</strong>。',
    publishFieldTitle: '标题（留空则从 SKILL.md 解析）',
    publishFieldUrl: 'GitHub 仓库地址（推荐）',
    publishFieldDesc: '一句话简介',
    publishFieldBody: 'SKILL.md 正文',
    publishHint: '正文和仓库地址至少给一个；简介要写清这个 skill 做什么（约 10 字以上）。',
    publishSubmit: '发布到 Feed', publishSubmitting: '提交中…',
    publishOkMsg: '已发布，去「我的」看它的状态。',
    publishNeedLogin: '发布要先登录。登录主体是认证服务号，手机号短信兜底。',
    publishLoginBtn: '去登录',
    publishOpenPage: '打开完整发布页',
    publishNoBackendTitle: '这份是静态镜像',
    publishNoBackend: '当前页面没有接云端 API，所以这里不放一个点了没反应的提交按钮。要发布请到接了后端的主站；本机看板里这个 tab 本来就不出现。',
    publishRemoteTitle: '发布页在主站上',
    publishRemote: '这份页面和 API 不同源，会话 Cookie 是 SameSite=Lax，不会跟着页面内的请求发出去。所以这里改成整页打开主站发布页——那边是同源，登录态正常。',
    publishFailed: '提交失败，请稍后再试。',

    /* 我的 */
    acctTitle: '我的',
    acctChecking: '正在确认登录状态…',
    acctSignedIn: '已登录',
    acctLogout: '退出登录',
    acctLoggedOut: '已退出登录',
    acctAnonTitle: '还没登录',
    acctAnon: '登录后，你发布的 skill 和赞/藏会记在账号上、换设备也在。没登录时下面这些只存在这个浏览器里。',
    acctLocalTitle: '未接云端',
    acctLocalOnly: '当前页面没有接云端 API，所以「我的」只能显示这个浏览器里的本机态：赞、藏、关注。',
    acctRemoteNote: '这份页面和 API 不同源，跨站请求带不上会话 Cookie，所以这里读不到你的账号。整页打开主站即可。',
    acctOpenSite: '打开主站',
    acctMyPosts: '我发布的',
    acctPostsLoading: '正在读取…',
    acctNoPosts: '还没发布过。去「发布」tab 交第一个。',
    acctPostsNeedLogin: '登录后这里显示你发布过的 skill 及其状态。',
    acctServerCounts: '云端记录：点赞 {{liked}} · 收藏 {{saved}}',
    acctLocalCounts: '本机记录：点赞 {{liked}} · 书签 {{saved}}',
    acctReactionsPending: '云端赞藏要等埋点链路接上才会有数，当前以本机记录为准。',
    quotaTitle: '发现额度',
    quotaSubscriber: '订阅会员 · 今日不限条数',
    quotaFreeToday: '今日还可看 {{n}} / {{limit}} 条',
    quotaSubscribeHint: '订阅后无限解锁',
    quotaCodePh: '激活码',
    quotaActivate: '解锁订阅',
    quotaActivateOk: '已解锁订阅',
    quotaActivateBad: '激活码无效',
    payDevBtn: '测试下单并开通',
    payDevOk: '测试订单已开通订阅',
    payDevFail: '测试开通失败',

    liteBanner: '<b>本机没有合适 skill 时</b>，在这里按意图浏览远程线索，点「打开 GitHub」自行安装；装好后回 skill-picker 再扫一遍。',
    storiesHint: '<b>顶部圆环 = 你关注的最新动态</b>：关注 Builder 或行业后，新内容会出现在这里优先观看。',
    demoTitle: '自动 Demo', feedbackTitle: '反馈说明',
    notUseful: '不感兴趣 · 不再推荐这条',
    notUsefulToast: '已隐藏，以后不再推荐这条',
    allScenes: '全部行业', allSub: '全部二级', allSections: '全部栏目',
    srcCatalog: '策展目录', srcXhs: '小红书', srcCorpus: '知识库',
    hostSite: ' · 网站',
    feedbackToast: '关注后最新进顶部动态圆环 · 双击点赞 · 书签收藏',
    addBuilder: '+ Builder', addIndustry: '+ 行业', closeHint: '关闭提示',
    storyGuide: '去关注，最新动态会出现在这里',
    storyView: '查看关注的最新动态',
    machineNote: '译自英文原文',

    /* 静态骨架：标题、无障碍标签、全屏卡按钮 */
    pageTitleLite: '去 GitHub 发现',
    langGroup: '语言 / Language',
    storiesAria: '关注动态圆环',
    sceneSr: '一级场景', sceneL2Sr: '二级场景',
    sceneStripAria: '行业筛选', sectionStripAria: '栏目',
    close: '关闭', prevStory: '上一条', nextStory: '下一条',
    /* 卡片操作按钮的读屏文案。原来硬编码成 like / not useful / save，
       中文用户听到的是英文；这里跟着语言开关走 */
    likeAria: '点赞', likedAria: '取消点赞',
    badAria: '不感兴趣', saveAria: '收藏', savedAria: '取消收藏',
    demoAria: '播放自动 Demo', feedbackAria: '反馈说明',
    refreshAria: '换一批', refreshTitle: '换一批',
    reshuffleToast: '已换一批',

    /* 关注面板（发现 Builder / 发现行业 / 单个行业） */
    sheetBuilderTitle: '发现 Builder',
    sheetBuilderLead: '关注后，Ta 的最新 skill 会出现在<strong>顶部动态圆环</strong>，方便优先观看。',
    sheetIndustryTitle: '发现行业',
    sheetIndustryLead: '关注行业后，该领域最新内容会出现在<strong>顶部动态圆环</strong>。',
    feedCount: 'Feed 内 {{n}} 条',
    followedTapUndo: '已关注 · 点按取消',
    industryLead: '关注后，该行业最新动态会出现在<strong>顶部动态圆环</strong>；也可只筛选发现流。',
    unfollowIndustry: '取消关注行业', followIndustry: '关注行业',
    industryRingOff: '圆环将不再优先展示该行业',
    industryRingOn: '最新内容进顶部圆环',
    onlyThisIndustry: '只看该行业 Feed',
    onlyThisIndustryHint: '用下方 pills 筛选发现流',
    filterAction: '筛选',
    ringFollowing: '关注',

    /* toast */
    followedToast: '已关注 {{who}} · 最新动态会出现在顶部动态圆环',
    unfollowedBuilder: '已取消关注 @{{who}}',
    unfollowedIndustry: '已取消关注「{{who}}」',
    publishLiteOnly: '发现子页不支持发布 · 请打开完整 skill-feed 网站',
    publishNeedApi: '请先启动 API：python skillfeed.py api（或配置 ui.api_base）',
    intentToast: '已提炼短关键词：{{q}}',
    feedbackLogged: '已记录 · {{action}}',
    feedbackFailed: '反馈失败',
    feedbackServeOnly: 'serve 模式下可写 feedback.jsonl',
    storyGuideToast: '先去关注一位 Builder 或一个行业',
    storyEmptyToast: '暂无最新动态 · 试试换个关注或 refresh',

    /* 意图关键词条 */
    intentDistilled: '已提炼', intentKeywords: '关键词',
    intentShortHint: '· 用短词结果更准',

    /* 发布者主页 */
    pubNoOtherSkills: '信息流里暂无 Ta 的其他 skill 卡。',
    pubLoadingRepos: '正在拉取 GitHub 仓库…',
    pubNoRepos: '暂无更多公开仓库，或 GitHub API 限流。',
    noDescription: '暂无描述',
    inFeed: 'Feed 内',
    pubSub: '发布者主页 · Feed 内 {{n}} 条 · GitHub 整合',
    pubFollowNote: '关注后，最新动态会出现在<strong>顶部动态圆环</strong>',
    followBuilder: '关注 Builder',
    backToFeed: '← 返回发现',
    allRepos: '全部仓库',
    pubSecFeed: '在 skill-feed 中',
    pubSecGithub: 'GitHub 上的其他内容',

    /* 空状态 */
    emptySavedTitle: '还没有收藏',
    emptySavedBody: '双击帖子点赞，或点书签收藏。可在「我的」里查看。',
    emptyTitle: '没有匹配帖子',
    emptyWithIntent: '关键词：<b>{{q}}</b> — Feed 内暂无匹配，可到 GitHub 继续搜。',
    emptyNoIntent: 'Feed 内暂无结果。试短关键词（如「去AI味」），或直接去 GitHub 搜 SKILL.md。',
    ghSearchCode: '在 GitHub 搜 SKILL.md（代码）',
    ghSearchRepos: '在 GitHub 搜仓库',
    noInstallNote: '不代装：在 GitHub 选中仓库后自行安装，再回 skill-picker 跑 scan。',
    funnel: '漏斗：', funnelPassed: '过门禁',

    /* 我的 */
    unfollowAria: '取消关注',
    meNoBuilders: '还没关注 Builder。在卡片点「关注」，最新动态会出现在顶部动态圆环。',
    meNoIndustries: '还没关注行业。点卡片上的场景标签即可关注。',
    meLead: '关注的 Builder / 行业，其<strong>最新内容会出现在发现页顶部动态圆环</strong>。赞/藏仍保存在此浏览器。',
    meMyBuilders: '我关注的 Builder',
    meMyIndustries: '我关注的行业',
    meLocalTitle: '本机收藏',
    meCounts: '点赞 {{liked}} · 书签 {{saved}}',
    meViewSaved: '查看收藏',
    mePublishTitle: '发布与后台',
    meApiPrefix: 'API：',
    meNoApi: '尚未配置云端 API（ui.api_base / skillfeed.py api）',
    meGoPublish: '去发布 Skill',
    meApiDocs: 'API 文档', meApiHome: 'API 首页', meGithubLogin: 'GitHub 登录',
    meAboutTitle: '发现站',
    meAboutBody: '动态圆环 = 关注动态；行业与栏目筛选搬到「主题分类」tab，只在真的筛着时才回到发现页顶部。',

    /* 列表尾 */
    moreShown: '下滑加载更多 · 已显 <b>{{n}}</b> / {{total}}',
    allDone: '你已看完 · 共 <b>{{total}}</b> 条（含知识库 backup）',

    /* 动态全屏卡 */
    storyFollowing: '关注动态',
    storyWhoSuffix: ' · 关注最新',

    /* Demo 巡演 */
    demoStopBtn: '停止',
    demoIdle: 'Demo 巡演中',
    demoStarting: 'Demo 巡演开始',
    demoStopped: 'Demo 已停止',
    demoFollowIndustry: 'Demo：关注行业 → 顶部动态圆环',
    demoFollowToast: '关注后最新动态出现在顶部圆环',
    demoOpenStories: 'Demo：点动态圆环看关注最新',
    demoPills: 'Demo：pills 筛选行业（非动态圆环）',
    demoSearch: 'Demo：意图搜索「{{q}}」',
    demoLike: 'Demo：双击点赞 · {{name}}',
    demoSave: 'Demo：收藏书签',
    demoMe: 'Demo：打开「我的」',
    demoLoop: 'Demo 循环 · 回发现',
  }},
  en: {{
    updated: 'Updated', solves: 'Solves', forWho: 'For',
    openGithub: 'Open on GitHub', openGithubHome: 'Open GitHub profile',
    readSkillMd: 'Read the full SKILL.md on GitHub →',
    fallbackHl: 'Open GitHub for the full SKILL.md and usage',
    kb: 'Library', lead: 'Lead', leadLong: 'Library lead', because: 'Because',
    localOne: 'Same name here', localMany: '{{n}} copies here',
    localDrift: '{{n}} copies differ',
    localTip: 'A skill named "{{name}}" already exists on this machine under {{hosts}}. Same name is not the same repo — compare before installing.',
    localTipDrift: '{{hosts}} each hold a copy of "{{name}}" and they have diverged. Sort the drift out in the dashboard first.',
    softTime: 'Soft skill · open GitHub to check',
    corpusTime: 'From library', suggestTime: 'Suggested for you',
    follow: 'Follow', following: 'Following',
    followTitle: 'Followed builders show up in the top updates ring',
    viewPublisher: 'View publisher',
    filterByScene: 'Filter by industry',
    followScene: 'Follow industry · newest goes to top ring',
    searchPlaceholder: 'Short keywords work best, e.g. de-slop / weekly report',
    navDiscover: 'Discover', navTopics: 'Topics', navPublish: 'Post', navMe: 'Me',
    tabsAria: 'Main navigation', backToTop: 'Back to top',

    topicsTitle: 'Topics', topicsSecSection: 'Browse by section',
    topicsLead: 'One block per top-level topic. Tap the heading to see only that topic, or a subcategory to land one level narrower.',
    topicsCount: '{{n}} items · {{k}} subcategories',
    topicsCountNoL2: '{{n}} items',
    topicsBrowse: 'Show only this →',
    topicsNoL2: 'Nothing in this topic is split into subcategories yet.',
    topicsEmpty: 'The feed has no categorised items yet — run a refresh first.',

    publishTitle: 'Post a skill',
    publishLead: 'Hand your own skill to this feed: paste the <strong>SKILL.md</strong> body, or give a public GitHub repository URL. Posted skills join the merged feed and <strong>are never installed for anyone</strong>.',
    publishFieldTitle: 'Title (parsed from SKILL.md when blank)',
    publishFieldUrl: 'GitHub repository URL (recommended)',
    publishFieldDesc: 'One-line summary',
    publishFieldBody: 'SKILL.md body',
    publishHint: 'Give the body or the repository URL, at least one of the two. The summary has to say what the skill does (about ten characters or more).',
    publishSubmit: 'Post to the feed', publishSubmitting: 'Submitting…',
    publishOkMsg: 'Posted. Check its status under “Me”.',
    publishNeedLogin: 'Posting needs a sign-in. The account is the verification service account, with SMS as the fallback.',
    publishLoginBtn: 'Sign in',
    publishOpenPage: 'Open the full posting page',
    publishNoBackendTitle: 'This is a static mirror',
    publishNoBackend: 'This page has no cloud API attached, so there is no submit button here that would do nothing. Post from the main site, which does have the backend. In the local dashboard this tab does not appear at all.',
    publishRemoteTitle: 'Posting lives on the main site',
    publishRemote: 'This page and the API are on different origins, and the session cookie is SameSite=Lax, so it is not sent with requests made from this page. The button opens the posting page on the main site instead, where it is same-origin and the sign-in works.',
    publishFailed: 'Could not submit. Try again in a moment.',

    acctTitle: 'Me',
    acctChecking: 'Checking your sign-in…',
    acctSignedIn: 'Signed in',
    acctLogout: 'Sign out',
    acctLoggedOut: 'Signed out',
    acctAnonTitle: 'Not signed in',
    acctAnon: 'Once you sign in, the skills you post and the things you like or save live on your account and follow you across devices. Until then everything below stays in this browser.',
    acctLocalTitle: 'No cloud attached',
    acctLocalOnly: 'This page has no cloud API attached, so “Me” can only show what is in this browser: likes, bookmarks and follows.',
    acctRemoteNote: 'This page and the API are on different origins, so cross-site requests carry no session cookie and your account cannot be read here. Open the main site instead.',
    acctOpenSite: 'Open the main site',
    acctMyPosts: 'Posted by me',
    acctPostsLoading: 'Loading…',
    acctNoPosts: 'Nothing posted yet. Submit your first one from the “Post” tab.',
    acctPostsNeedLogin: 'Sign in and the skills you have posted show up here with their status.',
    acctServerCounts: 'On your account: {{liked}} liked · {{saved}} saved',
    acctLocalCounts: 'In this browser: {{liked}} liked · {{saved}} bookmarked',
    acctReactionsPending: 'Server-side likes and saves need the analytics pipeline wired up; until then this browser is the source of truth.',
    quotaTitle: 'Discovery quota',
    quotaSubscriber: 'Subscriber · unlimited today',
    quotaFreeToday: '{{n}} / {{limit}} left today',
    quotaSubscribeHint: 'Subscribe for unlimited unlocks',
    quotaCodePh: 'Activation code',
    quotaActivate: 'Unlock',
    quotaActivateOk: 'Subscription unlocked',
    quotaActivateBad: 'Invalid code',
    payDevBtn: 'Test-pay and unlock',
    payDevOk: 'Test order unlocked the subscription',
    payDevFail: 'Test checkout failed',

    liteBanner: '<b>When no local skill fits</b>, browse remote leads by intent here and install them yourself via “Open on GitHub”. Then run a skill-picker scan again.',
    storiesHint: '<b>Top rings = updates you follow</b>: follow a builder or industry and new items land here first.',
    demoTitle: 'Auto demo', feedbackTitle: 'About feedback',
    notUseful: 'Not interested · never show this again',
    notUsefulToast: 'Hidden — we will not recommend this again',
    allScenes: 'All industries', allSub: 'All subcategories', allSections: 'All sections',
    srcCatalog: 'Curated', srcXhs: 'Xiaohongshu', srcCorpus: 'Library',
    hostSite: ' · site',
    feedbackToast: 'Follow to get updates in the top ring · double-tap to like · bookmark to save',
    addBuilder: '+ Builder', addIndustry: '+ Industry', closeHint: 'Dismiss',
    storyGuide: 'Follow someone and their updates land here',
    storyView: 'See updates from what you follow',
    machineNote: 'Translated from Chinese',

    pageTitleLite: 'Discover on GitHub',
    langGroup: 'Language',
    storiesAria: 'Updates you follow',
    sceneSr: 'Industry', sceneL2Sr: 'Subcategory',
    sceneStripAria: 'Filter by industry', sectionStripAria: 'Sections',
    close: 'Close', prevStory: 'Previous', nextStory: 'Next',
    likeAria: 'Like', likedAria: 'Unlike',
    badAria: 'Not interested', saveAria: 'Save', savedAria: 'Remove from saved',
    demoAria: 'Play auto demo', feedbackAria: 'About feedback',
    refreshAria: 'Show another batch', refreshTitle: 'Show another batch',
    reshuffleToast: 'Here’s another batch',

    sheetBuilderTitle: 'Discover builders',
    sheetBuilderLead: 'Follow someone and their newest skills land in the <strong>top updates ring</strong>, so you see them first.',
    sheetIndustryTitle: 'Discover industries',
    sheetIndustryLead: 'Follow an industry and its newest work lands in the <strong>top updates ring</strong>.',
    feedCount: '{{n}} in feed',
    followedTapUndo: 'Following · tap to unfollow',
    industryLead: 'Follow it and its updates land in the <strong>top updates ring</strong>. You can also just filter the feed by it.',
    unfollowIndustry: 'Unfollow industry', followIndustry: 'Follow industry',
    industryRingOff: 'The ring will stop prioritizing this industry',
    industryRingOn: 'Newest items go to the top ring',
    onlyThisIndustry: 'Show only this industry',
    onlyThisIndustryHint: 'Filters the feed with the pills below',
    filterAction: 'Filter',
    ringFollowing: 'Following',

    followedToast: 'Following {{who}} · their updates will land in the top updates ring',
    unfollowedBuilder: 'Unfollowed @{{who}}',
    unfollowedIndustry: 'Unfollowed “{{who}}”',
    publishLiteOnly: 'Posting is not available in the embedded feed · open the full skill-feed site',
    publishNeedApi: 'Start the API first: python skillfeed.py api (or set ui.api_base)',
    intentToast: 'Distilled to short keywords: {{q}}',
    feedbackLogged: 'Logged · {{action}}',
    feedbackFailed: 'Could not send feedback',
    feedbackServeOnly: 'feedback.jsonl is only writable in serve mode',
    storyGuideToast: 'Follow a builder or an industry first',
    storyEmptyToast: 'No new updates · follow something else or refresh',

    intentDistilled: 'Distilled', intentKeywords: 'Keywords',
    intentShortHint: '· short keywords match better',

    pubNoOtherSkills: 'No other skill cards from them in the feed yet.',
    pubLoadingRepos: 'Loading GitHub repositories…',
    pubNoRepos: 'No more public repositories, or the GitHub API is rate-limited.',
    noDescription: 'No description',
    inFeed: 'In feed',
    pubSub: 'Publisher profile · {{n}} in feed · merged with GitHub',
    pubFollowNote: 'Follow to get their updates in the <strong>top updates ring</strong>',
    followBuilder: 'Follow builder',
    backToFeed: '← Back to feed',
    allRepos: 'All repositories',
    pubSecFeed: 'On skill-feed',
    pubSecGithub: 'More on GitHub',

    emptySavedTitle: 'Nothing saved yet',
    emptySavedBody: 'Double-tap a post to like it, or tap the bookmark to save it. Everything shows up under “Me”.',
    emptyTitle: 'No matching posts',
    emptyWithIntent: 'Keywords: <b>{{q}}</b> — nothing in the feed matches. Keep looking on GitHub.',
    emptyNoIntent: 'Nothing in the feed yet. Try short keywords (e.g. “stop-slop”), or search GitHub for SKILL.md directly.',
    ghSearchCode: 'Search SKILL.md on GitHub (code)',
    ghSearchRepos: 'Search repositories on GitHub',
    noInstallNote: 'We do not install anything for you: pick a repo on GitHub, install it yourself, then run a skill-picker scan.',
    funnel: 'Funnel: ', funnelPassed: 'passed gates',

    unfollowAria: 'Unfollow',
    meNoBuilders: 'No builders followed yet. Tap “Follow” on a card and their updates land in the top updates ring.',
    meNoIndustries: 'No industries followed yet. Tap the industry tag on a card to follow it.',
    meLead: 'Builders and industries you follow put their <strong>newest work in the updates ring on Discover</strong>. Likes and bookmarks stay in this browser.',
    meMyBuilders: 'Builders I follow',
    meMyIndustries: 'Industries I follow',
    meLocalTitle: 'Saved on this device',
    meCounts: '{{liked}} liked · {{saved}} bookmarked',
    meViewSaved: 'View saved',
    mePublishTitle: 'Posting and backend',
    meApiPrefix: 'API: ',
    meNoApi: 'No cloud API configured (ui.api_base / skillfeed.py api)',
    meGoPublish: 'Post a skill',
    meApiDocs: 'API docs', meApiHome: 'API home', meGithubLogin: 'Sign in with GitHub',
    meAboutTitle: 'About this feed',
    meAboutBody: 'The top updates ring shows what you follow. Industry and section filters moved to the “Topics” tab and only come back to the top of Discover while a filter is on.',

    moreShown: 'Scroll for more · showing <b>{{n}}</b> of {{total}}',
    allDone: 'That is everything · <b>{{total}}</b> items, library backup included',

    storyFollowing: 'Updates you follow',
    storyWhoSuffix: ' · latest',

    demoStopBtn: 'Stop',
    demoIdle: 'Demo running',
    demoStarting: 'Demo starting',
    demoStopped: 'Demo stopped',
    demoFollowIndustry: 'Demo: follow an industry → top updates ring',
    demoFollowToast: 'Followed items show up in the top ring',
    demoOpenStories: 'Demo: tap the updates ring for the latest',
    demoPills: 'Demo: pills filter by industry (not the updates ring)',
    demoSearch: 'Demo: intent search “{{q}}”',
    demoLike: 'Demo: double-tap to like · {{name}}',
    demoSave: 'Demo: bookmark it',
    demoMe: 'Demo: open “Me”',
    demoLoop: 'Demo loop · back to Discover',
  }},
}};

let LANG = 'zh';
try {{
  const savedLang = localStorage.getItem('sf_lang');
  if (savedLang === 'zh' || savedLang === 'en') LANG = savedLang;
}} catch (e) {{}}

function tr(key) {{
  const table = I18N[LANG] || I18N.zh;
  return (key in table) ? table[key] : (I18N.zh[key] || '');
}}

/* 带 {{name}} 占位符的取词。部分条目本身含 <b>/<strong>，所以这里不做转义，
   调用方要么整串当 HTML 用，要么先把变量 escapeHtml 过再传进来 */
function trn(key, vars) {{
  let s = tr(key);
  const v = vars || {{}};
  for (const k of Object.keys(v)) {{
    s = s.split('{{' + k + '}}').join(String(v[k]));
  }}
  return s;
}}

/* 中文缺失回退英文，英文缺失回退中文；两者都缺回退原文，绝不留空 */
function pickText(item, base) {{
  const zh = (item[base + '_zh'] || '').trim();
  const en = (item[base + '_en'] || '').trim();
  if (LANG === 'zh') return zh || en;
  return en || zh;
}}

function pickList(item, base) {{
  const zh = Array.isArray(item[base + '_zh']) ? item[base + '_zh'] : [];
  const en = Array.isArray(item[base + '_en']) ? item[base + '_en'] : [];
  const primary = LANG === 'zh' ? zh : en;
  const backup = LANG === 'zh' ? en : zh;
  return primary.length ? primary : backup;
}}

/* 注意：下方另有 sceneLabelOf(sceneId)，按 id 取标签；这两个按 item 取，勿混用 */
// 行业标签一律从页面内嵌的标签表按 id 查，不依赖 item 上是否带 *_en 字段
// （item 的 scene_label_en 只在 refresh 阶段写入，build/i18n 不会补）
function itemSceneLabel(it) {{
  const row = SCENES.find(s => s.id === it.scene);
  if (row) return chipLabel(row);
  return it.scene_label || it.scene || (LANG === 'en' ? 'Other' : '其他');
}}

function itemSceneL2Label(it) {{
  if (!it.scene_l2) return '';
  const kids = SCENES_L2[it.scene] || [];
  const row = kids.find(k => (k.id || k[0]) === it.scene_l2);
  if (row) return chipLabel(row);
  return it.scene_l2_label || '';
}}

function chipLabel(row) {{
  if (!row) return '';
  return LANG === 'en' ? (row.label_en || row.label || row.id) : (row.label || row.id);
}}

/* 一场景一色族。每套三档：pal[0] 深、pal[1] 中（头像/徽章纯色底）、pal[2] 浅，
   渐变只在同一色族内从深走到浅。这两条约束是有来由的：
     - 键入 scene 而不是名字哈希，颜色才承载信息（蓝=工程、紫=Agent 工具链）；
       随机哈希的颜色对读者恒等于噪声
     - 单色族的深→浅斜推，不会凑出任何一家的多色相扇推商标外观
   可用色相被两头挤掉：150-180 留给品牌 accent，310-360 是禁用的洋红/红。剩下约
   280° 分十类，硬凑等距会把某几类推进禁用邻域，所以按占比分配：占比最大的三类
   （工程 24%、Agent 18%、设计 17%）拿最拉得开的色相，最小的两类（其他 4%、
   业务垂直 1%）走中性/低饱和，不占色相预算。
   agent 与 design 色相只差 8°，靠明度档位错开：agent 取 violet-800、design 取
   purple-600，肉眼是「深紫 vs 亮紫」。选值的对比度与色距见
   docs/brand-tokens.md，测试在 test_feed_dashboard.py 逐套复核。 */
const SCENE_PAL = {{
  'quality':       ['#7c2d12','#c2410c','#ea580c'],  //  17° Bug与质量
  'content':       ['#854d0e','#a16207','#ca8a04'],  //  35° 内容创作
  'research':      ['#3f6212','#4d7c0f','#65a30d'],  //  86° 研究与知识
  'collab':        ['#166534','#15803d','#16a34a'],  // 142° 协作办公
  'engineering':   ['#075985','#0369a1','#0284c7'],  // 201° 工程开发
  'data-review':   ['#4338ca','#4f46e5','#6366f1'],  // 243° 数据与复盘
  'agent-tooling': ['#4c1d95','#5b21b6','#6d28d9'],  // 263° Agent工具链
  'design':        ['#7e22ce','#9333ea','#a855f7'],  // 271° 设计与视觉
  'biz-vertical':  ['#5c2508','#78350f','#9a4a16'],  //  22° 业务垂直
  'other':         ['#334155','#475569','#64748b'],  // 215° 其他
}};

/* 发布者头像没有 scene 可依，仍走哈希——头像色是身份指纹而非分类，读者本来就
   不会去解读它。但哈希池换成上面这十套，池子里再没有需要豁免的颜色。 */
const PAL_POOL = Object.keys(SCENE_PAL).map(k => SCENE_PAL[k]);

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
const hidden = loadSet('sf_hidden');
const batchSkip = new Set();
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
  toast(trn('followedToast', {{ who }}), 3200);
  flashStoriesHint();
}}

function escapeHtml(s) {{
  return String(s ?? '').replace(/[&<>"']/g, c => ({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }})[c]);
}}

/* escapeHtml 只挡属性逸出，挡不住协议：href="javascript:..." 里一个引号都不需要。
   url / skill_url / cover_url 都直接来自陌生人的仓库元数据，所以进 href/src 之前
   必须过一遍协议白名单。用 URL 解析而不是比前缀，是因为 `JaVaScRiPt:`、前导空白、
   内嵌 \\0 都能绕过朴素的 startsWith 检查。
   注意：解析基准是 document.baseURI，所以把 feed.html 当 file:// 本地文件打开时，
   相对地址会被判成 file: 而降级——GitHub 链接都是绝对 https，不受影响。 */
function safeUrl(u) {{
  const s = String(u ?? '').trim();
  if (!s) return '';
  try {{
    const proto = new URL(s, document.baseURI).protocol;
    return (proto === 'http:' || proto === 'https:') ? s : 'about:blank';
  }} catch (e) {{
    return 'about:blank';
  }}
}}

/* 头像字母原来恒为白色，落在旧随机调色板里最亮的那组黄上只有 1.45:1。
   现在的十套 scene 板 pal[1] 都过了白字 4.5，但这段仍留着：它防的是「以后又
   加进来一组亮色」，而不是当下的取值。按背景亮度选前景，不改任何一个品牌色。
   INK_HEX 必须与 CSS 的 --ink 保持一致。 */
const INK_HEX = '#0a1848';
function relLum(hex) {{
  const h = String(hex || '').replace('#', '');
  if (h.length !== 6) return 1;
  const f = (c) => {{ c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }};
  const p = [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16));
  return 0.2126 * f(p[0]) + 0.7152 * f(p[1]) + 0.0722 * f(p[2]);
}}
function contrastRatio(l1, l2) {{
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}}
function readableOn(bgHex) {{
  const lb = relLum(bgHex);
  return contrastRatio(1, lb) >= contrastRatio(relLum(INK_HEX), lb) ? '#ffffff' : INK_HEX;
}}

/* ---------- 卡内去重：同一句话在一张卡里只出现一次 ---------- */
/* 离线生成的 problem 是 description 的 110 字截断版，两串裸比永远不等，
   所以先归一化（折叠空白、去尾部省略号与句号、统一大小写）再看前缀关系 */
function normDup(s) {{
  return String(s ?? '')
    .replace(/\\s+/g, ' ')
    .trim()
    .replace(/(?:\\.{{2,}}|[…。．]+)+$/, '')
    .trim()
    .toLowerCase();
}}

function sameText(a, b) {{
  const x = normDup(a);
  return !!x && x === normDup(b);
}}

/* 短串不做前缀判定，否则「AI」会把「AI 写作助手」整段判成重复 */
const DUP_PREFIX_MIN = 12;
function dupText(a, b) {{
  const x = normDup(a), y = normDup(b);
  if (!x || !y) return false;
  if (x === y) return true;
  if (Math.min(x.length, y.length) < DUP_PREFIX_MIN) return false;
  return x.startsWith(y) || y.startsWith(x);
}}

/* 截断版与全量版重复时留全量版，别让卡上只剩「支持群发、收发附件和人…」这种断句 */
function preferFuller(a, b) {{
  const x = String(a ?? '').trim(), y = String(b ?? '').trim();
  if (!x) return y;
  if (!y || !dupText(x, y)) return x;
  return normDup(y).length > normDup(x).length ? y : x;
}}

const PITCH_MAX = 180;
function clampText(s, max) {{
  const t = String(s ?? '').trim();
  return t.length > max ? (t.slice(0, max - 1) + '…') : t;
}}

/* corpus / soft 条目是 HelloGitHub 收录的普通仓库，它们的 skill_url 是按
   blob/HEAD/SKILL.md 拼出来的，点进去 404；只认离线扫描真命中过的 skill_path */
function hasSkillDoc(it) {{
  if (it.skill_path) return true;
  if (it.from_corpus || it.soft) return false;
  return !!it.skill_url;
}}

/* 占位亮点在离线阶段就写进了 feed.json，客户端还得再拦一道 */
function isFillerHighlight(text) {{
  return sameText(text, I18N.zh.fallbackHl) || sameText(text, I18N.en.fallbackHl);
}}

function sourceLabel(src) {{
  if (!src) return 'unknown';
  if (src === 'github.com/trending') return 'trending';
  if (src === 'hellogithub') return 'HelloGitHub';
  if (src === 'github-search') return 'GitHub Search';
  if (src === 'catalog') return tr('srcCatalog');
  if (src === 'xiaohongshu') return tr('srcXhs');
  if (src === 'corpus') return tr('srcCorpus');
  return src;
}}

function hashHue(s) {{
  let h = 0;
  for (let i = 0; i < (s||'').length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
}}

function paletteFor(key) {{
  return PAL_POOL[hashHue(key) % PAL_POOL.length];
}}

/* 分类色的唯一入口。未知 scene 落到 other 的中性灰蓝，而不是随机挑一套——
   否则「没分好类」会伪装成一个有含义的分类色。 */
function paletteForScene(sceneId) {{
  return SCENE_PAL[sceneId] || SCENE_PAL['other'];
}}

function initials(name) {{
  const s = (name || '?').replace(/[^A-Za-z0-9\\u4e00-\\u9fff]/g, '');
  return (s.slice(0, 2) || '?').toUpperCase();
}}

function allPool() {{
  const live = FEED.items || [];
  const backup = FEED.corpus || [];
  const seen = new Set();
  const out = [];
  for (const it of live.concat(backup)) {{
    const k = it.full_name || it.id;
    if (!k || seen.has(k) || hidden.has(k)) continue;
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
  if (mode === 'skills') return kind === 'skill' || !!it.skill_path || sec === SECTION_SKILLS;
  if (mode === 'ai') return kind === 'ai' || sec === SECTION_AI;
  if (mode === 'oss') return kind !== 'skill' && !it.skill_path && sec !== SECTION_SKILLS;
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
  return chipLabel(SCENES.find(s => s.id === sceneId)) || sceneId;
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
  else toast(trn('unfollowedBuilder', {{ who: owner }}));
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
  else toast(trn('unfollowedIndustry', {{ who: sceneLabelOf(sceneId) }}));
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

/* 面板 HTML 与 DOM 注入分开：纯函数好测，也让 data-sheet 这个稳定标识只有一处写入 */
function followSheetHtml(kind) {{
  const closeBtn = `<button type="button" class="sheet-close js-sheet-close">${{escapeHtml(tr('close'))}}</button>`;
  const actLabel = on => escapeHtml(on ? tr('followedTapUndo') : tr('follow'));
  if (kind === 'builder') {{
    return `<h3>${{escapeHtml(tr('sheetBuilderTitle'))}}</h3>
      <p class="lead">${{tr('sheetBuilderLead')}}</p>` +
      topBuilders(16).map(r => {{
        const pal = paletteFor(r.owner);
        return `<button type="button" class="sheet-row js-sheet-follow-builder" data-owner="${{escapeHtml(r.owner)}}">
          <div class="ava" style="background:${{pal[1]}};color:${{readableOn(pal[1])}}">${{escapeHtml(initials(r.owner))}}</div>
          <div class="meta"><b>@${{escapeHtml(r.owner)}}</b><span>${{escapeHtml(trn('feedCount', {{ n: r.n }}))}}</span></div>
          <span class="act-label">${{actLabel(isFollowingBuilder(r.owner))}}</span>
        </button>`;
      }}).join('') + closeBtn;
  }}
  return `<h3>${{escapeHtml(tr('sheetIndustryTitle'))}}</h3>
    <p class="lead">${{tr('sheetIndustryLead')}}</p>` +
    SCENES.filter(s => countScene(s.id) > 0).map(s => {{
      const pal = paletteForScene(s.id);
      const label = chipLabel(s);
      return `<button type="button" class="sheet-row js-sheet-follow-industry" data-scene="${{escapeHtml(s.id)}}">
        <div class="ava" style="background:linear-gradient(135deg,${{pal[0]}},${{pal[2]}})">${{escapeHtml(initials(label))}}</div>
        <div class="meta"><b>${{escapeHtml(label)}}</b><span>${{escapeHtml(trn('feedCount', {{ n: countScene(s.id) }}))}}</span></div>
        <span class="act-label">${{actLabel(isFollowingIndustry(s.id))}}</span>
      </button>`;
    }}).join('') + closeBtn;
}}

function industrySheetHtml(sceneId) {{
  const on = isFollowingIndustry(sceneId);
  return `<h3>${{escapeHtml(sceneLabelOf(sceneId))}}</h3>
    <p class="lead">${{tr('industryLead')}}</p>
    <button type="button" class="sheet-row js-sheet-follow-industry" data-scene="${{escapeHtml(sceneId)}}">
      <div class="meta"><b>${{escapeHtml(on ? tr('unfollowIndustry') : tr('followIndustry'))}}</b>
      <span>${{escapeHtml(on ? tr('industryRingOff') : tr('industryRingOn'))}}</span></div>
      <span class="act-label">${{escapeHtml(on ? tr('following') : tr('follow'))}}</span>
    </button>
    <button type="button" class="sheet-row js-sheet-filter-scene" data-scene="${{escapeHtml(sceneId)}}">
      <div class="meta"><b>${{escapeHtml(tr('onlyThisIndustry'))}}</b><span>${{escapeHtml(tr('onlyThisIndustryHint'))}}</span></div>
      <span class="act-label">${{escapeHtml(tr('filterAction'))}}</span>
    </button>
    <button type="button" class="sheet-close js-sheet-close">${{escapeHtml(tr('close'))}}</button>`;
}}

function showSheet(sheet, html) {{
  const panel = document.getElementById('followSheetPanel');
  // data-sheet 是「当前开着哪张面板」的唯一判据，点关注后靠它决定重渲染哪张
  panel.dataset.sheet = sheet;
  panel.innerHTML = html;
  const el = document.getElementById('followSheet');
  el.classList.add('open');
  el.setAttribute('aria-hidden', 'false');
}}

function openFollowSheet(kind) {{
  if (IS_LITE) return;
  const builder = kind === 'builder';
  showSheet(builder ? 'builder-list' : 'industry-list', followSheetHtml(builder ? 'builder' : 'industry'));
}}

function openIndustrySheet(sceneId) {{
  if (IS_LITE || !sceneId) return;
  showSheet('industry-detail', industrySheetHtml(sceneId));
}}

/* 关注/取关行业后要重渲染哪张面板，只能看 panel 的 data-sheet。
   原实现拿 <h3> 文案和 '发现行业' 比，EN 模式下永远不相等，
   「发现行业」列表会被换成单行业详情页，用户一次只能关注一个就被踢出列表。 */
function reopenSheetAfterIndustryToggle(sheet, sceneId) {{
  if (sheet === 'industry-list') {{
    openFollowSheet('industry');
    return 'industry-list';
  }}
  if (sceneId) {{
    openIndustrySheet(sceneId);
    return 'industry-detail';
  }}
  return '';
}}

function apiUrl(path) {{
  if (!API_BASE) return '';
  return API_BASE + (path.startsWith('/') ? path : ('/' + path));
}}

const INTENT_STOP = new Set(
  '的了呢吗啊把被在是有我要帮做一份一个能否可以怎么如何请帮忙去掉删除去除一下帮我给我用到进行进行中以及还有就是这个那个什么哪些为了把它给工具用来实现功能需求'.split('')
);
// 真实词表（长的优先）。禁止用滑动窗口造「产品设/品设品」这类假词。
const INTENT_PHRASES = [
  '去ai味', 'stop-slop', '周报复盘', '产品设计', '交互设计', '视觉设计', '跟团选品', '选品工具',
  '剪视频', '短视频', '知识图谱', '代码审查', '架构图', '网页推荐', 'ai味', '去ai',
  '周报', '复盘', '文案', '写作', '润色', '飞书', 'figma', '图表', 'ppt', '演示',
  '选品', '跟团', '设计', 'ui', 'ux', 'mcp', '看板', 'cad', '口播',
];
const MAX_INTENT_KEYS = 2;

/* 场景特判产出的是「我们自己的规范化关键词」，会直接显示在搜索框和关键词条上，
   所以必须跟随语言；而上面那些正则和 INTENT_PHRASES 是拿来匹配用户输入的，
   用户什么语言都可能输，那些中文必须保持中文，不能进 I18N。
   两种写法都被 intentTokens 映射到同一组 token，换语言不改匹配结果。 */
const INTENT_CANON = {{
  deslop: {{ zh: '去AI味', en: 'stop-slop' }},
}};

/* INTENT_PHRASES 里指向「去AI味」的那几个别名。这是词表数据的分组，
   不是展示文案——别改成拿 UI 文案比字符串。 */
const DESLOP_ALIASES = new Set(['ai味', '去ai', '去ai味']);

function canonIntent(id) {{
  const row = INTENT_CANON[id] || {{}};
  return (LANG === 'en' ? row.en : row.zh) || row.zh || id;
}}

/** 长意图 → 真实短关键词（最多 2 个；绝不滑动切碎中文） */
function compressIntent(raw) {{
  const src = String(raw || '').trim();
  if (!src) return {{ keys: [], query: '', shortened: false }};
  const lower = src.toLowerCase().replace(/\\s+/g, ' ');
  const compact = lower.replace(/\\s+/g, '');
  const keys = [];
  const push = (k) => {{
    const t = String(k || '').trim();
    if (!t || t.length < 2 || keys.length >= MAX_INTENT_KEYS) return;
    const tl = t.toLowerCase();
    for (let i = 0; i < keys.length; i++) {{
      const x = keys[i];
      const xl = x.toLowerCase();
      if (xl === tl) return;
      if (tl.includes(xl) && t.length > x.length) {{ keys[i] = t; return; }}
      if (xl.includes(tl)) return;
    }}
    keys.push(t);
  }};

  let cjk = '';
  for (const ch of compact) {{
    if (/[\\u4e00-\\u9fff]/.test(ch) && !INTENT_STOP.has(ch)) cjk += ch;
  }}
  // 纠正历史滑窗拼贴：产品设品设计 / 产品设*设计 → 产品设计
  if (/产品设.*设计/.test(cjk) || /产品设计/.test(cjk)) {{
    cjk = cjk.replace(/产品设品设计/g, '产品设计').replace(/产品设+品?设计/g, '产品设计');
  }}

  // 0) 场景特判
  if (/ai味|去ai|ai写作|stop-slop|slop/.test(compact) || (cjk.includes('文案') && (compact.includes('ai') || cjk.includes('味')))) {{
    push(canonIntent('deslop'));
    // 「文案」是用户自己输进来的词，原样回显不算漏中文，所以不跟随语言
    if (cjk.includes('文案')) push('文案');
  }}
  if (/周报|复盘/.test(compact)) {{
    push(compact.includes('复盘') && compact.includes('周报') ? '周报复盘' : (compact.includes('周报') ? '周报' : '复盘'));
  }}
  if (/剪视频|短视频|口播/.test(compact)) push('剪视频');
  if (/产品设.*设计|产品设计/.test(compact) || /产品设.*设计|产品设计/.test(cjk)) push('产品设计');

  // 1) 词表：按长度降序匹配，避免先命中短词挡住「产品设计」
  const phrases = INTENT_PHRASES.slice().sort((a, b) => b.length - a.length);
  for (const p of phrases) {{
    if (keys.length >= MAX_INTENT_KEYS) break;
    if (compact.includes(p) || lower.includes(p)) {{
      if (DESLOP_ALIASES.has(p)) push(canonIntent('deslop'));
      else if (p === 'ui' || p === 'ux' || p === 'mcp' || p === 'ppt' || p === 'cad') push(p.toUpperCase());
      else push(p);
    }}
  }}

  // 2) 英文词（短且真）
  for (const w of lower.match(/[a-z][a-z0-9\\-]{{1,24}}/g) || []) {{
    if (keys.length >= MAX_INTENT_KEYS) break;
    if (['the', 'and', 'for', 'with', 'from', 'this', 'that', 'skill', 'skills', 'http', 'https'].includes(w)) continue;
    push(w.length <= 3 ? w.toUpperCase() : w);
  }}

  // 3) 无词表命中时：整段短查询当 1 个词；长句不再切碎
  const spaceParts = src.split(/\\s+/).filter(Boolean);
  const alreadyShort = compact.length <= 8 && spaceParts.length <= 2 && cjk.length <= 6;
  if (!keys.length) {{
    if (alreadyShort) {{
      return {{ keys: [src], query: src, shortened: false }};
    }}
    if (cjk.length >= 2 && cjk.length <= 6) {{
      push(cjk);
    }} else if (spaceParts.length && spaceParts.length <= 2 && compact.length <= 12) {{
      spaceParts.slice(0, MAX_INTENT_KEYS).forEach(push);
    }} else if (cjk.length > 6) {{
      // 宁可少词，也不造「产品设」：只取词表扫过仍空时的末 2 字实体（常为题眼）
      // 但若末 2 字是虚词则放弃
      const tail = cjk.slice(-2);
      if (tail && ![...tail].every(ch => INTENT_STOP.has(ch))) push(tail);
    }}
  }}

  const picked = keys.slice(0, MAX_INTENT_KEYS);
  if (!picked.length) {{
    const fallback = alreadyShort ? src : (cjk.slice(0, 4) || compact.slice(0, 6) || src.slice(0, 8));
    return {{ keys: fallback ? [fallback] : [], query: fallback, shortened: compact.length > 8 }};
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
  el.innerHTML = `<span>${{escapeHtml(shortened ? tr('intentDistilled') : tr('intentKeywords'))}}</span>` +
    keys.map(k => `<span class="ik">${{escapeHtml(k)}}</span>`).join('') +
    (shortened ? `<b>${{escapeHtml(tr('intentShortHint'))}}</b>` : '');
}}

function applyIntentInput(raw, {{ forceCompress = false, silent = false }} = {{}}) {{
  const src = String(raw || '');
  const packed = compressIntent(src);
  const el = document.getElementById('intent');
  const tooLong = src.replace(/\\s+/g, '').length > 8 || src.length > 12;
  // lite / 发现页：始终压成真实短词，避免「产品设品设计」这类滑窗残骸留在输入框
  const use = (forceCompress || tooLong || IS_LITE || packed.shortened) ? (packed.query || src.trim()) : src.trim();
  state.intent = use;
  if (el && el.value !== use) el.value = use;
  if (!silent && packed.shortened && use && use !== src.trim()) {{
    toast(trn('intentToast', {{ q: use }}), 2200);
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
  // 只用真实关键词做匹配，禁止再滑窗造假二元组污染结果
  const packed = compressIntent(q);
  const raw = (packed.query || q || '').trim().toLowerCase();
  if (!raw) return [];
  const out = new Set(packed.keys.map(k => k.toLowerCase()));
  for (const part of raw.split(/\\s+/).filter(Boolean)) out.add(part);
  if (/ai\\s*味|去\\s*ai|slop|人味|润色|去ai|去ai味/.test(raw) || (/文案/.test(raw) && /ai|味/.test(raw))) {{
    ['slop', 'stop-slop', 'ai writing', 'ai味', '去ai', '去ai味', '写作', '文案', '润色', 'human'].forEach(t => out.add(t));
  }}
  // 产品设计：映射到生态里真实 skill 名（frontend-design / figma / shadcn…）
  if (/产品设计|交互设计|视觉设计|frontend-design|web-design|ui\\s*ux|figma|shadcn|taste/.test(raw)
      || out.has('产品设计') || out.has('交互设计') || out.has('设计')) {{
    [
      'frontend-design', 'web-design', 'web-design-guidelines', 'figma', 'ui', 'ux',
      'design', 'shadcn', 'hallmark', 'taste-skill', '产品设计', '交互', '界面',
      'prototype', 'design system', 'canvas-design',
    ].forEach(t => out.add(t));
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
  const strong = [
    'stop-slop', 'slop', 'ai味', '去ai', '去ai味', 'hallmark',
    'frontend-design', 'web-design', 'figma', 'shadcn', 'taste-skill', '产品设计',
  ];
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

function sessionSeed() {{
  /* 同一标签页稳定、换标签页或关页再开就换序。静态 feed 没有 /api/feed，
     会话种子只能躺在 sessionStorage。 */
  try {{
    let s = sessionStorage.getItem('sf_session_seed');
    if (!s) {{
      s = 's' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
      sessionStorage.setItem('sf_session_seed', s);
    }}
    return s;
  }} catch (e) {{
    return 'offline';
  }}
}}

function sessionJitter(key, seed, amp) {{
  if (!seed || !(amp > 0)) return 0;
  const s = String(seed) + ':' + String(key || '');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {{
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }}
  const frac = (h >>> 0) / 4294967296;
  return amp * (frac - 0.5);
}}

function scoreRow(it, q, seed) {{
  const query = q || '';
  const searching = !!String(query).trim();
  const base = (Number(it.personal_score) || Number(it.rel_score) || 0) + liveIntentBoost(it, query);
  const fn = it.full_name || it.id || '';
  let extra = 0;
  if (liked.has(fn)) extra += 0.03;
  /* 静态页没有后端 ε(session)。0.12 让同分簇会换序；质量分明显领跑的仍领跑。
     搜索态关掉抖动，相关性优先。 */
  const amp = searching ? 0 : 0.12;
  return base + extra + sessionJitter(fn, seed || sessionSeed(), amp);
}}

function applyDiversity(items, searching) {{
  const maxRun = searching ? 3 : 2;
  const remaining = items.slice();
  const out = [];
  while (remaining.length) {{
    let pick = 0;
    let run = 0;
    const lastScene = out.length ? (out[out.length - 1].scene || '') : '';
    if (lastScene) {{
      for (let i = out.length - 1; i >= 0; i--) {{
        if ((out[i].scene || '') === lastScene) run += 1;
        else break;
      }}
    }}
    const ownerTail = {{}};
    for (const prev of out.slice(-7)) {{
      const o = prev.owner || '';
      if (o) ownerTail[o] = (ownerTail[o] || 0) + 1;
    }}
    for (let relax = 0; relax < 3; relax++) {{
      let found = -1;
      for (let i = 0; i < remaining.length; i++) {{
        const scene = remaining[i].scene || '';
        const owner = remaining[i].owner || '';
        if (relax < 1 && run >= maxRun && lastScene && scene === lastScene) continue;
        if (relax < 2 && owner && (ownerTail[owner] || 0) >= 2) continue;
        found = i;
        break;
      }}
      if (found >= 0) {{ pick = found; break; }}
    }}
    out.push(remaining.splice(pick, 1)[0]);
  }}
  return out;
}}

function injectExplore(items, searching) {{
  if (searching || items.length < 10) return items;
  const slots = [4, 11, 16];
  const out = items.slice();
  const start = Math.floor(out.length * 0.45);
  const used = new Set();
  for (const slot of slots) {{
    if (slot >= out.length) continue;
    let pickAt = -1;
    for (let i = Math.max(start, slot + 1); i < out.length; i++) {{
      const k = out[i].full_name || out[i].id;
      if (!k || used.has(k)) continue;
      pickAt = i;
      break;
    }}
    if (pickAt < 0) continue;
    const [pick] = out.splice(pickAt, 1);
    used.add(pick.full_name || pick.id);
    out.splice(slot, 0, pick);
  }}
  return out;
}}

function rankRows(rows, q, seed, hist, now) {{
  const query = q || '';
  const searching = !!String(query).trim();
  const scored = rows.slice().sort((a, b) => {{
    const d = scoreRow(b, query, seed) - scoreRow(a, query, seed);
    if (d) return d;
    return String(a.full_name || '').localeCompare(String(b.full_name || ''));
  }});
  return applyPositionCap(
    injectExplore(applyDiversity(scored, searching), searching),
    hist, now);
}}

function itemKey(it) {{
  return (it && (it.full_name || it.id)) || '';
}}

function loadPosHist() {{
  try {{
    const raw = JSON.parse(localStorage.getItem('sf_pos_hist') || '{{}}');
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {{}};
  }} catch (e) {{
    return {{}};
  }}
}}

function prunePosHist(hist, now) {{
  const week = 7 * 24 * 60 * 60 * 1000;
  const out = {{}};
  now = now || Date.now();
  for (const fn of Object.keys(hist || {{}})) {{
    const slots = hist[fn];
    if (!slots || typeof slots !== 'object') continue;
    const keep = {{}};
    for (const pos of Object.keys(slots)) {{
      const live = (Array.isArray(slots[pos]) ? slots[pos] : [])
        .filter(t => now - t < week);
      if (live.length) keep[pos] = live;
    }}
    if (Object.keys(keep).length) out[fn] = keep;
  }}
  return out;
}}

function posHits(hist, fn, pos, now) {{
  if (!fn || !hist) return 0;
  const week = 7 * 24 * 60 * 60 * 1000;
  now = now || Date.now();
  const stamps = hist[fn] && hist[fn][String(pos)];
  if (!Array.isArray(stamps)) return 0;
  return stamps.filter(t => now - t < week).length;
}}

function applyPositionCap(items, hist, now) {{
  /* 同一张卡、同一个位次，滚动 7 天内最多出现 2 次；第 3 次必须换人。 */
  const out = (items || []).slice();
  now = now || Date.now();
  if (hist == null) hist = loadPosHist();
  const cap = 2;
  for (let i = 0; i < out.length; i++) {{
    const fn = itemKey(out[i]);
    if (!fn || posHits(hist, fn, i, now) < cap) continue;
    let swap = -1;
    for (let pass = 0; pass < 2 && swap < 0; pass++) {{
      for (let j = i + 1; j < out.length; j++) {{
        const other = itemKey(out[j]);
        if (!other) continue;
        if (posHits(hist, other, i, now) >= cap) continue;
        if (pass === 0 && posHits(hist, fn, j, now) >= cap) continue;
        swap = j;
        break;
      }}
    }}
    if (swap >= 0) {{
      const tmp = out[i];
      out[i] = out[swap];
      out[swap] = tmp;
    }}
  }}
  return out;
}}

function noteShownPositions(slice, reset, now) {{
  if (reset || noteShownPositions._through == null) noteShownPositions._through = -1;
  if (!slice || !slice.length) return loadPosHist();
  now = now || Date.now();
  const week = 7 * 24 * 60 * 60 * 1000;
  const hist = prunePosHist(loadPosHist(), now);
  let changed = false;
  for (let i = noteShownPositions._through + 1; i < slice.length; i++) {{
    const fn = itemKey(slice[i]);
    if (!fn) continue;
    if (!hist[fn]) hist[fn] = {{}};
    const key = String(i);
    const live = (hist[fn][key] || []).filter(t => now - t < week);
    live.push(now);
    hist[fn][key] = live;
    changed = true;
  }}
  noteShownPositions._through = slice.length - 1;
  if (changed) {{
    try {{ localStorage.setItem('sf_pos_hist', JSON.stringify(hist)); }} catch (e) {{}}
  }}
  return hist;
}}

function filtered() {{
  const q = effectiveIntent();

  if (state.mode === 'saved') {{
    const keep = new Set([...liked, ...saved]);
    const rows = allPool().filter(it => {{
      const fn = it.full_name || '';
      if (!fn || !keep.has(fn)) return false;
      if (q && !intentMatch(it, q)) return false;
      if (batchSkip.has(fn)) return false;
      return true;
    }});
    return rankRows(rows, q);
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
    if (batchSkip.has(it.full_name || it.id || '')) return false;
    return true;
  }});
  return rankRows(rows, q);
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
    .filter(k => countL2(k.id || k[0]) > 0)
    .map(k => ({{ id: k.id || k[0], label: chipLabel(k) }}));
  if (!kids.length) return [];
  return [{{ id: 'all', label: tr('allSub') }}].concat(kids);
}}

// HelloGitHub 栏目名是中文原文，EN 模式下按表映射；"X 项目" 剥掉后缀就是语言名
const SECTION_EN = {{
  '人工智能': 'AI',
  '开源书籍': 'Books',
  '其它': 'Other',
  '其他': 'Other',
}};

/* 下面这些中文是 feed.json 里 hg_section 的**数据值**（HelloGitHub 上游原文），
   不是展示文案，所以不进 I18N；展示时才过 sectionLabelOf() 翻。
   写成常量是为了让「这里的中文不该翻」一眼看得出来。 */
const SECTION_AI = '人工智能';
const SECTION_SKILLS = 'Skills';
const SECTION_ORDER = [
  'Skills', '人工智能', 'Python 项目', 'JavaScript 项目',
  'Go 项目', 'Rust 项目', '开源书籍', '其它',
];

function sectionLabelOf(sec) {{
  if (!sec) return '';
  const short = sec.replace(/ 项目$/, '');
  if (LANG === 'en') return SECTION_EN[sec] || SECTION_EN[short] || short;
  return short;
}}

function sectionOptions() {{
  const set = new Map();
  for (const it of allPool()) {{
    if (!matchMode(it)) continue;
    const sec = it.hg_section;
    if (sec) set.set(sec, sectionLabelOf(sec));
  }}
  const preferred = SECTION_ORDER;
  const rest = [...set.keys()].filter(k => !preferred.includes(k)).sort();
  const ids = preferred.filter(k => set.has(k) && countSection(k) > 0)
    .concat(rest.filter(k => countSection(k) > 0));
  if (!ids.length) return [];
  return [{{ id: 'all', label: tr('allSections') }}].concat(ids.map(id => ({{ id, label: set.get(id) }})));
}}

async function sendFeedback(action, it, opts) {{
  const silent = !!(opts && opts.silent);
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
    if (!silent && !demo.on) toast(data.ok ? trn('feedbackLogged', {{ action }}) : (data.error || tr('feedbackFailed')));
  }} catch (e) {{
    if (!silent && !demo.on) toast(tr('feedbackServeOnly'));
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
  const s1 = itemSceneLabel(it);
  const s2 = itemSceneL2Label(it);
  if (s1) bits.push(s1);
  if (s2) bits.push(s2);
  if (it.soft) bits.push(tr('leadLong'));
  else if (it.from_corpus) bits.push(tr('kb'));
  if (it.source) bits.push(sourceLabel(it.source));
  return bits.length ? (tr('because') + ' · ' + bits.join(' · ')) : '';
}}

function extractHighlightsClient(it) {{
  // 所有分支都从这里出，保证亮点既不复述 problem 也不互相复述
  const pack = (rawProblem, rawHl, rawWho) => {{
    const problem = clampText(rawProblem, PITCH_MAX);
    const highlights = [];
    for (const raw of (rawHl || [])) {{
      const text = String(raw ?? '').trim();
      if (!text || isFillerHighlight(text)) continue;
      if (dupText(text, problem)) continue;
      if (highlights.some(x => dupText(x, text))) continue;
      highlights.push(text);
      if (highlights.length >= 4) break;
    }}
    // 真 skill 抽不出亮点时「去看 SKILL.md」还算真话；知识库条目没有 SKILL.md，宁可空着
    if (!highlights.length && hasSkillDoc(it)) highlights.push(tr('fallbackHl'));
    const whoFor = String(rawWho ?? '').trim();
    return {{
      problem,
      highlights,
      whoFor: (whoFor && !dupText(whoFor, problem)) ? whoFor : '',
    }};
  }};
  // 优先用离线生成的双语人话字段；没有才退回从 md 里抽行
  const humanLine = pickText(it, 'one_liner');
  const humanHl = pickList(it, 'highlights');
  if (humanLine && humanHl.length) {{
    return pack(humanLine, humanHl, pickText(it, 'who_for'));
  }}
  if (Array.isArray(it.highlights) && it.highlights.length && it.problem) {{
    return pack(preferFuller(it.problem, it.description || it.one_liner), it.highlights, pickText(it, 'who_for'));
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
  const problem = desc || paras[0] || headings[0] || (it.name || 'Skill');
  return pack(problem, bullets.concat(headings).concat(paras.slice(1)), pickText(it, 'who_for'));
}}

function cardHtml(it, idx) {{
  const url = it.url || ('https://github.com/' + it.full_name);
  const fn = it.full_name || '';
  const pal = paletteFor(fn || it.name || String(idx));
  const stars = (it.stars == null) ? '—' : Number(it.stars).toLocaleString();
  const tips = extractHighlightsClient(it);
  const cover = it.cover_url || (fn ? ('https://opengraph.githubassets.com/1/' + fn) : '');
  const skillUrl = it.skill_url || (it.skill_path ? ('https://github.com/' + fn + '/blob/HEAD/' + it.skill_path) : url);
  const isLiked = liked.has(fn);
  const isSaved = saved.has(fn);
  const focus = demo.focus === idx ? 'focus' : '';
  const owner = it.owner || (fn.split('/')[0] || 'skill');
  const softCls = it.soft ? ' soft' : '';
  const noCoverCls = cover ? '' : ' no-cover';
  const sceneId = it.scene || '';
  // 分类徽章用场景色实心底。它压在任意封面图上，所以不能靠半透明黑——
  // pal[1] 十套都过了白字 4.5:1，实心底才是可预测的那一种
  const scenePal = paletteForScene(sceneId);
  const hl = tips.highlights.map(h => `<li>${{escapeHtml(h)}}</li>`).join('');
  const headName = it.name || fn;
  const pitchText = tips.problem || headName;
  // 顶部作者行带头像、@owner 和关注按钮，是导航锚点删不掉；封面兜底层的大字与描述
  // 只是同一份 name / problem 的第二遍，当前数据下必然重复，所以留正文那一份
  const coverTitleRaw = it.name || fn;
  const coverTitle = sameText(coverTitleRaw, headName) ? '' : coverTitleRaw;
  const coverDescRaw = clampText(pitchText, 120);
  const coverDesc = dupText(coverDescRaw, pitchText) ? '' : coverDescRaw;
  const bareCoverCls = (coverTitle || coverDesc) ? '' : ' bare';
  // 头像与作者行点的是同一个「打开发布者」。头像只是重复的鼠标热区，所以挂
  // aria-hidden + tabindex=-1：继续可点，但不占 Tab 序、读屏也不重复播报一遍。
  return `<article class="post ${{it.from_corpus ? 'corpus' : ''}}${{softCls}} ${{focus}}" id="post-${{idx}}"
      data-fn="${{escapeHtml(fn)}}" data-src="${{escapeHtml(it.source || '')}}"
      data-scene="${{escapeHtml(sceneId)}}" data-l2="${{escapeHtml(it.scene_l2 || '')}}"
      data-owner="${{escapeHtml(owner)}}"
      data-fc="${{it.from_corpus ? '1' : '0'}}">
    <div class="post-head">
      <button type="button" class="avatar clickable js-publisher" data-owner="${{escapeHtml(owner)}}" tabindex="-1" aria-hidden="true"><span><b style="background:${{pal[1]}};color:${{readableOn(pal[1])}}">${{escapeHtml(initials(owner))}}</b></span></button>
      <button type="button" class="who clickable js-publisher" data-owner="${{escapeHtml(owner)}}" title="${{escapeHtml(tr('viewPublisher'))}}">
        <span class="name">${{escapeHtml(headName)}}</span>
        <span class="sub">@${{escapeHtml(owner)}} · ${{escapeHtml(sourceLabel(it.source))}} · ★ ${{stars}}</span>
      </button>
    </div>
    <div class="media js-media${{noCoverCls}}${{bareCoverCls}}" data-idx="${{idx}}">
      ${{cover ? `<img class="cover" src="${{escapeHtml(safeUrl(cover))}}" alt="${{escapeHtml(headName)}}" loading="lazy" referrerpolicy="no-referrer" />` : ''}}
      ${{(coverTitle || coverDesc) ? `<div class="cover-fallback">
        ${{coverTitle ? `<div class="t">${{escapeHtml(coverTitle)}}</div>` : ''}}
        ${{coverDesc ? `<div class="d">${{escapeHtml(coverDesc)}}</div>` : ''}}
      </div>` : ''}}
      <div class="badges">
        <button type="button" class="badge scene ${{IS_LITE ? 'clickable js-scene-filter' : 'clickable js-scene-tag'}}" data-scene="${{escapeHtml(sceneId)}}" style="background:${{scenePal[1]}}" title="${{escapeHtml(IS_LITE ? tr('filterByScene') : tr('followScene'))}}">${{escapeHtml(itemSceneLabel(it))}}</button>
        ${{itemSceneL2Label(it) ? `<span class="badge">${{escapeHtml(itemSceneL2Label(it))}}</span>` : ''}}
        ${{it.from_corpus ? `<span class="badge kb">${{escapeHtml(tr('kb'))}}</span>` : ''}}
        ${{it.soft ? `<span class="badge soft">${{escapeHtml(tr('lead'))}}</span>` : ''}}
        ${{localBadgeHtml(it)}}
      </div>
      <div class="heart-burst" id="burst-${{idx}}">${{heartSvg(true)}}</div>
    </div>
    <div class="pitch">
      <div class="problem"><em>${{escapeHtml(tr('solves'))}}</em>${{escapeHtml(pitchText)}}</div>
      ${{hl ? `<ul class="highlights">${{hl}}</ul>` : ''}}
      ${{tips.whoFor ? `<div class="who-for"><em>${{escapeHtml(tr('forWho'))}}</em>${{escapeHtml(tips.whoFor)}}</div>` : ''}}
    </div>
    <div class="actions">
      <div class="actions-left">
        <button class="act js-like ${{isLiked ? 'liked' : ''}}" type="button" data-fn="${{escapeHtml(fn)}}" aria-label="${{escapeHtml(tr(isLiked ? 'likedAria' : 'likeAria'))}}">${{heartSvg(isLiked)}}</button>
        <button class="act js-bad" type="button" aria-label="${{escapeHtml(tr('badAria'))}}" title="${{escapeHtml(tr('notUseful'))}}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3zM17 2h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"/></svg>
        </button>
      </div>
      <button class="act js-save ${{isSaved ? 'saved' : ''}}" type="button" aria-label="${{escapeHtml(tr(isSaved ? 'savedAria' : 'saveAria'))}}">${{bookmarkSvg(isSaved)}}</button>
    </div>
    <div class="open-row{install_row_cls}"><a class="open-gh js-open" href="${{escapeHtml(safeUrl(hasSkillDoc(it) ? skillUrl : url))}}" target="_blank" rel="noopener">${{escapeHtml(tr('openGithub'))}}</a>{install_slot}</div>
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
          <div class="meta">${{escapeHtml(itemSceneLabel(it))}} · ★ ${{stars}} · ${{escapeHtml(tr('inFeed'))}}</div>
        </div>`;
      }}).join('')
    : `<p class="lead" style="color:var(--muted);font-size:.85rem">${{escapeHtml(tr('pubNoOtherSkills'))}}</p>`;
  let ghHtml = '';
  if (ghRepos === undefined || ghRepos === null) {{
    ghHtml = `<p class="lead" style="color:var(--muted);font-size:.85rem">${{escapeHtml(tr('pubLoadingRepos'))}}</p>`;
  }} else if (!ghRepos.length) {{
    ghHtml = `<p class="lead" style="color:var(--muted);font-size:.85rem">${{escapeHtml(tr('pubNoRepos'))}}</p>`;
  }} else {{
    ghHtml = ghRepos.map(r => `<a class="pub-item" href="${{escapeHtml(safeUrl(r.url))}}" target="_blank" rel="noopener" style="display:block;text-decoration:none;color:inherit">
      <strong>${{escapeHtml(r.name)}}</strong>
      <p>${{escapeHtml((r.description || tr('noDescription')).slice(0, 140))}}</p>
      <div class="meta">★ ${{Number(r.stars || 0).toLocaleString()}}${{r.language ? ' · ' + escapeHtml(r.language) : ''}} · GitHub</div>
    </a>`).join('');
  }}
  const followed = isFollowingBuilder(owner);
  return `<div class="pub-panel">
    <div class="pub-head">
      <div class="ava" style="background:${{pal[1]}};color:${{readableOn(pal[1])}}">${{escapeHtml(initials(owner))}}</div>
      <div>
        <h2>@${{escapeHtml(owner)}}</h2>
        <p>${{escapeHtml(trn('pubSub', {{ n: local.length }}))}}</p>
        ${{IS_LITE ? '' : `<p style="margin-top:6px;color:var(--ink)">${{tr('pubFollowNote')}}</p>`}}
      </div>
    </div>
    <div class="pub-actions">
      ${{IS_LITE ? '' : `<button type="button" class="js-follow-builder ${{followed ? 'following' : 'primary'}}" data-owner="${{escapeHtml(owner)}}">${{escapeHtml(followed ? tr('followedTapUndo') : tr('followBuilder'))}}</button>`}}
      <button type="button" class="js-pub-back">${{escapeHtml(tr('backToFeed'))}}</button>
      <a href="https://github.com/${{escapeHtml(owner)}}" target="_blank" rel="noopener">${{escapeHtml(tr('openGithubHome'))}}</a>
      <a href="https://github.com/${{escapeHtml(owner)}}?tab=repositories" target="_blank" rel="noopener">${{escapeHtml(tr('allRepos'))}}</a>
    </div>
    <div class="pub-sec">${{escapeHtml(tr('pubSecFeed'))}}</div>
    ${{localHtml}}
    <div class="pub-sec">${{escapeHtml(tr('pubSecGithub'))}}</div>
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
  const nFollow = followBuilders.size + followIndustries.size;
  // 没关注任何人时圆环只有两个「+」，七个角色都说这是空货架占门口。
  // 加关注的入口留在「我的」，首屏不再教一套还没发生的社交。
  wrap.classList.toggle('hidden', hide || nFollow === 0);
  if (hide || nFollow === 0) {{ el.innerHTML = ''; return; }}

  const rings = [];
  if (nFollow > 0) {{
    rings.push({{
      kind: 'following', value: 'all', label: tr('ringFollowing'), face: '★',
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
  rings.push({{ kind: 'guide', value: 'builder', label: tr('addBuilder'), face: '+', cls: 'guide' }});
  rings.push({{ kind: 'guide', value: 'industry', label: tr('addIndustry'), face: '+', cls: 'guide' }});

  el.innerHTML = rings.map(st => {{
    // 关注的行业圆环取该行业的分类色，和卡片徽章、行业 sheet 对上；
    // 关注的发布者没有分类，仍走身份哈希
    const pal = st.kind === 'industry'
      ? paletteForScene(st.value)
      : paletteFor(st.kind + ':' + st.value);
    const faceBg = st.cls === 'guide'
      ? ''
      : `style="background:linear-gradient(135deg,${{pal[0]}},${{pal[2]}})"`;
    // face 是 label 的缩写/图形化重复（引导圆环上两边都是 '+'，读屏会念成
    // 「+ + Builder」），所以整个圆环对无障碍树隐藏，可及名字只留 label
    return `<button type="button" class="story ${{st.cls || ''}} ${{st.hot ? 'hot' : ''}}" data-kind="${{escapeHtml(st.kind)}}" data-value="${{escapeHtml(st.value)}}" title="${{escapeHtml(st.kind === 'guide' ? tr('storyGuide') : tr('storyView'))}}">
      <div class="ring" aria-hidden="true"><div class="face"><i ${{faceBg}}>${{escapeHtml(st.face)}}</i></div></div>
      <span class="label">${{escapeHtml(st.label)}}</span>
    </button>`;
  }}).join('');
}}

function sceneOptions() {{
  const rows = SCENES.filter(s => countScene(s.id) > 0)
    .map(s => ({{ id: s.id, label: chipLabel(s) }}));
  if (!rows.length) return [];
  return [{{ id: 'all', label: tr('allScenes') }}].concat(rows);
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
      <div class="feide-wrap"><img class="feide" src="data:image/png;base64,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" alt="feide" /></div>
      <h2>${{escapeHtml(tr('emptySavedTitle'))}}</h2>
      <p>${{escapeHtml(tr('emptySavedBody'))}}</p>
    </div>`;
  }}
  const packed = compressIntent(state.intent);
  const intent = packed.query || (state.intent || '').trim();
  const gh = githubSearchUrls(intent);
  const intentLine = intent
    ? `<p>${{trn('emptyWithIntent', {{ q: escapeHtml(intent) }})}}</p>`
    : `<p>${{tr('emptyNoIntent')}}</p>`;
  return `<div class="empty">
    <div class="feide-wrap"><img class="feide" src="data:image/png;base64,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" alt="feide" /></div>
    <h2>${{escapeHtml(tr('emptyTitle'))}}</h2>
    ${{intentLine}}
    <p style="margin:14px 0 10px;display:flex;flex-wrap:wrap;gap:8px;justify-content:center">
      <a class="open-gh" style="display:inline-block;padding:10px 16px;width:auto;min-width:180px" href="${{escapeHtml(safeUrl(gh.code))}}" target="_blank" rel="noopener">${{escapeHtml(tr('ghSearchCode'))}}</a>
      <a class="open-gh" style="display:inline-block;padding:10px 16px;width:auto;min-width:180px;background:#fff;color:var(--ink);border:1px solid var(--line)" href="${{escapeHtml(safeUrl(gh.repos))}}" target="_blank" rel="noopener">${{escapeHtml(tr('ghSearchRepos'))}}</a>
    </p>
    <p style="font-size:.78rem;color:var(--muted)">${{escapeHtml(tr('noInstallNote'))}}</p>
    <p style="font-size:.72rem;color:var(--muted);margin-top:12px">${{escapeHtml(tr('funnel'))}}trending ${{funnel.trending_repos ?? '—'}} · search ${{funnel.search_candidates ?? '—'}} ·
      ${{escapeHtml(tr('funnelPassed'))}} ${{funnel.passed ?? (FEED.gates && FEED.gates.passed) ?? 0}}
      · rejected ${{escapeHtml(JSON.stringify(rejected))}}</p>
  </div>`;
}}

/* ---------- 四个入口：形态判定 ---------- */
/* 三种运行形态的判据全部由已有信号推出来，不新造探测：
     IS_LITE   —— 生成时就定了（skill-picker 的发现子页，按产品约定无关注/发布/后台）
     API_BASE  —— FEED.ui.api_base，publish-site 从 SKILLFEED_PUBLIC_URL 写进来
     同源与否  —— API_BASE 的 origin 和本页 origin 比
   为什么要分「同源」这一档：会话 Cookie 是 SameSite=Lax，跨站的 fetch 根本带不上
   它，所以 Pages 镜像即使配了 api_base 也读不到登录态。那一档只给整页跳转的入口，
   不摆一个永远显示「未登录」的账户页。 */
function apiSameOrigin() {{
  if (!API_BASE) return false;
  try {{
    const base = typeof document !== 'undefined' ? document.baseURI : '';
    return new URL(API_BASE).origin === new URL(base).origin;
  }} catch (e) {{
    return false;
  }}
}}

function accountMode() {{
  if (IS_LITE) return 'off';
  if (!API_BASE) return 'local';
  return apiSameOrigin() ? 'live' : 'linked';
}}

/* ---------- 四个入口：URL 可寻址 ---------- */
/* tab= 存稳定英文标识而不是展示文案：切语言不会让分享出去的链接失效。
   已有的 ?q= / ?intent= / ?demo=1 照旧，这里只多认一个键。 */
function tabAllowed(mode) {{
  if (!Object.prototype.hasOwnProperty.call(TAB_QUERY, mode)) return false;
  // 试用期对外只做信息流：发布整条链路先关。?tab=publish 也不能把它逼出来。
  // 代码和 /publish 后端都留着，下一期接微信登录后再开入口。
  if (mode === 'publish') return false;
  // lite 是 skill-picker 发现子页，按产品约定不含关注/个人后台
  if (IS_LITE) return mode === 'all' || mode === 'topics';
  return true;
}}

function tabFromQuery(search) {{
  let want = '';
  try {{
    want = (new URLSearchParams(search || '').get('tab') || '').trim().toLowerCase();
  }} catch (e) {{
    want = '';
  }}
  if (!want) return '';
  for (const mode of Object.keys(TAB_QUERY)) {{
    if (TAB_QUERY[mode] === want && tabAllowed(mode)) return mode;
  }}
  return '';
}}

/* saved / publisher 不是独立 tab，但用户是从某个 tab 钻进去的，
   高亮要留在那个 tab 上，不能四个都灭 */
function tabForMode(mode) {{
  if (mode === 'saved') return 'me';
  if (mode === 'publisher') return 'all';
  return tabAllowed(mode) ? mode : 'all';
}}

/* 纯函数，好测：给定当前 query 和目标 tab，算出新的 query 串 */
function tabSearch(search, mode) {{
  let params;
  try {{
    params = new URLSearchParams(search || '');
  }} catch (e) {{
    params = new URLSearchParams('');
  }}
  const tab = tabForMode(mode);
  if (tab === 'all') params.delete('tab');
  else params.set('tab', TAB_QUERY[tab]);
  if (tab === 'all' && state.scene && state.scene !== 'all') params.set('scene', state.scene);
  else params.delete('scene');
  if (tab === 'all' && state.scene_l2 && state.scene_l2 !== 'all') params.set('l2', state.scene_l2);
  else params.delete('l2');
  const q = params.toString();
  return q ? ('?' + q) : '';
}}

function syncTabUrl() {{
  // replaceState 而不是 pushState：要的是「刷新/分享不丢当前 tab」，
  // 不是把每次点 tab 都塞进后退栈
  if (typeof history === 'undefined' || !history.replaceState) return;
  if (typeof location === 'undefined') return;
  try {{
    history.replaceState(null, '', location.pathname
      + tabSearch(location.search, state.mode) + location.hash);
  }} catch (e) {{ /* file:// 下 replaceState 会抛，不影响页面 */ }}
}}

function tabButtons() {{
  const all = Array.from(document.querySelectorAll('#tabBar .nav'));
  return all.filter(b => tabAllowed(b.dataset.mode || ''));
}}

function renderTabs() {{
  const active = tabForMode(state.mode);
  const feed = document.getElementById('feed');
  document.querySelectorAll('#tabBar .nav').forEach(n => {{
    const mode = n.dataset.mode || '';
    const on = mode === active;
    n.classList.toggle('on', on);
    n.setAttribute('aria-selected', on ? 'true' : 'false');
    // roving tabindex：tablist 整体只占一个 Tab 位，内部用左右键走
    n.setAttribute('tabindex', on ? '0' : '-1');
    if (on && feed) feed.setAttribute('aria-labelledby', n.id || 'tab-all');
  }});
}}

function switchTab(mode, opts) {{
  if (!tabAllowed(mode)) return;
  state.mode = mode;
  if (mode === 'all') state.section = 'all';
  state.shown = 0;
  render(true);
  syncTabUrl();
  if (!(opts && opts.keepScroll)) scrollToTop();
}}

/* 键盘：左右键在 tab 之间走、Home/End 到两端。这是 role=tablist 的既定交互，
   不给的话 roving tabindex 反而让键盘用户只能停在当前那一个 tab 上。 */
function tabKeyTarget(key, current) {{
  const modes = tabButtons().map(b => b.dataset.mode || '');
  if (!modes.length) return '';
  const at = Math.max(0, modes.indexOf(tabForMode(current)));
  if (key === 'ArrowRight') return modes[(at + 1) % modes.length];
  if (key === 'ArrowLeft') return modes[(at - 1 + modes.length) % modes.length];
  if (key === 'Home') return modes[0];
  if (key === 'End') return modes[modes.length - 1];
  return '';
}}

/* ---------- 回到顶部 ---------- */
/* 阈值一屏：低于这个值按钮会在几乎没滚的时候就冒出来，挡住第一张卡的操作行 */
function shouldShowToTop(scrollY, viewportH) {{
  return Number(scrollY || 0) > Math.max(240, Number(viewportH || 0));
}}

function prefersReducedMotion() {{
  try {{
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }} catch (e) {{
    return false;
  }}
}}

/* 减少动态偏好下直接跳：平滑滚动本身就是这条偏好要关掉的那类动画 */
function scrollTopBehavior() {{
  return prefersReducedMotion() ? 'auto' : 'smooth';
}}

function scrollToTop() {{
  window.scrollTo({{ top: 0, behavior: scrollTopBehavior() }});
}}

function syncToTop() {{
  const btn = document.getElementById('toTop');
  if (!btn) return;
  // 用 hidden 而不是 opacity：隐藏时要一起退出 Tab 序和无障碍树
  btn.hidden = !shouldShowToTop(window.scrollY || window.pageYOffset || 0, window.innerHeight || 0);
}}

/* ---------- 主题分类 ---------- */
function countSceneL2(sceneId, l2Id) {{
  return allPool().filter(it =>
    (it.scene || 'other') === sceneId && (it.scene_l2 || '') === l2Id
  ).length;
}}

function topicRows() {{
  return SCENES
    .map(s => {{
      const n = countScene(s.id);
      const kids = (SCENES_L2[s.id] || [])
        .map(k => ({{ id: k.id || k[0], label: chipLabel(k), n: countSceneL2(s.id, k.id || k[0]) }}))
        .filter(k => k.n > 0);
      return {{ id: s.id, label: chipLabel(s), n, kids }};
    }})
    .filter(r => r.n > 0)
    .sort((a, b) => b.n - a.n);
}}

function topicsPanelHtml() {{
  const rows = topicRows();
  if (!rows.length) {{
    return `<div class="topics-panel"><h2>${{escapeHtml(tr('topicsTitle'))}}</h2>
      <p class="lead">${{escapeHtml(tr('topicsEmpty'))}}</p></div>`;
  }}
  const cards = rows.map(r => {{
    const pal = paletteForScene(r.id);
    const count = r.kids.length
      ? trn('topicsCount', {{ n: r.n, k: r.kids.length }})
      : trn('topicsCountNoL2', {{ n: r.n }});
    const kids = r.kids.length
      ? `<div class="topic-l2">` + r.kids.map(k =>
          `<button type="button" class="pill js-topic" data-scene="${{escapeHtml(r.id)}}" data-l2="${{escapeHtml(k.id)}}">${{escapeHtml(k.label)}} · ${{k.n}}</button>`
        ).join('') + `</div>`
      : `<p class="topic-none">${{escapeHtml(tr('topicsNoL2'))}}</p>`;
    return `<div class="topic-card">
      <button type="button" class="topic-head js-topic" data-scene="${{escapeHtml(r.id)}}" data-l2="all">
        <span class="dot" aria-hidden="true" style="background:linear-gradient(180deg,${{pal[0]}},${{pal[2]}})"></span>
        <span class="meta"><b>${{escapeHtml(r.label)}}</b><span>${{escapeHtml(count)}}</span></span>
        <span class="go">${{escapeHtml(tr('topicsBrowse'))}}</span>
      </button>
      ${{kids}}
    </div>`;
  }}).join('');
  const secs = sectionOptions().filter(s => s.id !== 'all');
  const sections = secs.length
    ? `<div class="sec">${{escapeHtml(tr('topicsSecSection'))}}</div>
       <div class="topic-l2">` + secs.map(s =>
         `<button type="button" class="pill js-topic-section" data-id="${{escapeHtml(s.id)}}">${{escapeHtml(s.label)}} · ${{countSection(s.id)}}</button>`
       ).join('') + `</div>`
    : '';
  return `<div class="topics-panel">
    <h2>${{escapeHtml(tr('topicsTitle'))}}</h2>
    <p class="lead">${{escapeHtml(tr('topicsLead'))}}</p>
    ${{cards}}
    ${{sections}}
  </div>`;
}}

function goTopic(sceneId, l2Id) {{
  state.mode = 'all';
  state.publisher = '';
  state.scene = sceneId || 'all';
  state.scene_l2 = (l2Id && l2Id !== 'all') ? l2Id : 'all';
  state.section = 'all';
  state.shown = 0;
  render(true);
  syncTabUrl();
  scrollToTop();
}}

/* ---------- 发布 ---------- */
function loginUrl() {{
  return API_BASE ? (API_BASE + LOGIN_PATH) : '';
}}

function publishFormHtml() {{
  const msg = ACCT.user === null && ACCT.loaded
    ? `<p class="pub-msg err" id="pubMsg">${{escapeHtml(tr('publishNeedLogin'))}}</p>`
    : `<p class="pub-msg" id="pubMsg"></p>`;
  const login = loginUrl();
  return `<form class="pub-form" id="pubForm">
    <label for="pubTitle">${{escapeHtml(tr('publishFieldTitle'))}}</label>
    <input id="pubTitle" name="title" type="text" maxlength="120" autocomplete="off">
    <label for="pubUrl">${{escapeHtml(tr('publishFieldUrl'))}}</label>
    <input id="pubUrl" name="github_url" type="url" inputmode="url" placeholder="https://github.com/owner/repo" autocomplete="off">
    <label for="pubDesc">${{escapeHtml(tr('publishFieldDesc'))}}</label>
    <input id="pubDesc" name="description" type="text" maxlength="200" autocomplete="off">
    <label for="pubBody">${{escapeHtml(tr('publishFieldBody'))}}</label>
    <textarea id="pubBody" name="body_md" maxlength="20000"></textarea>
    <p class="hint">${{escapeHtml(tr('publishHint'))}}</p>
    ${{msg}}
    <div class="me-actions">
      <button type="submit" class="primary" id="pubSubmit">${{escapeHtml(tr('publishSubmit'))}}</button>
      ${{login ? `<a href="${{escapeHtml(safeUrl(login))}}">${{escapeHtml(tr('publishLoginBtn'))}}</a>` : ''}}
      <a href="${{escapeHtml(safeUrl(API_BASE + '/publish'))}}" target="_blank" rel="noopener">${{escapeHtml(tr('publishOpenPage'))}}</a>
    </div>
  </form>`;
}}

function publishPanelHtml() {{
  const mode = accountMode();
  const head = `<h2>${{escapeHtml(tr('publishTitle'))}}</h2>
    <p class="lead">${{tr('publishLead')}}</p>`;
  if (mode === 'local' || mode === 'off') {{
    // 没有后端就不摆按钮：点了没反应比没有入口更糟
    return `<div class="me-panel">${{head}}
      <div class="me-card">
        <strong>${{escapeHtml(tr('publishNoBackendTitle'))}}</strong>
        <p>${{escapeHtml(tr('publishNoBackend'))}}</p>
      </div>
    </div>`;
  }}
  if (mode === 'linked') {{
    return `<div class="me-panel">${{head}}
      <div class="me-card">
        <strong>${{escapeHtml(tr('publishRemoteTitle'))}}</strong>
        <p>${{escapeHtml(tr('publishRemote'))}}</p>
        <div class="me-actions">
          <a class="primary" href="${{escapeHtml(safeUrl(API_BASE + '/publish'))}}" target="_blank" rel="noopener">${{escapeHtml(tr('publishOpenPage'))}}</a>
        </div>
      </div>
    </div>`;
  }}
  return `<div class="me-panel">${{head}}
    <div class="me-card">${{publishFormHtml()}}</div>
  </div>`;
}}

/* ---------- 我的：服务端拉取 ---------- */
function acctFetch(path, opts) {{
  const init = Object.assign({{ credentials: 'include' }}, opts || {{}});
  return fetch(API_BASE + path, init);
}}

/* device_id 是客户端自铸的，凭据由服务端在**首次**见到它时下发一次、之后不补发，
   所以两个都得存住。丢了就只能换一个新 device_id 重新注册。 */
function deviceId() {{
  try {{
    let id = localStorage.getItem('sf_device_id');
    if (!id) {{
      id = 'web-' + Math.random().toString(36).slice(2) + Date.now().toString(36);
      localStorage.setItem('sf_device_id', id);
    }}
    return id;
  }} catch (e) {{
    return '';
  }}
}}

function deviceToken() {{
  try {{ return localStorage.getItem('sf_device_token') || ''; }} catch (e) {{ return ''; }}
}}

async function ensureDeviceToken() {{
  const id = deviceId();
  if (!id) return '';
  const have = deviceToken();
  if (have) return have;
  try {{
    // 凭据只随注册那一次的响应返回，而注册的唯一入口是带 X-Device-Id 打一次读接口。
    // source=ugc 是最便宜的一支（不去拉官方 feed）。
    const resp = await acctFetch('/api/feed?limit=1&source=ugc&unlock=0', {{
      headers: {{ 'Accept': 'application/json', 'X-Device-Id': id }},
    }});
    if (!resp.ok) return '';
    const data = await resp.json();
    const token = (data && data.device_token) || '';
    if (token) localStorage.setItem('sf_device_token', token);
    return token;
  }} catch (e) {{
    return '';
  }}
}}

async function loadAccount() {{
  if (accountMode() !== 'live' || ACCT.loading) return;
  ACCT.loading = true;
  try {{
    const resp = await acctFetch('/auth/me', {{ headers: {{ 'Accept': 'application/json' }} }});
    const data = resp.ok ? await resp.json() : null;
    ACCT.user = (data && data.user) || null;
    ACCT.quota = (data && data.quota) || null;
    ACCT.devAuth = !!(data && data.dev_auth);
  }} catch (e) {{
    ACCT.user = null;
    ACCT.quota = null;
    ACCT.devAuth = false;
  }}
  if (ACCT.user) {{
    try {{
      const resp = await acctFetch('/api/posts/me', {{ headers: {{ 'Accept': 'application/json' }} }});
      const data = resp.ok ? await resp.json() : null;
      ACCT.posts = (data && data.posts) || [];
    }} catch (e) {{
      ACCT.posts = [];
    }}
  }} else {{
    ACCT.posts = null;
  }}
  try {{
    const token = await ensureDeviceToken();
    if (token) {{
      const resp = await acctFetch('/api/profile/reactions', {{
        headers: {{
          'Accept': 'application/json',
          'X-Device-Id': deviceId(),
          'X-Device-Token': token,
        }},
      }});
      const data = resp.ok ? await resp.json() : null;
      if (data && data.ok) {{
        ACCT.remote = true;
        ACCT.liked = (data.liked || []).length;
        ACCT.saved = (data.saved || []).length;
      }}
    }}
  }} catch (e) {{ /* 赞藏读不到就退回本机计数 */ }}
  ACCT.loading = false;
  ACCT.loaded = true;
  if (state.mode === 'me' || state.mode === 'publish') render(false);
}}

async function submitPost(form) {{
  const btn = document.getElementById('pubSubmit');
  const msg = document.getElementById('pubMsg');
  const val = (id) => {{
    const el = document.getElementById(id);
    return el ? String(el.value || '').trim() : '';
  }};
  const body = {{
    title: val('pubTitle'),
    github_url: val('pubUrl'),
    description: val('pubDesc'),
    body_md: val('pubBody'),
  }};
  if (btn) {{ btn.disabled = true; btn.textContent = tr('publishSubmitting'); }}
  if (msg) {{ msg.className = 'pub-msg'; msg.textContent = ''; }}
  try {{
    const resp = await acctFetch('/api/posts', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json', 'Accept': 'application/json' }},
      body: JSON.stringify(body),
    }});
    let data = null;
    try {{ data = await resp.json(); }} catch (e) {{ data = null; }}
    if (resp.status === 401) {{
      if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('publishNeedLogin'); }}
      return;
    }}
    if (!resp.ok || !data || !data.ok) {{
      // 400 的 detail 是服务端逐字给的校验说明（描述太短 / 链接格式），照原样显示
      const why = (data && (data.detail || data.error)) || tr('publishFailed');
      if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = String(why); }}
      return;
    }}
    if (form && form.reset) form.reset();
    if (msg) {{ msg.className = 'pub-msg ok'; msg.textContent = tr('publishOkMsg'); }}
    toast(tr('publishOkMsg'));
    ACCT.posts = null;
    ACCT.loaded = false;
    loadAccount();
  }} catch (e) {{
    if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('publishFailed'); }}
  }} finally {{
    if (btn) {{ btn.disabled = false; btn.textContent = tr('publishSubmit'); }}
  }}
}}

async function logoutAccount() {{
  try {{
    await acctFetch('/auth/logout', {{ method: 'POST' }});
  }} catch (e) {{ /* 服务端不在也要把本地态清掉 */ }}
  ACCT.user = null;
  ACCT.posts = null;
  ACCT.loaded = true;
  toast(tr('acctLoggedOut'));
  render(false);
}}

function acctIdentityHtml() {{
  const mode = accountMode();
  if (mode === 'local') {{
    return `<div class="me-card">
      <strong>${{escapeHtml(tr('acctLocalTitle'))}}</strong>
      <p>${{escapeHtml(tr('acctLocalOnly'))}}</p>
    </div>`;
  }}
  if (mode === 'linked') {{
    return `<div class="me-card">
      <strong>${{escapeHtml(tr('acctAnonTitle'))}}</strong>
      <p>${{escapeHtml(tr('acctRemoteNote'))}}</p>
      <div class="me-actions">
        <a class="primary" href="${{escapeHtml(safeUrl(API_BASE + '/'))}}" target="_blank" rel="noopener">${{escapeHtml(tr('acctOpenSite'))}}</a>
      </div>
    </div>`;
  }}
  if (!ACCT.loaded) {{
    return `<div class="me-card"><p>${{escapeHtml(tr('acctChecking'))}}</p></div>`;
  }}
  if (!ACCT.user) {{
    const login = loginUrl();
    return `<div class="me-card">
      <strong>${{escapeHtml(tr('acctAnonTitle'))}}</strong>
      <p>${{escapeHtml(tr('acctAnon'))}}</p>
      <div class="me-actions">
        ${{login ? `<a class="primary" href="${{escapeHtml(safeUrl(login))}}">${{escapeHtml(tr('publishLoginBtn'))}}</a>` : ''}}
        <a href="${{escapeHtml(safeUrl(API_BASE + '/auth/github'))}}">${{escapeHtml(tr('meGithubLogin'))}}</a>
      </div>
    </div>`;
  }}
  const login = String(ACCT.user.login || '');
  const pal = paletteFor(login || 'me');
  const name = String(ACCT.user.name || '') || ('@' + login);
  return `<div class="me-card">
    <div class="acct-id">
      <span class="ava" aria-hidden="true" style="background:${{pal[1]}};color:${{readableOn(pal[1])}}">${{escapeHtml(initials(login))}}</span>
      <span class="meta"><b>${{escapeHtml(name)}}</b><span>@${{escapeHtml(login)}} · ${{escapeHtml(tr('acctSignedIn'))}}</span></span>
    </div>
    <div class="me-actions">
      <button type="button" class="js-acct-logout">${{escapeHtml(tr('acctLogout'))}}</button>
    </div>
  </div>`;
}}

function acctPostsHtml() {{
  const mode = accountMode();
  if (mode !== 'live') return '';
  let inner;
  if (!ACCT.loaded) inner = `<p>${{escapeHtml(tr('acctPostsLoading'))}}</p>`;
  else if (!ACCT.user) inner = `<p>${{escapeHtml(tr('acctPostsNeedLogin'))}}</p>`;
  else if (!ACCT.posts || !ACCT.posts.length) inner = `<p>${{escapeHtml(tr('acctNoPosts'))}}</p>`;
  else {{
    inner = ACCT.posts.map(p => `<div class="pub-item">
      <strong>${{escapeHtml(String(p.title || p.name || ''))}}</strong>
      <p>${{escapeHtml(String(p.description || '').slice(0, 160))}}</p>
      <div class="meta">${{escapeHtml(String(p.scene_label || ''))}} · ${{escapeHtml(String(p.status || ''))}} · ${{escapeHtml(String(p.created_at || '').slice(0, 19))}}</div>
    </div>`).join('');
  }}
  return `<div class="me-card">
    <strong>${{escapeHtml(tr('acctMyPosts'))}}</strong>
    <div style="margin-top:8px">${{inner}}</div>
  </div>`;
}}

function acctPlanHtml() {{
  const quota = ACCT.quota || (FEED.ui && FEED.ui.quota) || null;
  const u = ACCT.user || {{}};
  if (!u.id && !quota) return '';
  const sub = !!(u.subscriber || (quota && quota.unlimited));
  let body;
  if (sub) {{
    body = `<p>${{escapeHtml(tr('quotaSubscriber'))}}</p>`;
  }} else {{
    const left = quota ? quota.remaining : '?';
    const lim = quota ? quota.limit : 8;
    body = `<p>${{escapeHtml(trn('quotaFreeToday', {{ n: left, limit: lim }}))}}</p>
      <p>${{escapeHtml(tr('quotaSubscribeHint'))}}</p>
      <form id="meActivateForm" class="me-actions">
        <input id="meActivateCode" maxlength="64" placeholder="${{escapeHtml(tr('quotaCodePh'))}}">
        <button type="submit">${{escapeHtml(tr('quotaActivate'))}}</button>
      </form>
      <p id="meActivateMsg" class="pub-msg"></p>`;
  }}
  if (ACCT.devAuth) {{
    body += `<div class="me-actions" style="margin-top:8px">
      <button type="button" class="js-pay-dev">${{escapeHtml(tr('payDevBtn'))}}</button>
    </div>`;
  }}
  return `<div class="me-card"><strong>${{escapeHtml(tr('quotaTitle'))}}</strong>${{body}}</div>`;
}}

async function activateSubscription(form) {{
  const input = document.getElementById('meActivateCode');
  const msg = document.getElementById('meActivateMsg');
  const code = input ? String(input.value || '').trim() : '';
  if (!code) return;
  if (msg) {{ msg.className = 'pub-msg'; msg.textContent = ''; }}
  try {{
    const resp = await acctFetch('/api/account/activate', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json', 'Accept': 'application/json' }},
      body: JSON.stringify({{ code }}),
    }});
    let data = null;
    try {{ data = await resp.json(); }} catch (e) {{ data = null; }}
    if (!resp.ok || !data || !data.ok) {{
      if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('quotaActivateBad'); }}
      return;
    }}
    ACCT.user = data.user || ACCT.user;
    ACCT.quota = data.quota || ACCT.quota;
    FEED.ui = FEED.ui || {{}};
    FEED.ui.quota = ACCT.quota;
    toast(tr('quotaActivateOk'));
    hydrateLiveFeed();
    if (state.mode === 'me') render(false);
  }} catch (e) {{
    if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('quotaActivateBad'); }}
  }}
}}

async function payDevCheckout() {{
  const msg = document.getElementById('meActivateMsg');
  if (msg) {{ msg.className = 'pub-msg'; msg.textContent = ''; }}
  try {{
    const created = await acctFetch('/api/pay/create', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json', 'Accept': 'application/json' }},
      body: JSON.stringify({{ sku: 'subscriber_year' }}),
    }});
    const createdData = created.ok ? await created.json() : null;
    const tradeNo = createdData && createdData.order && createdData.order.out_trade_no;
    if (!created.ok || !tradeNo) {{
      if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('payDevFail'); }}
      return;
    }}
    const paid = await acctFetch('/api/pay/dev-notify', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json', 'Accept': 'application/json' }},
      body: JSON.stringify({{ out_trade_no: tradeNo }}),
    }});
    const paidData = paid.ok ? await paid.json() : null;
    if (!paid.ok || !paidData || !paidData.ok) {{
      if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('payDevFail'); }}
      return;
    }}
    ACCT.user = paidData.user || ACCT.user;
    ACCT.quota = paidData.quota || ACCT.quota;
    FEED.ui = FEED.ui || {{}};
    FEED.ui.quota = ACCT.quota;
    toast(tr('payDevOk'));
    hydrateLiveFeed();
    if (state.mode === 'me') render(false);
  }} catch (e) {{
    if (msg) {{ msg.className = 'pub-msg err'; msg.textContent = tr('payDevFail'); }}
  }}
}}

function paintQuotaBanner(quota) {{
  if (!quota) return;
  let host = document.getElementById('quotaBanner');
  if (!host) {{
    host = document.createElement('div');
    host.id = 'quotaBanner';
    host.className = 'lite-banner';
    const after = document.getElementById('previewBanner');
    if (after && after.parentNode) after.parentNode.insertBefore(host, after.nextSibling);
    else {{
      const top = document.querySelector('header') || document.body;
      top.insertBefore(host, top.firstChild);
    }}
  }}
  host.style.display = 'block';
  if (quota.unlimited) {{
    host.innerHTML = '<b>' + escapeHtml(tr('quotaSubscriber')) + '</b>';
    return;
  }}
  host.innerHTML = '<b>' + escapeHtml(trn('quotaFreeToday', {{
    n: quota.remaining, limit: quota.limit,
  }})) + '</b> · ' + escapeHtml(tr('quotaSubscribeHint'));
}}

async function hydrateLiveFeed() {{
  if (IS_LITE) return;
  if (location.protocol === 'file:') return;
  const base = API_BASE || '';
  try {{
    const resp = await fetch(base + '/api/feed?limit=100&source=all', {{
      credentials: 'include',
      redirect: 'manual',
      headers: {{ 'Accept': 'application/json' }},
    }});
    if (resp.type === 'opaqueredirect' || resp.status === 302 || !resp.ok) return;
    const data = await resp.json();
    if (!data || !Array.isArray(data.items)) return;
    FEED.items = data.items;
    FEED.ui = FEED.ui || {{}};
    FEED.ui.quota = data.quota || null;
    ACCT.quota = data.quota || ACCT.quota;
    paintQuotaBanner(data.quota);
    render(true);
  }} catch (e) {{}}
}}

function mePanelHtml() {{
  const nLiked = liked.size;
  const nSaved = saved.size;
  const builders = [...followBuilders];
  const industries = [...followIndustries];
  const unfollowAria = escapeHtml(tr('unfollowAria'));
  const builderChips = builders.length
    ? builders.map(o => `<span class="follow-chip">@${{escapeHtml(o)}} <button type="button" class="js-unfollow-builder" data-owner="${{escapeHtml(o)}}" aria-label="${{unfollowAria}}">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">${{escapeHtml(tr('meNoBuilders'))}}</p>`;
  const industryChips = industries.length
    ? industries.map(id => `<span class="follow-chip">${{escapeHtml(sceneLabelOf(id))}} <button type="button" class="js-unfollow-industry" data-scene="${{escapeHtml(id)}}" aria-label="${{unfollowAria}}">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">${{escapeHtml(tr('meNoIndustries'))}}</p>`;
  // 云端赞藏读到了就以它为准，读不到（无后端 / 埋点链路还没接）才退回本机计数。
  // 两句文案不同，用户能看出这个数是从哪来的。
  const counts = ACCT.remote
    ? escapeHtml(trn('acctServerCounts', {{ liked: ACCT.liked, saved: ACCT.saved }}))
    : escapeHtml(trn('acctLocalCounts', {{ liked: nLiked, saved: nSaved }}));
  const countsNote = (accountMode() === 'live' && !ACCT.remote)
    ? `<p>${{escapeHtml(tr('acctReactionsPending'))}}</p>` : '';
  return `<div class="me-panel">
    <h2>${{escapeHtml(tr('acctTitle'))}}</h2>
    <p class="lead">${{tr('meLead')}}</p>
    ${{acctIdentityHtml()}}
    ${{acctPlanHtml()}}
    ${{acctPostsHtml()}}
    <div class="me-card">
      <strong>${{escapeHtml(tr('meLocalTitle'))}}</strong>
      <p>${{counts}}</p>
      ${{countsNote}}
      <div class="me-actions">
        <button type="button" class="primary js-me-saved">${{escapeHtml(tr('meViewSaved'))}}</button>
      </div>
    </div>
    <div class="me-card">
      <strong>${{escapeHtml(tr('meMyBuilders'))}}</strong>
      <div style="margin-top:8px">${{builderChips}}</div>
      <div class="me-actions">
        <button type="button" class="primary js-me-find-builder">${{escapeHtml(tr('sheetBuilderTitle'))}}</button>
      </div>
    </div>
    <div class="me-card">
      <strong>${{escapeHtml(tr('meMyIndustries'))}}</strong>
      <div style="margin-top:8px">${{industryChips}}</div>
      <div class="me-actions">
        <button type="button" class="primary js-me-find-industry">${{escapeHtml(tr('sheetIndustryTitle'))}}</button>
      </div>
    </div>
    <div class="me-card">
      <strong>${{escapeHtml(tr('meAboutTitle'))}}</strong>
      <p>${{escapeHtml(tr('meAboutBody'))}}</p>
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
  renderIntentKeys();
  renderStories();

  const hideChrome = state.mode === 'me' || state.mode === 'publisher'
    || state.mode === 'topics' || state.mode === 'publish';
  const scenes = sceneOptions();
  const secs = sectionOptions();
  const l2s = l2Options();
  // 场景 / 二级场景 / 栏目这三排 chips 搬到「主题分类」tab 去了。这里只在真的筛着
  // 的时候才长出来，此时它们的作用是「看清在筛什么、并且能清掉」——每排都带一个
  // 「全部…」。不筛的时候首屏因此省掉约 120px 控件，第一张卡直接进视口。
  const showFilters = !hideChrome && (state.scene !== 'all' || state.section !== 'all');
  renderPills(document.getElementById('sceneStrip'), scenes, 'scene', showFilters && scenes.length > 0);
  renderPills(document.getElementById('l2Strip'), l2s, 'scene_l2', showFilters && l2s.length > 0);
  renderPills(document.getElementById('sectionStrip'), secs, 'section', showFilters && secs.length > 0);

  renderTabs();

  document.getElementById('searchWrap').style.display = hideChrome ? 'none' : '';

  if (state.mode === 'topics') {{
    feed.innerHTML = topicsPanelHtml();
    return;
  }}
  if (state.mode === 'publish') {{
    feed.innerHTML = publishPanelHtml();
    return;
  }}
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
  noteShownPositions(slice, reset);
  feed.innerHTML = slice.map((it, idx) => cardHtml(it, idx)).join('') +
    `<div class="sentinel" id="sentinel">${{
      state.shown < items.length
        ? trn('moreShown', {{ n: state.shown, total: items.length }})
        : trn('allDone', {{ total: items.length }})
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

function rotateSessionSeed() {{
  const s = 's' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  try {{ sessionStorage.setItem('sf_session_seed', s); }} catch (e) {{}}
  return s;
}}

function reshuffleFeed() {{
  if (['me', 'topics', 'publish', 'publisher', 'saved'].includes(state.mode)) {{
    state.mode = 'all';
    state.publisher = '';
  }}
  const shown = filtered().slice(0, Math.max(state.shown || 0, PAGE));
  for (const it of shown) {{
    const k = itemKey(it);
    if (k) batchSkip.add(k);
  }}
  rotateSessionSeed();
  if (filtered().length < Math.min(PAGE, 3)) {{
    const keep = new Set(shown.map(it => itemKey(it)).filter(Boolean));
    batchSkip.clear();
    keep.forEach(k => batchSkip.add(k));
  }}
  state.shown = 0;
  try {{ window.scrollTo({{ top: 0, behavior: 'smooth' }}); }} catch (e) {{}}
  render(true);
  toast(tr('reshuffleToast'));
  const btn = document.getElementById('btnRefresh');
  if (btn) {{
    btn.classList.remove('spin');
    void btn.offsetWidth;
    btn.classList.add('spin');
  }}
  return true;
}}

function hideItem(fn, card) {{
  if (!fn) return false;
  hidden.add(fn);
  persistSet('sf_hidden', hidden);
  if (liked.delete(fn)) persistSet('sf_liked', liked);
  if (saved.delete(fn)) persistSet('sf_saved', saved);
  const payload = card ? itemPayload(card) : {{ full_name: fn }};
  sendFeedback('bad', payload, {{ silent: true }});
  toast(tr('notUsefulToast'));
  if (card && card.classList) card.classList.add('leaving');
  return true;
}}

/* —— 动态全屏（.story-viewer） —— */
function stopSvTimer() {{
  if (sv.timer) clearTimeout(sv.timer);
  sv.timer = null;
}}

function sceneGradient(it) {{
  // 有 scene 就用分类色——全屏 story 的背景是这张卡属于哪一类的最大一块面积。
  // 没有 scene 才退回名字哈希，免得全部落成 other 的灰蓝一片
  const pal = it.scene
    ? paletteForScene(it.scene)
    : paletteFor(it.full_name || it.name || 'x');
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
    img.src = safeUrl(cover);
  }} else {{
    wrap.style.display = 'none';
  }}

  // 摘要和行业徽标都走卡片那一套取词，全屏卡才不会和它下面的卡片语言不一致
  const tips = extractHighlightsClient(it);
  const excerpt = (tips.problem || it.body_preview || it.description || '').trim().slice(0, 280);
  const chips = [
    itemSceneLabel(it),
    itemSceneL2Label(it),
    it.from_corpus ? tr('kb') : '',
    it.soft ? tr('lead') : '',
  ].filter(Boolean).map(c => `<span class="chip">${{escapeHtml(c)}}</span>`).join('');
  document.getElementById('svContent').innerHTML =
    `<div class="chips">${{chips}}</div>` +
    `<h2>${{escapeHtml(it.name || fn)}}</h2>` +
    `<p>${{escapeHtml(excerpt)}}</p>` +
    `<div class="meta">★ ${{stars}} · ${{escapeHtml(sourceLabel(it.source))}} · ${{escapeHtml(fn)}}</div>`;
  const url = it.url || ('https://github.com/' + fn);
  const cta = document.getElementById('svCta');
  cta.href = safeUrl(url);
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
    label = tr('storyFollowing');
    items = followingItems(8);
  }} else if (kind === 'builder') {{
    label = '@' + value;
    items = builderItems(value, 5);
  }} else if (kind === 'industry' || kind === 'scene') {{
    label = sceneLabelOf(value);
    items = industryItems(value, 5);
  }}
  if (!items.length) {{
    toast(kind === 'guide' ? tr('storyGuideToast') : tr('storyEmptyToast'));
    return;
  }}
  sv.open = true;
  sv.scene = value || kind;
  sv.items = items;
  sv.idx = 0;
  document.getElementById('svWho').textContent = label + tr('storyWhoSuffix');
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
/* 演示用意图必须能被 INTENT_PHRASES / intentTokens 命中，否则 demo 走到搜索那步是空结果。
   'stop-slop' 和 '去AI味' 走的是同一组 token，两种语言下都有卡片。 */
function demoIntent() {{
  return LANG === 'en' ? 'stop-slop' : '写作 去AI味';
}}

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
  document.getElementById('demoText').textContent = tr('demoStopped');
}}

function demoTick() {{
  if (!demo.on) return;
  const steps = [
    () => {{
      document.getElementById('demoText').textContent = tr('demoFollowIndustry');
      state.mode = 'all';
      state.scene = 'all';
      state.scene_l2 = 'all';
      if (!isFollowingIndustry('content')) toggleFollowIndustry('content', {{ silent: true }});
      persistSet('sf_follow_industries', followIndustries);
      state.shown = 0;
      render(true);
      flashStoriesHint();
      toast(tr('demoFollowToast'), 2800);
    }},
    () => {{
      document.getElementById('demoText').textContent = tr('demoOpenStories');
      openStoryViewer('industry', 'content');
    }},
    () => {{
      closeStoryViewer();
      document.getElementById('demoText').textContent = tr('demoPills');
      state.scene = 'content';
      state.scene_l2 = 'writing';
      state.shown = 0;
      render(true);
    }},
    () => {{
      state.intent = demoIntent();
      document.getElementById('demoText').textContent = trn('demoSearch', {{ q: state.intent }});
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
      document.getElementById('demoText').textContent = trn('demoLike', {{ name: list[0].name || '' }});
      setTimeout(() => {{ if (demo.on && el) toggleLike(list[0].full_name, 0, el); }}, 600);
    }},
    () => {{
      document.getElementById('demoText').textContent = tr('demoSave');
      const list = filtered();
      if (list.length && document.getElementById('post-0')) {{
        toggleSave(list[0].full_name, document.getElementById('post-0'));
      }}
    }},
    () => {{
      document.getElementById('demoText').textContent = tr('demoMe');
      state.mode = 'me';
      demo.focus = -1;
      state.shown = 0;
      render(true);
      window.scrollTo({{ top: 0, behavior: 'smooth' }});
    }},
    () => {{
      document.getElementById('demoText').textContent = tr('demoLoop');
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
  document.getElementById('demoText').textContent = tr('demoStarting');
  demoTick();
}}

/* —— Events —— */

/* 封面图加载失败时降级到文字兜底层。原来写成 img 标签上的内联 error 属性，
   改成这里的委托监听有两个原因，各自都足够：

   1. 内联事件处理器是哈希覆盖不到的脚本执行点 —— script-src 一旦用哈希，
      'unsafe-inline' 就会被忽略，那个属性直接失效，封面挂掉时会留一个 2:1 的
      空黑盒而不是兜底文字。
   2. GitHub 的 OG 图相当一部分会 404（仓库没设封面），这条路径是常态而非异常，
      不该依赖一个会被安全策略静默关掉的机制。

   error 事件**不冒泡**，所以必须用捕获阶段（第三个参数 true）在 document 上收，
   写成 bubble 阶段的监听是收不到的。 */
document.addEventListener('error', (e) => {{
  const img = e.target;
  if (!img || img.tagName !== 'IMG' || !img.classList.contains('cover')) return;
  const media = img.closest('.media');
  if (media) media.classList.add('no-cover');
}}, true);

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
    const panel = document.getElementById('followSheetPanel');
    const sheet = (panel && panel.dataset.sheet) || '';
    toggleFollowIndustry(sceneId);
    reopenSheetAfterIndustryToggle(sheet, sceneId);
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

document.getElementById('tabBar').addEventListener('click', (e) => {{
  const nav = e.target.closest('.nav');
  if (!nav) return;
  switchTab(nav.dataset.mode || 'all');
  if (state.mode === 'me' || state.mode === 'publish') loadAccount();
}});

document.getElementById('tabBar').addEventListener('keydown', (e) => {{
  const next = tabKeyTarget(e.key, state.mode);
  if (!next) return;
  e.preventDefault();
  switchTab(next);
  if (state.mode === 'me' || state.mode === 'publish') loadAccount();
  const btn = tabButtons().find(b => (b.dataset.mode || '') === next);
  if (btn && btn.focus) btn.focus();
}});

document.getElementById('toTop').addEventListener('click', scrollToTop);
document.getElementById('btnRefresh').addEventListener('click', () => reshuffleFeed());

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

document.getElementById('feed').addEventListener('submit', (e) => {{
  const form = e.target;
  if (!(form instanceof HTMLFormElement) || form.id !== 'meActivateForm') return;
  e.preventDefault();
  activateSubscription(form);
}});

document.getElementById('feed').addEventListener('click', (e) => {{
  const t = e.target;
  if (!(t instanceof Element)) return;

  const topic = t.closest('.js-topic');
  if (topic) {{
    goTopic(topic.dataset.scene || 'all', topic.dataset.l2 || 'all');
    return;
  }}
  const topicSec = t.closest('.js-topic-section');
  if (topicSec) {{
    state.mode = 'all';
    state.scene = 'all';
    state.scene_l2 = 'all';
    state.section = topicSec.dataset.id || 'all';
    state.shown = 0;
    render(true);
    syncTabUrl();
    scrollToTop();
    return;
  }}
  if (t.closest('.js-acct-logout')) {{
    logoutAccount();
    return;
  }}
  if (t.closest('.js-pay-dev')) {{
    payDevCheckout();
    return;
  }}
  if (t.closest('.js-me-saved')) {{
    state.mode = 'saved';
    state.shown = 0;
    render(true);
    syncTabUrl();
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
  if (t.closest('.js-bad')) {{
    hideItem(card.dataset.fn, card);
    window.setTimeout(() => render(false), 220);
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

/* 发布表单是 render() 写进 #feed 的，所以在容器上收 submit（submit 会冒泡）。
   不用 form 的 action/method：那会整页跳转，而 form-action 在本页 CSP 里是 'none'。 */
document.getElementById('feed').addEventListener('submit', (e) => {{
  const form = e.target.closest('#pubForm');
  if (!form) return;
  e.preventDefault();
  submitPost(form);
}});

window.addEventListener('scroll', () => {{ maybeLoadMore(); syncToTop(); }}, {{ passive: true }});
document.getElementById('btnDemo').addEventListener('click', startDemo);
document.getElementById('demoStop').addEventListener('click', stopDemo);
document.getElementById('btnHeart').addEventListener('click', () => toast(tr('feedbackToast')));

/* 语言切换：只改渲染，不发请求；卡片内容用离线生成的双语字段 */
function applyLang(next) {{
  if (next !== 'zh' && next !== 'en') return;
  LANG = next;
  try {{ localStorage.setItem('sf_lang', LANG); }} catch (e) {{}}
  document.documentElement.lang = LANG === 'en' ? 'en' : 'zh-CN';

  document.querySelectorAll('#langToggle button').forEach(b => {{
    b.classList.toggle('on', b.dataset.lang === LANG);
  }});
  document.querySelectorAll('[data-i18n]').forEach(el => {{
    el.textContent = tr(el.dataset.i18n);
  }});
  document.querySelectorAll('[data-i18n-aria]').forEach(el => {{
    el.setAttribute('aria-label', tr(el.dataset.i18nAria));
  }});
  document.querySelectorAll('[data-i18n-title]').forEach(el => {{
    el.title = tr(el.dataset.i18nTitle);
  }});
  // 这几条文案自带 <b>/<strong>，只能整段换 innerHTML，不能用 textContent
  document.querySelectorAll('[data-i18n-html]').forEach(el => {{
    el.innerHTML = tr(el.dataset.i18nHtml);
  }});

  const intent = document.getElementById('intent');
  if (intent) intent.placeholder = tr('searchPlaceholder');
  // <title> 是服务端渲染的中文默认值，只有 lite 变体带中文，切语言时补一刀
  if (IS_LITE) document.title = tr('pageTitleLite');

  render(true);
}}

document.getElementById('langToggle').addEventListener('click', (e) => {{
  const btn = e.target.closest('button[data-lang]');
  if (btn) applyLang(btn.dataset.lang);
}});

{install_js}
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

/* 深链：?tab= 决定落在哪个入口，?scene= / ?l2= 直接落到发现流的某个分类。
   在 applyLang() 那次首屏渲染之前跑完，免得先渲一遍发现再跳走。 */
(function openTabFromQuery() {{
  const params = new URLSearchParams(location.search);
  const scene = (params.get('scene') || '').trim();
  const l2 = (params.get('l2') || '').trim();
  if (scene) {{
    state.scene = scene;
    state.scene_l2 = l2 || 'all';
  }}
  const tab = tabFromQuery(location.search);
  if (tab && !scene) state.mode = tab;
}})();

renderIntentKeys();
applyLang(LANG);
hydrateLiveFeed();
syncToTop();
if (state.mode === 'me' || state.mode === 'publish') loadAccount();

if (!IS_LITE && new URLSearchParams(location.search).get('demo') === '1') {{
  document.body.classList.add('show-demo-tools');
  setTimeout(startDemo, 400);
}}
</script>
</body>
</html>
"""
    return _with_csp(html, api_base=str(ui.get("api_base") or ""))


def write_feed_html(feed: dict, path: Path, *, variant: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_feed_html(feed, variant=variant), encoding="utf-8")


def write_feed_variants(feed: dict, *, full_path: Path, lite_path: Path) -> None:
    """同时写出独立站 full 页与 picker 用 lite 页。"""
    write_feed_html(feed, full_path, variant="full")
    write_feed_html(feed, lite_path, variant="lite")
