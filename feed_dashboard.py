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
    page_title = "去 GitHub 发现" if variant == "lite" else "skill-feed"
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
    --bg: #fafafa;
    --ink: #262626;
    /* 承载「适合谁 / 为什么推荐」这类决策文案，全站最需要读清的字。
       #737373 是纯灰里在 #fff 和 #fafafa 上都过 AA 的最亮值（4.74 / 4.54），
       再亮一档 #747474 就掉到 4.48。 */
    --muted: #737373;
    --line: #dbdbdb;
    --card: #ffffff;

    /* 全站唯一的强调色。当文本用（字标、链接、导航激活态）实测 5.48 / 5.25。
       这里的取舍是「提饱和，不提亮」：白底上饱和绿的 AA 天花板在明度 24-28%
       那一段，想更亮就掉线（emerald-600 #059669 只有 3.77）。但同一段明度里
       饱和度有大把空间 —— 上一版 #1e7362 饱和只有 59%，是个发灰的青绿；
       换成 94% 饱和，对比度只从 5.70 掉到 5.48，仍远超 4.5。 */
    --accent: #047857;
    --accent-strong: #02503a;   /* hover / press，9.50 / 9.10，同色相 163° */

    /* 头像环与动态圆环。刻意留在 accent 的单一色族内（色相跨度 2°）：
       「圆形头像环 + 鲜艳多色渐变」这个组合本身就是别人的识别要素，换个
       色相也还是那个结构，所以这里只动饱和与明度，不做多色扫掠。
       这条由 TestBrandIdentityIsOurOwn 盯着，别顺手改宽。

       上一版是 59% / 43% 饱和的两段，颜色本身发灰 —— 这才是「素」的真因，
       不是渐变不够花。现在三段都是 93-94% 饱和，同样的明度段里鲜得多。

       明度只跨 24% → 27% → 30%，看着窄是有原因的：环的着色是「有新内容」
       这个状态的唯一提示，要和未激活的灰环拉开 WCAG 1.4.11 的 3:1，而同族内
       过线的最亮档就是 #059669（明度 30%，配 #e8e8e8 是 3.08）。再亮一档
       #06a877 就掉到 2.49。上一版最弱段只有 2.12，本来就不合格。
       想让环既亮又鲜，得先给这个状态加一个非颜色提示，见 docs 里的待办。 */
    --ring: linear-gradient(135deg, var(--accent) 0%, #05865c 50%, #059669 100%);

    /* --like 只做图标填充与背景：非文本元素 3:1 即可，实测 4.37 / 4.18。 */
    --like: #e0364f;
    /* --like 当文本用在 #fafafa 上只有 4.18，掉出 AA。--like-ink 锁住同一色相
       （偏离 0.07°）与饱和度，只把明度从 .88 降到 .84，换来 4.71 / 4.52；
       再亮一档 #d7344c 就掉回 4.49。 */
    --like-ink: #d6344c;
    /* 链接复用 accent，不引入第二个「差不多但不一样」的绿。 */
    --link: var(--accent);

    --font: "Outfit", "PingFang SC", "Microsoft YaHei", sans-serif;
    --logo: "Outfit", "PingFang SC", sans-serif;
    --phone: 448px;
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
  /* 字标：Outfit 800 实心字，不用手写体、不做渐变填充。实心色顺带省掉一次
     background-clip:text（它在部分安卓 WebView 上会把字渲染成透明）。 */
  .logo {{
    font-family: var(--logo);
    font-size: 1.6rem;
    font-weight: 800;
    line-height: 1.1;
    letter-spacing: -.02em;
    color: var(--ink);
  }}
  .logo span {{ color: var(--accent); }}
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
  .media .badge.kb {{ background: rgba(237,73,86,.85); border-color: transparent; }}
  .media .badge.soft {{ background: rgba(255,193,7,.92); color: #262626; border-color: transparent; }}
  /* 「本机已有同名」只在 skill-picker 注入了本机索引时出现，公开站上不存在。
     用中性深色而不是绿色：它是一条装前提醒，不是「已装好」的成功态。 */
  .media .badge.local {{ background: rgba(17,17,17,.82); border-color: rgba(255,255,255,.3); cursor: help; }}
  .media .badge.local.drift {{ background: rgba(237,73,86,.9); border-color: transparent; }}
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
  /* 动态全屏的翻页热区是 <button>：原来是带 aria-label 的 div，读屏会播报「上一条」
     却无法聚焦触发，等于告诉用户有这个控件又不给用 */
  .sv-tap-left, .sv-tap-right {{
    position: absolute; top: 60px; bottom: 80px; width: 28%; z-index: 1;
    appearance: none; border: 0; background: transparent; padding: 0;
    font: inherit; color: inherit; cursor: pointer;
  }}
  .sv-tap-left {{ left: 0; }}
  .sv-tap-right {{ right: 0; }}

  /* lite：skill-picker 发现子页 — 无动态圆环/关注/发布/我的 */
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
        <!-- 首次 render() 就会写成 fmtGeneratedAt()，静态占位留空免得漏中文 -->
        <div class="status" id="genStatus"></div>
      </div>
      <div class="top-actions">
        <div class="lang-toggle" id="langToggle" role="group" aria-label="语言 / Language" data-i18n-aria="langGroup">
          <!-- 语言名一律用本语言书写（中文 / EN），这里的中文不跟随语言开关 -->
          <button type="button" data-lang="zh" class="on">中文</button>
          <button type="button" data-lang="en">EN</button>
        </div>
        <button class="icon-btn" id="btnDemo" type="button" title="自动 Demo" data-i18n-title="demoTitle" aria-label="播放自动 Demo" data-i18n-aria="demoAria">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="6,4 20,12 6,20"/></svg>
        </button>
        <span class="demo-badge" id="demoBadge" hidden>DEMO</span>
        <button class="icon-btn" id="btnHeart" type="button" title="反馈说明" data-i18n-title="feedbackTitle" aria-label="反馈说明" data-i18n-aria="feedbackAria">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>
        </button>
      </div>
    </header>
    <div class="lite-banner" id="liteBanner" data-i18n-html="liteBanner">
      <b>本机没有合适 skill 时</b>，在这里按意图浏览远程线索，点「打开 GitHub」自行安装；装好后回 skill-picker 再扫一遍。
    </div>

    <div class="search-wrap" id="searchWrap">
      <input class="search" id="intent" type="search" placeholder="短关键词更好，如：去AI味 / 周报 / 剪视频" maxlength="40" />
      <div class="intent-keys" id="intentKeys" hidden></div>
    </div>

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

    <main class="feed" id="feed"></main>

    <nav class="bottom">
      <button class="nav on" type="button" data-mode="all">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>
        <span class="nav-label" data-i18n="navDiscover">发现</span>
      </button>
      <button class="nav" type="button" data-action="publish">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
        <span class="nav-label" data-i18n="navPublish">发布</span>
      </button>
      <button class="nav" type="button" data-mode="me">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"/></svg>
        <span class="nav-label" data-i18n="navMe">我的</span>
      </button>
    </nav>
  </div>

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
    navDiscover: '发现', navPublish: '发布', navMe: '我的',
    liteBanner: '<b>本机没有合适 skill 时</b>，在这里按意图浏览远程线索，点「打开 GitHub」自行安装；装好后回 skill-picker 再扫一遍。',
    storiesHint: '<b>顶部圆环 = 你关注的最新动态</b>：关注 Builder 或行业后，新内容会出现在这里优先观看。',
    demoTitle: '自动 Demo', feedbackTitle: '反馈说明',
    notUseful: '不感兴趣 · 少推这类',
    notUsefulToast: '已记下，之后少推这类',
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
    meAboutBody: '动态圆环 = 关注动态；下方 pills = 逛发现时的行业/栏目筛选。两者不再重复。',

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
    navDiscover: 'Discover', navPublish: 'Post', navMe: 'Me',
    liteBanner: '<b>When no local skill fits</b>, browse remote leads by intent here and install them yourself via “Open on GitHub”. Then run a skill-picker scan again.',
    storiesHint: '<b>Top rings = updates you follow</b>: follow a builder or industry and new items land here first.',
    demoTitle: 'Auto demo', feedbackTitle: 'About feedback',
    notUseful: 'Not interested · show fewer like this',
    notUsefulToast: 'Noted — fewer like this from now on',
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
    meAboutBody: 'The top updates ring shows what you follow. The pills below filter the feed by industry and section — the two no longer overlap.',

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

const PALETTES = [
  ['#ff6a3d','#c32bad','#7028e4'],
  // pal[1] 是头像字母的纯色底。#0072ff 上白字 4.33、深墨 3.50，两边都过不了 AA，
  // 是八组里唯一一个；同色相（213.2°）同饱和度只把明度 1.00 降到 .965 得 #006ef6，
  // 白字升到 4.60。渐变端点 pal[0]/pal[2] 不动。
  ['#00c6ff','#006ef6','#7b2ff7'],
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

/* 头像字母原来恒为白色，落在 PALETTES 里的亮色上只有 1.45:1（#ffd200）。
   这里按背景亮度选前景，不改任何一个品牌色，只让字读得出来。
   INK_HEX 必须与 CSS 的 --ink 保持一致。 */
const INK_HEX = '#262626';
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
  return PALETTES[hashHue(key) % PALETTES.length];
}}

function initials(name) {{
  const s = (name || '?').replace(/[^A-Za-z0-9\\u4e00-\\u9fff]/g, '');
  return (s.slice(0, 2) || '?').toUpperCase();
}}

function fmtGeneratedAt() {{
  const g = FEED.generated_at;
  const host = (FEED.ui && FEED.ui.hosting === 'pages') ? tr('hostSite') : '';
  const lead = tr('updated') + ' ';
  if (!g) return lead + '—' + host;
  const locale = LANG === 'en' ? 'en-US' : 'zh-CN';
  try {{
    const d = new Date(g);
    if (Number.isNaN(d.getTime())) return lead + String(g).slice(0, 16) + host;
    const s = d.toLocaleString(locale, {{ month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }});
    return lead + s + host;
  }} catch (e) {{
    return lead + String(g).slice(0, 16) + host;
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
      const pal = paletteFor('scene:' + s.id);
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

function openPublish() {{
  if (IS_LITE) {{
    toast(tr('publishLiteOnly'));
    return;
  }}
  const url = apiUrl('/publish');
  if (url) {{
    window.open(url, '_blank', 'noopener');
    return;
  }}
  toast(tr('publishNeedApi'));
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
    if (!demo.on) toast(data.ok ? trn('feedbackLogged', {{ action }}) : (data.error || tr('feedbackFailed')));
  }} catch (e) {{
    if (!demo.on) toast(tr('feedbackServeOnly'));
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
      ${{IS_LITE ? '' : `<button type="button" class="follow-mini js-follow-builder ${{followed ? 'on' : ''}}" data-owner="${{escapeHtml(owner)}}" title="${{escapeHtml(tr('followTitle'))}}">${{followed ? tr('following') : tr('follow')}}</button>`}}
    </div>
    <div class="media js-media${{noCoverCls}}${{bareCoverCls}}" data-idx="${{idx}}">
      ${{cover ? `<img class="cover" src="${{escapeHtml(safeUrl(cover))}}" alt="${{escapeHtml(headName)}}" loading="lazy" referrerpolicy="no-referrer" />` : ''}}
      ${{(coverTitle || coverDesc) ? `<div class="cover-fallback">
        ${{coverTitle ? `<div class="t">${{escapeHtml(coverTitle)}}</div>` : ''}}
        ${{coverDesc ? `<div class="d">${{escapeHtml(coverDesc)}}</div>` : ''}}
      </div>` : ''}}
      <div class="badges">
        <button type="button" class="badge ${{IS_LITE ? 'clickable js-scene-filter' : 'clickable js-scene-tag'}}" data-scene="${{escapeHtml(sceneId)}}" title="${{escapeHtml(IS_LITE ? tr('filterByScene') : tr('followScene'))}}">${{escapeHtml(itemSceneLabel(it))}}</button>
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
      ${{hasSkillDoc(it) ? `<a class="doc-link" href="${{escapeHtml(safeUrl(skillUrl))}}" target="_blank" rel="noopener">${{escapeHtml(tr('readSkillMd'))}}</a>` : ''}}
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
    <div class="likes">★ ${{stars}} · score ${{score}}</div>
    ${{why ? `<div class="why-line">${{escapeHtml(why)}}</div>` : ''}}
    <div class="time">${{escapeHtml(it.soft ? tr('softTime') : (it.from_corpus ? tr('corpusTime') : tr('suggestTime')))}}</div>
    <div class="open-row{install_row_cls}"><a class="open-gh js-open" href="${{escapeHtml(safeUrl(url))}}" target="_blank" rel="noopener">${{escapeHtml(tr('openGithub'))}}</a>{install_slot}</div>
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
  wrap.classList.toggle('hidden', hide);
  if (hide) {{ el.innerHTML = ''; return; }}

  const rings = [];
  const nFollow = followBuilders.size + followIndustries.size;
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
    const pal = paletteFor(st.kind + ':' + st.value);
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

function mePanelHtml() {{
  const nLiked = liked.size;
  const nSaved = saved.size;
  const pub = apiUrl('/publish') || '';
  const docs = apiUrl('/docs') || '';
  const home = apiUrl('/') || '';
  const builders = [...followBuilders];
  const industries = [...followIndustries];
  const unfollowAria = escapeHtml(tr('unfollowAria'));
  const builderChips = builders.length
    ? builders.map(o => `<span class="follow-chip">@${{escapeHtml(o)}} <button type="button" class="js-unfollow-builder" data-owner="${{escapeHtml(o)}}" aria-label="${{unfollowAria}}">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">${{escapeHtml(tr('meNoBuilders'))}}</p>`;
  const industryChips = industries.length
    ? industries.map(id => `<span class="follow-chip">${{escapeHtml(sceneLabelOf(id))}} <button type="button" class="js-unfollow-industry" data-scene="${{escapeHtml(id)}}" aria-label="${{unfollowAria}}">×</button></span>`).join('')
    : `<p style="margin:0;font-size:.82rem;color:var(--muted)">${{escapeHtml(tr('meNoIndustries'))}}</p>`;
  return `<div class="me-panel">
    <h2>${{escapeHtml(tr('navMe'))}}</h2>
    <p class="lead">${{tr('meLead')}}</p>
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
      <strong>${{escapeHtml(tr('meLocalTitle'))}}</strong>
      <p>${{escapeHtml(trn('meCounts', {{ liked: nLiked, saved: nSaved }}))}}</p>
      <div class="me-actions">
        <button type="button" class="primary js-me-saved">${{escapeHtml(tr('meViewSaved'))}}</button>
      </div>
    </div>
    <div class="me-card">
      <strong>${{escapeHtml(tr('mePublishTitle'))}}</strong>
      <p>${{API_BASE ? (escapeHtml(tr('meApiPrefix')) + escapeHtml(API_BASE)) : escapeHtml(tr('meNoApi'))}}</p>
      <div class="me-actions">
        ${{pub ? `<a class="primary" href="${{escapeHtml(safeUrl(pub))}}" target="_blank" rel="noopener">${{escapeHtml(tr('meGoPublish'))}}</a>` :
          `<button type="button" class="primary js-me-publish">${{escapeHtml(tr('meGoPublish'))}}</button>`}}
        ${{docs ? `<a href="${{escapeHtml(safeUrl(docs))}}" target="_blank" rel="noopener">${{escapeHtml(tr('meApiDocs'))}}</a>` : ''}}
        ${{home ? `<a href="${{escapeHtml(safeUrl(home))}}" target="_blank" rel="noopener">${{escapeHtml(tr('meApiHome'))}}</a>` : ''}}
        ${{API_BASE ? `<a href="${{escapeHtml(safeUrl(apiUrl('/auth/github')))}}" target="_blank" rel="noopener">${{escapeHtml(tr('meGithubLogin'))}}</a>` : ''}}
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

/* —— 动态全屏（.story-viewer） —— */
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
  if (t.closest('.js-bad')) {{
    sendFeedback('bad', itemPayload(card));
    toast(tr('notUsefulToast'));
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

renderIntentKeys();
applyLang(LANG);

if (!IS_LITE && new URLSearchParams(location.search).get('demo') === '1') {{
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
