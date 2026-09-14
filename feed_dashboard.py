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
      <div class="feide-wrap"><img class="feide" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKAAAACgCAYAAACLz2ctAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAALe3SURBVHhelP33kzzfmtcH8i/sjwpWgdzuBmIQrASSEH5AEkSAkHaR2BUaEMMAg0YTzAxzx8+9c+/9mo/3tr333nvvfXdV+zJdvtqWSZ+VVe+N55is7P58LrAd8URWp89zXuf9PMfkyT92opb+9hXw6Dj3pR1mH1iu+Ojw4Xr6/+G6LB4df+X/41xRnFsupRUfHWbL29j+X+zzpT285hfG7u0r53l4b/K64vnYud3/79/Xw2d6eA3vOeQ52bN47+nhfWbxyHeHRz5afmXb/fssn/uY0uwr+/3/bV/Lw6+s+yIdf0ZesXXsHGK9gkenCh6dC5O/s8CjP3ailt46ANIAUmIpfycf2NfWJYQ9XE/7es17Xvn/5YN1P8u89/Zw28PrPrSH+/+s4+S6h/v92+zfdszD68j0+prFhf2b0vNhGjzc72fZ187p3fZv2i7t4bP9LPPuK/Od8vrKYzfgf3+MaKQVh9kijjx2mCnBT3ZXFEtuvrsifLclZgdi+fC3T+xLx9F5mGWFedd9xfxZcV2xdI+V9+OauC+2X9Fzf/fvw3sv3udwTaz74hjv/vLeHt6ntC/uTezjuSdKH2Y3nt8/wx7ei/sMd57ru89azo8vjvPkjXtebzrJ/JT7yt/i/y+O+1n59UU68Lzx7neULdtxvoRTpYRbApCkkACU0N17wAcPQLZ/Q1bE/nWRLQ/ot9euRSLfeBLGk4hy3cMEdR8mI/elxLifIP8udv8+uT3M4IdWPraIg1vni/Ve80L1s+6L37vnfuS9UJq56cbTiNbvXXPj2/j6gxuH7/fw3N77pX1ZevPzyt/yemzpnrdsbJ+vpIPXaD95TzIvvQXW/S3y615aCLAfQsiMBC5XxEm+xFSwDGCuDKAERT6YtD1pVw72rh3sf9UK2L8qeP4Xie0+WDmRHmbc1+xhwki7t10m9m25EPB7pfuU9+8tPPczhZ9Dwicynt1zEQcexb93X+Ka/FnKGSrvSe7Dr83Tonw/5fSS6/jSa3Z5P+81xDOU88bB3lXBkx/388zNk4f59DUYBbj8fmgp8tktDJ4CIaC7ny+UVuX08kLKYGRekAN4nCsxV+wCeEgAZjm1PPFEAtHDXRWwS9BdOdi9LJSNPTh/OHe/Sxu7lxb2Lm32/8MHdjPfVQJpPAF8/xbFcoHxZLR7XrfEkz1IcA9wbsJeOyIDitgXGcCuwUAmGMsA8mt5FV9kjHw2Cbn7fOVrH1zZzGRaee/pHnQsnctG+38dLJE3tF3mydXD5xX70Hq69j1RKN+3Kw4sXaSJc1/TPfP7liByCB8oqCy8bDv3IGUARagkPBx3x18DkODLCqpFyaWH8sK2c+lgJ21hJ2VhJ21jh8FGD1c2DqDtAZBnDM+4LzPHm2nMhUg38gA8V+2+sk4CeHANZl9eoww6B5Ansrv+YYIyE/A9iN/cgsSu6YHwARz3jNLhyqNonvsqAyaBEvCxAl8u4OVryN9yHyEMHgAPvgD9S69Ufvb7eXNfjTl45QIrFPBOgOhJU/fa4pxSJWU4cl8JuQpSxYRVQugHKSADMCMy9brEHmrnksAr23bKwnbKZEYw7hJ4DFK5pATk8Lk3TWCIeOXLjJL/l9XLLZVe2KTke4BgAMr/2fm/Bt999/EQIvdcmSIOMjzuJPDovCyO+SKWkwl+/zplFSt7A24O9i7L6+7fmyg4UlGF6sjz8f8fPAuZ99zSPGl54NnX+5v/74HPA9DDwvnldT2FldKHQpWfsY90w6wC6wlhpEsmV/wFgLTCL1wwA5BigasiSzymfEz9bBfAnZRUO29iiN+eEsMTRKiTjJnczJMZwkug3C5v+N7/BAILeO/Xwr1ASuXmCV0QxkvlvWM8ALOgnp27eN88FQ0Z+JevQwldTngXPLl0CyR5EO5FGIRkbrrQPYpC48am5XN+qWJfM65sZbDLoQwD6tqB77rIjNJcqpMXPnedW/Hgxu7h3jaPd3rw/MxESCK3MwhZ4ZVAchhdALNF1jzjNsOQT6YNRGn5ZrgMUyJKAMn9bpMbvrTcRJYA0o2UAfS4uWse25XBkontAc8DxZewSCDug+E1mbDlzOUxic+twYnSKPZ1r+PGKSL+9UB4L34RSvjwGaTb9JoMQ8goTJGhCg9neBrxwicLpyyo8v7Lz1Fels1VJ+ba74PqrQRIUFhBvFewpeKV04KnnwBNgPfF8zLovPfmBdAbypR/cxDFfVEeyIrI1wCkNhqZ0OWYQJbicmKyODBNFQ1Rsh+4AW8wy0ulLBX3H+hrD8rtwb60FColIWHKJwG8l4BfPy8HsLw/Mwn1PQAlhBLOcjuXC7owqVocPJurEaWXrEh4IJQhClfCMqxMmVgFyqss5bhKNse469xaqhcACXRZgVzIPPs93CYLfjktHuaDJ21F+FRWyPvGCo8rJF4YZX46bnrKighzwVQJuXYVkDfFsIT2AOh1K1wFTVbT5e7XCyDtX27XImPgeeDztmM9BO0LY9AJhfI2UMtYVQLkBULGNJ7Ec89zTzU9rlYA517Ds497TbHehe9BIeWZfD9TeOXAm0Yl7FNY43oMCd99qN11LkQcOrn8EgKCj2JHqYYSxgcq5XWrrucRyuRVe0oPN/04qOVry3spx47c29z3ZGUh4PEiA1C44XsABjU8ogZBap1+2AwjYzkOIXcf2yIOZC6YVTZk4lKpvw+gV+Jl6SIA3bhLNmh6gv2HAHqhe2hcrbzK9HX1cyH2JDAHquzS3W0PAmd+H1I974PtrTm6lSePMXVkJguHPEYsBWTlzBbP8EWtXFYQvJWD++pWVsGy8SaRshLyZhLvdcoAyoLsFkDPvXD4yvBz+Lxul19HPocrAmw7b5ohAA/uHPhvHRdA1gzzBYBM/fgNSzchf7suRcSAvKnFwa5sEriX4GX4OGT3oXMbvb3GHrysaEzhZDwmoGNxqgQwW4RPgsgSUJpH6bwVi4cQS+C88Z57rw8hlIWIX8PNSI8rewg+335//UO4yvt7QHCtDD0D4bbAM15kqmx7kzVoZjfcOBBlK/8vn0dCJ9c9KAgSItEyId2+DKu8Xuarx8t2QY9xFZQAinbAoCIAJBcsMoAuLlVNPtjD4Nqt/UoX/bDNSCb8wzYgz/ILCEWFQLpH1ixC611oeGM5azQX5s+Vt7mKyIAtQyvV8t7xQu2/2EeC6IJdvj8JRRlaT6Fy71+YALxcEMTxngrOF+vYPcvWCE/BEeEGh5CURLZRclWRzSIHtwX4yGS6ebyLKwDewubuI/fzACsVTIB43+0/LFj34ZYFxguh74buTbphDiB3wRJAUkDX/T6Qd08TixdC3kjqgVTEHgSgLOGy6i3NC96XJgdBlDNCdt9I4I5yvDP7WLm/5NvFko519y8DJxtAj/LUDsXbouR6di0GdPlYF1I3BuWZx+5VHifAlhDzGp7oeGfXoHuSS3mP8rd4PnGf0uTADff55b2IdeXrle+fb3fKzyiuKSuX7mAQT3p6B54w8xQkCZZUcdlZwOJWBma5x+Oesj4w5n4JPgGgjAGPsyVQ3YNVQmhUAgeQn0hWQLwQcoUrQ8h7PizsM5O9HiL4FQDSuf5N0B15Rkkci5s6po7qXBGneeqwpmUJZ4owtbwMqCUExfKc1ottNMpCHnMuTK6X6+Qx9JvW0zXZdcU1XRP3IrfRPZ157NRzn+Xtnmt77s/7230Or8n1wui+ToSxZ/oZRvvKZ6HzS5Npw64p0yBfYoMAyLyF0IXQM1rJ/wAqpnhuO6CMJ+83+3xpXBn9Nzz2c9WP8jonAJQKSDdFAHIX7O21kACWl96uNwbgg35fOp7dgHe0y72hXkUcZXjGBpUiInoJUb2EsFZCQCniXCnilExkKgOBLUsCzhID4FxuF9uoENFzcACKOGNGCS/gEOd2ryHOzfom6Z48HeUSvGPWbykgJMs6zI6zDj/O3U4FqPy/hFcav18vCOVtBPLD/e9dkz1jiQMvjc7hpgV/Xvlc7rOLgkLpRNtCahEXWgkxo4S4ydOcQKVzsPv3quWDmjBz/W4Fi0MoG56/jAclfEKEJIi3RRyRPQSQFJAykECRtJer+N5mFh7suo2vslH1kjrbBYAibpC0y5JFmcUB4iUyTKVToe0ONi8dzMVtTFxYGAtbGAnZGAqaGAoYGDw3MHBOSxODARNDQctjtJ+NwYDl2hAZbfOsGwjQPjYGaV92jIVBMnlM0MIwWcjCkDD2+8F5Bs8tDJwZ6D/V0Heiof+Uft+3Ptp+ZmKA7vecnoGsfM90naFgAYNk8r4CNgbObQyc0flNdjzZ4Bk9O52Hrs/PQ/sOCRs8tzF4RvfFr0VG+9M5yAbPTAydW8xGAhbGgjYmwjbmogWspniF5jxXRELnRvnBPRIPI5gSPqiMSQB5XvPab7nxuhwzeo8h8A4FgId3HMDTnBgP6ALIasHyIrJVXlZAZHuWp+LhAZO3xosamqfHg7lZ5lZ5KQupJVzo/AGXEgWMBG30npnoPjXZso9gCxBolPGUeAYGAzoGArSefpsYJDAfQMjWS5OZ4f62MEBGILKlF2QC0gNHyBYQFjDECoEElY6h64sCcapzO9PYsp/9r/H/z3T0i+XguY7BoHHPOIwSJk8hYeAQvHQ8LbnROlYA5fUl0KIw0POw9BEFlRdWWtL98XsYPqfrGhgOGhgJmhgOyvTiaTAdKWDnykFYKSJpFBHICy/lQugB0DNaqNwMI2vOsrGbg1oGsAzhkRAlEqL7AN5TwPvtS2WXKyH0xISe/bjyiYuKC1GcQTEKuVdyw3NxB/3nNnpPLfQ/UDWmQsxsjAQtN7FcC3F1lDYaLv9mxwX48QQ2nYNMqmR5u8nPHbIwGipgJFTAaJjMcZdj7LeDUXleT8YNB8gIAIMXELGkTGZGGR3QxbJ87/x56LnIaB0BwZ91mIAXassVS6jnuYVhsgBXMGaec/HnEc/JwBTXZ8eY7H5Gzk2MsuMsjAYtjIVICWlpYzxsY4ylYQEDAQdDQQfLySJC+SJiGoUbnjGiwiSEbi3ZA6YL6YP2TVeQiAkWA/LQwh2QynpCqFYl2wBdAL9sgmEguk0uZTfN23lIZsWFhPqRuyUFXEgU0R8ooI9cA1MyCQY3maijwQIDg+AiACjRuNH/BAwlmMW3M6P9xb4STnYurrBfGNuPjucAkhFw963IjF3PBZArCDcJEIePAyjgJEAYpIZY8n35PUmAJJRk8p7L98vAEiAy+MR6SgOCh4Hkgii3E6AmA44dd85/j5wbGA2Y4lhhobKNs/SgaxcwHHDQd1bAwFkB25cOkuSW86Lmz1oWymoom1oeQvazTCqgZIOYuDci2h2IIBo13cGIVxaHjsEnfovaLq+Sl+l3g0zRzkMB8PZ1CSNhB73nPOaRSuQqXuA+IBy+AsZCBZY440GTJRTBxZcCnjDFiwSPBJFKs4DXNXE+CSjbTx7L978H3kXZuAI64r7K7qsMkVRTDtMQ7cNURyoPN6ZIAloJHwHECpEHLHaf3oJCEAr43O1UWCgdGEimMK5oTOXEMXQfDL4Arafr8Wsy9QtZPF3p+dk90D3Rs/HCTyBSfNl3XsBclKshVRTvtasKJZQguqB5XHW5vVQ27XgA/OqAVFH1piaU+y633OTC7F6fY1mCWfVaGGtSyRSxkixiMOhgIEAuhpdsL2zc+EN7wWEwSAApwQWQZXC88NCybOVzFDAedpjJ/fj/cl86N63zHl/ejymgRwW56gglZkCIpfsM9HxSeSSA5d8MhIBRhoGdg0PO75lgJwil4otricoDSw9x3xxCC2MBCWBZ3Wh/aWPBgjDhdsMFTIQdVhGZoN/sPBJkcXzQYTYWdJgijoeLrKJyoXKY3J4o2ej/0P16VU+o3b8TgHIkDK/12qyfl7ldT5MLa3bxAOj186x2c1fCiWjfm4sReA6r7Q3Tw9xTOSn79zPUBYuVdA4CJRgDx7OOZ0RZuZhiCmgZqCG+Xh7Pz0HH0vlF/OMx7o7EdR+44y+Vh6tIWV2FEYQBLwAmB0TCcA8WOh9382wZKvLQg8HicZUeY4XFdZsFjActjLNz8vNxb3EfRg7f/XPI9HDThZ1LPBctKe3EPY2HShgV93maLSJESiia1NzeI6/qua5ZACi7YUVoxv8vdwgwAOVwLAKQTuY2vdzI9wG8cZ8XvnIjJCNdNjBmipiPEXhFDIeKGHFLuDf24BkqS/m9RJMZzfYR8ElFFFA8VLZ7aimO4/uVE5zv781E73U9KvMQQgmfe18cYJ65XCnIuGp8DSC+jgHDTKxjGSwhpOvQegdjAa5aHFqpYGUAx0MCnqAlTG4T9+5JR+8zcrX3wlcU5oGQnYP+5/c2wdKf7q/ElpS3pIb3IBQ9Rfe64lhYJtfJ9WLp1g88I6JdF0x9im43XIFDeCNV7wF8nqHX8qRUkVlOUG2qiBHpwlhAz2uUFL+57uAeACJTWII/WCdKPHOZwj26QF3cB7Sc+CIhPYnthZb99u7vBVAcU4ZQKnK58Lj3QOC44In9Hrg9Do2E0PNcdBwrKBxADoE4H0uH+2pGx0rIJHjkQiceqJoXRrYvSzOxD0El4buQvx1+7oDJ4m1+HO1LLlqem0KRIqYiJQTzvLGddZu6jdb32wvv95pwTryuWVZQ7w/JZy643IHsrQWX4RND3O/RXe5e2Ug7GCHVC5N9xY0xdysDYq9b89oDNyL24+7zvluViVgGUFyDVTi4kknwvJkkM0peT0LyUDFlfOgqBJ3/wfnuqfBXFNCFQZyHp4FdVjemfjLmlVCXgZXQ8t+WiN0IQoLvy+dixuCRCieUzN23gMkLB5MXRUzK/elcEmqvyfOESmw5GixiKV5EMM/7dCnPWb+yJ84jN+sCKCqp/q81z2W+4oJZLZgBKMGTfbuy0kFtfZ7+P1HTIfdL74/QQ46GqdbLAXSDbJbo5RqZq4AMLq9qSABFbMPA88LA1ZTcAZlMUNf1SnfIFJPA4K5j4oLvdw9AAe19BXm4T1kNGDyeDHdV0OPK+L38DJP7u+5bAllWUen6+DXJhMqJCsO9e5UqJf4nmCZDZAVMEmTuOaQqlu99KlzAFFvScbQvnZ8fXwaQx5m0LINcxEigiO1L7o6Z8MgBExJCyYbsHfG8jiFjQtkM4w5GcN8JYbUa2QPiVUE5+uF+yzcHkC5QxCw1aAYJEApcefA6EuQ1O9l0IWt/ZXWQpZ+XUKkg5QrCl0DI+I4nCq9YjMumBbdWKc4pAZEASiVya7oSOmnla0nImAmF4hlaVl0WJz04hpt3/X1A5XV4bCXjPw7JPdX64pxeK3n2ISXjasZgkjCy3zaHy3MsKd9U2GsSyKLYVxRKSs+AJQpA+XgqLHSfNMCAqdvDQQzerruHDdJiuJ0E8F4tmDryWUWENcVwl+u2drvw3a/xSKo3Eg6GzyhTSxxABiEPzHnTAlfAMnz8tyyZ99WCB/q0LGeWdxuZVCBRcxbqVAaa7+tVHm48gSVU8ry8WUJeTwIqY08ZA4pQQLg+vg8vBF8C4oWIqzW/F6m4XFXKAEtFL/9fXpZ4qEEmKgblWI5fm4BjAJGRaxU2JWDzriP3O0VG8Hn2kcbcsuvipQsWahosYpwql4ESVpO8WYWYKMMnBOkrnHAAyz0rLoDSBTMFdAEs9+26Q29Ev5/3hNzXFzFFzQ9M/Xiwykq2qBnypoWy8UBbuqAyMDJjZOZ7M7Zcm5Nxkzce4hlSzkwJq4h7yLV8RYHuJayrEsJ1ifPeKyDi+hJAqVY8wwR4cr0bN3GlckMGuU3A4gIWLgkVk0uvlcrwyGPEvXOXy00C5aphyHMOD2Ry3X0VvK+I/JlIEclE+rgeoMSaZ6YuKO95b5gccsfaBv9NAJJgfQ1A971gUZ2WQ21kzFfu93sgr9fARryAoVPKlBIrHdJ4XEPBNjUnSHiEglBc4ZYuCQKVOlHy2HaZoXTMA4gFEHIfnkgCBqlubB+v4jwAhbaRi3FLuoif2Dax3TUeC9H52DmZla/Nj/HuL84hn03+H+Tnd5XKAyXP7DIc07RPpITpeBHTsSLGIyKepfXyukFhAhR2Xi847rbyMVPM+Dq55Nvk/x6o3XSwMUn3HqTtvGCNBUtYT9F741wFGVhfe5/GC59HAWmMwINasHgjjilbudIhG5y5edSPajlXJcxQ3+MZ3fB9AMcDZA7GAwVmstbnzUD54N4E8iYaUzb3fHwbKSiZm9lugt0PvDnQ3G3IjOXwSfjLx0sg3eM9CV+uIXoBE4VEAPBw23igvP3+ti8BLD+/gILguyhhKlrCRsRG5NRCOGDjOF7AZtLBfJyO5SpE6UPQlEEqcRWjZbAkAC1iSqZBkKCipbAQ7UP7es9ThpQAJPAkgPJ5Wd4Ei5iPFrGTdrBzJdyrANBtH3yghrxrrjyinL0X7J2ejbds86aY8oAEjwsWw2zYSyqXJWwnCxg5prYj4W6C/MY4KPyGmcsNUKZwEMsAigeSLkk8PFcpoRzSnQrXzeI1WWP82nm8iurJfA5oSZhc/xA2bnSP5d8cJg6UsAD1QJRrim6miIxyj3O3PzRRwB66wlAR02ThEqZJ+cJFnK0ZCIzpOB/XEZozENkwEPGbOA/aOKAxffEiZqLcvVNjMeWBC6A0BmCBwcQsIO9XgijUT4DKQeT7ctWzMRmgpdfoOH7+zUQBW0k+JtB9N+Zhf7HHe7oAZkr3X0yX1Wl5AHu1zq0Ji35fMfkPvd+6my5i5cLE0JHFSuREkANYVj1ZlS+r4Pi5zc2z/V6GuOrldcvkxh+aOJ8HFu4aOPyui2XAUE2wrLYcuIfKxO9RwiPX8YJjY+KczkP3X3B/l92fyCg6noy2S6PtlOHntN3rMkl5hOJJ1QsVMRMuYYbUL1LCnM9GcNrE2ZSJ0ykDJ5MGDsc1HI5pOJ1UEZrXENk0ED6ycBq0sBt1sBxzMBWhc5XY+UgFyaYDEjxxH3T/bEnKZruqyCEUoEoA2b7cps7J6Lgis4lAEWsxB5txeiWXt4ywioiMBxmAohIrm+9kv3CmxGZQvTc9G5FLb199CZ8cDV1Wv51UEbNnBgaPbOYyuLsUsImM4upRhsWrKFIhJTDSBbHfbB0HiPYdO79vDyEvx3ACYpHRbJtQK+aiRQl2AZQAe0IFto65e0pghx8vIZQACqB4BktXZWPSA58LHWUyy2iPCrmZXXZ9XgCpQrWxaeFitoDzWRunMxZOpk0cTes4muJGMPpHNRyNajib0BCa1xHbNnEWsDFLQBN47P4IPhtTHpDofibOLUyd28zYs7hWvk+2L3sOfgw3+i3UM1DCUqSI9Ri9qsu9o2xqKbtfAaBsVRGqWAZQEwoo+vhYG989AOXwa1ryBudd4X7Hj3WMnDgMQJJkKhEs0zwZ5WYmZbpXuURMJ0Fw3QKLVbhr4DDw/aX6kYJ618vzuDGNANirSl4XItWNn0Oc6x5cZHy7zDAXQgEiyxRaeqBimXNusYxlFrDEPhYDQLqzaY/CkE0Hi5ghI/jCJcwSgKcFHC3bCM2VcDbn4GTWwvEMAWjgiIHIfx9OGgzG40kdRxMGTsYthOdMLPlI1YCZQIkDRQAy2LiKTZ7x+5+SEJ453Nh2sS87hraTCfVjKuhgOlDENJ07WMLCRRGrERtbVCGhRmcZ60n3y2Za84ZzDwC854K9r2XKOUncCggHkKR2O13CRszCkF/D2JnDEo3iAS7LBCCHkJSwDAxlqoBT/nbtAUjSVbluTaoqN+lC+P/cJUyRycDbLeUyfpHrpCrxYwkkec57AEpwpUoyuDj8DCppQlmmWcZwAMsmVZBDKl2wV/0IRrLZUIkbxX8XJcz6CgjMOTifK+F0roiT2QKOZiwcTts4nHJwNGuz/4+mLRxPmziZMRmkZ3MFppRDyzpLi5kAwVLAtITKq3pnZBa3U1uYhYlTg9nUmeUx03NsATOBIoObFHYuXMRS2GZtwRSaPWwrZux4etMoFpSjolkt+PjB9GwkobLxufwOKJdXIpwAJNpXIyb69jWMnwsAWeYLFZQZSo3TBOPZw4yWgJLrk8CKTBLxhRszSWgkfK5rE3ZexCQ7nruSMpj3YWUgCCiotNMxLJ5h55TnonvmasiBLxcmWi8zbeqsrCZ0DrZ0t4ntZ7SOrOhRGAKCjOAg5XO4+pGFipgT7YDrWwUEZ4s4FQAeMwA5hIE1BYczBGEBxzM2jmctBt/pvI3QQhFbUzq6N03MCADZ/ZwSZLQ0hfH/pbn/n5iYPDH48pjvx83ENC3PbEyzZ6BzlzBLNeFQEfNBC2sUB17enxGDq58YMS+my6N+YQKQuvLutwOKSogMHuUbTrLbjZ3sRgCYdLAcNhiAE2dFVnoZgATDmYMJahdkxiGURtvuqQ4BSvuLzJkSMPHMKgoTGecCKrd5jqHzU+kleOh8tC+7HgfDdS8CiunzIqbPS+xYlqC0FJBMnvLj+D3T+YRS0PlPZKZxwKZdyOh/mVlkHHIJnfxN+8+cO5hhKuKFz+N+zx0crFDsV8LpbAkncyUczxThGwNS/jgcYwWnizoOp0sMzBOKEedsnM0XEJ4vYHpGxdCRgzmChD2XjakTG1PHFqaPTUyfGJg+KYM4Rc8in+nEYvtNEXzM6BiL7U8ATp/a7jPMEoAMviJriluJ0ixgnBGv+nHXywe0cAAd99VMtxb8EEA+KMFzIvE/A/CyiM0EAWiid09j0FHJZZJMcQFlosh8Ao7/z42Bc0bAyGU5gwgADkWJASEBZHAwtRBL10QCs3PStciFSOgkAAI4lmiUUBw49pvOIdZx42BMe0Bl0IoM8qoBLdn9imvQ+Smjp88s5u5cqEXB4dfk558l8ISRgjALUV86r4DMHDk4W3A4fDMlHE4AvnHgcLIA83odsMeQOExhbwzwTwLH0w5O58j92swVD63omAqUGIBzDMACB+fEwsyJiZlTixlbd1rADBUWzzPSfgQc7Tt9wo+T8NG+sxRynRPgRcwFi1igfDkzsBIhAO+3FZNxBSy482T7rwv87bjMw4ZoOUHlg+4U7+CDMoAFLIV09O5qDJJ5Kr1UEghCkYnMXMA4EDwzaBv/TRnMlmybCHBlhjHIRGaJjGJuhX5LFyYylp+DEpGUiEDwXkuWWlFymRV5BlEpZkbnLGKW7SOO8RqBxc4vAeSqOn0mMpjOz9yTLdSNKxx3twI2sZ4AnHWXDstEKsDS/a7s2AjOOTidAQKLFnKxUyhJP/T0Lkr5WZRyM7DvNpCJniAbPUN4PYvjKQfBWRvbUzoGd23Mh0qYp+c7KzJoZhg8HLxZV8XEfZ86Yh/aToBySGk/eSwDU6ybPStgTgC4ECxhUQC4HLHZKBmqJ3wxGSnNg3hpcQDZLAl8+N69AanyHdD7fXqe0S9iOjHpgpdCJnp3OIALlIAMDAGNJyO9tS8KiDlUXM2YubGUAJMF9QJAipGk2jHApQkwhXKx41y36IHPVT8OHe1PSwkcy3wKpNmyiHlaJ2EUgDBY5POc2QI0WYgIOEs8L/0WAHrNcz5+3zwN+Dpx7XAJ89SUdV7E7rKF4EwRJ3NFnC7YDD5Y40B+GsXMPIqZBSC3CFjTKClLCK9lcDxZRGDGxuyMhrFjBwuhEhbOS5ingkaK5RopGD1PkUFEv6cZgDaHi0FHSypQ0kgpCU6x7czG3HmBpZUL4CkHkLlgMRXzfRWkLwUU4LumOWJoLKEHwPJrmWJgoZxFyY0D5Tx2fEkVEaqELJELdgEUroRBIhOZAych5GCV1UHCxNfL7VIxBGhCVblxIF3I3fOTkkrlKwNYdqkcVK503CRwDDoGICk4QS4UVlzXVV3XXVPmSTDLBe1nAuiBzU0Xd1tZ2akmOXdRwvShg+N5G2ez5FYdHM05OJgu4OrsFMhNo3RHAM6jlJuFltrC2WIOR1NF1lZ4PGlgeFFnz0JucSEgABSw0W9uDoOHGYOQCpXFjIHH4KN1cllWTwnq3JnNjl0gCCkmP9Y5gOn7AHJ+xLtDbBQ9NUaXxwTeB5DNC3J/okjZ9sdHt/JGaFJA6pNcFApIGbxIAFIzAlNBGWSL5gkRoLMYSSgczwSpdlJRZPVeuHKWQR4YXWA5UGUXK9WovJTnl6BL8DhslOkcOIq9qPCsRIvYiDvYjhewlyjgIFmAL+nAl3KwnyxiO+5gLepg6aKAuRAvJCy08ELECsfX7T6EXI35Nn4/VJOkLrilXZs1vxB8J3MODucK2J8EQpvXTAGRmwLyU4A2iYQvwmLD0/kCgvMFbE1oGNi0sBgmVeJGgDDoBHALlFdnBKPDKg9M8ZkqWtxcJRT/n3GXPE1uWcSPcp+5UwEhpcORxl1wWsyK622CESYHMXsHJLh9wWUA+ctF7sFuFVrM5s664EpsBMxCyED/rs5goIcmOWaqIuMdMhZjyABYyLgsVezBuVLxuIzHFfRQPD6TmeR1h1yNWAZ6zOtiyebOKQDnMR4lMlO3EG+zWo0WsRd3cJpwEEk4SEYdXF84uA07uA06uD0v4kbYbbCIu1ARd5EiMnEHt2kH19cO4tcOzlIF7MQKWArzgkPhBLt/j7rKsIQByrbzigEzWVFgAPIWhO01ApDcr4PjuQID8GAayMd9gDEONbkFNbEDWGPIx49wNFMGcGZSweghxeYlLJIJCBcDfLl0XsRq3Mbalc0K2iJ5rgCHlCBi6U7x3amFuVOTGQHIYJQKyPKQK+XcaYEDSB6HFDBKn/HgIuUq4L13Q+6r31cVsDwq+j69XgB30qQWBSwEDQzs6QwKWepY4lNCk6s647EEiyu8AHriC77d4caCW+kmROmUsYqolPDYpYRZZmXQuKJ4XKww1l4VKmI1VsRRoohovIjLYBFpv4P4poPwkoOz6QKOJiwcjlvwj1nwjxfgmyCz4Zu04Z+ycDhj42TeRmDFRnTHweVxEZlwEblkEXeXDhIU37CKmYMZirUCQmGEOpZdHrlFXrj4kqcZATh95OBooSDUr4DjOQuHs/zat6EQ0sdR+KdN+KdspI8juA1EWZx4Nk8VFgtDcwpLlyWCjbrIyOh3sISV8xJWIgXUJyy8i1roubSwfWVjPUwKRpCWIZynGI8APBNGwJ1wN8xdtI3ZEx5LLpwVsUhe58RwAeTzgksBE/GfaIxmL7J53opzFVDOkOoF8B6Ebh8wmJ8nd0UA9u/oLBGXL4osGGWSz8Ch0kRgScjuW7nmJWtoHFY6RgLIYhipiAI2ua38f9lkaabaH6kOudadWBEXkSKuTopIbVFNsQD/cAG7fRa2e7ht9ZjY6jOxPWBgZ9DCzpCF3RFuOyMmtkcN7Iya2Bm1sDtuYW/Shm/GxtGSjbN1B5G9Ii7PSsglisjeOLhI29i4sLmii+fg7lCoDYvNeC1VbpsjxdqxcU7tegK+ozkTR7Mm+3086+BouojjOZsrIzXRzJdYc01woYgdqv1u6FgKwgNfEcuhIlZowMBFAa0JE+/CBj6GTbwNmaiLGVi6srBNoQWDkIO4eFbEPKkbxXkMRhtzJwXMndBvUj4HcycO5k9J/YpMWaePqRJScF0wD9voo0GeLjgJoGcEtTsYQc6Q6u2Ok0GkO6k26weWLpgANNFHAJ4XsXwh5J5AOCthXpi8WbakBmupdgxAYSeiRIl9GExnvBYnz8X+/4pJNyLdDWXkcqQIf7SI2FkRSYJu2sbBgInNbh0bXTo2Og1sdJh8Sf93G9jotbDZb2Kr38LWgIXtIQvbwza2RshMbI1a2B61sT1mY3uCmjss7Mza2Ju3cbBow7dcwNF6EeGDIm5IGa8cxJjCUAEjdSmrkpvR7u8SZs6K2F61cE5tefM2q4gQgMdk8xZOvLZg42SxgNNFai8sILxQxCLVfv0FLDP1K2I5UMQKARgsYj3ooC9p4d2FgYqwjs8XBj6HdbwPGXgf1jGQMliz2irdE90nhVRnReZaF04LzAhIgpD/JvgIUr4fB1DHkugPpjoCU0GhfvxNSl4D9rNZUsujot2+YOaCxSTlZRdcBo8aE9ks6WIY1kacquAcQFKkZSrBVKIFGHRzcwxAfqMElvyfjEF4QvAVMHNcwIyAlD0YQSghE8ffg5CgE4pH1yQXQ80Oy9EijmJFJI4dRBYdHA5Y2Oo0sNquY7VNGP3uMLDWYWCdLXWsdelY6zGx3mdhvd/C5kABW4MFbA0XsDlCZmNzVNiYjY0JCxuTFjZnbGxT29uchd0FC7tLNvZWCvCtF3B+UMTVRRG5WwehSxtLAVIOj2uU9x4osvufPCxgd85EaKmIk4UCg85rJwsmTudNnCxwAKl5howAJGjHFlTuiYJkHD6ytfMixhMWPkYIOhMVFxJAbh/DOt4ENdTHNSylDWyFC1gSUFHhZiCKfGGqx5SvDKEEcOZYx+KFhc1kkbvhK1F3oPa/K8sFkJln3kgXQNkXzN52/wJAWRMWlZBLegmJALQwsGtwAD3q5wIozAXQs44ehgFI8B2T+xUqSSCyhxTgPQCQrkEJIzOObPGiiJ1oERfHDsJzBex1m1ht1rHcrGG5Rcdyq8GtTcdyO7eVdgMrHWQ6Vjp1rHYZWO0xsdJrYW3AxsZgARtDBawPF7A+4mBtxMLaqIm1MRNrEybWpiysTVtYn7GwPmtiY97C5qKJrWUL26s2dtcLONgqInBUQuayhEymgIMoPadQGQ+I9AxThw56B+6wPazinCoVSwWcL9k4XbQFcCZOF00c0/+LBa6C8xbOF23sTmkY3jCwHIILHtk6hStRG5UxE58uTFRGDFRdGGxZQUsB4aewhnchFR8iGoZTOrZjFlYpjYVxCD0AivyhdbRtWSggB5A+aEShmmx8tlkDtO/aho/1gsiGaC50LAb0DkZgYwLvAcjh8xpdYDNBFQ8bA3smg4MDSLIt3aYAT9wsqR9zy2KdBJC5XqZ+EswytF5j8J1xxaDEXQ1T3FnCeqyI00ARocUC9rpMLDfqWGzQsNSgY6nRwFKzjqUWHYstBpZaDSwRhG0GlttNLLXrWGrXsNypY7nLwHK3geVeCyv9NlYHbKwN2lgbKmBlxOY2amFl1MTKuImVCRPLkyZWpkyszFhYnbOwOm9ibdHE+rKJjVULWxsFbG85ONgvIhoqQaMJfq4ocKfYSQJIhamE5fMSBjZNVHVcorYugb6mSyz3UhufgdBSAaEVB+dLBQbf8YLtWnDBxuKUggl/AavBElZd+Gg4fwGNpH4XFiojFqoiFqojJqrZ0kDlBSmigc9MFXV8DGt4E9LQktCwcWlhK+hgie6T0v60hIWTEuapkZu5Yq6My2eksiUXQOaCPQASdKwLjtyvtJsCn8LvIYDuTPKiF6SsgBRMeuJAAjDJAezfM+4BSCWC3awoIQsntKT/+bpFsW6ePUyRG+1D/7NlEQvH9Js/MB1H51s6LWHlrIS1QBHr4RLWYiUcJEoI7Ts4GrCx2mhgsU7HYr2BhQZui2SNOhaadCw0cwgZiGRtBKCJxXYDCx0GFrtMLPaYWOw1sdRnY2nAwvKghaUhC4vDFhZHLCyOWVgat7A4bnKbMLE0ZWJpxsLSnIWleQvLixaWly2srFpYXbewtmFjc9vB7l4RZ6clZK6LuLwtYC3AIWSFKSAsCMyfAkPbFlqnc6jvuUR9YwIdDQlMdd5gZ5SrY3jZQXC5gPPlAgILFsbnFaaqa+Ryg0VsBEvYviiiO0mut4CKaAEVkQKqIjaqozaqog4+XBRREbFQQa5ZAEjxIbloigsrojqmLrlLXqX7JBApH07Iilg6LTIwVxiAvBKyGKGPWNLnPehrUDz+I+CY+nlcsIwDXQAfumAZA8ov+Ujw5FcdKchkLjjEY0ACi0oeyfUyu1ECzRFWxOJJiZuASRqDjQHKoS2v5yaPkfCtskQuYT1agv+iiLNFG5vNJuardczXGFiotZjN1xvM5sgaDMw16phr1BiEC80mFlpMLLaaWGgzMd9uYqHTwHyngYVuA/M9JuZ7Tcz3m5gfsDA/ZGFu2MLciIX5UQvz42QG5iZMzE6ZmJsxMTdrYX7OwsKCjYVFC4vLNpZWLCyvWVjesLC2VcDGjoOt/SJ8R0WkkiXcZgrYChaYqlOhYvDQMlDCClNEYOkMmPYV0LesoHnkGnUdabS0XGKw/QbLAzn4xzXMDWcwtmViPcQBpOV2qIjBhI2P5H4ZcARaAR8vivgULaEq7mDq6ga15JojNj4LJWRGQEYMfLww8DFuYCpkYv2Epz3Btnxaco3DV2KungCkSsh2mtcVWG8IY4Zqvzb7RIMcFc17Qzwu2O0LFt+Kkz0h8is5EjypiBxAaucy0LdrMJWihKNYgJUMYRw+saR14jcBxWCj/6V5lM5r7GHp4c9LWA2UsB4p4fC4CP+QhaU6HbOVOmardMxVm5ivsbjVWZirtzBTb2C2QWfGIdQx12RgvtnCXIuFuTYTc+0W5jpMzHUamOsyMddtYrbHxGyfidkBE7MMQBuzwxZmRyzMjpmYmdAxPWlietrEzKyJmTkTs/MmZhctzC5ZmFmxMLdmYWHdxuKGjcUtGys7BaztOdg4KGL3sMTaIyku3BFBP4ePZ+gaFTbXwBWIPMdhAWPbBjpmsqjvu0JdRxJ9cznmbrcCJWwGS9ilYfgJGx9iFj5HbbyPlLB9HcWVuoux9B3qoiaid/uAtoiOhIq3kQI+RSx8jpgMPAKwImKiio4P6ehazTMA2T2dFrFyQuaw+3EBPCMXbGLBA6B8d0jOM87HlpYBZBOZ3j0cjCA/WO0OPPgy/iOjWs56vID5oIn+XYMBxEouuWIGTRHLJNPCFo+Fsf+5hHPwHCweO571Hug8pYxlBD1ouAT/gYPdbgtzVTqmKzTMVOiYYRCaDMK5WjILs3UGZup1bg0GZht1zDTqmG00MNdkYqbFxGybidl2CzMdFmY6Lcx0W5jqMTHVa2K638T0gIGZQRPTQxamhi1Mj9qYHrMxNWFictLA5JSJqRkTU3MGpuYNTC2amF62MLViYXrNwuy6jblNG3PbNhZ2bSztFbB84GDNX8TWcREXiRKyOceFcJ3VWklRyhnOMp3S4YRMAlDE0jFZCRvnwOZ5EVuBInbomJiN6oTFlI3U730EWEglAW0UUGZhZpaA7Aj07DJTxveRAj4zALk7royaqIxZqE4WULV4jfFljQFG90PQrZ46WD1x3Hsj9ds8K7Gxg4uiK44ESiqg9zMf3kGppIAE4BdvxckJB2UDdBlC8T4IAZguYj1uY44UcFvF0hFPOEooBg4DyhGJREa/HbYfJdrycbFsR3y5clzE6jFP6NUT/nBrZ0VsyFIWLuFgs4CNVh0zFSqmPxGABrOZSmHVJmZqTMzUGpiu1TBdq2O6XlgDB3Gm0cBMk4GZFgPTrQZm2i1Md1iY7iL4bEz2WpjsM5hNDOiYGDQwOWRgYtjAxKiJiXEbE5MWJqYMTEwbmJgxMTFnYGLBwMSSiYllE5OrJqbWLExvWJjZtDC7bWGOhkjtF7DoK2Dp0MHKscMyLpIq4S5bwFaI2uFKLH6jTF2nDKZ0kNCx9KHjaF0Ja0yVitg4L3EAz0pYDxbQkDDxIWKy+K464qAy5rCYL3u3DmTHgMw4cDcOM7+I4eQt3oQL+BixURG1GHxVURO1lzY+b96gdzLLrrPBACxijfLkxMHaqYM1Eh0GYAmbNCTt2HoAoLcd8Ct247AxgQ9iwPJ4QD6U2hsHym+FEYC8L3g+oKN3S2FgUSlxJVoAtXJE5mCZWcFdz4Bj20piWcQqQXzME5YSn863cU4JXMRmuIS9TRurDRomPyqY/KRh6pOOqc8cwhkB4XSVgelqHVM1OqbJag1M1XEAJxsMTDVym24yMNWiY6rVxFS7halOC5PdBJ+NyT4LE30mJvp1jA/oGBvUMT5kYGzYwNioibFxC2OTFsamTYzNmhibMzG2YGBs0cDYkomxVQNj6wYmNg1MbpmY2rYwtWNheq+AmYMCZn025g5tLBwXsHLqYDtQQvSyhJtMARsBh2coAUgZTgDSfhK8Ywdrx950KsO3c+6gO27gfVSoWNRCdczGxxjQmjCg5FaA7ARKmSlmyE0C5iwC2SCqojYqYgVURy3UpGxUHObQMnKNVV8Rm6dFbJyWsHFSxMZxEesnDtaPyYpsHRWirVMaREsA8p6QXbfOwAFkqsdm1pUfvuTvhlBN+MGIaDEW8MG3gssnEwp4yfuCCcC+LYUBRKWEldgjh8NEy8MCVqi0E3xHBawectBWDskcsa3I1q8JACneoHOR0cNthErY2y5gpcHAxDsV4x9UTHwkEHVMMgg1TFfqmK40MFWlYbJaZTZVo2GyVmMATtYbmGQQ6phq4jbZYmKyzcRku4GJLgMTPTYmem2M9VkY6zcw2q9jdEDHyKCBkSEDIyMGRsZMjExYGJm2MDJjYWTOxOiCiZFFHSPLBkZWTIysGRjd0DG6pWNsW8fEroGJPQsT+yamDixMH9qYObIxe2yzZgwKMbZDJSRvS0jdFph7o2cvA8jTzE1XApDUh4A4LTH49k6LGIsa+BDVWO21MmqgKmbgU7SAlqQOQ10CtBEgP4lidoYZDe2ylXkklWPUJwhABzWpAqrCOurHrrG8U8C2gGtTwLdx7GDjyME6Gbn/4xI2T0vYPi1hVgC4leY9IazOQMxcOW5bINnepfi0mxgTeL8hWswPKPuAy5JZfimJD0Zw2Hugs2cq+jZyLGHoRljiHDoMPg4gt5XDAlYZgNLK29YYfCX2QOyhTvhDkW0EStjedbDabGHyg4HxdxrG3wsIP2gcxM8apio0TFZqmKgi+ASEtQom6zRM1umYqDcw0aBhokHHRKOOyWYDE60EoIXxdhPjXSbGuy2M9doY7bMw0m9geEDH8ICB4SEDw8MmhkdNDE2YGJoyMTRjYGjWwPA8wWdieMnE0KqBoTUDQ+sGhjcNDG8ZGN02MLZrYGzPxOiBiTG/hYkjG5PHBUxT3yr1JpwXWFvg7kUJ17kSwkkbS4e8QJPCccVzhPoJOyEl4mm+e1LC3IWJzzENnyMaKgWAZO8iBQynbnCT20Tkzof03S6DkIZ1raciqKXml4iD6gTB56AyYaFq4gZz6zaLJ3eocJwWGYCbJwVsHAs7omURm2QnHMC5IxOLF6IrTrwXwjzoPQBNd1Q08XWvL5i9mO4BkMd+wgR8nGgajFDEGmvVV9G3nmUAUkkhgDhQwhhkBawdkRGU8rfcxwOeLFEnvNRRrW6HEr/LxOR7A+PvNQ7gOxVj7xSMvVcYiOOfVEx8VjFZoWKiUsGEUL7JWh0TdRrGyeqlqRhv1DHerGOszcBYh4mxDhtjXRbGui2M9FkY7rcYeEMDBgaHDAwOmxgcMTE4bmJg0sTAtI6BGR0DcwaGFkwMLpkYXDYwuGpgcJ0PCBjcMjC0Y2Bo18TwnonhAwPDfhMjRxZGjy2Mi5e1aJwkDVmbCxbYoIH9WAk39E2OkIVlCSHFei58BbYkF0jub+ekhOVQAXUJAklHFYOvDCCp4ceIyQcfhAusCy6XWQOUKbTHNbyPAdVxB7VJBzXXRXyav8HYnIbtM2CHhoadkXt3sMUgLGDzmMxmS6pEEYBbBCAVgkPD7QnxjoghAPeF+kkjFyybYe4BKF2wOwpGuF4XPtEXTDMirEVpsKKK/o08g44BSEARgFLZBIAMQi+MYvs6xY5HJOtFbBLEJ7zE0YNT6dscsTD1gYAj5dMxRvC9VTH6TsHouzxG3ysY+6BwCBmAKiZIARmAGiYEhGN1Krd6FWONGkZbdYy06Rjp0DHSaWCky8Rwj4WhPhNDAyaGBg0MDhoYGDIxMGKgf0xH36SBvikDvTM6+mZ19C8Y6F8y0L9som/FQP+ajoENHQNbBgZ2uA3uGRg8MDHgMzHoNzF8ZGLkxMTIqYXRM5rhgeaYsTAdtDEXKmAx7OAwVcR1jjLYYgWb3CypHQNQFGACcPPEwfaRg44jHZ9SJqpj3O0ShFURHZURHRURDRW0JBhjBt7HbAynbhG6OUFdnGrLDmqSDmpvi6jcyWFoUmFQUx5QfrK8OHGwdUL3Q2Zj60haAVuUbyckFBzApQuTvarhHRNIHpS5XaZ+ZKJXxPtWnBwN4x0N/cU4QBdAYCdV4gp4pmFwU2EgkQwTRATg+qEjlhLGAtb9tI6Wwg4dbDArYvOwxEoUPfAOPXyghK3FAmY+6Rh9Q7ApHL73HMb7AJIKKhir0DBepWK8WmMqOF5LpjMFHKvXMErWoGGkWcNQq46hNg3D7RqGuwwM9ZgY6jUx2GdicMDAwKCB/iED/cMm+sYM9Eyo6J3U0TOto2dGQ8+Cjt5FA73LBvpWDfSs6ejdoHjYQO+Ogb4d3jw1sGeg/8BEv8/EgN/E4JGJwRMTg6cmhs8s99shNDH4VMjGTNhmo4rDt0Ukri2sHNgiJOEulwf/DlceBkcR3dM5vNq4Q1XKQm2CIBRKyNyxxpcxnVk1bU/YrCG6NmGjJllA7Q1QfaqhdzyLHV8Ju6clBiFBRR5o+7iA7SNh4jcByJWQ4Cx6ALTYJEU0ZK/MDe+So8/5ym456g2591acHJB6PwaUEJYbFSn+YwqY5u2As+cahrdUBt4Ouc2jEgNKQrUpf/vJHGz4HGz4C9gUtnXoYIvU85A/8C4DsITtPQeL9SbGXmsYfaNi9K2G0fcah/CdUMD3ZQDHPqsYq9QwWqVhtEbHWC2ZgbE6HaP1OkYauA03ahhq1jDYqmKoXcNgp46BbgMDBF+/gYEBA/2DJvqGDPSNmOgdM9EzoaNnUkf3tI7uGQ3dcyp6FjT0LOnoWTHQu2aiZ91Az6aB7h0dPbs6evYM9O6b6D0gM9BzaKD3yETvick+U0YmPyjIvq4UNDAaMjERtjAdsbGeKCCed3AeN7FyQGrHQxMWcxF8DAy+XN1z0D50g+cTSXyKaGhI26iOUVseV0TuknX2uyZuojZBoNrM6q6KqIlZaBvPYHPHwd4Jjyl3KS8EgLtHRezSkq3j/+8cOdzof7H/7KHGFHBbAMgrrgJAT/ML64oTCnjPBX9RCfF8A06Cx/r4LsVomHgBc/QJqk2NQUQ3QgASTAQeh47gKmLL52CTEpIA9EBIAG6T0UPRAx+VsE2x4LCD8dcGRl5pGHmjcQDfEYBkOkbfqRj5oGDkg4qRTypGP2sYqdQwUqVhpMbASK2B0VoJn4GRRgPDTToGmzUMtGjob9Mw0K6hv1NDf7eOvl4D/f0mh2/YRO+IiZ4xE10TBromDXRN6eic0dE1p6N7QUfPoo7uZQNdaya61g10E3xbBrp2DHTvWeg6MNHl49btM9FzZKDnhH8RtOfcRO+5gb4Amc6sP6RjMGxg5MLEeNTEbMzCzqWDK72Ig3OTNYdQrEWVAVIcAo8yf+fYYem16S9hYPwOr7ou8GY/g7qrAmoSFmqiJmoIvKiO2qiBupiJuriFuoSN+lQB9WkbTbMZLK9Y2D8pYY8gOyphl/JT2pHDoNsjEMX/O/SbGR1TxP5xEXMEYNjAFk3PQS5Y9AWzGPBBQ7R8LZMATHprwfdmRWDvclLHsvwkq4CQZsXytAMOb2jY8hdZ6dkhV+on49Bt+4rY9jns99aBMLFux+9g188fao8e5EgAuOZgttLC8Csdw681DL8hCBUXwtH3Bkbf6xj5qGLko4YRgu+zhuFKDcNVOoarDYzU6AzCkToTIw0WhptMDLYaGCDw2jT0t+vo69DR26Wht1dHT7+O3gEDvUMmekYs9Ixa6J4w0TVloHPaQOeMgc5ZHZ0LOjoJvBUdHas6OjYMdGya6Nwy0Lmto2vXQNeBhU6fiQ6/iY5DE51HJrqOTXSdmuimz9KeG+gJmOgOGugOaugJqugN6eingaERA0MxA2NxE3NJi82dksoXsOG3mSehMIdcL3eRUoE4jFSIpxcUVLZF8XLuClVxE/UpmwMXp9HPHD5qcmlI2mi8dlC/nMX8ooGD4xL2j4rMCLQ9yhOCjeWPw2zviIyDx/Y5omNKDD7q354/1LEY1u8DyFxvebJ76heWU72wQal3xTKAFAzKb4CVFZBatT0Ain5gCjI34jYDcGhTY6AdUAk6LGLHX2KxxI6v6Nr2gcNs56CAHYLPxx9uz1/E/qF4cHLDviJWerjrHXqpY+iViqE3Ckbeqhh5pzEj+EY/EIAaRj7pGP6sYYisQsNQpY6hKh1DNToG6wwMN5gYarIw2GJioM3g4LXr6O3Q0NOpo6fHQE+fyQDsGdLRM2KgZ9RE9zhXPgbfrIHOOQMd8zo6lnS0rxpoXzPQvm6gfdNkALZvGejY0dG+Z6CdwWeh/dDkdmyg48RAx6mBjjMDnec6OgMGOoI6OqivNaSjO6ShJ6yhN6JhIKZjOGFiPG1h8dpGUC8hcm1jbc/mXsKN0bgCkpFrJFUiW9ux0TV4g7cDSXw+UdB07TDgSPXqkhYakhaabh3UbmYwOp7HwWEJB6RiBCCBJ/KFQchEwsHeoYN9ts7BPrMiDpiVcHBUgp9GLx3qWAjpbGQ1jZhnw7EuqQb8EELvzAkeAJkCihfSvQNRaWSrhI+NhhbzAjIAgwSgjh1/Eb5jrmKy5HD4Stg5ICMIi9ghCH0Odn0e+ITtULy4aGPqo4qhFxzAwZcqBl+rGH4A4MgHA8MEIQNQx9BnHYMVGgYrDQxW6Rio0TBQZ2Co0cRgs4n+VgN9bTq3Dh3dnRq6ujV09Rro7jfQNWCge9hA96iBLgFfx7SBjlkTnXM6OuY1tC3qaF820LZqoI3gWzfRtmmibctE246Ftl0TrQcGWv0GWg8NtB0ZaDs20XpioPVER9upwaz9zEB7QEd70EB7WEcHMxUdFyq6Yxp6ExoGkwZGLk1MXttYuSsgYRcRjJtY33d4zHUq4zJuUpHIJRKE5IWof7qqK4U3K1douHLQfOWgMWWj+a6ImqMc+oZvsLdfxMERmVAzoXwcQofZPtlhAft+aQ4O/Bw+HxkNDDkqYd7PAdxyAaRwrchqvVwJPW74oQLKGJAAlLMZcfD4BNSu+xUAbqcc1hdMo2GGN3QGFN0I3RR/gBJ2CTQCbl8YDSJg8DnY8xWx7y+xUkVLOn5r32HDooZfqBh8oTH4Bl4qGHylYvCNUobwvY5hAvCjjqFPAr7PGgYqNAxU6uiv1tBfq6G/XkN/k46+Zh29rQK+dp0pX3e3jq5eHV19BjoHdHQO6egc0dE5rqNzQkfnlI6OGR3tczraF8g0tC5raF3R0Lqqo23DROumhZYtE600dm/XQsu+iWafgRa/juZDHS3HBlpOTLSc0FJHy6mO1jMdzQENLUENLWENrWQXCtouFLRHNXTGdfQkdfSldQxeGRi+sTB1a2MnX8BlwcFRwGRxNYU7LPaSbpOBQ0rFYeSutIS1zQLae9N4OxJHbcREaxaoDWvoGL3E3q4D/0mJuU+fUDNXEOgaPgf7ZASdj8CzhZUBZBB6AFykGNAdEQ0G4L4EUAxCkADKb0q7PSHMBYv4j/p8yfXuXhawd3k/BuQA0oyYFnPBIxsaUzySYfYQ7OaLDL7d/QJ2hO0eFLFHRurHFLCEA38Je6SS+0WsL9kY/6hi4JmKgRcaBhiAKgZeKeh/nXchHHqnYeiDhqGPGgY/aRgg+CrL1l+joq9OQ1+Djr5GHb0CwN42HT0dGoevR8DXb6BzUEfnsI6OMQ0dEzo6JnWmfu2zGtpI+RZ0tC3paF3RGXyt6wZaNk00b1to2TbRsmcy+Jp8Bpp8Ohr9GhoPdTQdG2g6MdB0qqPpVEPTmYrGcxWNARVNQRXNYQUtFwpaIipaYira4ho6khq60jp6LjX0XekYvDEwemti5s7EgVbApeng4NjENhVcKvBH3CV6XSNzjwQVUzaeDxNTOVT1pfB+6hJtY9fY2bZxeEquk/KNiweDUOQJGYPPNYLQZnbgK+CAIBRumK7jPyxhwe9thuGs8I6LIm96EU0wXgV0ATzOfQ1AmuuNG4eQn5gmJtohBYxxFzyyoTPJplLAAGSAEXxeI/gcZrSdjD0kwUruec/BAjWDPFfR91xF/wsyjS37Xijoe5VnEA68VTDwXsXABxUDBOsnFQOfVQxW6Mz1kvr11Wroq9cZgL1NOnpadPS0auhp15jr7Sb4enUGX8eggfZhDW0jGtrHNbRP6mib0tE+raN1XkULKd+SjpYVHS2rOlrWDTRtGmjaNtG0Y6F510TzvoGmAwONPgONfgMNhzoajnU0MvhMNJ4ZaDhX0RAgU9AYzKMhrKLxQkNTVENzTENLnIbBq2hLaehI6+i81NFzpaPvWsPgnY6RjIG5rIkT00Eyb2PnwGTQeWM3DmCBGYeDIOFG22i636V5Fft7Do5OaExl2fxHRRz6gRNSNPJm0r0SYEzxCvCRHcpl+dzsWAKQtQPaohmGV0JY8x1rxuMVEPZappim998ZQAYfc8NUpeYnlzHgQlDH6IaBfR9/EF5yCDAOG7cC9nwF7PpstuQligCkhytib58Sx2Y9Fn1PVfQ+4xByU9D7XEHfyzz6XufQ/y6P/vd59H9QOICfNQYfU78qHX3VOnrrNPTW6+hp0tHdoqO7VUdXu4auDh73dfZq6OzT0TFgoH3IQNuIgbYxDW3jGloJQIJvRkPzvIbmRQ3Nyxy+5nUdjZsGGrdMNOyaaNy10LRnoWnfRMOBgQa/gfojA3VHOupPdDScGmg4M9F4bjD46gMa6oMK6kM51IcVNFCbXUxDQ1xDU4ID2JJS0Xqpoe1KReeVhu4bDf23GgYzOkazBhZyJgIFB4k7CzsHFoOPQ8gViUFIblIo1oHfxgFBc8gF4vAYOD4ucQAlhIclnBOEaQPbShbnMQPHPgeHVLlg6ubAf1gQy7IdSjsq4viIKyC9orGV5PEffb7D7UWTL6XLD126MeDPAJB3IhN8EkAOH2sPJBVMiak5SAHXDewflNgN+0i+BYAStP0DMgf7Bzb2920cHBRw4HO4UYy4V8DKrIXBtwp6n+bR81RBzzMVPc8U9D5T0PNCQe+rHHpf59D3Novedzn0fcij/6PCAayiioeBfoKvVmfw9TYQgBq6WnR0EoAdOjq7dHT0GOjo09Her6OdqZ+B1lEDLeM6Wic0tE7paJ7R0Tyno3lBQ/OShuYVHU1rOho3DDRsmajfNlG/a6J+z0TDvon6AwN1fp2BV3eso5bsREfdmYH6czIddQENtUEVtWGF24WC+oiG+pjOAGxMqGhMqmhKKWi+VNFCEF6r6LhV0XOnoT+jYTirYTynYUU1EEUBoaSJ7T2bu08CkcFXdpWuy/Q7HMDDEvyHRRwdFRmAR8clnBwCYfrwYDaPfi2FTiWBBf0G4YiFE18JJ8clBtcxHUPHHjpiSdBxo31Oj0tYpL7gsM3eFdpjExRJ+Ph3BDl8ojb87w4gh4+N4WIKyKWVajk0LT/NjDCypuHggB6MyzYpG8FHIBJk7PcBWQG+Awc+d+lgf6+A7R0bc/0GU7rup2Qqugm8pyp6nivoeZlHDwH4Joeed1n0vs+i70MOfZ8U9LP4T8dAtYG+GgO9dUZZ/Zo1dBKAbQY6O3S0d+to79XRPkDw6Qy+thGdwdc8YaB5SkfTjI6mOQNNCzqalgw0rhhoXDXQuGYwAAm+uh0Tdbsm6vZN1B0YqPXrqD3UUXNMpqHmVEf1qY6aMx01AQ01QQ01IRU1YRU1FypqIgpqYyrq4irqEhrqExoaUgoa0nk0pvNoSufRfKmg5SaPtts8OjIKurMK+nIKhnIKJhQN64aOWNHCccBkFTwJIIONxWnleE26VFI6gu/4mKyE80PghPrzlVt0KUn05tLoy6XQnU9iRbtDKGB7ICziWIBHENLvEw98ZzTQ+NDAwgUBKEbDeACUCuhtD2Qu2H0rLodHROK9Zhj5ZhNzu9wNyx4RDiCfmmNsXYf/gG6mCL+/BD89sGuUIGRFFzwaUk/mo7hw18Hmmo2JRhW9pHwEHUH4jBupHwHY+1pB39s8U7/e9zn0fcyj75OKvs8a+io17npJ/ep09NTr6G7SGXwdrTo62jW0d+po69HR1q+jbVBHGynfiIGWUQPNBKCAr3HeQOOCgcZFCZ+JhnUT9WSbAkCCb0/A5zM4fEc6qo41ZtUnHMDqMw3VQRVVIQ1VYQ3VFyqqIyqqYwpq4ipqEipqkyrqUjrqUgrq03nUpXNouMyh8SqP5pscWm+zaMvk0JHNozOXQ18uh2Elj0lVwY6tI2mRizVZISd3SbGZn2I0n+2xAvx+Hqdx1SshfFKC/1pjqteWJ/gu0SeMfveql9hWcwifFnDi5xAScATe8aGDE6GAtI4DWMKi38CCcMHlEdGiC9eFT37698EElVIB2WAEtydEHkwfpeHwefuCGYDUf7mp48jHAaQScujjRiBKk+toP/abANxz2EDTtQULI585gN3C9RJ8vc9V9L7I3wfwPVkOvZ8U9FZo6KnU0VOlo6fGQE+dju56HV2NGjqbNQGfjvYOHW1dOtp6dbT2a2gd1NE6bKBlREfzGKmfjsZpHQ2zBhoWDDQs6mhYNlC/ajD46jZM1G2ZqN02ULdjoHbXQO2egZoDAzU+HdWHGjMG4ImGqlMVlecaKgMaKiWAF2QqqiIKquIKqhMKapIqalMat7SC2ss8ai6zqLvMov46h8bbPJrvsmjJZNGezaIjl0V3PoeBfB4jSh4zmoLjoo1YzsLensViPDdm8xN0BfgJTD+P1ShvTn0lhMMOtpQcuowkOpQk+pU0uvNpdORS6Myl0Z+7wkD+CgP6JfZzeYSOHJweEoAEr4SwyH4TgATf+VEJS34D818FUHTJeRVQNsM8BPB+V1y5QVo2QvNmGLA3n+RrmTT0/IgUUMQJh/TAVOJc8BwckR2IJa2j1xN3C9jdtLE8aWDgjVQ/ApBcsCoAJAXMuTEgU8CPefR+VtBTqaG72mDwddcSfBo6Cb5GDR0tGjraDHR0GGgT6tfap6F5QEPzkI7mYQ1NoxpTv6ZJHfUzOhrmOXz1SzoaVkzUrxmo29BRt2Uw+Gp2dNTsGKjeNVC1r6PqQEe1T0eVC5+OylMVFWcqKgM6KoI6KkI6KsM0UFRBRURBZTSPypiCyoSCqqSC6rSG6rSKmksF1Zd5VF9mUX2dQd1NFg23WTRmsmjOZNCazaA9l0VnniDMol/JYlTLYsFUEYSNcNzEAb0fTZUKViuVEAr4/EUEyJ0mDEzq12jXkujIJ9GfTyFrW8g5Ns5NFavaHYaUawwqBOElBrQ0Dm8UBHwcwlOCzs/tmIygPi4hcFjCok/HXIhPzfHQBT8ckEAx4CFTQPmZBk8MWJ4hX/QHkwJ6IGQAJvncMDQ1/8SGzgA8lXGCnytd2Qo49hVw4nNwfFBg+x7tOTjYtrGzYWJh0GBK1/0kx2NAUsHnGnpequh5qbD4r+d1Fj0sBiwD2FupoadaR0+tge56A50NGjqaVLRL9esw0N5loK1bR2uPgZY+Hc2DBJ+OphENjWMaGsc11E9pqJvTUT+vo54AXDZQt2qibt1A3aaBmm0dNQTgromqPYLPQNWBgUqfiYpDAxVHOioZfDoqznRUnHP46JXGT2GdjVD5FFHxOariUzSHT/EcPify+JzMozKtoPJSQdVVHlXXZDlUXWdRc5ND3W0WDZkMmjJ3aM7cojV3h7b8HTryd+hSbjGg3mJMz2C1oCLqmDg5MXF0WMLxSbnSwNTqqIQAddfdKOgz0mjNJ9GdS6Mnl0ZnLoW+bAonag7yb0G9RV/+EkP5K/Tn0hjT0jhPGTj3lXBGEPqLDERmRyWcHZcQpBjQr2M+fB9A9jVVz2cavApIAB7f/TsAyAkWELJaMLCdouFYNPkiAWjgxFdkVXkmyww0B0dUIg84dGQugPsFHO4WsL9pYnvVwEyXjh6C73EOXU/y6KLY77mG3pcEoYLuVzl0v8mi+20G3e9z6PmYQ0+Fgp4qDT01OlO/znoNHY0ag6+9RUd7m8ZdL4NP4/D1cwCbRnQ0jeloIPgmVdRPC/gWuPrVL+uoXTNQu2GidtPk8O2YqN4zUX1gMfAq/QY+H1p4d1zAuxMbH09NfBbwfQrq+BSiaS50fLzQ8SFCc66o+BBV8CGWx4d4Dh8TOXxK5vE5lUdFOofKqzwqGXwcwOqbDGrvMqjP3KExc8sAbM7doiV3izblBh3KDbrVawxqtxg3MtiHjkTOwuGBjZMT4OSkxO2IA7N0m0O7QbXcFLqVNHryBF8SHbkEtvQ7ZG0TedOAUXQwkr9iCkgADpMrNtJYuszgfK/IXO3ZYfGeUb67AMpKCH2yS3wxiXvTh69m8nGnX8SA3omJygd7ABTzwtCAVAYgfYpqw8SZAJAe1gsa2fF+AScMxCKOCcq9AvzbBeytm9hc1DDRpHH4hDElZBUQFd2v8uh6nUPXmyy6BIDdn3LoqlDQVaWiu0ZDV52G9noNbU0CwFYN7e06Wrt0tHTraOkh+DQ0DWpoGtLQOKKhYUxH/YSK+ikVdbMa6uZ11C7pqF3RUbuqo2ZdAmihbs9Bva+ImoMCA7DaZ+HDoY0PRxZa/Bo6/AqqTgy8PbfwOWDgY5DD94GmuIhoeB9R8D6q4F0sj/cMwCw+JHL4mMoz+5TO4fNlBhVXwq4zqLrNoCZzi7rMHRqyd2jM3qIpd4Pm/A1alWu0qdfo0q7Rp99g2LjDnJ1DCBZCEZN5HZoC5PS0hPMTYHfLRNdVGr3mFXoVskt05dOYUa6QKZgwCwXM3sSR0hUkLZ0pI7nhEfUGY/Yt+hIJzCze4pQBKMDzewA8KiF4WOQumDXDeFywFDJXAeWghPIcgW4tmAHo+VISg88dVMgHGLpdcUk+KdBcwMTkpoFTXxEBqg2RPFOFhGDzqt+Bw40ApD7ILRu7aybWZmn8noKuR1l0PSIA80wFyQ13vVDQxQBU0PU2i653WXS9z6LrYw6dFQo6q1V01mroqC0D2MbUT0dbh45Wgq/XQBPZgI7GQZ3B1zimon5cZepXN6My91u3QAAaqF4xULNmomadw9dyBFSt5fFhNoV6v43GU+CTz0b3vor4ZgiF1UOU1g6R2TzHqP8Or4MWPoQMF753UZXZ+5iKd3EF7+I5vI9n8T6Rw7tkDu9SObxPZ/Dp8hafrm7x+foWn29uUckAzKAue4f63A3q8zdoyN+gMX+NFgFgh3aNHv0aA+YtxqwM1koq4qaFE7+Ns5MSzk6LOD8tYX/DQudsFH3qFQb1G/QpV+jKX+JMVxA3NAxlEui7i6HgONhSM+jLX2HUvMWodYvu/RiGexPYXzZY3p57LODnsR/N/hXyUwzIKyESQOJGetIyfGUASdi+aAf0fuOVk+sdii8aodP0iQYvgDpOD4o4F/EBuWMCkGA7IfVjJgEs4Gi3gIMNGzsrBlYnVYxUegB8lEencMNdL/LofEkQEoA5DuCHHDo/5dFRqaCjRkVHrYr2Og1tDSoHsFVHW7vOKh4tPQaaew009htoGjTQOKyjcVRDw7iKOgafxtSvluBbNFCzbKBm1WDw1axbaPSV8FtPe/C3/+Yv4m//1X+Ef/gLf4CXI+foP3Ggr5wCyz4UV/xwVv3AygFKq370nmTx4oImgtTxLqLiLVM+BW/jebyJ5/AmnsXbhLBkBm9TGbxP3+LD5Q0+Xd3g4/UNPt3coPLuBtWZW9Rmb1CXu0J9/toFsEm5Rqt6jXb9Gp3GNXqNG/Sbt5iwMziBjouoyUIfgo+UkGK0pekcOtZiGDZvMaTdMIXrz1OTSxoDuTRG8mnMKzcYU68xUbjD0O0V2qcuMN17jeNNG+c+B2c+B+ckNL4SzgV8pHzkfsOHRSwxAOmD2vcBvO+Cyz0hEkA2Gka2A7KxgHJEjPtdONEHzL6QSV/HLmErQYMRBIAbOs72eakg9yuVjmA73iOzcbxH/xdxQv2Q2zZ8Gxa2FzWsjKkYqdDQQeCRPSYAFXQSgM85gJ2vFHQyAHPo/Jhn6tdRpaK9RkVbrYq2OhWtjRpam1W0tWloZepnMPVr7jfQyNSPADTQMKahYUJFHVU8ZjUW+3H4TNSscuWr2aCBBcDvvBzEX/+z/yN+/r/8n/Hz/+Xfx1/7s38Pf/Nv/DPsjPuBjVM4K0corByisOJHYcUHLO8jvBvBSwIwouNtRMHbaJ4B+CbG4WOWyOJNMos3qSzepjN4l77F+/QNPlxd4+P1NQcwc43qzA1qc9eozV2hLn8tILxCg3KFZvWKA6hfo8u4Ro9xjUHrFiulPKK6gaM9gzWPBE54NxtVHuYnMug6iGGscIcR9RpDFOcpPM4boaV+hQnnBv2BFHr749ic1hCg0IqZg7ODAlvy/0kBHQQOHQZh+LCEJZ/JAGSDETzdcBJA3hNCLyR9ZTCCHA3D3G9GwsdHwexekgn42EAEDiB9skACeL5PN1TE6b6DU6F6tGS/9wo43XO47RZxvFPgAC7oWBnTOIBP8mh/kkcHwfeUA9jxIo8OAvB1Hl3v8uh8n0PHxzw6KhS0V6loIwAJvnoCUEVri4rWNg0tFPtRrZdcbz93vQ3DOhqE+pHrrZ3mAFLsR/BVr5qoXjdRvWGiZtNG1aaG/+5v/lO8fDSBX/nnL/Hn/tTfwl/5c38fP/cf/7eo+oPPwH4UxdUTOKvHHEKmgj5kNgN8xtEouV8F76J5vI2R+pFl8TqRwRuyZAavU1m8Sd/ibfoa7y8JwBt8vLnB59sbVGVuUJO9Rl3umsFXp3CrFwA2qVdo1QjCK3Tol+gyrtBn3TD1IhU8D+os1iYAmVEFcd/B9PgVus9jGLPvMKLcYFi5xnD+GmPWDYbzl+haiWN66A7HWw5CRwIy+mqnj+CTAPJlwF9A8JDvF/GXsOwCWB4J4w5GoHY/1hfM34hj6vfVwQgi/mMAssEIEkAJIbgLTtA3M+hTUyamGIAOgv4Sm5b2jEHosCX7vefgjAFYwNluESfbDvzrFnYIwFEVI1UqOp7k0P6YIMyh42keHQxABR2vFHS8UdDxTkHHhzw6PuXRLgGsVdFapzH4WppVtLSqaGEAamju1dHcR7EfKZ+GhlEd9dL9TqmoJdc7p6FmQUe1iP0kgNVbFj6v5vDX/vIv4L//S7+Iv/EXfgH/1Z/+u/hv/szfw//jP/hrePHrLwBfAsW1UzhkBOHqIQMwvRXC2wsNb0Xsx92vwtwvwfc6eYfXyVu8Tt0we5O+wdvLG7y/vu9+azPXaMjdsGaXNiWDBvUW9QrFgRLAS7Sol2jT0mjXL9GhX6HHvMawfY115BDOajjasRA4LiJ4UkTwmM/UerLrYGw0hZ5oEhN2FmP6La9oxFLoG4ljfVxFyFdCiCoWBJ+fphq2ETiwEDggEDmQITK/w+zisIgo1bR9JquEUAvJPQA907T52CTl/HvBcoree5UQOTERNRQy9RMKyEbDMOMx4HayDOD0ho7gPpfhgADQBY7BVxRLArCAk+0CDtdt7C4Y3AVX62h/nEPbY4Iwx9TwHoBvFbS/V9D+IY/2TwoDsK1aRWuthtZ6Da1NGlpaNLS0amhp19DcpaKxV0PjgIbGIQ0NIxqDr25MQ92EhtppDmD1vIaqRR2VyzqqVnVUreuo3CQzUH8I/C+/9B3+/f/Lz+G/+JN/C//1n/67+C/+5H+Pn/sP/xrWqoaAvQs4a2dw1rgKOqtHwNIh5g/TeBojAEn9uAsm9/s6lnEBfMUAvOaWvsabyxu8u77Fh5s7fLq9RfXdDeoyN2jOUXtfFkOqgn4txyBs0G7QoF6hQb1Ek5pGi5pCm5ZiKthjXGLAvMRM4RonTh6nhwaL20ICQG4lHG1YGJpIoi+ZYurXvR3DRP8N+zg2wRQiI7iY8kn4LAQPbAQPCD4bIT9ZgcV+EsDlAw4g+2i1dzgWg49/b4YAZPGfGIjwRUM0AUhfxZQjornykRLaLoQSwA0C8NzA1LqK0AHdSAkhig8oHtwv4HxP2L7D7GzPxtlOASdbHMC9RQOrYyp7hZLcL1fAvKuA7QTgay+ACto+5dFWqaC1WmPq11KvoblJZQA2t6loblfQ2KWioU9D/YCG+iEV9SMa6kY11E5oqJnSUDOjoWZWQ9W8hspFDZXLGgOwkgGooWpLR/WBg1eTUfzlv/GP8H/79/48/uQf/6/wp//Ef4Nf+t2PODu8BQi41RNg9RhY9gOLPgS2Y3hzoeJVRMWbSB6vozm8iWU5fHEO4KvELV6mbvAqdc0tfYXXl1d4c0UqyGvA1bfU/ELtfhl0KlmMaApWLR3degbV2g3q1Rs0KJdoVFJolgBqKXTrKfQZKYyaaewgg0BEw8muxcALeSxIg0bWTIyOpjAwmsTquILADoFHXoyUTSicr8CgC+ybCByYCB6YAj4LYYJPqF/kqIg4zXDmM4QCegGUAxGkCy6Ij59zF/xVAF0XTBC6ANLImPJwLDYeUAA4sa4xACNUHafgdN9BYM/B+Z7NAAzsFxAgEHcLAkAbh2s29kgBx/NsIALFfR1PFbSTEXzPFbS/JADzAkCVAdj6KY/WSgUtNSpa6lQ016toblLQ3KygqU1BY4eChm4VdX0q6gZU1A1qqBvWUDumoXpSRc20zuGbU1E5r6JyUWEAVqxpXP22DVTumKjYNVBzCHzeUPCbb4bxL/6wFj9uXUV1sIjPpzbWdtPIrgVYbfh6LYDl/TRehzW8FPC9iZLqkRGAd3gVv8OrxB1eJm/wUsD3MnWFV6lLvE5f4s3lFd5f3eDTtQDw7o4B2K5k0aflsWYbWDFVVOQvUatdo169ugdgpwCw10hiyExhsXSDQEbB8ZaB4JGD8HGR21GJGcVtwb0igjtcOEjJuEsVCics6CPlI/gMBH0mg48B6CP1c3Bx5CByzAFcdfuCvwYgTdXLXTBTQtYXzD9a/TNcsFBBORyLjQcUgxEoDmRD8gWAaxrC+w4iQgGDBw6DTiogwRfYJQBtnO/YON2k72kUOIBjWUy15NH1nAPY9jTPAOyg/1+oaH+toP0NV8C2jwpaP+fRUqWguUZBU52CpgYFTU15NLbk0dCWR0OHgvoeFbX9KmoHNNQNaagZ1VA9QQBqqJ7RUD2no3JBQ8WiisollavfhoGKbROV2yaq9m1U+x1U7FNXm4O6EFAfAarDwMdjHe+PNbw4M/DxTEXVqYI3QRVPIzpTvtcEXySHN5EsXsXIMgzAl4lbvEhcuwC68KWu8CZ1iTfpS7y7vGJNMdU3BOAtGlmvRwY9Wg5TporDgoGW3CUqlDRqtTQatRSaaTSLnkaHnkS3nkCPkcSAmcJU4RKndh5newaL2ziAjusyGThHfHlx6DA1uwef3yrDt29wYwpoIuwjALkKXhwWEP0KgKwhWg7JF++XuzGgMFkJud8QLSYnlwpYfiXTMxpGKKAEcHJVRXjPQZRKkq/kAkjgBT0AMggJwK0CjtYK2F8wsDaWxUxHDt2vSP3yzKT7JQVsf6WgTQDY+jGPlgoBYC0BqKKxXkVTk4qG1jzq2/Oo71RQ18sBJPWrHdFRM26gZlJH9bSOqjkd1QsGqpYMHvutGKhaN1C1SfBZqNy1ULGt4tP6DSoPTFT4DHz26/h4qOHDkcbge3ei4c2pilfnKl6GNLwKqXgdVvCGTLjeV5EMXkbv8JLgi93hRfwWzxPXeJEk+C5de03w0TKZwptkGp/S16i6vuEAZm/QSv2+Wg6jRh77jokx9RYf8gnUMQDTAsAkA7CLIDQS6DWTGLGS2EcGwRMdpzs2QkcFNqqFqZarXLTkEIX9NoOKAAsJ0EIHBkIHOkL7tDTYMrxfBvDCb7Pjo0dFJGjaPZ+OhXD5nRCawIBBSG2ClzQ/YHlIPqmhnKL3CwApOCw3w9CEghLAsgumGHA9Sh8jNDHhAfCCalAHRQSpVrxf4CZADO3aCO7YONsq4HjNhm/RwPpYFnPdGfSSwj3jxlzwCwVtLxW0CQDbBICtFUoZwHoNjQ0aGhsFgKR+XSpqexWmfrVDOmpHCT4DNdMmamZNVC9YqF40UbVsomrVQuW6iapNC1UE346N+hPgx/VL+J/+we+g8sTBZ7+Bj34dHw5VAZ+KN6cKXp8peH2u4HVQwatgDq9DOby+IOXL41U0y+GL3uJF7BbP46R+Nwy+F6krBt6rVNp1v/T7RSyB17EkPiavUEmTh9/eoil7ywDsVrMY0rJYN3XMaFl8yMZQp6XKCqglmXXoCXQxFUxg0ExgAzcIxVScbJisNksxHgETOXIQJQAljKRkzK1auGBwGbggO9BxccCXYVrum7jYp/9NRHwWIv4CoocO4kclJAWAiwJA97VMMZ6UAKT3g/n3gh13ZoTjTBE0KdYXAMohNO6sCKInpAwgKSB9PJCmo1VwQQAelXDhL7FPVdGnE8L7BYT2bIQIPlru2ghtFxDYKuBkzYZ/0cTmRB7zPXcYrMoLAFW0PVfQ9kJB60sFra8VtL1V0PpBResnBS0VCpqrFTTVqmgi+Ej9mglAFfUdKuoIwD4NtQM6aocN1I4bqJ42UDNroW6xiPpVoHrFRtWKhao1C1UbHMDaA6DxBOhMAf/nH1Tjf/h7v46aQInB9/5QxbsjBe+OFbw5KcP36jyPV4EsXoUyeBXO4mWELIcX0QxeSPhiN3gev8aLxBVeJC/xIpV2AST4yF4kU3h8EcXLizg+Ji5Rmb5C7c0NG4TQxmrCGQyoGSzqCqbUDD5koqhTk2hQkwzAVi3BrF2Lo1OLoVuPod+MY7F0icBNHv4lHee7VKslt8tNAsggZBUKm8EXOSAIDUTIBHyuEXwMQhNRn4Wov4DYYREJF0ANC2GTtRETgEwB2ch6+i2+lk4frGEfq+Gfbi2PB5Rzw2T4KAX5dXTZFSffEZYxIBuMIACcWlURIQD9RaaAYV8RFwcFhPdthPcKCO/auNi12TJEn6LfsnG2YeNo2cLOtIr53huM1edZxYMgbH2uoPVFHi0v82UAP6po/ayitUpDU7XK3W+DhoYmDY0tGhraNdR3aqjt0VDTr6GGuV8DNeMmaqYttKwD1XMaXgxcoGajgLpt6uO1mOut2bXxeiqG79s28Huvh/AX/8zfxR+1rKAqUMIHv453RyreHil4c6zg9WkOr85yeHWeY/C9DGTwKpjBy3AGLy4yeB7J4lk0g2cufML1EoApMlK+NF6lyS6ZPU8k8JNgAE8DEXyKplGdvETd1RWa7m7Qlr1DVz6DASWDRSWPoewlPmTCqFMSaFATaFITaFHjaFFjaNWiaNcu0KlF0GvEMF1II2jkETnVkIpYSAVtploRX5G5TYoBI4cFRPwOIr4Coj6bKxsDUQIoIPRxNeTrTUT9ZDbiDMAiUjT3I3sx3cRmwnEBdOcXYpNUivkBGYAPRkR/fYbU8iyXZfWTb8XxvuDpgIWZNRXRPQcxf5E9XMTn4GK/gIt9my/3bET2aFnAxW4BoW0b5xsWjlYs7M5oWOi9wWTLHRt00PYszwBseaGg+aWCljd5tLzLo5UqIBUqWqp0NFVraPQA2NCqob5dR12XjtpeDTWkftL9jhtoWgb+4OU0/ubP/yJ+/q/+r/if/uEf4s1EEnV7YApYd1TCD2vm8ef+n38Pf/Ev/G/4jQ/jqAwA730G3h/qeHOk4vVRHi+on5fsNIuX58ICd3gRvMOz8C2eXdwJ+O7wLH7LjOBjlrzC89QlXqQp9pMApvEyncSzVBw/CpzhJ0en+BBOoiqWRn3qGs03N2jL3KIrd4eB3B3mcxnUXYbw8S6EOiWGBiWORjWGZjWKFmYXaFMv0KFdoEePYsJMYrd4izAyiCOLG+SRUzTEjsmFchUkF0oQEkyu+chI4QgyA1GfMIKPlrTObyJ+WED8qIDEUQEpmo6PAWhhK+5gL1XEfppcr2dyIvbNOD5XtBwRTQAyF/wQQNkXXIZPTFTEekO4C14TAE6va4juFxGnb1/Qg+0XECH49sgsASD95mooATxeMbE/q2Gp7xqTLZfsPY/WpxzAZgLwlYLmN3k0v8+j5RNVQBSmfo01KgOwoYG733oCsIMA1BiAtYM6aoZ11IzSMPsivqvcwZ/6E38Z/++/9S/R2e3HX/rP/kf8jb/+T1G5mkfVVgGftkx83rXxZjWH9zsaKs6At/s63jH10/H6WMGr4zyen2SZEYAvzrN4ESDL4DkBGLrBs4sbPIvcMvVjACYIwCsOHxm523Sa2cvLNF5dCgCTMfz0IoDf2NvB4+MgKi9SqIldojF9jZbrG3Tc3mL0LoPOdBRP4z5UZS5Ql4+igUyNokmLMPhalQu0qmG0q2F0aRcYMWKYMZJYUBPY0NLwG1dIlu6QVVQBGAFIcRy5UhuxQ1rHIYz5LcQYgBaDjynfvs5BZOtNdkz80GYApmneR5+GeQHgPmsLlAByBeTfjROVEdETQq+AcAXMeeaGkQCKUTBEr6yI8L7hIhuORX3B0+cmZtY1xPYcJA5LiB1wAKP7EjqTWWTXwsWuhfCOhdC2hcCGhZMVAwdzGlYH7zDRFMdQTRatL3JoeZ5HMy1f5hmATe/zaP6YR1NFHo3VeTTUKGioU1HfoKG+WUVdm4Jacr/dGmr6yP0SgAZqRg00zJXw//2HP8XP/Ym/gr/y5/4/+J//7q/jL/xn/wN+7v/6F/Hbb6ZQ4wc+bBl4v23iw0EB7w9MBt/bAx1v/TpeH6kMvpfHOTwnIwgZgBk8D9wJ+G7xLHyN5xc3eB658wB4g2dJoX5CAV+SAl6ScQhfXqbwPJXAo9gFfvfEj1/d3MCT43NUh9NojF2jNXmLjvQ1GuJRfBvax+vLU9RkL1CXi6I+H0GDEkGTeoEWNYxWJYw2AWCnFkafEcGIEsVkLobFfArraho+7RKpYgaJoM68UYziOBbLEYAmYj6TgRfzWa4x5dvXywD6KAak/SzE/RYSh/YXAO6lyOUSgFy4GHjMBdM0HeKr6eKD1V+MiC63A4rGaOoRcQclFNj80HwwQgHT5xZm1nXE94pIHpYQ9xUFhAQgqZ+Ji10yAeCuAHCTA+ib17A5ksFkUxxjjTfoeJdH04scml/l0fI6h6a3OTR+yKPpUx6NFTk0VOXRUJ1Hfa2CugYFdc0KatsU1HSqqOlWUdOnMgCrGYAm6qcK+Ht/51/jz/7H/y3+/H/6d/Fn/pP/Dn/+T/0d/Ny//5fwL3/YxhqbOYAG3u0aeLOn482+jjcHOl77NLw8VPDiiMP37CSH56c5PD/L4tn5HZ4Fbzl8AsBnF9d4Fr3B09gNnsRv8DR5jWeJKzxLXuFZ6hLPqbbL1E8CmMKLdJIB+DQRxffREH776AD/bGMZv7azid8/9OFHJ3784cke/uB8By+Sp6i8C6M2G0VdLsIBzEfQpITRrIbQoobQpobQwQC8QI92gYF8BKOZCGZzCSzlU9hWkji1LhGJ5RHa5O42RorHlgJArx0YiO4biJEdGIj5pPHticMCkqSANG0wVUJCJgOQx4Ce2q+YpFxOUsQA/FpfsASwXAsuT1C0m3bY7Pg0LQfNgCSbYSgGjAsFdAE8IBW0EGHqxxWQKaJQwcCGidMVA/4FDdvjOcy2pTBcG8dADdV882h5o6LlrYKmdxzAhk851FfkUF+VQ31NHnV1CmoaFdR6AexRUd2noZoAHCIALdTOAf/iN1vwn/x7/zX+8z/5d/Dn/tO/g//8//638Gf+o5/HT5v2ULlfYgC+2zHwdlfHmz0Nr/c1vD7Q8NKv4OVhDs+PMnh2nMXTkwyenXJ7cn6LJ4EbPA3e4SkDkNTvBk+j1wLAazxJCAATl3iaTONZKoXn6TSeX0pXnOR2mcCLVAxPkxE8ioXxw8Axfv1wG7/qW8evHW/gj8IHeJ0+R8VtGNWZCGpzBGAU9TkC8IIB2EKmhtGmhdGhXqBLi6BHi6Avf4GhuzAmMlHMZuNYycWxbyRwHrpDYI3XZrnScUVj5kJG0OmI+XTEPev4b9NVPwLwkqYOlu2AbiWEKyCL+whAMUUbH5BQBvDBaJgvu+J4d5zoF04XGICsHTBGABqYWVUQ36OS4CBOcn5gMwWM7pUBpN9RFgtauCA3vGnibM3A0ZKOvWkVy303GKoKY6j2Fp3U5PJGRTMB+J4AzHIAK3Oor86htjaPmnoF1Y0KaprzqJEA9mqo7tdQNaijatjAhxEHXRM6tkfD+OX/16/iP/zjfwX/0R//q/iTf+Kv45d/uxo1+8DHDYsB+HZHw+tdFa/3VbzaV/HyQMVLfx7PD7N4enSHp0cZBuCT0wwend/hUeAGjwM3eBK8xZPQDZ5c3OBp5AZPItd4ErvB49i1gPAKTxJpPEum8CxFFQ5yuWk8TxOMHL6XzOJ4kY7hRTqKZ8kInibDeJYM4EUqgHfXYXy6vUBVJoKaXBS1+SiLAR8C2KqGmPulSgjFgD1qGL35EPpuAxi5DWPi7gKzmQtsalEc7dwisFZWMgkUh9ELG8HHAYz7DST8JhIEHlVC/CaSRzbSxw6uCEA2Sz4fD+jWgmVFxJ2iTQxKkOMBXQAVz4BUASAfiCoh5OMB6Uvp1AvC2wE5gNMrecT3OYAxHwFoIbpvMtiiexw++s1UUKhheMtEYN3gbnhOx+ZoFlNNMQx+jrLJhZrfSfjyaPAAWFeVQ01dHjUNCqqbVNS0KKhpz6O6S0F1r4rqAYoBDXwYLmBm9Bb2hJ8+Nwl9fB+jj1pQ/xtvUF+5gsodoGLDxud1Ex+2dLzdUTmAeype7qt4caDguT+PZwTgIQF4h6cnd3h8lsHj8zs8DpAC3uJJ8AZPQrd4EubwPY5c4XH0Co/jl3hCyicAfEoAJqnCkcLzZIK53ecMvCReXcbx+jKG11dxvL6iZRSvr6N4cx3Bu+sLfLiN4FMmgspsBNUCwNp8BHW5C+aGOYBBDqBCChhGF5kSRHfuHN03J+i9PsPw7TnGsydYC1zAN5lBaMtw4zimZu5vDhcBR+Bx6MqWFPsyO7SQOnZwTZ+NOKRvxZE48bZitzdETFLJpnkRM6a6A1K9LyV9CSCfCas8FOthLVgCqCK+Ty5Yxn8EnMHU70sAyWxcUPfQpoXzVQvHiwb2plRs9F6jr+4KDZ+y6KxS0fghh4YPedR/zKP+Uw51lTnUkgK6ACqoaVFR0666AFITTOWQjb4RBcVJP0qTPliTfthTh8BiEFgOwlq6QOOyjverJj6u63i/peHNtoZXuype7il4sa/g2UEez/w5PD3M4slRFk+OM3hMAJ4ShLd4fH7LFPBx8AaPQ9d4HL7G4wsJ4CUex9N4nEjjSSLFjAB8mkoyIyVkAKbjeHmVxOurBN5cxfHuOsHtJo73zGL4cBfFx7soPmWi+Jy9QGWOVDCC2jzVhMOoV6QChtCmEIAhdDAIQ+hUztCVO0HnzSE6LvfRfbmP6dwxfFtXOJxUEN4m2KgWazNXyo1DxQBkyvg1CC0kfBzAJAF45OD6yMHmIX0pqQyg7LRg3Mh5hsRs+cwVP/xgNXfBfEQ01YLlcPyyEspYUABIlZAzAeCug4SfAOSxH4HHFdBClLlgcsk2g48suuvgYqeA0IaN8xULZ/M6tqdVVFXk8NM/iKL1cxatnxU0fMyj4aOCugpSvyxqa/JMAcn9cgAVVHeoqOoS8V+/jo+DNnxjCWD6APaUH+bUIcypI1jTZIfAjB+T89d4sWri/ZqGt5sKXm+reLGj4Pkeh++JL4fH/gyeCAAfCwAfnd7h0dkNHp1zF/yIwXeDRxfXeHQh1C9GCkjwEYQpPE4k8SSVwhMXQK6AL9IJvLpM4vV1Cm8FfO9vyDiAH27j+HgXw2eCLxNFZe4CVQQgKaBCjdEhNChh1wUzAPMEIFkAXcopevIn6MkeouNqF13XW1hQThF3sri+1pE+J5BsJH0Oa8ejWC55RFBxdywhJPOqH0EnFTBJNWAGIH0VwcYSAUgDUmlyynttxxxAPqyPV0ZkUwwD0PvBavdDheKdEHeW1HsDUssAzqyqiO84SLg1YN4Mw9XPUwkRxmEsMAij2w5iNDxrvYCubgMvX97hj/4wge/+8IINvW9i6qegviKP2qp8GUBSwGYF1S15VHUo9wHsN3E2FgWm/bCmjhiABJ89c8wMs0eYWbjGs1UTb9dUvNnI4+WWghc7eTzby+MJAXiQw2NflkH4+CiDx8d3AsBbPDq7YwBSHPgodINHYYLvGo8iV3j0EMBkGo9TZfV7mkqwhmcC8GU6jleXCby+SjIA398kGYAfCD4B4KcMARhDRTaKqryAj9yvQuoXQqNygWYlhJZ8CG15AjCIdiWIDuUcPeo5hpQARtVzjOVPMK2cYNUIYa8YQwjXuEIeWd1ALlXA9WkBqQMbKVK0Q6rdCjdMSsfUjitf0m8z6BiIftqXYsACU8ANv4XFi/sKWAZQjiugWjGPB9nL6Q8/1yrfC/4CQGZSUstdcbNnVAvWXADjBw5iEkChhFwFhRru2Yjt2azWnKbG6wMHqysOWrotfKpU8eZtDk+e3OJ3fhDGsz+Ks6H39Z/zqKtQUFuloKZaQXWtBFBFFQHYnkdlp4LKHhWVfSre9RlYG00zAEn5TKZ8R7BmjlCcOUJh9hSNizm8XNHxZk3Fq40cXmzm8Gy7DOAjAvAgi8e+Ozw+vMOj4zt8LxWQVULu8Ch4ew/AxxQDMgC5CyYAnzwAkLtf7oJl5cPrfpn63Ur1i+PjPQCjqCEIFQFgPoxGaoIhBcyH0EoAKgRgAJ3qOfq1IMb1EGbMMBasC6xYEWzYUWwXYtgtxnBQiuMcl0ghiztHx921gasTA8kDA0kC7lAont9Eyke/CVDq9SgwFWQgMgUs4Jo+SuQz2eREBKDsB6Y5Al0XLAEk+NhHqx98sJo1ROfuf6qVQ3dfATmARWwQgNQOuKYjvltA0ldC/IC74di+jdi+hdiehTjZron4Lv1P8Nm4oRG3+w5Gpx3UtRdQ1WCiotbA+88qXr7N4dvvrvEbvxbAi2+TaK5WUVuhoKYqj+oaAlBBdb2CqiYVlS15VLTlUdGZR0W3iooeFR9YU4yCq8kAq4AUpg9hzxwBM4fA9DEW5i7xfMnAmxUNr9ZUvNjI4zkDMIunOzk83svi+/0MHh0I82fw6IhDyF3wHb4P3N4HkFVAvABSJYQDSO6XAZhO4Rmr/fL2P14BITccx9srApC73ne3BGECH10FjDMAK3NRVDMVvEBtPozafAgN+TCa8mE050gFg2hj8AXQr4UwpocxbVxg3opgyYpi1Y5ioxDDViHGINxxYth1YtgvxnGMNGLIIGvruIsRhELhhNIlfcJcCG2khBqmCEBfEWsHOm+IFsOx+ASV8uNGYoq/B9NzEID3R8OIT3W5vSAP4j9Zu9mhuWHYa5k2Ztd1JPYcJD0KSADG9y3E920k9sgEiHs2rg9s+LcK6BiyUdtmoa61gOqmAj7XWfhYbeDtJxXPXmfww58k8X/+yjGefZdEY7WGmkoFVUwBVVTVK6hsVFDRrOBzm4JPHXl87srjY4+KT30q3vbrqBvM4Xg8AmXqDMb0Ga6ngpiYvsbLBR1vljS8XlHxcl3F8w0FTzdzzB5vZfBoO4Pvdu/w/d4dB9CXxfeHd/iOqWAG359l8N35Hb4PZfAofIfHFzd4FL3BY2mxa7cW/IQqH0keA3oBpCYY6oZjMeBlggN4k8AbqnjcxvDpNo63txG8u6PKBwEYYwBSDFjNKiJh1OZCqMuFUJ8LoDEXQHP+nKlfnxbEmH6BKSOCOTOCRSuKZSuKNSuGdTuOTQkggzDKbNeJYt+J4wyXuIGC7LWJ1D4BSO6WW4riReGG+XruglNHNq7pM2wHBuZDNuukoAkqJYB8QIsYWeVOzUFtgZy1r/SE8DH75blgPADKzzQkaYbU+wCmaGSEiAMZePs2kmzpILlXQGK/gKsDG0ebBbT2k/JZaOggCG2099voH7NR12rhfZWB15/yePLqFr/zwzj+xS8f4rs/iqCuSkVVdR4VNXlU1CmoaMjjc5OCj615fGzP4UNnDh+68/jAVFDF6wEVrwZV1IzkUD+WxYcJBc9nNLyZU/B6UcGLFQXPVxU8Xc/jyUYWjzfu8P3mLb7bvMN323f4dvcO3+1l8P1+Ft8ThEcZfHecwXenWXxznsG3oQy+D9/hUeQWj6O3eCTa/76PXeORUEGqhDxhAMoYMCkg5I3Qshnm1VUM767iGLq9wX5eQUjXcGzk0Z1NMQgrcjFU5Kgp5gJV2RCqs0FUZwOoyZ6jLnuOptw52vMB9KlBjBphTJkRzJoRV/1WSAEZgDFsfA3CQoRBuOfEcFhK4hI53KV1JAlCUjx/AWkfhzDls7j5LaT9NtL+AgfQR5MTFbApAOQjoj3Ts7HYj3+0Wr4b7FZC3CH5HgDlWK6HAMoYcCNewhx95XFdR5JiusOSGwcyAA/IHGbJfQfpAz4apmekiIYuB41dBdR12OgesbC0XsT8ahHNPRY+1Jl4V63jxacsvn15gx/8KIZ/+i99+L3fC+LTpywqahR8qsnjU30OHxvz+NCcx/vWPN51KHjfpeB9t4J3vQreDuTxdjiPN6N5vB5X8GYyjzf0Yb+5HF4u5PB8KYenKzk8Wc3i8VoWj9Yy+G79Dt9u3uGbrQy+3eIgPtrN4ul+Di8O83hNA1LPFbwM5PFN4A4/Cd5yCC9u8H3kmlVCvotd4fvYJR7F0ngUT+H7ZAKPkwlRARFxoOiCo5ow9YK8SEYwfXmHUNZELG8ipZlQbBuGU0B/NoW3d2F8ylzg810QlZlzVDE7Q132DM05qvEGMaiGMa5HMEWDEMwY5q0YFu0Ylu0YVqwYA3DNjmLNjmG9EOPumMWEpIIEYAx7TpzZUSmFK+RwFdSRYrVkDqA0ApGWl2SHBdzQJOhsQGrhXiWEAchmyS+PByzPlP9gSL47Q6rbFSf89z0XDE8lpIjZQAHz6zrSDMAiq9InfAXED2zED0j1HAYkLdP7BczOFFDf7aCpp4iGbgf1nTa6R21MLjhoHbTwqdXAx2YD7xo0vKxV8ORzBj99c43f+S6Gf/av/fiV3/Dj0dM0Plbl8bE2h/f1WbxryuJtaw5v2vJ425HH2+48Xvfm8Lo/h9eDWbwZzuHVWA6vJrJ4NZXBi9ksns9l8WwhgyeLGTxayeA7Zrf4du0W36zd4qfrd/hmI4PvNjN4tpnHqx0F7w9oHkADzQEL3VEb3QkLr0I5/Oj8Ft+GbvDtxQ2+i1wy+zZ6ie+iaXwXS+E7gjCR5BAmEngqYUzG8TwZw/fxMJqjcfivdPhvdRxldJzlNIQUA3emhbCu4O11AO9uA/h0F2AA1mTO0Jg9R3suiD4ljBEtikkjjmkjjhkzjlkrjgUrjqVCAstkdtyFkGLBtUIU6xQTWlFsWRFs2RHs2BHsUgXFiWPfSTB3fKnkkTygwQZFoYSkeML1UgXEZ+PK7+D2sIBNH80RXWDe0R2M6r4TIlwv65IjAMtTc9wHUMSA5UoIfWjkPoS8GYYDOBOwML+mMQCv6CZ9BSQPCsL1ShfM3e/pmo22fgcNvUU09Tlo7C2gvtdGbbeFqk4DnzvITHxsM/ChRcfbJhUv6nN4XH2Hbz5e4fdfJfArPznFP/nNffyr3z/F9y/TeFuVxdv6LF435fCqNYfX7Vm86sziVU8WL/syeDmQwYuhLJ6P5PB8LIsXExk8m8rg6UwGj+cyeDR/i+8W7/DN8i1+unzHbeUWP1m9wzerpIp5vKCmmk0V73dVVPg01J4YaAsWMJYoYubKwbPAHX7//Bp/FLrGTy6u8NOLNH4aSeMbsmgSP40l8G08ge/jcTxOxPGEWYzZ40QU31wEMHxxid2Uit0rFXs3Kvy3Ko4zGoJ5DUlNQ+1NCG9vSfWCaMwG0UFdbPkwhtQIxrUopnSCL4EZg+CLYd6OY5EZwUcQCgBNcsWkghQTRrFONWMrgk2C0IowNdwtRLFXSOCgmMRF6Q7JExNpX4mNeGHQEYBHHMBLv42rwwJu6QvqPj5Fr6uA7H1gCaDogqOhWKwWLIZk3Xq64ojEe1P0ShfM7AGAbG4YBzPnFubWVAbgpb+INMk1A9Bk8YML4F4Ba9MW6ruLaOwroolA7LdR12ehttdGVY+Fym4Tn7sMfOo08KFDw7t2Fa/a8njeksPjhjt8U3ONH1Uk8YM3F/jnPznCP/5dH37lj07xoxdJPK64wfP6DJ63ZPG8LYvnnRk8687gae8dng5k8GQ4iyejGTwZy+DxxB2+n7rDtzO3+GbuBj+Zv8FPFm/x46U7ZvT7JwTlUgaPF3N4saSw5pr32yo+79N0vDoazyx0XxQwnSqiJ27gt49S+P1AGn8YSuNH4RT+KJzEjy+S+EkkgR9H4vhpNIZvY6R2MTxKxPAoHsWjeATfxcL4UeAEg8EUNuI5bKby2L5UsHut4uA2j5M7BWfZHBpugqjPhNCZj6BfjWJYi2FUi2Jcj2FKj2Jaj2HaiGHWTGDOjmNBALhQiGGJ4CvEsWrHWUWEAUjumGJCM8Ig3GRKGMW2TfEgxYIJ7DtJHOESkZDCmsyowZkgTDP14xBeHkoAKQY0sBASMyMIF+wT/b4cPs8I6YezY5U/VigU0DMYlYNXnh2BXsnkfcFFNhpmdk1BercgACT4CDyDLamPmNr84lsWpkYM1HYRgCU0DjioH7BRN2Chtt9Edb+Bqj4dFb0aPlElolvF+6483nTm8aozj+cdOTxpy+D75hv8tPESP6xJ4Tc/x/DPnwfwT749xi/99AT/6kkQv/Mmhh9VpPFN/TW+bbnBtx3X+K7nGt/13+G7oQy+HbnFt6O3+OnYLX48cYc/mr7FD2dv8aO5W/xw7gY/nL/FH87d4EezN/jp7B2ezmbxej6PtysK3m8q+Lyrsql56+g7cOcWBqM2RmIWfs+XwG8ex/F75wn8fjCOPwjF8cNwHD+6iDH7cSSKn8Zi+C4WxfcCvu9jYXwXCeB3T/2oOQ5iNXKH5dgd1hNZbKZy2L7M4PAqi/l0DHU3Z+hT4hjS4hjRExjV4xjT45ggAA0BoYj95qw45m0e/y26ACawIgBcsyJYtS6wZkaxYUZd+DiAMewWyAUnsU8qWIrjLJTB5W4Rl0cSQqoFW0gfktm4OnI4gOK1TKmAsgJCI18khPIDmAxI72AE2Q5IkxO5AAr4+CiY8gRF9I0Q5oLjRTYgdXY1LwB0uAtmqmcyo8oIDVa9WDcwNqCgsstGfX8RDYMO6ods1A9aqBswUTNgsJEsn/uoGUXBxz4FH/ryeNebw5veHF715vCiJ8tU7VHXHb7tuMVP2m7wo5Yr/G5DGr9eHcf/8eECv/Q6iF96eY5//jKIf/kmhF/9cIFfq7zAv66L4QfNSfxWexK/1ZXCb/em8VsDl/itoSv8YPQKPxi/wm+NXeIHY2n85mgKPxhJ4cejN3g2mWWVlvdLCj6tK/i8raJyT0WNX0PTiY6eAP/k6q9vh/Brvgv8zkkMv3cewx8GYvhhKI4/Ckfxk4sYvoly9Xscj+FJPMrsUTSMby/O8ftnfvxgbwOdR2Eshm6wdHGD1cgtNqO3mInEURXzoT0XxqCewLCeEAAmMGrEMW5EMWFEMGlEMWVEMW3FMGfHmAISeGTkfsmkApLrXTUjWGPqR+DFsG1FsSPg2yskceCksGcnmBoeHd3hcqeIq2OCkCtg2m9yO7RwdcQrIWs0S/5FgSmgWwHxfCfEO1fMF6Nhyt8LLgMo1Y/Bl+YzI8iuODk/4PQZAajgcpdcMLlfGfeR8Xa/CA08WNUw3nuHCmp2odhvyEHDsI36IRN1QyZqafzeoI7KARUV/So+DSj4MKDg/WAebwdyeD2QxcuBLF4MZPF0IIvH/Rl813eHb/tu8U3vLX7Sd4sf9d3gD3qv8bs9V/jXHWn8alMcv1x7gX9aHcQv1gTwT6rP8Qs1Z/iFunP848Yg/lFTEL/QHMQvtAXxC+1k5/iF9jP8b22n+IfNp/jl1iC+G7zG6+kc3i0o+LSi4vOmisodFTX7Kur9KjqODbzdv8Y/Wz3Br/vC+N3jC/zhWRQ/Csbw43Ac34Sj+DYSw/dRAo/Hfk+TMTxLRPA0foHH0RC+DZ/id4/38JvbK3izt48m/zmaj85RfXKIN6F9NNxSw3IcQ0aC2YgRZ/C5AOoEYATTRgQzVgyzHuVbdgi+GDNW+WCxH3e/MgbcsmNM+XYYfAkG30EhzYDc0CI4XL3F5T7F+A5zuUz5BIDkiglKBiC5YALQbYK5D6H86oI7NyC9E3JXvN8X7AIoPs0gxwDKqTnYrAiXHMC1aBFTAkCugLw/kWpNDMI93hNysW0huKphsTuNqhYFVT3kem0O4IiJ+hEDdSMme4+jakhHxZCGT0MKPg7nmb0fyeHtcBavh7N4NZLDy5EcnlE8N5LB49EMvh+9w3djGXw3nsG343f4ZiKDn05k8JOJDH40fos/GLvB743f4HfHr/CDiTR+czyJ3xhP4NfGE/hXE3H86kQcvzIRw69MRPArYxH8i9Ew/veBc/z91gP848ZjfNt/jfczCj4sKvi4qrDpOiq38qjbUVG9k8WvLp3iV3cC+P3jCH4SiOHbUBzfRRJ4HE3gSSyBp/EEXiQSeJlK4nU6ibdXSdbm9/4yhg/pKN6nIngTD+JJ5Bg/Cezh+8A+nl/48T55jOZMBH1qEoMawZfEiEHKl8CYGce4GcMEuV96A44BGMWcFWUVEBc+J44VJ45VZgRghEFI4K3bomvOjjP49p0U/MVL+JxLbFtxrJeiWA5e4HQmx2q61NzC4ZMAGtwds4boQhnAr86OVW6Q5hUSXs+41xfMARTDsTzxn3S9/LccjFDCatTBFA1GWMkjvVNgDZK8FuwBkAYibJkIrunYGbpEc1Ucn7os1PRZTPkaRi00jFuoH7dQN26iekxH5ZiGz2MqPo8p+DSm4MO4gvfjebwdz+H1RJ7Zy8ksXkxlmIt8MpXFkxluj2cyeDSTwfdzWXw/n8O381l8s5DDN4s5/GQpix8vZfDj5Vv8aOUGP1q/wY82bvGjzVv8UNrGDf5g/Qa/u3qJfzUXxf86cIT/pdmH3+i8wPej13g1k8Xb+SxeL9zgu/kk/o/ZE/zq1jl+ep7E44sUnscu8TKRxqtkGq9TKbxNp/DuMokPl0l8vE7i800KlbfC7pKovk2g+jaO6tsYam+jqL+LoikbQ3s+wb5e1KcmMEDw6UmMGimMGUmMmUlMGGRxTLoAUgUkjnmL13xZ80uR20qRA7hGEBZkG2AUm4U4tinWI/CcSxwXrxl8G2YMy04EczchLA9FEF83WXsfA481Qhusb5gZiwV51+raAQfQ/VacBE98M4R/NZO/nCTbAe+NhnF7QmQTjDtDlpwliwPIJqhko2EcTJ0amCUAdwlAWQPmACap623HRHTbRGhdx8mCgvG6ID5WJFHRa7O4j1xv/ZiFhkkbDVM2aicNNo9LxYSOz5MaPk0q+Dil4MOUivfTGt5OK3gzo+DNbB6vZvN4OZfDc7L5HJ4v5PF0IYsnC1k8XczhyXIOj1ZyeLSax/dreXxHtp5j7XvfUGPzzh2+2c3gp3t3+Ol+Fj894PZjsr07/HD7Br+9nsK/mA3hH/T78Q86ffjfu4/wS/3H+MURP35x9hD/ejeE74ME3hVeJWmelyu8TV/h3WUaHy5T+HCVxMerJD5dJ1Fxk0TlXQpVdylU3yVQm+FWn02gKZtESy7BvlrEZrJXU+jVksz1Uuw3YhCASQ6gkcCEkWLtfqwCwgCMY85MYMFKYMlKYKWQxKqTxJqTxIawLbJCEjuFJPYKKewX0jhwLnFQuMSulcY6vcxuRLDgRDB+FcBE/ynOJjNI71MzDIFnInVA4GlI+aiBmoN46bdwLQDklRDuKXllQ/SEPHgxSQ5G+GpD9NcBlCZiQHopKcIVcG6VN8MQgLINkNmujcSOhdi2hYtNE8FVHQfjd+j7dIZ372P42G2gashG9bCJWoJwykbbfAHtizaaFyw0zJuomzdQu2Cw+VwqFwxU0KRCCzoqlgxULBuoWNFRsarh85qOz+saPqyreLum4BVrv1PwlPp5hT3eVPD9dg7f72Tx/V4O3+/n8P1BhnWzfXeYw/dHeXx/nMd3xzl8e5jFN/47/MR3jR/tX+H3d9P4wVYcv7ERxW9uRfD7vji+D1zhxcU1XsWv8CZ5zWY6fXd1jffX1/hwfYlP1ykG3ufrBCpuCb4kqu9SqMkkUMfAi6MhG0dTPolWJYl2JYlONYVuLYUegk9PYkAn9eMVD1n54AAmMCUbnkn9jDgWrSRWrTQ27DQ27TTW7RTWmCWwZiWwasVdWzG5LRkxzOtRzGoRzJgXmNTDGPCfYKT1GCfjt0jt6EjvG0gfmEgf6Ejta0gdqEgdSAg5gDc0qmlfAEhdcexdEOGGKf6jJhl6GYm+G3xp8/dCHs6Sz0ZEewEUg1F3LullJDlbqqyEOFiNFJgCzlElRLQDkgtO0fB8oYAJGgGzYyGyaSG8buB8WcPBRBZDn8/x7tkZXjdk2ADSilEblWM2qids1M3YaJy30bJko221gI71Ajo2bLSTbZJZaNuy0bpdQAszm327t2HHQv2OxT4mSF80qtiht910vNzhg02f7uT/f41991sUSRvtP3732/Ctq2t2RRTMmSgoKIqCkvMwwxAkDzA5wOSEeu5z3requ2fw23t/OE91V1dXV8+cflMlXPTn8XeAw63yuBDM428OPF3L4e/1HC58zeHCZhZ/b+Xw91YWFzj/g6NfmG4dyyhoTkK6sn+MawcZXD86xo1wRsjXEk/L8mqtabvOcwpt6YSoXEq+dpLvJIqHJ1E8ykZF6j2l5MtH8KIQRUeBS6xF0VuK4lUpjr5yHG/KMZF+JKDj/VbCeF8JGwJGpNdjvBrGXC2GhVoSs7U4xqtRjJaP8KF8iCHODy7tCYbKexiq7GGoSuzjfS2E97UDGTUzmNxGj38DXb2rGHmyh63RLGLLZcT8JB0JSPCY/cNFRElCjwRMB+tCQO4bsxA5hT+uq2g4TogMzeIgBM/EpIbVsbKevmBDQLsouXrBFrpPHGc+KQHLqoKlJ+SHBKIZC2S3mxCRw684AtpIQUvCtZEcPj8/wuPL27h6cR9X2lP4p7uEW29P0fr+FK0f6mgZruHWxxpaR2q4PVrF7S8VxVgZreNltBjcnCjp6JapMq5PF3F9uoDrM3ncmCvixkIRN3wlme3GyUZXZah9ARfXDNZzuCQz3nK4uJXDxe0cLu3kcWmHaQ6XdnO4vJfDlb0sru6f4BpXvRLiHeNm9Bg3YxmXfFxml8TLpNCeSaL9OCEqVyTfCSVfDI+yMTzORfEkFxXyPS9E8LIQQUcxgu5SBL3lKPoqMbyuxDFQcQmo5FMVLOSrRvGlSokXw2I9gYVaAmOViPSKDFZCeFMJoZ+Tk7I76E5toSuxha7YJjqPvqJjbx0v1lfxYnEVL74E8aJvBT1PNzD8+ACBgQwO59m3r1AClhoQ9RcRZUpCWgKukoBlfNnl0hynOinJOxpGBqfqygi2W65RBWeNBPR2w5kANIlHRisZdWk22oCWgKOTecR82hVHKZggCVdOEfMTSsCwr46jxRoO5qvYmy1je7KIr2M5LA+dYORJDC+u7KDlz6+4dGEH568f4q+7SZx/zphfHn+/LuHSYBEXh0q4+L6MS8MVXPpYxMUPBVx4n8f5oRz+Gsri3Pss/hzO4txIFufGczg/XcCFuSIuLxRwzVfQGW+c67tewrWNIq5+zeMysZnDZc713cnj8m4el/eIHC7vZ3FlP4urXOvvkAtNmlXuwydoiZ6gRbZYOJYtFm4n02gzC4xzjee7x0m0nyRwPxvHg2wcj7JxPM4l8DgXw9N8FE8LUTwrRJWARbOwkFnfjwTklloDhCWgeL5RDFdj+FiNYqwWx2IticC3Y8zVEvhY5hYMh3iV38OzjVXc/7yI9r553H2xgPuPF/Dw/hwe3ZvDk/Z5vLjjQ/edIAbubWLkWQjz/Ql8/VzA4UIFEUM8h4ABQ0CSrhkk4GpVQjPp1VNMGgJyH2nyRIbu2Z40TlA3q2M5TkjqG9bSdmJ69rujgu18EPV6VfU6A1FllfzvMuRm5qCOj19LGJ7IIbJ0aiSgdsepBKwh5q+pM8JZ+IaEofmKxAV3pgrYmshhczyHtdEsFgZS+PjkCN03d/Dw4lfcPreB6/9dw8X/ruKvP1fx33Nr+OOvNfxxYQ3/vbCKc38Hcf7CCi6cD+D8OT/OnfPhv3/58MffAfz+zzp+fbCLX/ui+IMOia+IK8sFXOV0y3Vd3++frQKubeVxbTuPa7t5XN0r4Op+HteIUA5XQ7ri1fVDLjKp5OP+HreiObTGs7id4AYzx7LBTHuKm8so+e6dZHCf2yxkE3iQTeg+H7kknuQSeJqLic33rBARAr4oRmXjQJV+XOE0hv5qDK+rCQxUYyb0opLvQzWKT7U4xsTGS2H1WxaLp2l8qkbwtn6Ezo11PH65iK42P4YebmGs4wCzfREsDsbgG4oj8D6B1Y8pbHxOY3syi/25PA4WCzjylRBe5pC6KiL+ipKPPVkOEYuILhMFxJYLkjIvtlJGPFhFkr0hwTo++wpKwCNO3bVLtOngFeUPQ3mcE6JzhO2WrSIB15okoB2KLwT02H9Uv1wD2BLw09cSBsaPEZqvIrX+AwkScEUlYHylhhj7hGVAKiVhDeGlGg4XK9ifL4sk3J0pYme6gO3pvBJyuoCNiSJWPxew/D6LuddpTPUkMNYRw8jzCD49CwtGXkTwpTOO8Z4Epl6lMNWXxGRfEuO9CYy+jOLdw0N03trGnctBnL8axO9dBzi/UMCllRKuBrnYUAkt2yW07pbQsleSxSVv7OdxI5SXVU6vHyrsMrs3w1nZ2ag1lsPteA53ElmztdYx7qWO8TBzgqfc1ZLL6ua5q+UJegpcWu0Y3YUMOgu6xdbLQgIvC7q4+AtZ24/rO8fRW0mgrxLH62ocA7Uk3laTeFdLyHrPH6pxfKwlMFJPYqqexvLpCda+5bF4msFINYahegSd06t4c38DiwNJbM0UsLdYREhQEJIJFvI4XMjjaDGPo6UCwr4iIsslRPyEIZ0HEdp7/jIiy1qOJIyRiCRfoIR4sCLxwBQHJvjrGPYVMGYkIAnIFTQ0fGe0qcyMMwSkNEzphoUOAbljDQnoOCFG/YoDYtIlWRnBEvAUo5tl9I6lsDFZRGYdSFIFG/IpASkF6+KMMCQTXqriaLGMgwWigtBcCftzZexzofPZEnYoGadL2J4uYnuqiK3JArZIzKkiNqdK2GSeXDdlzPHWdBGb0yXB18kS1idKWBsvYnkkiy/dUTy9uYaLrav4cziOiwGueFDCjY0yWrbLaAtVce+oirtHZbSFS2gN67Za3F7hZiSPW5E8WqN53JGNBbmlag6PUnk8TefReVzEq5MS+rIl9OeK6MsV0J3LoyOblS1WX+a4yyWRFhL2FDPoLaVli61X3FqB4G5H1STe1FIYrJF4KQzVUvhQTeBjLYnRehqTpxksfMsi+D2P1W95zNXTsvrV229RdE+vY+TxDnamijj0lXGwXMKhjyjiaKmEoyWmBQdhX8ElVZPKbYA4HARtP2sLGrVMp8Taf+t17C9W8M5XkAUq58PkiO6q6k7rdScl6bwQYwNmTE+IQ0Crgo30I+kUrJRRbmW3JeCXrQp6ptJY/JzF8doPJIO0AS0BdVg3JWB0uYaIELAiOCQWymJ3HMyXEFooITRfxv58SSSjxe5sSXpRSE4Gs3dI0tkidokZguclbHsxU5Z0a7aEzdkiNqYLCHzJYqTzEA9agvjryZaM/buyUcbVzRKub5dxa7+Ce4dVPIpU8SxWxYt4Fc/jVbxIVNGRrKIzXUVXuoqedAWvMkQZPekSOtIFPE3pRtN341ncEZvwGLcYjkkm0ZJMoCWVQGs6gfZMAvdPEniaTaIjl0RvIYnX3DarksFQ5RjD1RN8qmXxuU6cYKx+gul6FgunlHY5LJzmMF3PYLQaw/taFAPVMHqmNjH28hAhmRhGVdqIo+UijnyWfJR8eYSX8ogsFRDxUa2WXfhpA1pJR7tPPWCXfEpAesOUfiQf7b/jde77UsLbQAGTobqRgFb9qiA7Q0AZJePZqGYt50pA3aSG4RZWRNQN7DnXhqEXXMeXrRL65o8x+jGNdOA7UmZIVpyDGB0VXBMCRn2GhL6KYqki0vCQEnGxhIMFRUikY1nSn2FfypSErJSee1TnC0wrgl2DHe5fMqek3ZwuYH0yi6WPaQw83kFrSxAXunZwYTaDy1slXNuv4jp3ONovyz5vrYdltB2VcTdSxv1oCfdjZdyLl9AeK4gkvBOjOs7KRoP/xLnr0QmuhzO4tpfA1bUori4f4upiCJfn93FpKYQrqwe4sR9GazKOdmsbnsTxJJuQhce7C0n0k4zljOx+OVQ9xnuC5OSOmOUEBsoxDNZiGKxH8Cq+h67BVUx1hXEwXxEbjoQTdcpUCMjpsnnB0VLOQI/DSwVERQVb9UqUJfTC47h4wJZ8jZ6wEpC23ynSG99xvPoDk9MFDK0WMSUSUIWUo3odAmovCAloR8lQBSsBjQ3oXZZDJJ8h31IDCbk61ilmD+sY365gcDmLvg9xHM3XkHZCMSShqmA1aEnCKiIC2hUVh4xHS2XBIbFojklMm+fFYknSAyFtGaFFJWxIjiuC/YWKIaRFRYi4PUNVnsfaRBYL7xIYeLCFuy0ruPxgHedf7+LCVByXglz5qogreyVcPSjh2lEJ18IFXIkUcDWSx9VIDlfC9IyPcXU7hUvLEZwf2cFfr1Zx8YkP/7T7cPfOMp60BfG8bRVPb6/h4a0g2m8FcOuOHzcer+Bq/ypuTG7i1kYI7dEoHhzH8ZR2YSmJDmf7rSS6ywl0lHUR8o5yBC9PDvBsewuPP67g9fMN+N4k5Hei88DxlxHabWKzWRKSXFS5KvlcEuYkL+LLI7qclzJEzF8ykk+JpxqM5KPN5xKRMcFEsIbU2imOv35HLPAN76az+Pi1jClHArrjR11YCejululKQI8TYgm4FLeEIwFrDgGX7OpYBzVM7FQwHMzhxacolj9nkVmjI2IJyIA0Y4GUghVDwIohII8pESkNqT7Kjnp2pKRM5fRITJLVA5eYFXFsmDrEtBKTap3SkpJzvojduSJ25grYns1jgxJxKIlPT/fQeTOI9ivL+OefAC7dXcP5Jxv48+Um/uzZxp+vDLo3ce7FBs4/CuJyWwAtLX7c+8ePF7eCGLi/ibGuAyy8iyE4msHGRBYbkzmsT5xgbTyL4CiflcJkbxTvH++hu20dj277cfvuIlpe+nBrYAW3R9fRNr2JtvkttC1soW1uE3em1tH6MYC2V0t4/GQJ/Q9XMd1ziL1JeqMkX8k4DSSLeq7qVNC+sxLxLAlJPiWokjTqVwLGST4hoIK9IM1xQEpAEjC5WkN24zvW58rom8/i83ZVzLIFsQGbJaDrgOgCRbqTprs40Rkv2PaAWAlYc6Vg9BRLsjxbDZO7FXxay6NjIoGBgSiSnPkmUpB2YF1Hx9C2EOJZUMy7hBT14VPiCZhvelEkNeEBKWul5v8koysplYiUkEVV8YtMi5K3R5CMs3mRjBuTeayMnmDhbQoT3REMP93HwL0dvLqzhd7bm+i98xWv27fw9sG2xM5mXsWw/CGD9bGc2Jv7JD4dAF8JoaUi9pe49koB+4tEUdI9YqGA3QV+BEWsj2Wx9C6Byd4DfHy2g8H7G+htC6KrNYDO2ysSq+u/u4ahh5uY6DxAcDiN0HxBHAM6Aa7Hqh6sENA4DdJbIV6sRwpSHYsNmEOUdqCP5FSJSXvPCb+IpHMJGHdUsHq/DL8kglWkVmvIcAPE8SwGAgWM7dRkfIAuz/YT6WfWCfQSkD7HT/qCddQqPRhVw00gAcN1zB/WML1XweeNAt4sZPB4ICwDDjIbMLFA7Y5T6aeGrrywxJoUlpRCLCPxSEC9T8GBrRIWEPVCwqrUPPKVhXw8FxL6/rfK1mObTzIqSE5iX0Bi0p4sYW++hN35Anbm8tieK2CH0nNBwbKhJXqZZeNt0tgnygZsWwmHy/RKC4IDg9BSASGmyzxmPUU9N6TdJUHnFXt8jrRf6w9TmpEM7AJbqcoKBjyPeL1Tx2kwxyIBuXYP7UETevHR/lNP2A04u1LvLJqdEI6OqeF4/VQiE11f0hheK2Fyr465MJfm8GzTwJWx2C0ngWjOB2EAWvuHKewa1ge0BNTR0MpcGwd07UFOuzvFYvgU80c1zOxXMbZZxHt/Fk9G4ng7GBdnhOPHSMAY1a9IO0NCIZ4hmDgoJKC1Dc9KP0d9m5TkVfVMo5swhDSqmqTkH6awxz8h5hnYchUc0MYUlEwszRJF04OlIg6FcCaA6/mo+JGECeuBLpOAeYeIDI0I/NZDVWKF/Sxr6zR53mMDks2VdnymqlqF12GwBFTHwrULDYwDov/JWQKq6vWSWW0/JR+lXx0p/yneD6fQO38s0ZDpUB0LtP/MTklWBQv5zDoxdqCqMyLa3a7V9IQ4YwEt+epnnJGlKGe/1zF/VMfsQRUTO2V8Ws3j1UwG994cIjCaw8k6wzF14wV7yWftFY6YMQSjxKOX7KhbEtDk+1lWJzhZj1pWWbCq25LQQ8pGErpkdBwdb55IUSWSJfIRJaohNq+JNBOJpqShZHOIIn+oElAktCGOkk9DIEK8JcKQj+fmupVqQlxTH71QGyAO+7n4ZwFhqlGRZPaaS6rG+B3VqZVWhkzi3VpPl46GkpJILHNKrTvowBK7gZAO8Wpq+wVryK5/w8qXPJ5/iuJ9MI+J3SrmDskLdUBUAroq2BkhzcnohnxnBiNYL9hZls3E/rwhGBJwMcoRD3S365g7qGJK1HAJ75ZyeDoSx7PeQxzOVmSiSlwC0Uo8SkNLJh2yZdSsdUgMubzSUAgq5ZWsSlCFl4DWdhQCiWfNAKxLQCGS5CkJxfOm42MlGOuwtqagijClrX0GicoAr0iqRgJS4llbyoY1bFjEltXnMyBs4nLNBPR6rk54xKhOseE0bqd1a4jFIaCRdkrAovTbWpuOJCMBz8BfESSY2vCLIbAVFOqMcBiWh3yrdRxvfENkvorOt1H0zKUwumHCL0fqG1BALcc8W/xyaq/MiuN2rUpA2SfObNXV4IS4m1XrzV7VSyzGuPgMQXFbF0dkimp4u4zhYB79sxm0Dx6hvzeCpI+L1tSNZ6Xki9neEUsqsRMJl1iqyjy2oJTzkkNVsnjQHk9Z7UOPk+IhWgPobRvbUYmnBNQ2uM8QdS+SSdWqqkgvAe0H4CWgtbm8ZT1g7wQJyNQQrEE1Gq+UZKO9pnZbAZElJaaQT5wHTwzPqF9LwIZzE9fzEpHSkFJP/xdKP+OENLRDiajqWEdEk3zpjW84Xvkmptbj0Qjer2Tlv58O1UT9culmyxVnn2mJ/+mq+c40TSMBnWmZznhAu0kN54SIF0zvVz1gC5JvMco1QGgH1jFzUMMkpeBmEUPLWXRNJHGrdx8fXyeR9n1DwgSkSTqJDdpzrsBECOk0lqVq1qhakk5sQi8xjL1lVLRKPWsHWkK6YZuwENBKIOO0iMdty1ryNJoIZ0i4QmOfRFRiKcEa7TX54yT0QcnmEszeQ9KRVCSgkMshnJF2Eo5ivgaPIwyXsMdCgsYaq7OkayCryXdVsOlCk9+K0MEEEuMz97nnhpQkpNdR9JnAtIwFrMkEdAad8+s/MPnhBHffhvFmMS3Sj/89BRG9X3ZSOASULlyGXtwgtBBRJKLriDgE9A7JdwgoatcQUIinEEckauKBR3X5AsZ3GJIpYHDhGM9GYrjxchefB9JI+41TIr0jLhwiWjiBa6OaSUYbOyQZpIPcSxI3RGMJqGEZDesoEV07z0pAKy3dmKRCyOj10OWZxqlgGigpxDZrlIiWRBL2ELhkFEKK5DKSz3iiLqFcaaYSzxMoNuRjwFhGodjnmMEB3vulB0PIpBJQbVOrVt3BBFKe3XCse6mImM8loiWgSk4j/VY06Jxb/4H54TzaX0fQM52S+C+l30yoKtqQ0s/OoCTxBJ6NzoWAsm2DWbDcTEw64wW7gxE49KqJgJSAoor1gWQ9A4/sFZkK1TDG/YNXCuifOcbjD1Fcf7mL4f4kUsvfkRHHhPFBAydWaKSiRzq63q9H6on96OY7YRohkqt6VfpRKtljks72lRqv26nDIymcP8wjBT0OgrXZHPvNSUkk7VFw4m4N9puJv5luMZLM7YEwAWMjzdwyRgou5xD1EXkl4lJRutCs9HLvtaS0vRn2fdygNMmnzojWIXUJATmrUclrnUUrFCj9UuunyK5+x9S7E9zqPsLL8ZRous9fS2J+qfSjmaYSUKMmNSwL6vA7g5ldYioJtT+YXcANQ/LtgFRdEd8NQiv5FByUID0iRPibGKBCwv06vmxW8N6fQ990Rkh4+ek2ejsiiCyc4uQrR8x801WVDBFJOjt6xu0/NuTzqkbH/rOwYRzjRAjRDDySTaSbIaD+KRoW8qpe77FDdBt7FBWrEs+SjuEVkoupPXbVoZtnCeiQSIjndn85YRDH+7UE1vtY1t4baRhEoCEU7elQ8jmkNCq2wZ5bLiIu4/nMvazDQMjnL6tD4u0FWamKI5nxn2K4P4HrL/fx/EsS75ZzGP1akE4IRkEWjlQ4NcaLyZEqfLGqEjFWhz/GtCZpIO6uEx3RwQjfZTCCLFBuVkWgESkVRatYFNTUCXGISEmoapgGKPsAZw5PMblXk6+DX0nfVBpPhqO49Gwb7Y92EfiURyb4AxnOsudEZ8/IGSc1nlkDKSwxvMdOHLFRlQrhms4bYeKSDWRWsjUSkPUrQRpie44DYYmXP0NASySHaE7wVwd0uiq70WFoVMmu6pWuM5/tQvOoYvF4NfRiHQslsvGaxabUujiYlHDbp88X+y9QQYLqVlRuFam1Ok5WT7HFUMvLA1zt3MOzzwm89Z3g03pBQm8z+xXpjNDQSyNIPvKGsKRTVB1wrUAPAXU0DAkYSJuFKO0QLBIvwn1g1QNeECJ6SUh78BTzHnuQcaHRDUPCmTSef4zhRtcuLt1bR39HGDvjZaSDP5Be/y6jKujiKwmrOg1QSOGNTXlsRQ+UJJaYHpJZMhkwpNBMaNfu9NTVULfp2jLepdhoxulwbDyHUI1/rEsgK3VsHK5JOnnigEpG95odgayqk7CS05DO6Z3gu3iOjefr2olmBLNfpZ0TE7QTjgz5Uis1ZFZPccK9XmZK+NQXxbWHX3GjNyRqd2DpBJ9WC2L3MfQ2e0DPV/2BRgLW4ItW4ItUsRwl2Tzki1bgj1Xgj1d1VEyzBPSOB2RfsKpa1/lwCOjYg4aExiGhJKQqng5pgHr0q/aSvJ5JoWMkhrbXIVx4soGr9zbQ3xnG6mgBcV8dx6unssYcjV0ZZxbkXFSNuksMqkFNq7TUPJcwNqygfaX6Jbv3sYwb1xJIbIuLLOqEa68Z4H4MtjdAJ+EIIZmyL3ZFr8mATSf+5u0WU4cgYdSbqjjrJBjJJ32r5hmmJ8P27cp7ONKthLjt4TCDQZ3fh/MyOD6Po1QkaKzq0xtUliFU7MMNECQcy1aRYpeaSLs6MoEa9iaL+PgqitsPt3Dx2Sbuvj1C92QKb305fFwrYWyLXW4VzIYqEgHhf+4loA5aqcAXpfol6WgDqvp1CVjVgQlm10yxAUlAcUKyP7BigtFCwLg6HAuiekk+JaJLQpWA1iumQyL24EEN0/uGhBsFfPBnMTCXQfd4Ck+HY7jZu49zD9Zw4c4qHtzfxsfuMFY/ZXDIpd58VSQDnGuqM+5dfEMm+E3S9MqpzEVlyjWn0wGihpS/KmmaX3OQ99e1HoMU7zN1NdedDn5HhostEsyTemtIESs1JA14TEjd/OOCfF5VkPIiUEWG7fHXkHZScxyoIE2pEzB1BupIBurOsySf8FeQ9JcF+owaMit8Zh3HwVMcr37DMYdF8QM278vYq0De19TPNjKUYtrKtiV9VcQ4bnK8gJnBJLqfh3Dt7gb+evgVN1/t4/lIHH1zGQz5cxhZL7uSL1TF/CE9X/3f3aF6preMajdK0pF86vn6Y0TNSMSqkJJL9dLhFQnoLlCpS3NQBdvRMJSCQkJLOiGgK/2sQyJOCSWh9BOzl0T7iid3yvjytSjddVTJr2eP0T2WwuMPEbT27uHCow38fnsF524GcKM1iAf3NtH5dBf9Lw8x2BXGYFcUg91RDHRF8KYzgjcdEcl7y/zOKAY6mEYw0BHGwMsjDHQcYrDzCG+7wnjXFcFbi04tpwhjgJB7WVcM77rjeNcVx2BnDIMdBizbZRGW+6Te7oiA9dpnvzEY6DjSdrw8whsB86OCAfP8d11RvOs27yB1M41hwLzPAN+RbeuIYID3v2S95jlyzmO2nffoffLb8B27oxjsYWre1bw/fwuCv0/Ps308e7iDO/c2caVtA3/dXcPfT7bQ+iqEp8NR9E6mMLh0guFgQez5id2KCBQKFo4BoOptln4OCePW0dC5HxJ6MVKQ9qDYhCSm2TVTvWDPXnF2UpJXAioB+VBVwS4BXY9Y9pATEupgBXpH7B9knGhqt4LxrSJGN/IYXslLtx17TbrHkmIfPhg8wq2eXVx+uoG/7gfxZ3sQf7QF8VtrAL/e8uM/gmX80rKMX3jcEjBYwS9Mb/rxiwGPf7sVwB+tK/jjThC/t67I+a83A/i1xYDnt1bwa8sKfiPM8X9urmg5Kat1ad3L+OUfH375Z1nOpWxLQJ73f26uCH65GdC2tKxI3XKddTDvFt9lFb8Kgvi1lWX4jGX8p2VZj5l/i9D7id9ag/jNyWMdQfx2m/cr/tO6quDzbvE55h4PfrfHci2A3++s4M+7qzj/aB1XXmxKp8GjdxG8HI2jdyqFgcUMPgSyGFkvYmyzLN7uDFXuYU3+038jn6hgIWC9iYCuIyJeMfPMGoE/DcPYEdFCPJJOYI85+di1BUlSd96IISJJSJvw6BTzh3XMhmoivie2S/iyWcToegEfgyoRGbjum8mgZyKNjtEEnn4I4+G7Q9wfDOHum3209e/h9qtd3OnbRXv/PtpfhwR3Xx94wPN93CP6FfffhHD/zYGkkv96X8pIOXONqUDuN8dvtK72/j209+2hrU/T9j7mmfz+PS3zWo8FUjfbzHq9bTuQPKK9P+TUwXrb+nbR1rejz5B307Yp9nGXbbGQ9h3g3oABy5jj+4MHuM/UeyzvrscPBg5xf+AQDwYP8OjdIZ4OH+HFSASdXxLonUzjzdwx3vmO8WGFXm5eerUmtouY2tNAM/9Dko/xPlG7DXafDdUR1su1ElBjfmIHkoQ2NshhWoaAqoK9A1LNFg2UgCLlxAP2ks9AQjMqAYV8JuAo27l6wzNHHLyqJKQYn9wti21Ig5ZjCdl7wn7kIX8Wb5eO8WYuhb6ZJF5NJdEzmUD3RAJdY3F0fYmhayyG7vG45HVPJDUdT6BHEPekcfRMJBTMk+Okk/ZOupBzQUrzJhICe6+tn6k8e5xtiGo6GUcPMcE26TO1bbZ9REoM+R6m4wl0fUmg80tc3qlbYOqSugnbZrYthZ5xbaPT/kmShtDf6NV0Cq+mCHPeBIbC+qYtUuifTePNfBpvF9MYIukCOXxczYt2GtssiJCY2ither+szoZIPu6EbuN9trtNhY2N+WnopYJlISCdDSWhOBwSgLYSsJGA6oR4pmVaFUzJ5njAEVW/DTBq2GmMnb5p7UIrBS0RD3XwAoOXopb3Kd7LGBcylsXWGKFkXM3hw0oW7wMnGFom9OsULGXwbonHJwL+gMx/u5SRH5SQMsznfYITBe+R+k7w3n+sdfuz4qW/9zMvKxJZn6nPZf2SShsyeOtj3XxGGm+Z8nw547l+rPA+1581yOHdsn5k0l6+hyCDIXknzdd31HcYYpuX9D0dSHvY3hP5jd4HcvoOts3Lx3IscN7NxYfACYZXsvi0msPoeh5fvhYwtsXYXhFTuyXMGOLNHZJ8dDb0/2Y4zh2YYofpkYAUOLzO0IuCzkZj/E9Vr6TSPUcCKtfOBqI9Q/KtA6L9v3YsoMYFJT4oX0RzFFwJqY6JklGlodoP4qCQjAdV8ahIxun9iqpoEnKb7n5RfpjPG/plNmC9ICnJSg+bGJHzHEbW6LHpNbm+bsuzjIKhoc+sW1AUdUMniamcO/klSRn1t8+WZ0j9/PP0D9RrOYxu0G7S69Iu3meg9dAGZrvcNmn7LNj+rIPGa+YZVI/mmfxtBFK/Httynw1G17P4vEHo+Rfiax5fNvNKuu0iJondoki8uYOKYJ7kO+Ikc+1mEwJKiMW1+di74f7Xqn7JCXrBGgesSB6JKD0iRjWLOiYBOUYw/QPhnxOw2QnRhzMOKA9xIt12pEwzAa2I1mMrDVUiWiLWRCJSxM8d0sNSKBlLmNwtYXKnJF8mf6jxnRLGjcRUlCSlOqenTUxIeU3HnfvMvSaV8rtliWc52CVMvnO9aq7ZehWsY2y7iLHtQlPdBrv0GsuYkFTfwx7rO9i6PPVum7ayTostPZdr5l0mzLktM7Gjkmtyp4BJlrGQcgZShte1jGBXpR1JR4k3EypjVojHpTUqWAhT8pnOB0f6eSRgXJ0Nd8qGVxBx3lBNpWG0ojwxKlr7iDlIoZmAWUNAOx7QDEp1SGjUsTLcGpyeiUp8cILLd6gqbiajE9AWaWq/KtqVnMbHwa0G/OqO2MGtEFKG1AsTYu5TdTPVcwa8Zw4q0i3EMpSmCuaV5QdWmPJyTwUzrNeYAwwtUBILxDzQupw8Wx/bEOLYtzKm9tkRT9i6zXPkun2GB9Ie20ZzbP58uW+viGnaXcb2mmbdclzEzL6qxek9+y7MZ1lKLb1GAmnd5tgSy1N+JkQYsgnhyqJm+TtTCPB395JOiCfks7af9unaldJ0wpqS0vJByUnoNVXN2ieswWlKTjNWsJGApivu+LuHgCYW6JGEzcRyvwhWaueRqEPCPPGQTVkJ2Vg17vSgWPvSSkbGmNTuECkppFRQWooNyZTnApWkAvkRTWrKWiIr1K6ZE5JrSIHmgOBQJ1k5dZ2B+5y5I9ZTxuxhBbMN9VdNm5jqcXPbHcgHQJWnRJg9KBm4pHDbfPaY0krOD6oSb9V31gCx8zz5kLWtFpRu2iaVdPP2txbt5AqGRvK5/7VLQEZJzFgBM+jAGXhgpJxISKN+tYxV4SoBGwlo+4IpAb27pRsCWhLakItINCf8otLPZxa01Nl05r643seHasxQvwwbQ7T2pR3m7zgtRk3L0H8vhJR1zFNyGgnqqHZjYzr3CjRfpGpY7ZrGMuog6bElvaKhPseZYhmSVyV1g/S291uy2naawLwSXp0xgRDFJcj8EWHaR0jA136MfJYhjYfYNi5n26+Ecs8XpLxBuKLRC6NeBXw307lgHUerrYR8TQKH8T1KMD23BFQpKJKNuylQxZqAtI6EUftP4cYBZaj+GQLKYAQPAZtgyWghZKPU+5cyDeS1Ktqcc/L7ImHsTKenxRDTiUGaPmj+WAuxUyxwRLYpK4Fv2y0ox/bcJbjcZ0iu9TXeq9dNGU/dTsDdOF/NYaiGOhvipbYu77khshBeiUxSzIfLAks2/aDcZ6rJYn4bj+mikstILVvWozqts7gQrjiDSdhuTZWMcq9xGO14vrNaTkGCaZfaN0lJMlf1Guno5BuJaFKNDWo/sG754a6O8D+84LMkbMz7pqmnDCWgwBLv/0FKHxc/Slgiuj0uP0eT1LTeuedcw0YedU+IBP4mNqwt6/Zje+tsrr8JQkjGPStYjNkYqBLQDtCwhJyXj8T70di6Tep8DCQyiUCUsRgta72m370BIo1UIjmmi3k222PLaWTCGv3GWYxVtN2mjQ5R5VlWylnBoOpVFyNVzWVhiWNXTRNJKCra+zyPg8pBCTH1hNUbZh8wJaBu+dEQhnF6QsxgBBmSxUXKU2cJaEnoHNsyDN0YEnqJ20zCs3lGMhoyqsS0UtOVng2SkqkjRc2ycUa6Uqo60tZKYOeaCQuZOpSkHtg8yXdDUBbqhNlzVyp5pZ6S27bTJbbjhDl1WiKRCBZuOds259j5oNjlqbPPWIerLi1+5hC411ziNppRQiqx483KViSiHc3cRECucuAlqIwZZfvtRyreb5MHbGOBxv6zQ/Ibu+Ky3x1PWFSxhYd8SjqFnHMtGU9ewzXjzMixXa61qS5LaC/RG+pqkq4kkxDKkNmpu0kau3W61xxCCkFd4vuStj6vdHadKS+cifrywTQSq8Fmcp5hUTcw5yRTwpJfrzuEOKMhbBl9H+djc0hm2m8cA5VYJk/MJEtEa+O5H63dhkNnsLkTyHVpXXd9F92syE63NEs3O7Yg6zRS1QxetqS3HrE6J3alLLOF108JSDVs14rO6BQ6S8hmYjp5Uta95i1r75d8Tzmb8rrzjIbr351zP9H8Mdj6bR3m/p+Vkec7hLfS3XMu28mrWmCe3GOuCckbYD+mRidNV5G1sBEB74egBHfRqCG8cOpO6i5Vbj2mzRwwLB+ULe/5AO2CQM7H2VS/bZd9V7MrqqR2UXH7u9prXtjfzfwGSlIzhcNKTPsbWHVuFygybWX9Oi3zuxKwYauu7A+HiJSGAkMSJaV7bIlKyE7rPDep3N8Et27dFnaVqXmmW06fLSv2m2NvO7xt4bMartvnes+lTY1ttedyzWn/2fY6170flAfOh2b+SN2eypx7yzbUod6fpE0fd0PdDcRoLNdwj/e/+Ume5P9EiEg57+9kftufwbapIc+Tb9vrJa+k9jfxlJP7j/X/ddaG2Sn+uPkDkBXLmUFWWtBIJOguN8Ne+xm8dbDOn4FTQZvzmp//M/yv5/z/4N/u+19taH63f0Nznf9WT3Nec9mf/dbNdTXX0VyfrefIA1tfc/u88P4GzfX92zObyzbn2brt//8NwP8F5AnrRKzLuowAAAAASUVORK5CYII=" alt="feide" /></div>
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
