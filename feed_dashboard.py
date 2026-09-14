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
    <div class="feide-wrap"><img class="feide" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKAAAACgCAYAAACLz2ctAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAALe3SURBVHhelP33kzzfmtcH8i/sjwpWgdzuBmIQrASSEH5AEkSAkHaR2BUaEMMAg0YTzAxzx8+9c+/9mo/3tr333nvvfXdV+zJdvtqWSZ+VVe+N55is7P58LrAd8URWp89zXuf9PMfkyT92opb+9hXw6Dj3pR1mH1iu+Ojw4Xr6/+G6LB4df+X/41xRnFsupRUfHWbL29j+X+zzpT285hfG7u0r53l4b/K64vnYud3/79/Xw2d6eA3vOeQ52bN47+nhfWbxyHeHRz5afmXb/fssn/uY0uwr+/3/bV/Lw6+s+yIdf0ZesXXsHGK9gkenCh6dC5O/s8CjP3ailt46ANIAUmIpfycf2NfWJYQ9XE/7es17Xvn/5YN1P8u89/Zw28PrPrSH+/+s4+S6h/v92+zfdszD68j0+prFhf2b0vNhGjzc72fZ187p3fZv2i7t4bP9LPPuK/Od8vrKYzfgf3+MaKQVh9kijjx2mCnBT3ZXFEtuvrsifLclZgdi+fC3T+xLx9F5mGWFedd9xfxZcV2xdI+V9+OauC+2X9Fzf/fvw3sv3udwTaz74hjv/vLeHt6ntC/uTezjuSdKH2Y3nt8/wx7ei/sMd57ru89azo8vjvPkjXtebzrJ/JT7yt/i/y+O+1n59UU68Lzx7neULdtxvoRTpYRbApCkkACU0N17wAcPQLZ/Q1bE/nWRLQ/ot9euRSLfeBLGk4hy3cMEdR8mI/elxLifIP8udv8+uT3M4IdWPraIg1vni/Ve80L1s+6L37vnfuS9UJq56cbTiNbvXXPj2/j6gxuH7/fw3N77pX1ZevPzyt/yemzpnrdsbJ+vpIPXaD95TzIvvQXW/S3y615aCLAfQsiMBC5XxEm+xFSwDGCuDKAERT6YtD1pVw72rh3sf9UK2L8qeP4Xie0+WDmRHmbc1+xhwki7t10m9m25EPB7pfuU9+8tPPczhZ9Dwicynt1zEQcexb93X+Ka/FnKGSrvSe7Dr83Tonw/5fSS6/jSa3Z5P+81xDOU88bB3lXBkx/388zNk4f59DUYBbj8fmgp8tktDJ4CIaC7ny+UVuX08kLKYGRekAN4nCsxV+wCeEgAZjm1PPFEAtHDXRWwS9BdOdi9LJSNPTh/OHe/Sxu7lxb2Lm32/8MHdjPfVQJpPAF8/xbFcoHxZLR7XrfEkz1IcA9wbsJeOyIDitgXGcCuwUAmGMsA8mt5FV9kjHw2Cbn7fOVrH1zZzGRaee/pHnQsnctG+38dLJE3tF3mydXD5xX70Hq69j1RKN+3Kw4sXaSJc1/TPfP7liByCB8oqCy8bDv3IGUARagkPBx3x18DkODLCqpFyaWH8sK2c+lgJ21hJ2VhJ21jh8FGD1c2DqDtAZBnDM+4LzPHm2nMhUg38gA8V+2+sk4CeHANZl9eoww6B5Ansrv+YYIyE/A9iN/cgsSu6YHwARz3jNLhyqNonvsqAyaBEvCxAl8u4OVryN9yHyEMHgAPvgD9S69Ufvb7eXNfjTl45QIrFPBOgOhJU/fa4pxSJWU4cl8JuQpSxYRVQugHKSADMCMy9brEHmrnksAr23bKwnbKZEYw7hJ4DFK5pATk8Lk3TWCIeOXLjJL/l9XLLZVe2KTke4BgAMr/2fm/Bt999/EQIvdcmSIOMjzuJPDovCyO+SKWkwl+/zplFSt7A24O9i7L6+7fmyg4UlGF6sjz8f8fPAuZ99zSPGl54NnX+5v/74HPA9DDwvnldT2FldKHQpWfsY90w6wC6wlhpEsmV/wFgLTCL1wwA5BigasiSzymfEz9bBfAnZRUO29iiN+eEsMTRKiTjJnczJMZwkug3C5v+N7/BAILeO/Xwr1ASuXmCV0QxkvlvWM8ALOgnp27eN88FQ0Z+JevQwldTngXPLl0CyR5EO5FGIRkbrrQPYpC48am5XN+qWJfM65sZbDLoQwD6tqB77rIjNJcqpMXPnedW/Hgxu7h3jaPd3rw/MxESCK3MwhZ4ZVAchhdALNF1jzjNsOQT6YNRGn5ZrgMUyJKAMn9bpMbvrTcRJYA0o2UAfS4uWse25XBkontAc8DxZewSCDug+E1mbDlzOUxic+twYnSKPZ1r+PGKSL+9UB4L34RSvjwGaTb9JoMQ8goTJGhCg9neBrxwicLpyyo8v7Lz1Fels1VJ+ba74PqrQRIUFhBvFewpeKV04KnnwBNgPfF8zLovPfmBdAbypR/cxDFfVEeyIrI1wCkNhqZ0OWYQJbicmKyODBNFQ1Rsh+4AW8wy0ulLBX3H+hrD8rtwb60FColIWHKJwG8l4BfPy8HsLw/Mwn1PQAlhBLOcjuXC7owqVocPJurEaWXrEh4IJQhClfCMqxMmVgFyqss5bhKNse469xaqhcACXRZgVzIPPs93CYLfjktHuaDJ21F+FRWyPvGCo8rJF4YZX46bnrKighzwVQJuXYVkDfFsIT2AOh1K1wFTVbT5e7XCyDtX27XImPgeeDztmM9BO0LY9AJhfI2UMtYVQLkBULGNJ7Ec89zTzU9rlYA517Ds497TbHehe9BIeWZfD9TeOXAm0Yl7FNY43oMCd99qN11LkQcOrn8EgKCj2JHqYYSxgcq5XWrrucRyuRVe0oPN/04qOVry3spx47c29z3ZGUh4PEiA1C44XsABjU8ogZBap1+2AwjYzkOIXcf2yIOZC6YVTZk4lKpvw+gV+Jl6SIA3bhLNmh6gv2HAHqhe2hcrbzK9HX1cyH2JDAHquzS3W0PAmd+H1I974PtrTm6lSePMXVkJguHPEYsBWTlzBbP8EWtXFYQvJWD++pWVsGy8SaRshLyZhLvdcoAyoLsFkDPvXD4yvBz+Lxul19HPocrAmw7b5ohAA/uHPhvHRdA1gzzBYBM/fgNSzchf7suRcSAvKnFwa5sEriX4GX4OGT3oXMbvb3GHrysaEzhZDwmoGNxqgQwW4RPgsgSUJpH6bwVi4cQS+C88Z57rw8hlIWIX8PNSI8rewg+335//UO4yvt7QHCtDD0D4bbAM15kqmx7kzVoZjfcOBBlK/8vn0dCJ9c9KAgSItEyId2+DKu8Xuarx8t2QY9xFZQAinbAoCIAJBcsMoAuLlVNPtjD4Nqt/UoX/bDNSCb8wzYgz/ILCEWFQLpH1ixC611oeGM5azQX5s+Vt7mKyIAtQyvV8t7xQu2/2EeC6IJdvj8JRRlaT6Fy71+YALxcEMTxngrOF+vYPcvWCE/BEeEGh5CURLZRclWRzSIHtwX4yGS6ebyLKwDewubuI/fzACsVTIB43+0/LFj34ZYFxguh74buTbphDiB3wRJAUkDX/T6Qd08TixdC3kjqgVTEHgSgLOGy6i3NC96XJgdBlDNCdt9I4I5yvDP7WLm/5NvFko519y8DJxtAj/LUDsXbouR6di0GdPlYF1I3BuWZx+5VHifAlhDzGp7oeGfXoHuSS3mP8rd4PnGf0uTADff55b2IdeXrle+fb3fKzyiuKSuX7mAQT3p6B54w8xQkCZZUcdlZwOJWBma5x+Oesj4w5n4JPgGgjAGPsyVQ3YNVQmhUAgeQn0hWQLwQcoUrQ8h7PizsM5O9HiL4FQDSuf5N0B15Rkkci5s6po7qXBGneeqwpmUJZ4owtbwMqCUExfKc1ottNMpCHnMuTK6X6+Qx9JvW0zXZdcU1XRP3IrfRPZ157NRzn+Xtnmt77s/7230Or8n1wui+ToSxZ/oZRvvKZ6HzS5Npw64p0yBfYoMAyLyF0IXQM1rJ/wAqpnhuO6CMJ+83+3xpXBn9Nzz2c9WP8jonAJQKSDdFAHIX7O21kACWl96uNwbgg35fOp7dgHe0y72hXkUcZXjGBpUiInoJUb2EsFZCQCniXCnilExkKgOBLUsCzhID4FxuF9uoENFzcACKOGNGCS/gEOd2ryHOzfom6Z48HeUSvGPWbykgJMs6zI6zDj/O3U4FqPy/hFcav18vCOVtBPLD/e9dkz1jiQMvjc7hpgV/Xvlc7rOLgkLpRNtCahEXWgkxo4S4ydOcQKVzsPv3quWDmjBz/W4Fi0MoG56/jAclfEKEJIi3RRyRPQSQFJAykECRtJer+N5mFh7suo2vslH1kjrbBYAibpC0y5JFmcUB4iUyTKVToe0ONi8dzMVtTFxYGAtbGAnZGAqaGAoYGDw3MHBOSxODARNDQctjtJ+NwYDl2hAZbfOsGwjQPjYGaV92jIVBMnlM0MIwWcjCkDD2+8F5Bs8tDJwZ6D/V0Heiof+Uft+3Ptp+ZmKA7vecnoGsfM90naFgAYNk8r4CNgbObQyc0flNdjzZ4Bk9O52Hrs/PQ/sOCRs8tzF4RvfFr0VG+9M5yAbPTAydW8xGAhbGgjYmwjbmogWspniF5jxXRELnRvnBPRIPI5gSPqiMSQB5XvPab7nxuhwzeo8h8A4FgId3HMDTnBgP6ALIasHyIrJVXlZAZHuWp+LhAZO3xosamqfHg7lZ5lZ5KQupJVzo/AGXEgWMBG30npnoPjXZso9gCxBolPGUeAYGAzoGArSefpsYJDAfQMjWS5OZ4f62MEBGILKlF2QC0gNHyBYQFjDECoEElY6h64sCcapzO9PYsp/9r/H/z3T0i+XguY7BoHHPOIwSJk8hYeAQvHQ8LbnROlYA5fUl0KIw0POw9BEFlRdWWtL98XsYPqfrGhgOGhgJmhgOyvTiaTAdKWDnykFYKSJpFBHICy/lQugB0DNaqNwMI2vOsrGbg1oGsAzhkRAlEqL7AN5TwPvtS2WXKyH0xISe/bjyiYuKC1GcQTEKuVdyw3NxB/3nNnpPLfQ/UDWmQsxsjAQtN7FcC3F1lDYaLv9mxwX48QQ2nYNMqmR5u8nPHbIwGipgJFTAaJjMcZdj7LeDUXleT8YNB8gIAIMXELGkTGZGGR3QxbJ87/x56LnIaB0BwZ91mIAXassVS6jnuYVhsgBXMGaec/HnEc/JwBTXZ8eY7H5Gzk2MsuMsjAYtjIVICWlpYzxsY4ylYQEDAQdDQQfLySJC+SJiGoUbnjGiwiSEbi3ZA6YL6YP2TVeQiAkWA/LQwh2QynpCqFYl2wBdAL9sgmEguk0uZTfN23lIZsWFhPqRuyUFXEgU0R8ooI9cA1MyCQY3maijwQIDg+AiACjRuNH/BAwlmMW3M6P9xb4STnYurrBfGNuPjucAkhFw963IjF3PBZArCDcJEIePAyjgJEAYpIZY8n35PUmAJJRk8p7L98vAEiAy+MR6SgOCh4Hkgii3E6AmA44dd85/j5wbGA2Y4lhhobKNs/SgaxcwHHDQd1bAwFkB25cOkuSW86Lmz1oWymoom1oeQvazTCqgZIOYuDci2h2IIBo13cGIVxaHjsEnfovaLq+Sl+l3g0zRzkMB8PZ1CSNhB73nPOaRSuQqXuA+IBy+AsZCBZY440GTJRTBxZcCnjDFiwSPBJFKs4DXNXE+CSjbTx7L978H3kXZuAI64r7K7qsMkVRTDtMQ7cNURyoPN6ZIAloJHwHECpEHLHaf3oJCEAr43O1UWCgdGEimMK5oTOXEMXQfDL4Arafr8Wsy9QtZPF3p+dk90D3Rs/HCTyBSfNl3XsBclKshVRTvtasKJZQguqB5XHW5vVQ27XgA/OqAVFH1piaU+y633OTC7F6fY1mCWfVaGGtSyRSxkixiMOhgIEAuhpdsL2zc+EN7wWEwSAApwQWQZXC88NCybOVzFDAedpjJ/fj/cl86N63zHl/ejymgRwW56gglZkCIpfsM9HxSeSSA5d8MhIBRhoGdg0PO75lgJwil4otricoDSw9x3xxCC2MBCWBZ3Wh/aWPBgjDhdsMFTIQdVhGZoN/sPBJkcXzQYTYWdJgijoeLrKJyoXKY3J4o2ej/0P16VU+o3b8TgHIkDK/12qyfl7ldT5MLa3bxAOj186x2c1fCiWjfm4sReA6r7Q3Tw9xTOSn79zPUBYuVdA4CJRgDx7OOZ0RZuZhiCmgZqCG+Xh7Pz0HH0vlF/OMx7o7EdR+44y+Vh6tIWV2FEYQBLwAmB0TCcA8WOh9382wZKvLQg8HicZUeY4XFdZsFjActjLNz8vNxb3EfRg7f/XPI9HDThZ1LPBctKe3EPY2HShgV93maLSJESiia1NzeI6/qua5ZACi7YUVoxv8vdwgwAOVwLAKQTuY2vdzI9wG8cZ8XvnIjJCNdNjBmipiPEXhFDIeKGHFLuDf24BkqS/m9RJMZzfYR8ElFFFA8VLZ7aimO4/uVE5zv781E73U9KvMQQgmfe18cYJ65XCnIuGp8DSC+jgHDTKxjGSwhpOvQegdjAa5aHFqpYGUAx0MCnqAlTG4T9+5JR+8zcrX3wlcU5oGQnYP+5/c2wdKf7q/ElpS3pIb3IBQ9Rfe64lhYJtfJ9WLp1g88I6JdF0x9im43XIFDeCNV7wF8nqHX8qRUkVlOUG2qiBHpwlhAz2uUFL+57uAeACJTWII/WCdKPHOZwj26QF3cB7Sc+CIhPYnthZb99u7vBVAcU4ZQKnK58Lj3QOC44In9Hrg9Do2E0PNcdBwrKBxADoE4H0uH+2pGx0rIJHjkQiceqJoXRrYvSzOxD0El4buQvx1+7oDJ4m1+HO1LLlqem0KRIqYiJQTzvLGddZu6jdb32wvv95pwTryuWVZQ7w/JZy643IHsrQWX4RND3O/RXe5e2Ug7GCHVC5N9xY0xdysDYq9b89oDNyL24+7zvluViVgGUFyDVTi4kknwvJkkM0peT0LyUDFlfOgqBJ3/wfnuqfBXFNCFQZyHp4FdVjemfjLmlVCXgZXQ8t+WiN0IQoLvy+dixuCRCieUzN23gMkLB5MXRUzK/elcEmqvyfOESmw5GixiKV5EMM/7dCnPWb+yJ84jN+sCKCqp/q81z2W+4oJZLZgBKMGTfbuy0kFtfZ7+P1HTIfdL74/QQ46GqdbLAXSDbJbo5RqZq4AMLq9qSABFbMPA88LA1ZTcAZlMUNf1SnfIFJPA4K5j4oLvdw9AAe19BXm4T1kNGDyeDHdV0OPK+L38DJP7u+5bAllWUen6+DXJhMqJCsO9e5UqJf4nmCZDZAVMEmTuOaQqlu99KlzAFFvScbQvnZ8fXwaQx5m0LINcxEigiO1L7o6Z8MgBExJCyYbsHfG8jiFjQtkM4w5GcN8JYbUa2QPiVUE5+uF+yzcHkC5QxCw1aAYJEApcefA6EuQ1O9l0IWt/ZXWQpZ+XUKkg5QrCl0DI+I4nCq9YjMumBbdWKc4pAZEASiVya7oSOmnla0nImAmF4hlaVl0WJz04hpt3/X1A5XV4bCXjPw7JPdX64pxeK3n2ISXjasZgkjCy3zaHy3MsKd9U2GsSyKLYVxRKSs+AJQpA+XgqLHSfNMCAqdvDQQzerruHDdJiuJ0E8F4tmDryWUWENcVwl+u2drvw3a/xSKo3Eg6GzyhTSxxABiEPzHnTAlfAMnz8tyyZ99WCB/q0LGeWdxuZVCBRcxbqVAaa7+tVHm48gSVU8ry8WUJeTwIqY08ZA4pQQLg+vg8vBF8C4oWIqzW/F6m4XFXKAEtFL/9fXpZ4qEEmKgblWI5fm4BjAJGRaxU2JWDzriP3O0VG8Hn2kcbcsuvipQsWahosYpwql4ESVpO8WYWYKMMnBOkrnHAAyz0rLoDSBTMFdAEs9+26Q29Ev5/3hNzXFzFFzQ9M/Xiwykq2qBnypoWy8UBbuqAyMDJjZOZ7M7Zcm5Nxkzce4hlSzkwJq4h7yLV8RYHuJayrEsJ1ifPeKyDi+hJAqVY8wwR4cr0bN3GlckMGuU3A4gIWLgkVk0uvlcrwyGPEvXOXy00C5aphyHMOD2Ry3X0VvK+I/JlIEclE+rgeoMSaZ6YuKO95b5gccsfaBv9NAJJgfQ1A971gUZ2WQ21kzFfu93sgr9fARryAoVPKlBIrHdJ4XEPBNjUnSHiEglBc4ZYuCQKVOlHy2HaZoXTMA4gFEHIfnkgCBqlubB+v4jwAhbaRi3FLuoif2Dax3TUeC9H52DmZla/Nj/HuL84hn03+H+Tnd5XKAyXP7DIc07RPpITpeBHTsSLGIyKepfXyukFhAhR2Xi847rbyMVPM+Dq55Nvk/x6o3XSwMUn3HqTtvGCNBUtYT9F741wFGVhfe5/GC59HAWmMwINasHgjjilbudIhG5y5edSPajlXJcxQ3+MZ3fB9AMcDZA7GAwVmstbnzUD54N4E8iYaUzb3fHwbKSiZm9lugt0PvDnQ3G3IjOXwSfjLx0sg3eM9CV+uIXoBE4VEAPBw23igvP3+ti8BLD+/gILguyhhKlrCRsRG5NRCOGDjOF7AZtLBfJyO5SpE6UPQlEEqcRWjZbAkAC1iSqZBkKCipbAQ7UP7es9ThpQAJPAkgPJ5Wd4Ei5iPFrGTdrBzJdyrANBtH3yghrxrrjyinL0X7J2ejbds86aY8oAEjwsWw2zYSyqXJWwnCxg5prYj4W6C/MY4KPyGmcsNUKZwEMsAigeSLkk8PFcpoRzSnQrXzeI1WWP82nm8iurJfA5oSZhc/xA2bnSP5d8cJg6UsAD1QJRrim6miIxyj3O3PzRRwB66wlAR02ThEqZJ+cJFnK0ZCIzpOB/XEZozENkwEPGbOA/aOKAxffEiZqLcvVNjMeWBC6A0BmCBwcQsIO9XgijUT4DKQeT7ctWzMRmgpdfoOH7+zUQBW0k+JtB9N+Zhf7HHe7oAZkr3X0yX1Wl5AHu1zq0Ji35fMfkPvd+6my5i5cLE0JHFSuREkANYVj1ZlS+r4Pi5zc2z/V6GuOrldcvkxh+aOJ8HFu4aOPyui2XAUE2wrLYcuIfKxO9RwiPX8YJjY+KczkP3X3B/l92fyCg6noy2S6PtlOHntN3rMkl5hOJJ1QsVMRMuYYbUL1LCnM9GcNrE2ZSJ0ykDJ5MGDsc1HI5pOJ1UEZrXENk0ED6ycBq0sBt1sBxzMBWhc5XY+UgFyaYDEjxxH3T/bEnKZruqyCEUoEoA2b7cps7J6Lgis4lAEWsxB5txeiWXt4ywioiMBxmAohIrm+9kv3CmxGZQvTc9G5FLb199CZ8cDV1Wv51UEbNnBgaPbOYyuLsUsImM4upRhsWrKFIhJTDSBbHfbB0HiPYdO79vDyEvx3ACYpHRbJtQK+aiRQl2AZQAe0IFto65e0pghx8vIZQACqB4BktXZWPSA58LHWUyy2iPCrmZXXZ9XgCpQrWxaeFitoDzWRunMxZOpk0cTes4muJGMPpHNRyNajib0BCa1xHbNnEWsDFLQBN47P4IPhtTHpDofibOLUyd28zYs7hWvk+2L3sOfgw3+i3UM1DCUqSI9Ri9qsu9o2xqKbtfAaBsVRGqWAZQEwoo+vhYG989AOXwa1ryBudd4X7Hj3WMnDgMQJJkKhEs0zwZ5WYmZbpXuURMJ0Fw3QKLVbhr4DDw/aX6kYJ618vzuDGNANirSl4XItWNn0Oc6x5cZHy7zDAXQgEiyxRaeqBimXNusYxlFrDEPhYDQLqzaY/CkE0Hi5ghI/jCJcwSgKcFHC3bCM2VcDbn4GTWwvEMAWjgiIHIfx9OGgzG40kdRxMGTsYthOdMLPlI1YCZQIkDRQAy2LiKTZ7x+5+SEJ453Nh2sS87hraTCfVjKuhgOlDENJ07WMLCRRGrERtbVCGhRmcZ60n3y2Za84ZzDwC854K9r2XKOUncCggHkKR2O13CRszCkF/D2JnDEo3iAS7LBCCHkJSwDAxlqoBT/nbtAUjSVbluTaoqN+lC+P/cJUyRycDbLeUyfpHrpCrxYwkkec57AEpwpUoyuDj8DCppQlmmWcZwAMsmVZBDKl2wV/0IRrLZUIkbxX8XJcz6CgjMOTifK+F0roiT2QKOZiwcTts4nHJwNGuz/4+mLRxPmziZMRmkZ3MFppRDyzpLi5kAwVLAtITKq3pnZBa3U1uYhYlTg9nUmeUx03NsATOBIoObFHYuXMRS2GZtwRSaPWwrZux4etMoFpSjolkt+PjB9GwkobLxufwOKJdXIpwAJNpXIyb69jWMnwsAWeYLFZQZSo3TBOPZw4yWgJLrk8CKTBLxhRszSWgkfK5rE3ZexCQ7nruSMpj3YWUgCCiotNMxLJ5h55TnonvmasiBLxcmWi8zbeqsrCZ0DrZ0t4ntZ7SOrOhRGAKCjOAg5XO4+pGFipgT7YDrWwUEZ4s4FQAeMwA5hIE1BYczBGEBxzM2jmctBt/pvI3QQhFbUzq6N03MCADZ/ZwSZLQ0hfH/pbn/n5iYPDH48pjvx83ENC3PbEyzZ6BzlzBLNeFQEfNBC2sUB17enxGDq58YMS+my6N+YQKQuvLutwOKSogMHuUbTrLbjZ3sRgCYdLAcNhiAE2dFVnoZgATDmYMJahdkxiGURtvuqQ4BSvuLzJkSMPHMKgoTGecCKrd5jqHzU+kleOh8tC+7HgfDdS8CiunzIqbPS+xYlqC0FJBMnvLj+D3T+YRS0PlPZKZxwKZdyOh/mVlkHHIJnfxN+8+cO5hhKuKFz+N+zx0crFDsV8LpbAkncyUczxThGwNS/jgcYwWnizoOp0sMzBOKEedsnM0XEJ4vYHpGxdCRgzmChD2XjakTG1PHFqaPTUyfGJg+KYM4Rc8in+nEYvtNEXzM6BiL7U8ATp/a7jPMEoAMviJriluJ0ixgnBGv+nHXywe0cAAd99VMtxb8EEA+KMFzIvE/A/CyiM0EAWiid09j0FHJZZJMcQFlosh8Ao7/z42Bc0bAyGU5gwgADkWJASEBZHAwtRBL10QCs3PStciFSOgkAAI4lmiUUBw49pvOIdZx42BMe0Bl0IoM8qoBLdn9imvQ+Smjp88s5u5cqEXB4dfk558l8ISRgjALUV86r4DMHDk4W3A4fDMlHE4AvnHgcLIA83odsMeQOExhbwzwTwLH0w5O58j92swVD63omAqUGIBzDMACB+fEwsyJiZlTixlbd1rADBUWzzPSfgQc7Tt9wo+T8NG+sxRynRPgRcwFi1igfDkzsBIhAO+3FZNxBSy482T7rwv87bjMw4ZoOUHlg+4U7+CDMoAFLIV09O5qDJJ5Kr1UEghCkYnMXMA4EDwzaBv/TRnMlmybCHBlhjHIRGaJjGJuhX5LFyYylp+DEpGUiEDwXkuWWlFymRV5BlEpZkbnLGKW7SOO8RqBxc4vAeSqOn0mMpjOz9yTLdSNKxx3twI2sZ4AnHWXDstEKsDS/a7s2AjOOTidAQKLFnKxUyhJP/T0Lkr5WZRyM7DvNpCJniAbPUN4PYvjKQfBWRvbUzoGd23Mh0qYp+c7KzJoZhg8HLxZV8XEfZ86Yh/aToBySGk/eSwDU6ybPStgTgC4ECxhUQC4HLHZKBmqJ3wxGSnNg3hpcQDZLAl8+N69AanyHdD7fXqe0S9iOjHpgpdCJnp3OIALlIAMDAGNJyO9tS8KiDlUXM2YubGUAJMF9QJAipGk2jHApQkwhXKx41y36IHPVT8OHe1PSwkcy3wKpNmyiHlaJ2EUgDBY5POc2QI0WYgIOEs8L/0WAHrNcz5+3zwN+Dpx7XAJ89SUdV7E7rKF4EwRJ3NFnC7YDD5Y40B+GsXMPIqZBSC3CFjTKClLCK9lcDxZRGDGxuyMhrFjBwuhEhbOS5ingkaK5RopGD1PkUFEv6cZgDaHi0FHSypQ0kgpCU6x7czG3HmBpZUL4CkHkLlgMRXzfRWkLwUU4LumOWJoLKEHwPJrmWJgoZxFyY0D5Tx2fEkVEaqELJELdgEUroRBIhOZAych5GCV1UHCxNfL7VIxBGhCVblxIF3I3fOTkkrlKwNYdqkcVK503CRwDDoGICk4QS4UVlzXVV3XXVPmSTDLBe1nAuiBzU0Xd1tZ2akmOXdRwvShg+N5G2ez5FYdHM05OJgu4OrsFMhNo3RHAM6jlJuFltrC2WIOR1NF1lZ4PGlgeFFnz0JucSEgABSw0W9uDoOHGYOQCpXFjIHH4KN1cllWTwnq3JnNjl0gCCkmP9Y5gOn7AHJ+xLtDbBQ9NUaXxwTeB5DNC3J/okjZ9sdHt/JGaFJA6pNcFApIGbxIAFIzAlNBGWSL5gkRoLMYSSgczwSpdlJRZPVeuHKWQR4YXWA5UGUXK9WovJTnl6BL8DhslOkcOIq9qPCsRIvYiDvYjhewlyjgIFmAL+nAl3KwnyxiO+5gLepg6aKAuRAvJCy08ELECsfX7T6EXI35Nn4/VJOkLrilXZs1vxB8J3MODucK2J8EQpvXTAGRmwLyU4A2iYQvwmLD0/kCgvMFbE1oGNi0sBgmVeJGgDDoBHALlFdnBKPDKg9M8ZkqWtxcJRT/n3GXPE1uWcSPcp+5UwEhpcORxl1wWsyK622CESYHMXsHJLh9wWUA+ctF7sFuFVrM5s664EpsBMxCyED/rs5goIcmOWaqIuMdMhZjyABYyLgsVezBuVLxuIzHFfRQPD6TmeR1h1yNWAZ6zOtiyebOKQDnMR4lMlO3EG+zWo0WsRd3cJpwEEk4SEYdXF84uA07uA06uD0v4kbYbbCIu1ARd5EiMnEHt2kH19cO4tcOzlIF7MQKWArzgkPhBLt/j7rKsIQByrbzigEzWVFgAPIWhO01ApDcr4PjuQID8GAayMd9gDEONbkFNbEDWGPIx49wNFMGcGZSweghxeYlLJIJCBcDfLl0XsRq3Mbalc0K2iJ5rgCHlCBi6U7x3amFuVOTGQHIYJQKyPKQK+XcaYEDSB6HFDBKn/HgIuUq4L13Q+6r31cVsDwq+j69XgB30qQWBSwEDQzs6QwKWepY4lNCk6s647EEiyu8AHriC77d4caCW+kmROmUsYqolPDYpYRZZmXQuKJ4XKww1l4VKmI1VsRRoohovIjLYBFpv4P4poPwkoOz6QKOJiwcjlvwj1nwjxfgmyCz4Zu04Z+ycDhj42TeRmDFRnTHweVxEZlwEblkEXeXDhIU37CKmYMZirUCQmGEOpZdHrlFXrj4kqcZATh95OBooSDUr4DjOQuHs/zat6EQ0sdR+KdN+KdspI8juA1EWZx4Nk8VFgtDcwpLlyWCjbrIyOh3sISV8xJWIgXUJyy8i1roubSwfWVjPUwKRpCWIZynGI8APBNGwJ1wN8xdtI3ZEx5LLpwVsUhe58RwAeTzgksBE/GfaIxmL7J53opzFVDOkOoF8B6Ebh8wmJ8nd0UA9u/oLBGXL4osGGWSz8Ch0kRgScjuW7nmJWtoHFY6RgLIYhipiAI2ua38f9lkaabaH6kOudadWBEXkSKuTopIbVFNsQD/cAG7fRa2e7ht9ZjY6jOxPWBgZ9DCzpCF3RFuOyMmtkcN7Iya2Bm1sDtuYW/Shm/GxtGSjbN1B5G9Ii7PSsglisjeOLhI29i4sLmii+fg7lCoDYvNeC1VbpsjxdqxcU7tegK+ozkTR7Mm+3086+BouojjOZsrIzXRzJdYc01woYgdqv1u6FgKwgNfEcuhIlZowMBFAa0JE+/CBj6GTbwNmaiLGVi6srBNoQWDkIO4eFbEPKkbxXkMRhtzJwXMndBvUj4HcycO5k9J/YpMWaePqRJScF0wD9voo0GeLjgJoGcEtTsYQc6Q6u2Ok0GkO6k26weWLpgANNFHAJ4XsXwh5J5AOCthXpi8WbakBmupdgxAYSeiRIl9GExnvBYnz8X+/4pJNyLdDWXkcqQIf7SI2FkRSYJu2sbBgInNbh0bXTo2Og1sdJh8Sf93G9jotbDZb2Kr38LWgIXtIQvbwza2RshMbI1a2B61sT1mY3uCmjss7Mza2Ju3cbBow7dcwNF6EeGDIm5IGa8cxJjCUAEjdSmrkpvR7u8SZs6K2F61cE5tefM2q4gQgMdk8xZOvLZg42SxgNNFai8sILxQxCLVfv0FLDP1K2I5UMQKARgsYj3ooC9p4d2FgYqwjs8XBj6HdbwPGXgf1jGQMliz2irdE90nhVRnReZaF04LzAhIgpD/JvgIUr4fB1DHkugPpjoCU0GhfvxNSl4D9rNZUsujot2+YOaCxSTlZRdcBo8aE9ks6WIY1kacquAcQFKkZSrBVKIFGHRzcwxAfqMElvyfjEF4QvAVMHNcwIyAlD0YQSghE8ffg5CgE4pH1yQXQ80Oy9EijmJFJI4dRBYdHA5Y2Oo0sNquY7VNGP3uMLDWYWCdLXWsdelY6zGx3mdhvd/C5kABW4MFbA0XsDlCZmNzVNiYjY0JCxuTFjZnbGxT29uchd0FC7tLNvZWCvCtF3B+UMTVRRG5WwehSxtLAVIOj2uU9x4osvufPCxgd85EaKmIk4UCg85rJwsmTudNnCxwAKl5howAJGjHFlTuiYJkHD6ytfMixhMWPkYIOhMVFxJAbh/DOt4ENdTHNSylDWyFC1gSUFHhZiCKfGGqx5SvDKEEcOZYx+KFhc1kkbvhK1F3oPa/K8sFkJln3kgXQNkXzN52/wJAWRMWlZBLegmJALQwsGtwAD3q5wIozAXQs44ehgFI8B2T+xUqSSCyhxTgPQCQrkEJIzOObPGiiJ1oERfHDsJzBex1m1ht1rHcrGG5Rcdyq8GtTcdyO7eVdgMrHWQ6Vjp1rHYZWO0xsdJrYW3AxsZgARtDBawPF7A+4mBtxMLaqIm1MRNrEybWpiysTVtYn7GwPmtiY97C5qKJrWUL26s2dtcLONgqInBUQuayhEymgIMoPadQGQ+I9AxThw56B+6wPazinCoVSwWcL9k4XbQFcCZOF00c0/+LBa6C8xbOF23sTmkY3jCwHIILHtk6hStRG5UxE58uTFRGDFRdGGxZQUsB4aewhnchFR8iGoZTOrZjFlYpjYVxCD0AivyhdbRtWSggB5A+aEShmmx8tlkDtO/aho/1gsiGaC50LAb0DkZgYwLvAcjh8xpdYDNBFQ8bA3smg4MDSLIt3aYAT9wsqR9zy2KdBJC5XqZ+EswytF5j8J1xxaDEXQ1T3FnCeqyI00ARocUC9rpMLDfqWGzQsNSgY6nRwFKzjqUWHYstBpZaDSwRhG0GlttNLLXrWGrXsNypY7nLwHK3geVeCyv9NlYHbKwN2lgbKmBlxOY2amFl1MTKuImVCRPLkyZWpkyszFhYnbOwOm9ibdHE+rKJjVULWxsFbG85ONgvIhoqQaMJfq4ocKfYSQJIhamE5fMSBjZNVHVcorYugb6mSyz3UhufgdBSAaEVB+dLBQbf8YLtWnDBxuKUggl/AavBElZd+Gg4fwGNpH4XFiojFqoiFqojJqrZ0kDlBSmigc9MFXV8DGt4E9LQktCwcWlhK+hgie6T0v60hIWTEuapkZu5Yq6My2eksiUXQOaCPQASdKwLjtyvtJsCn8LvIYDuTPKiF6SsgBRMeuJAAjDJAezfM+4BSCWC3awoIQsntKT/+bpFsW6ePUyRG+1D/7NlEQvH9Js/MB1H51s6LWHlrIS1QBHr4RLWYiUcJEoI7Ts4GrCx2mhgsU7HYr2BhQZui2SNOhaadCw0cwgZiGRtBKCJxXYDCx0GFrtMLPaYWOw1sdRnY2nAwvKghaUhC4vDFhZHLCyOWVgat7A4bnKbMLE0ZWJpxsLSnIWleQvLixaWly2srFpYXbewtmFjc9vB7l4RZ6clZK6LuLwtYC3AIWSFKSAsCMyfAkPbFlqnc6jvuUR9YwIdDQlMdd5gZ5SrY3jZQXC5gPPlAgILFsbnFaaqa+Ryg0VsBEvYviiiO0mut4CKaAEVkQKqIjaqozaqog4+XBRREbFQQa5ZAEjxIbloigsrojqmLrlLXqX7JBApH07Iilg6LTIwVxiAvBKyGKGPWNLnPehrUDz+I+CY+nlcsIwDXQAfumAZA8ov+Ujw5FcdKchkLjjEY0ACi0oeyfUyu1ECzRFWxOJJiZuASRqDjQHKoS2v5yaPkfCtskQuYT1agv+iiLNFG5vNJuardczXGFiotZjN1xvM5sgaDMw16phr1BiEC80mFlpMLLaaWGgzMd9uYqHTwHyngYVuA/M9JuZ7Tcz3m5gfsDA/ZGFu2MLciIX5UQvz42QG5iZMzE6ZmJsxMTdrYX7OwsKCjYVFC4vLNpZWLCyvWVjesLC2VcDGjoOt/SJ8R0WkkiXcZgrYChaYqlOhYvDQMlDCClNEYOkMmPYV0LesoHnkGnUdabS0XGKw/QbLAzn4xzXMDWcwtmViPcQBpOV2qIjBhI2P5H4ZcARaAR8vivgULaEq7mDq6ga15JojNj4LJWRGQEYMfLww8DFuYCpkYv2Epz3Btnxaco3DV2KungCkSsh2mtcVWG8IY4Zqvzb7RIMcFc17Qzwu2O0LFt+Kkz0h8is5EjypiBxAaucy0LdrMJWihKNYgJUMYRw+saR14jcBxWCj/6V5lM5r7GHp4c9LWA2UsB4p4fC4CP+QhaU6HbOVOmardMxVm5ivsbjVWZirtzBTb2C2QWfGIdQx12RgvtnCXIuFuTYTc+0W5jpMzHUamOsyMddtYrbHxGyfidkBE7MMQBuzwxZmRyzMjpmYmdAxPWlietrEzKyJmTkTs/MmZhctzC5ZmFmxMLdmYWHdxuKGjcUtGys7BaztOdg4KGL3sMTaIyku3BFBP4ePZ+gaFTbXwBWIPMdhAWPbBjpmsqjvu0JdRxJ9cznmbrcCJWwGS9ilYfgJGx9iFj5HbbyPlLB9HcWVuoux9B3qoiaid/uAtoiOhIq3kQI+RSx8jpgMPAKwImKiio4P6ehazTMA2T2dFrFyQuaw+3EBPCMXbGLBA6B8d0jOM87HlpYBZBOZ3j0cjCA/WO0OPPgy/iOjWs56vID5oIn+XYMBxEouuWIGTRHLJNPCFo+Fsf+5hHPwHCweO571Hug8pYxlBD1ouAT/gYPdbgtzVTqmKzTMVOiYYRCaDMK5WjILs3UGZup1bg0GZht1zDTqmG00MNdkYqbFxGybidl2CzMdFmY6Lcx0W5jqMTHVa2K638T0gIGZQRPTQxamhi1Mj9qYHrMxNWFictLA5JSJqRkTU3MGpuYNTC2amF62MLViYXrNwuy6jblNG3PbNhZ2bSztFbB84GDNX8TWcREXiRKyOceFcJ3VWklRyhnOMp3S4YRMAlDE0jFZCRvnwOZ5EVuBInbomJiN6oTFlI3U730EWEglAW0UUGZhZpaA7Aj07DJTxveRAj4zALk7royaqIxZqE4WULV4jfFljQFG90PQrZ46WD1x3Hsj9ds8K7Gxg4uiK44ESiqg9zMf3kGppIAE4BdvxckJB2UDdBlC8T4IAZguYj1uY44UcFvF0hFPOEooBg4DyhGJREa/HbYfJdrycbFsR3y5clzE6jFP6NUT/nBrZ0VsyFIWLuFgs4CNVh0zFSqmPxGABrOZSmHVJmZqTMzUGpiu1TBdq2O6XlgDB3Gm0cBMk4GZFgPTrQZm2i1Md1iY7iL4bEz2WpjsM5hNDOiYGDQwOWRgYtjAxKiJiXEbE5MWJqYMTEwbmJgxMTFnYGLBwMSSiYllE5OrJqbWLExvWJjZtDC7bWGOhkjtF7DoK2Dp0MHKscMyLpIq4S5bwFaI2uFKLH6jTF2nDKZ0kNCx9KHjaF0Ja0yVitg4L3EAz0pYDxbQkDDxIWKy+K464qAy5rCYL3u3DmTHgMw4cDcOM7+I4eQt3oQL+BixURG1GHxVURO1lzY+b96gdzLLrrPBACxijfLkxMHaqYM1Eh0GYAmbNCTt2HoAoLcd8Ct247AxgQ9iwPJ4QD6U2hsHym+FEYC8L3g+oKN3S2FgUSlxJVoAtXJE5mCZWcFdz4Bj20piWcQqQXzME5YSn863cU4JXMRmuIS9TRurDRomPyqY/KRh6pOOqc8cwhkB4XSVgelqHVM1OqbJag1M1XEAJxsMTDVym24yMNWiY6rVxFS7halOC5PdBJ+NyT4LE30mJvp1jA/oGBvUMT5kYGzYwNioibFxC2OTFsamTYzNmhibMzG2YGBs0cDYkomxVQNj6wYmNg1MbpmY2rYwtWNheq+AmYMCZn025g5tLBwXsHLqYDtQQvSyhJtMARsBh2coAUgZTgDSfhK8Ywdrx950KsO3c+6gO27gfVSoWNRCdczGxxjQmjCg5FaA7ARKmSlmyE0C5iwC2SCqojYqYgVURy3UpGxUHObQMnKNVV8Rm6dFbJyWsHFSxMZxEesnDtaPyYpsHRWirVMaREsA8p6QXbfOwAFkqsdm1pUfvuTvhlBN+MGIaDEW8MG3gssnEwp4yfuCCcC+LYUBRKWEldgjh8NEy8MCVqi0E3xHBawectBWDskcsa3I1q8JACneoHOR0cNthErY2y5gpcHAxDsV4x9UTHwkEHVMMgg1TFfqmK40MFWlYbJaZTZVo2GyVmMATtYbmGQQ6phq4jbZYmKyzcRku4GJLgMTPTYmem2M9VkY6zcw2q9jdEDHyKCBkSEDIyMGRsZMjExYGJm2MDJjYWTOxOiCiZFFHSPLBkZWTIysGRjd0DG6pWNsW8fEroGJPQsT+yamDixMH9qYObIxe2yzZgwKMbZDJSRvS0jdFph7o2cvA8jTzE1XApDUh4A4LTH49k6LGIsa+BDVWO21MmqgKmbgU7SAlqQOQ10CtBEgP4lidoYZDe2ylXkklWPUJwhABzWpAqrCOurHrrG8U8C2gGtTwLdx7GDjyME6Gbn/4xI2T0vYPi1hVgC4leY9IazOQMxcOW5bINnepfi0mxgTeL8hWswPKPuAy5JZfimJD0Zw2Hugs2cq+jZyLGHoRljiHDoMPg4gt5XDAlYZgNLK29YYfCX2QOyhTvhDkW0EStjedbDabGHyg4HxdxrG3wsIP2gcxM8apio0TFZqmKgi+ASEtQom6zRM1umYqDcw0aBhokHHRKOOyWYDE60EoIXxdhPjXSbGuy2M9doY7bMw0m9geEDH8ICB4SEDw8MmhkdNDE2YGJoyMTRjYGjWwPA8wWdieMnE0KqBoTUDQ+sGhjcNDG8ZGN02MLZrYGzPxOiBiTG/hYkjG5PHBUxT3yr1JpwXWFvg7kUJ17kSwkkbS4e8QJPCccVzhPoJOyEl4mm+e1LC3IWJzzENnyMaKgWAZO8iBQynbnCT20Tkzof03S6DkIZ1raciqKXml4iD6gTB56AyYaFq4gZz6zaLJ3eocJwWGYCbJwVsHAs7omURm2QnHMC5IxOLF6IrTrwXwjzoPQBNd1Q08XWvL5i9mO4BkMd+wgR8nGgajFDEGmvVV9G3nmUAUkkhgDhQwhhkBawdkRGU8rfcxwOeLFEnvNRRrW6HEr/LxOR7A+PvNQ7gOxVj7xSMvVcYiOOfVEx8VjFZoWKiUsGEUL7JWh0TdRrGyeqlqRhv1DHerGOszcBYh4mxDhtjXRbGui2M9FkY7rcYeEMDBgaHDAwOmxgcMTE4bmJg0sTAtI6BGR0DcwaGFkwMLpkYXDYwuGpgcJ0PCBjcMjC0Y2Bo18TwnonhAwPDfhMjRxZGjy2Mi5e1aJwkDVmbCxbYoIH9WAk39E2OkIVlCSHFei58BbYkF0jub+ekhOVQAXUJAklHFYOvDCCp4ceIyQcfhAusCy6XWQOUKbTHNbyPAdVxB7VJBzXXRXyav8HYnIbtM2CHhoadkXt3sMUgLGDzmMxmS6pEEYBbBCAVgkPD7QnxjoghAPeF+kkjFyybYe4BKF2wOwpGuF4XPtEXTDMirEVpsKKK/o08g44BSEARgFLZBIAMQi+MYvs6xY5HJOtFbBLEJ7zE0YNT6dscsTD1gYAj5dMxRvC9VTH6TsHouzxG3ysY+6BwCBmAKiZIARmAGiYEhGN1Krd6FWONGkZbdYy06Rjp0DHSaWCky8Rwj4WhPhNDAyaGBg0MDhoYGDIxMGKgf0xH36SBvikDvTM6+mZ19C8Y6F8y0L9som/FQP+ajoENHQNbBgZ2uA3uGRg8MDHgMzHoNzF8ZGLkxMTIqYXRM5rhgeaYsTAdtDEXKmAx7OAwVcR1jjLYYgWb3CypHQNQFGACcPPEwfaRg44jHZ9SJqpj3O0ShFURHZURHRURDRW0JBhjBt7HbAynbhG6OUFdnGrLDmqSDmpvi6jcyWFoUmFQUx5QfrK8OHGwdUL3Q2Zj60haAVuUbyckFBzApQuTvarhHRNIHpS5XaZ+ZKJXxPtWnBwN4x0N/cU4QBdAYCdV4gp4pmFwU2EgkQwTRATg+qEjlhLGAtb9tI6Wwg4dbDArYvOwxEoUPfAOPXyghK3FAmY+6Rh9Q7ApHL73HMb7AJIKKhir0DBepWK8WmMqOF5LpjMFHKvXMErWoGGkWcNQq46hNg3D7RqGuwwM9ZgY6jUx2GdicMDAwKCB/iED/cMm+sYM9Eyo6J3U0TOto2dGQ8+Cjt5FA73LBvpWDfSs6ejdoHjYQO+Ogb4d3jw1sGeg/8BEv8/EgN/E4JGJwRMTg6cmhs8s99shNDH4VMjGTNhmo4rDt0Ukri2sHNgiJOEulwf/DlceBkcR3dM5vNq4Q1XKQm2CIBRKyNyxxpcxnVk1bU/YrCG6NmGjJllA7Q1QfaqhdzyLHV8Ju6clBiFBRR5o+7iA7SNh4jcByJWQ4Cx6ALTYJEU0ZK/MDe+So8/5ym456g2591acHJB6PwaUEJYbFSn+YwqY5u2As+cahrdUBt4Ouc2jEgNKQrUpf/vJHGz4HGz4C9gUtnXoYIvU85A/8C4DsITtPQeL9SbGXmsYfaNi9K2G0fcah/CdUMD3ZQDHPqsYq9QwWqVhtEbHWC2ZgbE6HaP1OkYauA03ahhq1jDYqmKoXcNgp46BbgMDBF+/gYEBA/2DJvqGDPSNmOgdM9EzoaNnUkf3tI7uGQ3dcyp6FjT0LOnoWTHQu2aiZ91Az6aB7h0dPbs6evYM9O6b6D0gM9BzaKD3yETvick+U0YmPyjIvq4UNDAaMjERtjAdsbGeKCCed3AeN7FyQGrHQxMWcxF8DAy+XN1z0D50g+cTSXyKaGhI26iOUVseV0TuknX2uyZuojZBoNrM6q6KqIlZaBvPYHPHwd4Jjyl3KS8EgLtHRezSkq3j/+8cOdzof7H/7KHGFHBbAMgrrgJAT/ML64oTCnjPBX9RCfF8A06Cx/r4LsVomHgBc/QJqk2NQUQ3QgASTAQeh47gKmLL52CTEpIA9EBIAG6T0UPRAx+VsE2x4LCD8dcGRl5pGHmjcQDfEYBkOkbfqRj5oGDkg4qRTypGP2sYqdQwUqVhpMbASK2B0VoJn4GRRgPDTToGmzUMtGjob9Mw0K6hv1NDf7eOvl4D/f0mh2/YRO+IiZ4xE10TBromDXRN6eic0dE1p6N7QUfPoo7uZQNdaya61g10E3xbBrp2DHTvWeg6MNHl49btM9FzZKDnhH8RtOfcRO+5gb4Amc6sP6RjMGxg5MLEeNTEbMzCzqWDK72Ig3OTNYdQrEWVAVIcAo8yf+fYYem16S9hYPwOr7ou8GY/g7qrAmoSFmqiJmoIvKiO2qiBupiJuriFuoSN+lQB9WkbTbMZLK9Y2D8pYY8gOyphl/JT2pHDoNsjEMX/O/SbGR1TxP5xEXMEYNjAFk3PQS5Y9AWzGPBBQ7R8LZMATHprwfdmRWDvclLHsvwkq4CQZsXytAMOb2jY8hdZ6dkhV+on49Bt+4rY9jns99aBMLFux+9g188fao8e5EgAuOZgttLC8Csdw681DL8hCBUXwtH3Bkbf6xj5qGLko4YRgu+zhuFKDcNVOoarDYzU6AzCkToTIw0WhptMDLYaGCDw2jT0t+vo69DR26Wht1dHT7+O3gEDvUMmekYs9Ixa6J4w0TVloHPaQOeMgc5ZHZ0LOjoJvBUdHas6OjYMdGya6Nwy0Lmto2vXQNeBhU6fiQ6/iY5DE51HJrqOTXSdmuimz9KeG+gJmOgOGugOaugJqugN6eingaERA0MxA2NxE3NJi82dksoXsOG3mSehMIdcL3eRUoE4jFSIpxcUVLZF8XLuClVxE/UpmwMXp9HPHD5qcmlI2mi8dlC/nMX8ooGD4xL2j4rMCLQ9yhOCjeWPw2zviIyDx/Y5omNKDD7q354/1LEY1u8DyFxvebJ76heWU72wQal3xTKAFAzKb4CVFZBatT0Ain5gCjI34jYDcGhTY6AdUAk6LGLHX2KxxI6v6Nr2gcNs56CAHYLPxx9uz1/E/qF4cHLDviJWerjrHXqpY+iViqE3Ckbeqhh5pzEj+EY/EIAaRj7pGP6sYYisQsNQpY6hKh1DNToG6wwMN5gYarIw2GJioM3g4LXr6O3Q0NOpo6fHQE+fyQDsGdLRM2KgZ9RE9zhXPgbfrIHOOQMd8zo6lnS0rxpoXzPQvm6gfdNkALZvGejY0dG+Z6CdwWeh/dDkdmyg48RAx6mBjjMDnec6OgMGOoI6OqivNaSjO6ShJ6yhN6JhIKZjOGFiPG1h8dpGUC8hcm1jbc/mXsKN0bgCkpFrJFUiW9ux0TV4g7cDSXw+UdB07TDgSPXqkhYakhaabh3UbmYwOp7HwWEJB6RiBCCBJ/KFQchEwsHeoYN9ts7BPrMiDpiVcHBUgp9GLx3qWAjpbGQ1jZhnw7EuqQb8EELvzAkeAJkCihfSvQNRaWSrhI+NhhbzAjIAgwSgjh1/Eb5jrmKy5HD4Stg5ICMIi9ghCH0Odn0e+ITtULy4aGPqo4qhFxzAwZcqBl+rGH4A4MgHA8MEIQNQx9BnHYMVGgYrDQxW6Rio0TBQZ2Co0cRgs4n+VgN9bTq3Dh3dnRq6ujV09Rro7jfQNWCge9hA96iBLgFfx7SBjlkTnXM6OuY1tC3qaF820LZqoI3gWzfRtmmibctE246Ftl0TrQcGWv0GWg8NtB0ZaDs20XpioPVER9upwaz9zEB7QEd70EB7WEcHMxUdFyq6Yxp6ExoGkwZGLk1MXttYuSsgYRcRjJtY33d4zHUq4zJuUpHIJRKE5IWof7qqK4U3K1douHLQfOWgMWWj+a6ImqMc+oZvsLdfxMERmVAzoXwcQofZPtlhAft+aQ4O/Bw+HxkNDDkqYd7PAdxyAaRwrchqvVwJPW74oQLKGJAAlLMZcfD4BNSu+xUAbqcc1hdMo2GGN3QGFN0I3RR/gBJ2CTQCbl8YDSJg8DnY8xWx7y+xUkVLOn5r32HDooZfqBh8oTH4Bl4qGHylYvCNUobwvY5hAvCjjqFPAr7PGgYqNAxU6uiv1tBfq6G/XkN/k46+Zh29rQK+dp0pX3e3jq5eHV19BjoHdHQO6egc0dE5rqNzQkfnlI6OGR3tczraF8g0tC5raF3R0Lqqo23DROumhZYtE600dm/XQsu+iWafgRa/juZDHS3HBlpOTLSc0FJHy6mO1jMdzQENLUENLWENrWQXCtouFLRHNXTGdfQkdfSldQxeGRi+sTB1a2MnX8BlwcFRwGRxNYU7LPaSbpOBQ0rFYeSutIS1zQLae9N4OxJHbcREaxaoDWvoGL3E3q4D/0mJuU+fUDNXEOgaPgf7ZASdj8CzhZUBZBB6AFykGNAdEQ0G4L4EUAxCkADKb0q7PSHMBYv4j/p8yfXuXhawd3k/BuQA0oyYFnPBIxsaUzySYfYQ7OaLDL7d/QJ2hO0eFLFHRurHFLCEA38Je6SS+0WsL9kY/6hi4JmKgRcaBhiAKgZeKeh/nXchHHqnYeiDhqGPGgY/aRgg+CrL1l+joq9OQ1+Djr5GHb0CwN42HT0dGoevR8DXb6BzUEfnsI6OMQ0dEzo6JnWmfu2zGtpI+RZ0tC3paF3RGXyt6wZaNk00b1to2TbRsmcy+Jp8Bpp8Ohr9GhoPdTQdG2g6MdB0qqPpVEPTmYrGcxWNARVNQRXNYQUtFwpaIipaYira4ho6khq60jp6LjX0XekYvDEwemti5s7EgVbApeng4NjENhVcKvBH3CV6XSNzjwQVUzaeDxNTOVT1pfB+6hJtY9fY2bZxeEquk/KNiweDUOQJGYPPNYLQZnbgK+CAIBRumK7jPyxhwe9thuGs8I6LIm96EU0wXgV0ATzOfQ1AmuuNG4eQn5gmJtohBYxxFzyyoTPJplLAAGSAEXxeI/gcZrSdjD0kwUruec/BAjWDPFfR91xF/wsyjS37Xijoe5VnEA68VTDwXsXABxUDBOsnFQOfVQxW6Mz1kvr11Wroq9cZgL1NOnpadPS0auhp15jr7Sb4enUGX8eggfZhDW0jGtrHNbRP6mib0tE+raN1XkULKd+SjpYVHS2rOlrWDTRtGmjaNtG0Y6F510TzvoGmAwONPgONfgMNhzoajnU0MvhMNJ4ZaDhX0RAgU9AYzKMhrKLxQkNTVENzTENLnIbBq2hLaehI6+i81NFzpaPvWsPgnY6RjIG5rIkT00Eyb2PnwGTQeWM3DmCBGYeDIOFG22i636V5Fft7Do5OaExl2fxHRRz6gRNSNPJm0r0SYEzxCvCRHcpl+dzsWAKQtQPaohmGV0JY8x1rxuMVEPZappim998ZQAYfc8NUpeYnlzHgQlDH6IaBfR9/EF5yCDAOG7cC9nwF7PpstuQligCkhytib58Sx2Y9Fn1PVfQ+4xByU9D7XEHfyzz6XufQ/y6P/vd59H9QOICfNQYfU78qHX3VOnrrNPTW6+hp0tHdoqO7VUdXu4auDh73dfZq6OzT0TFgoH3IQNuIgbYxDW3jGloJQIJvRkPzvIbmRQ3Nyxy+5nUdjZsGGrdMNOyaaNy10LRnoWnfRMOBgQa/gfojA3VHOupPdDScGmg4M9F4bjD46gMa6oMK6kM51IcVNFCbXUxDQ1xDU4ID2JJS0Xqpoe1KReeVhu4bDf23GgYzOkazBhZyJgIFB4k7CzsHFoOPQ8gViUFIblIo1oHfxgFBc8gF4vAYOD4ucQAlhIclnBOEaQPbShbnMQPHPgeHVLlg6ubAf1gQy7IdSjsq4viIKyC9orGV5PEffb7D7UWTL6XLD126MeDPAJB3IhN8EkAOH2sPJBVMiak5SAHXDewflNgN+0i+BYAStP0DMgf7Bzb2920cHBRw4HO4UYy4V8DKrIXBtwp6n+bR81RBzzMVPc8U9D5T0PNCQe+rHHpf59D3Novedzn0fcij/6PCAayiioeBfoKvVmfw9TYQgBq6WnR0EoAdOjq7dHT0GOjo09Her6OdqZ+B1lEDLeM6Wic0tE7paJ7R0Tyno3lBQ/OShuYVHU1rOho3DDRsmajfNlG/a6J+z0TDvon6AwN1fp2BV3eso5bsREfdmYH6czIddQENtUEVtWGF24WC+oiG+pjOAGxMqGhMqmhKKWi+VNFCEF6r6LhV0XOnoT+jYTirYTynYUU1EEUBoaSJ7T2bu08CkcFXdpWuy/Q7HMDDEvyHRRwdFRmAR8clnBwCYfrwYDaPfi2FTiWBBf0G4YiFE18JJ8clBtcxHUPHHjpiSdBxo31Oj0tYpL7gsM3eFdpjExRJ+Ph3BDl8ojb87w4gh4+N4WIKyKWVajk0LT/NjDCypuHggB6MyzYpG8FHIBJk7PcBWQG+Awc+d+lgf6+A7R0bc/0GU7rup2Qqugm8pyp6nivoeZlHDwH4Joeed1n0vs+i70MOfZ8U9LP4T8dAtYG+GgO9dUZZ/Zo1dBKAbQY6O3S0d+to79XRPkDw6Qy+thGdwdc8YaB5SkfTjI6mOQNNCzqalgw0rhhoXDXQuGYwAAm+uh0Tdbsm6vZN1B0YqPXrqD3UUXNMpqHmVEf1qY6aMx01AQ01QQ01IRU1YRU1FypqIgpqYyrq4irqEhrqExoaUgoa0nk0pvNoSufRfKmg5SaPtts8OjIKurMK+nIKhnIKJhQN64aOWNHCccBkFTwJIIONxWnleE26VFI6gu/4mKyE80PghPrzlVt0KUn05tLoy6XQnU9iRbtDKGB7ICziWIBHENLvEw98ZzTQ+NDAwgUBKEbDeACUCuhtD2Qu2H0rLodHROK9Zhj5ZhNzu9wNyx4RDiCfmmNsXYf/gG6mCL+/BD89sGuUIGRFFzwaUk/mo7hw18Hmmo2JRhW9pHwEHUH4jBupHwHY+1pB39s8U7/e9zn0fcyj75OKvs8a+io17npJ/ep09NTr6G7SGXwdrTo62jW0d+po69HR1q+jbVBHGynfiIGWUQPNBKCAr3HeQOOCgcZFCZ+JhnUT9WSbAkCCb0/A5zM4fEc6qo41ZtUnHMDqMw3VQRVVIQ1VYQ3VFyqqIyqqYwpq4ipqEipqkyrqUjrqUgrq03nUpXNouMyh8SqP5pscWm+zaMvk0JHNozOXQ18uh2Elj0lVwY6tI2mRizVZISd3SbGZn2I0n+2xAvx+Hqdx1SshfFKC/1pjqteWJ/gu0SeMfveql9hWcwifFnDi5xAScATe8aGDE6GAtI4DWMKi38CCcMHlEdGiC9eFT37698EElVIB2WAEtydEHkwfpeHwefuCGYDUf7mp48jHAaQScujjRiBKk+toP/abANxz2EDTtQULI585gN3C9RJ8vc9V9L7I3wfwPVkOvZ8U9FZo6KnU0VOlo6fGQE+dju56HV2NGjqbNQGfjvYOHW1dOtp6dbT2a2gd1NE6bKBlREfzGKmfjsZpHQ2zBhoWDDQs6mhYNlC/ajD46jZM1G2ZqN02ULdjoHbXQO2egZoDAzU+HdWHGjMG4ImGqlMVlecaKgMaKiWAF2QqqiIKquIKqhMKapIqalMat7SC2ss8ai6zqLvMov46h8bbPJrvsmjJZNGezaIjl0V3PoeBfB4jSh4zmoLjoo1YzsLensViPDdm8xN0BfgJTD+P1ShvTn0lhMMOtpQcuowkOpQk+pU0uvNpdORS6Myl0Z+7wkD+CgP6JfZzeYSOHJweEoAEr4SwyH4TgATf+VEJS34D818FUHTJeRVQNsM8BPB+V1y5QVo2QvNmGLA3n+RrmTT0/IgUUMQJh/TAVOJc8BwckR2IJa2j1xN3C9jdtLE8aWDgjVQ/ApBcsCoAJAXMuTEgU8CPefR+VtBTqaG72mDwddcSfBo6Cb5GDR0tGjraDHR0GGgT6tfap6F5QEPzkI7mYQ1NoxpTv6ZJHfUzOhrmOXz1SzoaVkzUrxmo29BRt2Uw+Gp2dNTsGKjeNVC1r6PqQEe1T0eVC5+OylMVFWcqKgM6KoI6KkI6KsM0UFRBRURBZTSPypiCyoSCqqSC6rSG6rSKmksF1Zd5VF9mUX2dQd1NFg23WTRmsmjOZNCazaA9l0VnniDMol/JYlTLYsFUEYSNcNzEAb0fTZUKViuVEAr4/EUEyJ0mDEzq12jXkujIJ9GfTyFrW8g5Ns5NFavaHYaUawwqBOElBrQ0Dm8UBHwcwlOCzs/tmIygPi4hcFjCok/HXIhPzfHQBT8ckEAx4CFTQPmZBk8MWJ4hX/QHkwJ6IGQAJvncMDQ1/8SGzgA8lXGCnytd2Qo49hVw4nNwfFBg+x7tOTjYtrGzYWJh0GBK1/0kx2NAUsHnGnpequh5qbD4r+d1Fj0sBiwD2FupoadaR0+tge56A50NGjqaVLRL9esw0N5loK1bR2uPgZY+Hc2DBJ+OphENjWMaGsc11E9pqJvTUT+vo54AXDZQt2qibt1A3aaBmm0dNQTgromqPYLPQNWBgUqfiYpDAxVHOioZfDoqznRUnHP46JXGT2GdjVD5FFHxOariUzSHT/EcPify+JzMozKtoPJSQdVVHlXXZDlUXWdRc5ND3W0WDZkMmjJ3aM7cojV3h7b8HTryd+hSbjGg3mJMz2C1oCLqmDg5MXF0WMLxSbnSwNTqqIQAddfdKOgz0mjNJ9GdS6Mnl0ZnLoW+bAonag7yb0G9RV/+EkP5K/Tn0hjT0jhPGTj3lXBGEPqLDERmRyWcHZcQpBjQr2M+fB9A9jVVz2cavApIAB7f/TsAyAkWELJaMLCdouFYNPkiAWjgxFdkVXkmyww0B0dUIg84dGQugPsFHO4WsL9pYnvVwEyXjh6C73EOXU/y6KLY77mG3pcEoYLuVzl0v8mi+20G3e9z6PmYQ0+Fgp4qDT01OlO/znoNHY0ag6+9RUd7m8ZdL4NP4/D1cwCbRnQ0jeloIPgmVdRPC/gWuPrVL+uoXTNQu2GidtPk8O2YqN4zUX1gMfAq/QY+H1p4d1zAuxMbH09NfBbwfQrq+BSiaS50fLzQ8SFCc66o+BBV8CGWx4d4Dh8TOXxK5vE5lUdFOofKqzwqGXwcwOqbDGrvMqjP3KExc8sAbM7doiV3izblBh3KDbrVawxqtxg3MtiHjkTOwuGBjZMT4OSkxO2IA7N0m0O7QbXcFLqVNHryBF8SHbkEtvQ7ZG0TedOAUXQwkr9iCkgADpMrNtJYuszgfK/IXO3ZYfGeUb67AMpKCH2yS3wxiXvTh69m8nGnX8SA3omJygd7ABTzwtCAVAYgfYpqw8SZAJAe1gsa2fF+AScMxCKOCcq9AvzbBeytm9hc1DDRpHH4hDElZBUQFd2v8uh6nUPXmyy6BIDdn3LoqlDQVaWiu0ZDV52G9noNbU0CwFYN7e06Wrt0tHTraOkh+DQ0DWpoGtLQOKKhYUxH/YSK+ikVdbMa6uZ11C7pqF3RUbuqo2ZdAmihbs9Bva+ImoMCA7DaZ+HDoY0PRxZa/Bo6/AqqTgy8PbfwOWDgY5DD94GmuIhoeB9R8D6q4F0sj/cMwCw+JHL4mMoz+5TO4fNlBhVXwq4zqLrNoCZzi7rMHRqyd2jM3qIpd4Pm/A1alWu0qdfo0q7Rp99g2LjDnJ1DCBZCEZN5HZoC5PS0hPMTYHfLRNdVGr3mFXoVskt05dOYUa6QKZgwCwXM3sSR0hUkLZ0pI7nhEfUGY/Yt+hIJzCze4pQBKMDzewA8KiF4WOQumDXDeFywFDJXAeWghPIcgW4tmAHo+VISg88dVMgHGLpdcUk+KdBcwMTkpoFTXxEBqg2RPFOFhGDzqt+Bw40ApD7ILRu7aybWZmn8noKuR1l0PSIA80wFyQ13vVDQxQBU0PU2i653WXS9z6LrYw6dFQo6q1V01mroqC0D2MbUT0dbh45Wgq/XQBPZgI7GQZ3B1zimon5cZepXN6My91u3QAAaqF4xULNmomadw9dyBFSt5fFhNoV6v43GU+CTz0b3vor4ZgiF1UOU1g6R2TzHqP8Or4MWPoQMF753UZXZ+5iKd3EF7+I5vI9n8T6Rw7tkDu9SObxPZ/Dp8hafrm7x+foWn29uUckAzKAue4f63A3q8zdoyN+gMX+NFgFgh3aNHv0aA+YtxqwM1koq4qaFE7+Ns5MSzk6LOD8tYX/DQudsFH3qFQb1G/QpV+jKX+JMVxA3NAxlEui7i6HgONhSM+jLX2HUvMWodYvu/RiGexPYXzZY3p57LODnsR/N/hXyUwzIKyESQOJGetIyfGUASdi+aAf0fuOVk+sdii8aodP0iQYvgDpOD4o4F/EBuWMCkGA7IfVjJgEs4Gi3gIMNGzsrBlYnVYxUegB8lEencMNdL/LofEkQEoA5DuCHHDo/5dFRqaCjRkVHrYr2Og1tDSoHsFVHW7vOKh4tPQaaew009htoGjTQOKyjcVRDw7iKOgafxtSvluBbNFCzbKBm1WDw1axbaPSV8FtPe/C3/+Yv4m//1X+Ef/gLf4CXI+foP3Ggr5wCyz4UV/xwVv3AygFKq370nmTx4oImgtTxLqLiLVM+BW/jebyJ5/AmnsXbhLBkBm9TGbxP3+LD5Q0+Xd3g4/UNPt3coPLuBtWZW9Rmb1CXu0J9/toFsEm5Rqt6jXb9Gp3GNXqNG/Sbt5iwMziBjouoyUIfgo+UkGK0pekcOtZiGDZvMaTdMIXrz1OTSxoDuTRG8mnMKzcYU68xUbjD0O0V2qcuMN17jeNNG+c+B2c+B+ckNL4SzgV8pHzkfsOHRSwxAOmD2vcBvO+Cyz0hEkA2Gka2A7KxgHJEjPtdONEHzL6QSV/HLmErQYMRBIAbOs72eakg9yuVjmA73iOzcbxH/xdxQv2Q2zZ8Gxa2FzWsjKkYqdDQQeCRPSYAFXQSgM85gJ2vFHQyAHPo/Jhn6tdRpaK9RkVbrYq2OhWtjRpam1W0tWloZepnMPVr7jfQyNSPADTQMKahYUJFHVU8ZjUW+3H4TNSscuWr2aCBBcDvvBzEX/+z/yN+/r/8n/Hz/+Xfx1/7s38Pf/Nv/DPsjPuBjVM4K0corByisOJHYcUHLO8jvBvBSwIwouNtRMHbaJ4B+CbG4WOWyOJNMos3qSzepjN4l77F+/QNPlxd4+P1NQcwc43qzA1qc9eozV2hLn8tILxCg3KFZvWKA6hfo8u4Ro9xjUHrFiulPKK6gaM9gzWPBE54NxtVHuYnMug6iGGscIcR9RpDFOcpPM4boaV+hQnnBv2BFHr749ic1hCg0IqZg7ODAlvy/0kBHQQOHQZh+LCEJZ/JAGSDETzdcBJA3hNCLyR9ZTCCHA3D3G9GwsdHwexekgn42EAEDiB9skACeL5PN1TE6b6DU6F6tGS/9wo43XO47RZxvFPgAC7oWBnTOIBP8mh/kkcHwfeUA9jxIo8OAvB1Hl3v8uh8n0PHxzw6KhS0V6loIwAJvnoCUEVri4rWNg0tFPtRrZdcbz93vQ3DOhqE+pHrrZ3mAFLsR/BVr5qoXjdRvWGiZtNG1aaG/+5v/lO8fDSBX/nnL/Hn/tTfwl/5c38fP/cf/7eo+oPPwH4UxdUTOKvHHEKmgj5kNgN8xtEouV8F76J5vI2R+pFl8TqRwRuyZAavU1m8Sd/ibfoa7y8JwBt8vLnB59sbVGVuUJO9Rl3umsFXp3CrFwA2qVdo1QjCK3Tol+gyrtBn3TD1IhU8D+os1iYAmVEFcd/B9PgVus9jGLPvMKLcYFi5xnD+GmPWDYbzl+haiWN66A7HWw5CRwIy+mqnj+CTAPJlwF9A8JDvF/GXsOwCWB4J4w5GoHY/1hfM34hj6vfVwQgi/mMAssEIEkAJIbgLTtA3M+hTUyamGIAOgv4Sm5b2jEHosCX7vefgjAFYwNluESfbDvzrFnYIwFEVI1UqOp7k0P6YIMyh42keHQxABR2vFHS8UdDxTkHHhzw6PuXRLgGsVdFapzH4WppVtLSqaGEAamju1dHcR7EfKZ+GhlEd9dL9TqmoJdc7p6FmQUe1iP0kgNVbFj6v5vDX/vIv4L//S7+Iv/EXfgH/1Z/+u/hv/szfw//jP/hrePHrLwBfAsW1UzhkBOHqIQMwvRXC2wsNb0Xsx92vwtwvwfc6eYfXyVu8Tt0we5O+wdvLG7y/vu9+azPXaMjdsGaXNiWDBvUW9QrFgRLAS7Sol2jT0mjXL9GhX6HHvMawfY115BDOajjasRA4LiJ4UkTwmM/UerLrYGw0hZ5oEhN2FmP6La9oxFLoG4ljfVxFyFdCiCoWBJ+fphq2ETiwEDggEDmQITK/w+zisIgo1bR9JquEUAvJPQA907T52CTl/HvBcoree5UQOTERNRQy9RMKyEbDMOMx4HayDOD0ho7gPpfhgADQBY7BVxRLArCAk+0CDtdt7C4Y3AVX62h/nEPbY4Iwx9TwHoBvFbS/V9D+IY/2TwoDsK1aRWuthtZ6Da1NGlpaNLS0amhp19DcpaKxV0PjgIbGIQ0NIxqDr25MQ92EhtppDmD1vIaqRR2VyzqqVnVUreuo3CQzUH8I/C+/9B3+/f/Lz+G/+JN/C//1n/67+C/+5H+Pn/sP/xrWqoaAvQs4a2dw1rgKOqtHwNIh5g/TeBojAEn9uAsm9/s6lnEBfMUAvOaWvsabyxu8u77Fh5s7fLq9RfXdDeoyN2jOUXtfFkOqgn4txyBs0G7QoF6hQb1Ek5pGi5pCm5ZiKthjXGLAvMRM4RonTh6nhwaL20ICQG4lHG1YGJpIoi+ZYurXvR3DRP8N+zg2wRQiI7iY8kn4LAQPbAQPCD4bIT9ZgcV+EsDlAw4g+2i1dzgWg49/b4YAZPGfGIjwRUM0AUhfxZQjornykRLaLoQSwA0C8NzA1LqK0AHdSAkhig8oHtwv4HxP2L7D7GzPxtlOASdbHMC9RQOrYyp7hZLcL1fAvKuA7QTgay+ACto+5dFWqaC1WmPq11KvoblJZQA2t6loblfQ2KWioU9D/YCG+iEV9SMa6kY11E5oqJnSUDOjoWZWQ9W8hspFDZXLGgOwkgGooWpLR/WBg1eTUfzlv/GP8H/79/48/uQf/6/wp//Ef4Nf+t2PODu8BQi41RNg9RhY9gOLPgS2Y3hzoeJVRMWbSB6vozm8iWU5fHEO4KvELV6mbvAqdc0tfYXXl1d4c0UqyGvA1bfU/ELtfhl0KlmMaApWLR3degbV2g3q1Rs0KJdoVFJolgBqKXTrKfQZKYyaaewgg0BEw8muxcALeSxIg0bWTIyOpjAwmsTquILADoFHXoyUTSicr8CgC+ybCByYCB6YAj4LYYJPqF/kqIg4zXDmM4QCegGUAxGkCy6Ij59zF/xVAF0XTBC6ANLImPJwLDYeUAA4sa4xACNUHafgdN9BYM/B+Z7NAAzsFxAgEHcLAkAbh2s29kgBx/NsIALFfR1PFbSTEXzPFbS/JADzAkCVAdj6KY/WSgUtNSpa6lQ016toblLQ3KygqU1BY4eChm4VdX0q6gZU1A1qqBvWUDumoXpSRc20zuGbU1E5r6JyUWEAVqxpXP22DVTumKjYNVBzCHzeUPCbb4bxL/6wFj9uXUV1sIjPpzbWdtPIrgVYbfh6LYDl/TRehzW8FPC9iZLqkRGAd3gVv8OrxB1eJm/wUsD3MnWFV6lLvE5f4s3lFd5f3eDTtQDw7o4B2K5k0aflsWYbWDFVVOQvUatdo169ugdgpwCw10hiyExhsXSDQEbB8ZaB4JGD8HGR21GJGcVtwb0igjtcOEjJuEsVCics6CPlI/gMBH0mg48B6CP1c3Bx5CByzAFcdfuCvwYgTdXLXTBTQtYXzD9a/TNcsFBBORyLjQcUgxEoDmRD8gWAaxrC+w4iQgGDBw6DTiogwRfYJQBtnO/YON2k72kUOIBjWUy15NH1nAPY9jTPAOyg/1+oaH+toP0NV8C2jwpaP+fRUqWguUZBU52CpgYFTU15NLbk0dCWR0OHgvoeFbX9KmoHNNQNaagZ1VA9QQBqqJ7RUD2no3JBQ8WiisollavfhoGKbROV2yaq9m1U+x1U7FNXm4O6EFAfAarDwMdjHe+PNbw4M/DxTEXVqYI3QRVPIzpTvtcEXySHN5EsXsXIMgzAl4lbvEhcuwC68KWu8CZ1iTfpS7y7vGJNMdU3BOAtGlmvRwY9Wg5TporDgoGW3CUqlDRqtTQatRSaaTSLnkaHnkS3nkCPkcSAmcJU4RKndh5newaL2ziAjusyGThHfHlx6DA1uwef3yrDt29wYwpoIuwjALkKXhwWEP0KgKwhWg7JF++XuzGgMFkJud8QLSYnlwpYfiXTMxpGKKAEcHJVRXjPQZRKkq/kAkjgBT0AMggJwK0CjtYK2F8wsDaWxUxHDt2vSP3yzKT7JQVsf6WgTQDY+jGPlgoBYC0BqKKxXkVTk4qG1jzq2/Oo71RQ18sBJPWrHdFRM26gZlJH9bSOqjkd1QsGqpYMHvutGKhaN1C1SfBZqNy1ULGt4tP6DSoPTFT4DHz26/h4qOHDkcbge3ei4c2pilfnKl6GNLwKqXgdVvCGTLjeV5EMXkbv8JLgi93hRfwWzxPXeJEk+C5de03w0TKZwptkGp/S16i6vuEAZm/QSv2+Wg6jRh77jokx9RYf8gnUMQDTAsAkA7CLIDQS6DWTGLGS2EcGwRMdpzs2QkcFNqqFqZarXLTkEIX9NoOKAAsJ0EIHBkIHOkL7tDTYMrxfBvDCb7Pjo0dFJGjaPZ+OhXD5nRCawIBBSG2ClzQ/YHlIPqmhnKL3CwApOCw3w9CEghLAsgumGHA9Sh8jNDHhAfCCalAHRQSpVrxf4CZADO3aCO7YONsq4HjNhm/RwPpYFnPdGfSSwj3jxlzwCwVtLxW0CQDbBICtFUoZwHoNjQ0aGhsFgKR+XSpqexWmfrVDOmpHCT4DNdMmamZNVC9YqF40UbVsomrVQuW6iapNC1UE346N+hPgx/VL+J/+we+g8sTBZ7+Bj34dHw5VAZ+KN6cKXp8peH2u4HVQwatgDq9DOby+IOXL41U0y+GL3uJF7BbP46R+Nwy+F6krBt6rVNp1v/T7RSyB17EkPiavUEmTh9/eoil7ywDsVrMY0rJYN3XMaFl8yMZQp6XKCqglmXXoCXQxFUxg0ExgAzcIxVScbJisNksxHgETOXIQJQAljKRkzK1auGBwGbggO9BxccCXYVrum7jYp/9NRHwWIv4CoocO4kclJAWAiwJA97VMMZ6UAKT3g/n3gh13ZoTjTBE0KdYXAMohNO6sCKInpAwgKSB9PJCmo1VwQQAelXDhL7FPVdGnE8L7BYT2bIQIPlru2ghtFxDYKuBkzYZ/0cTmRB7zPXcYrMoLAFW0PVfQ9kJB60sFra8VtL1V0PpBResnBS0VCpqrFTTVqmgi+Ej9mglAFfUdKuoIwD4NtQM6aocN1I4bqJ42UDNroW6xiPpVoHrFRtWKhao1C1UbHMDaA6DxBOhMAf/nH1Tjf/h7v46aQInB9/5QxbsjBe+OFbw5KcP36jyPV4EsXoUyeBXO4mWELIcX0QxeSPhiN3gev8aLxBVeJC/xIpV2AST4yF4kU3h8EcXLizg+Ji5Rmb5C7c0NG4TQxmrCGQyoGSzqCqbUDD5koqhTk2hQkwzAVi3BrF2Lo1OLoVuPod+MY7F0icBNHv4lHee7VKslt8tNAsggZBUKm8EXOSAIDUTIBHyuEXwMQhNRn4Wov4DYYREJF0ANC2GTtRETgEwB2ch6+i2+lk4frGEfq+Gfbi2PB5Rzw2T4KAX5dXTZFSffEZYxIBuMIACcWlURIQD9RaaAYV8RFwcFhPdthPcKCO/auNi12TJEn6LfsnG2YeNo2cLOtIr53huM1edZxYMgbH2uoPVFHi0v82UAP6po/ayitUpDU7XK3W+DhoYmDY0tGhraNdR3aqjt0VDTr6GGuV8DNeMmaqYttKwD1XMaXgxcoGajgLpt6uO1mOut2bXxeiqG79s28Huvh/AX/8zfxR+1rKAqUMIHv453RyreHil4c6zg9WkOr85yeHWeY/C9DGTwKpjBy3AGLy4yeB7J4lk0g2cufML1EoApMlK+NF6lyS6ZPU8k8JNgAE8DEXyKplGdvETd1RWa7m7Qlr1DVz6DASWDRSWPoewlPmTCqFMSaFATaFITaFHjaFFjaNWiaNcu0KlF0GvEMF1II2jkETnVkIpYSAVtploRX5G5TYoBI4cFRPwOIr4Coj6bKxsDUQIoIPRxNeTrTUT9ZDbiDMAiUjT3I3sx3cRmwnEBdOcXYpNUivkBGYAPRkR/fYbU8iyXZfWTb8XxvuDpgIWZNRXRPQcxf5E9XMTn4GK/gIt9my/3bET2aFnAxW4BoW0b5xsWjlYs7M5oWOi9wWTLHRt00PYszwBseaGg+aWCljd5tLzLo5UqIBUqWqp0NFVraPQA2NCqob5dR12XjtpeDTWkftL9jhtoWgb+4OU0/ubP/yJ+/q/+r/if/uEf4s1EEnV7YApYd1TCD2vm8ef+n38Pf/Ev/G/4jQ/jqAwA730G3h/qeHOk4vVRHi+on5fsNIuX58ICd3gRvMOz8C2eXdwJ+O7wLH7LjOBjlrzC89QlXqQp9pMApvEyncSzVBw/CpzhJ0en+BBOoiqWRn3qGs03N2jL3KIrd4eB3B3mcxnUXYbw8S6EOiWGBiWORjWGZjWKFmYXaFMv0KFdoEePYsJMYrd4izAyiCOLG+SRUzTEjsmFchUkF0oQEkyu+chI4QgyA1GfMIKPlrTObyJ+WED8qIDEUQEpmo6PAWhhK+5gL1XEfppcr2dyIvbNOD5XtBwRTQAyF/wQQNkXXIZPTFTEekO4C14TAE6va4juFxGnb1/Qg+0XECH49sgsASD95mooATxeMbE/q2Gp7xqTLZfsPY/WpxzAZgLwlYLmN3k0v8+j5RNVQBSmfo01KgOwoYG733oCsIMA1BiAtYM6aoZ11IzSMPsivqvcwZ/6E38Z/++/9S/R2e3HX/rP/kf8jb/+T1G5mkfVVgGftkx83rXxZjWH9zsaKs6At/s63jH10/H6WMGr4zyen2SZEYAvzrN4ESDL4DkBGLrBs4sbPIvcMvVjACYIwCsOHxm523Sa2cvLNF5dCgCTMfz0IoDf2NvB4+MgKi9SqIldojF9jZbrG3Tc3mL0LoPOdBRP4z5UZS5Ql4+igUyNokmLMPhalQu0qmG0q2F0aRcYMWKYMZJYUBPY0NLwG1dIlu6QVVQBGAFIcRy5UhuxQ1rHIYz5LcQYgBaDjynfvs5BZOtNdkz80GYApmneR5+GeQHgPmsLlAByBeTfjROVEdETQq+AcAXMeeaGkQCKUTBEr6yI8L7hIhuORX3B0+cmZtY1xPYcJA5LiB1wAKP7EjqTWWTXwsWuhfCOhdC2hcCGhZMVAwdzGlYH7zDRFMdQTRatL3JoeZ5HMy1f5hmATe/zaP6YR1NFHo3VeTTUKGioU1HfoKG+WUVdm4Jacr/dGmr6yP0SgAZqRg00zJXw//2HP8XP/Ym/gr/y5/4/+J//7q/jL/xn/wN+7v/6F/Hbb6ZQ4wc+bBl4v23iw0EB7w9MBt/bAx1v/TpeH6kMvpfHOTwnIwgZgBk8D9wJ+G7xLHyN5xc3eB658wB4g2dJoX5CAV+SAl6ScQhfXqbwPJXAo9gFfvfEj1/d3MCT43NUh9NojF2jNXmLjvQ1GuJRfBvax+vLU9RkL1CXi6I+H0GDEkGTeoEWNYxWJYw2AWCnFkafEcGIEsVkLobFfArraho+7RKpYgaJoM68UYziOBbLEYAmYj6TgRfzWa4x5dvXywD6KAak/SzE/RYSh/YXAO6lyOUSgFy4GHjMBdM0HeKr6eKD1V+MiC63A4rGaOoRcQclFNj80HwwQgHT5xZm1nXE94pIHpYQ9xUFhAQgqZ+Ji10yAeCuAHCTA+ib17A5ksFkUxxjjTfoeJdH04scml/l0fI6h6a3OTR+yKPpUx6NFTk0VOXRUJ1Hfa2CugYFdc0KatsU1HSqqOlWUdOnMgCrGYAm6qcK+Ht/51/jz/7H/y3+/H/6d/Fn/pP/Dn/+T/0d/Ny//5fwL3/YxhqbOYAG3u0aeLOn482+jjcHOl77NLw8VPDiiMP37CSH56c5PD/L4tn5HZ4Fbzl8AsBnF9d4Fr3B09gNnsRv8DR5jWeJKzxLXuFZ6hLPqbbL1E8CmMKLdJIB+DQRxffREH776AD/bGMZv7azid8/9OFHJ3784cke/uB8By+Sp6i8C6M2G0VdLsIBzEfQpITRrIbQoobQpobQwQC8QI92gYF8BKOZCGZzCSzlU9hWkji1LhGJ5RHa5O42RorHlgJArx0YiO4biJEdGIj5pPHticMCkqSANG0wVUJCJgOQx4Ce2q+YpFxOUsQA/FpfsASwXAsuT1C0m3bY7Pg0LQfNgCSbYSgGjAsFdAE8IBW0EGHqxxWQKaJQwcCGidMVA/4FDdvjOcy2pTBcG8dADdV882h5o6LlrYKmdxzAhk851FfkUF+VQ31NHnV1CmoaFdR6AexRUd2noZoAHCIALdTOAf/iN1vwn/x7/zX+8z/5d/Dn/tO/g//8//638Gf+o5/HT5v2ULlfYgC+2zHwdlfHmz0Nr/c1vD7Q8NKv4OVhDs+PMnh2nMXTkwyenXJ7cn6LJ4EbPA3e4SkDkNTvBk+j1wLAazxJCAATl3iaTONZKoXn6TSeX0pXnOR2mcCLVAxPkxE8ioXxw8Axfv1wG7/qW8evHW/gj8IHeJ0+R8VtGNWZCGpzBGAU9TkC8IIB2EKmhtGmhdGhXqBLi6BHi6Avf4GhuzAmMlHMZuNYycWxbyRwHrpDYI3XZrnScUVj5kJG0OmI+XTEPev4b9NVPwLwkqYOlu2AbiWEKyCL+whAMUUbH5BQBvDBaJgvu+J4d5zoF04XGICsHTBGABqYWVUQ36OS4CBOcn5gMwWM7pUBpN9RFgtauCA3vGnibM3A0ZKOvWkVy303GKoKY6j2Fp3U5PJGRTMB+J4AzHIAK3Oor86htjaPmnoF1Y0KaprzqJEA9mqo7tdQNaijatjAhxEHXRM6tkfD+OX/16/iP/zjfwX/0R//q/iTf+Kv45d/uxo1+8DHDYsB+HZHw+tdFa/3VbzaV/HyQMVLfx7PD7N4enSHp0cZBuCT0wwend/hUeAGjwM3eBK8xZPQDZ5c3OBp5AZPItd4ErvB49i1gPAKTxJpPEum8CxFFQ5yuWk8TxOMHL6XzOJ4kY7hRTqKZ8kInibDeJYM4EUqgHfXYXy6vUBVJoKaXBS1+SiLAR8C2KqGmPulSgjFgD1qGL35EPpuAxi5DWPi7gKzmQtsalEc7dwisFZWMgkUh9ELG8HHAYz7DST8JhIEHlVC/CaSRzbSxw6uCEA2Sz4fD+jWgmVFxJ2iTQxKkOMBXQAVz4BUASAfiCoh5OMB6Uvp1AvC2wE5gNMrecT3OYAxHwFoIbpvMtiiexw++s1UUKhheMtEYN3gbnhOx+ZoFlNNMQx+jrLJhZrfSfjyaPAAWFeVQ01dHjUNCqqbVNS0KKhpz6O6S0F1r4rqAYoBDXwYLmBm9Bb2hJ8+Nwl9fB+jj1pQ/xtvUF+5gsodoGLDxud1Ex+2dLzdUTmAeype7qt4caDguT+PZwTgIQF4h6cnd3h8lsHj8zs8DpAC3uJJ8AZPQrd4EubwPY5c4XH0Co/jl3hCyicAfEoAJqnCkcLzZIK53ecMvCReXcbx+jKG11dxvL6iZRSvr6N4cx3Bu+sLfLiN4FMmgspsBNUCwNp8BHW5C+aGOYBBDqBCChhGF5kSRHfuHN03J+i9PsPw7TnGsydYC1zAN5lBaMtw4zimZu5vDhcBR+Bx6MqWFPsyO7SQOnZwTZ+NOKRvxZE48bZitzdETFLJpnkRM6a6A1K9LyV9CSCfCas8FOthLVgCqCK+Ty5Yxn8EnMHU70sAyWxcUPfQpoXzVQvHiwb2plRs9F6jr+4KDZ+y6KxS0fghh4YPedR/zKP+Uw51lTnUkgK6ACqoaVFR0666AFITTOWQjb4RBcVJP0qTPliTfthTh8BiEFgOwlq6QOOyjverJj6u63i/peHNtoZXuype7il4sa/g2UEez/w5PD3M4slRFk+OM3hMAJ4ShLd4fH7LFPBx8AaPQ9d4HL7G4wsJ4CUex9N4nEjjSSLFjAB8mkoyIyVkAKbjeHmVxOurBN5cxfHuOsHtJo73zGL4cBfFx7soPmWi+Jy9QGWOVDCC2jzVhMOoV6QChtCmEIAhdDAIQ+hUztCVO0HnzSE6LvfRfbmP6dwxfFtXOJxUEN4m2KgWazNXyo1DxQBkyvg1CC0kfBzAJAF45OD6yMHmIX0pqQyg7LRg3Mh5hsRs+cwVP/xgNXfBfEQ01YLlcPyyEspYUABIlZAzAeCug4SfAOSxH4HHFdBClLlgcsk2g48suuvgYqeA0IaN8xULZ/M6tqdVVFXk8NM/iKL1cxatnxU0fMyj4aOCugpSvyxqa/JMAcn9cgAVVHeoqOoS8V+/jo+DNnxjCWD6APaUH+bUIcypI1jTZIfAjB+T89d4sWri/ZqGt5sKXm+reLGj4Pkeh++JL4fH/gyeCAAfCwAfnd7h0dkNHp1zF/yIwXeDRxfXeHQh1C9GCkjwEYQpPE4k8SSVwhMXQK6AL9IJvLpM4vV1Cm8FfO9vyDiAH27j+HgXw2eCLxNFZe4CVQQgKaBCjdEhNChh1wUzAPMEIFkAXcopevIn6MkeouNqF13XW1hQThF3sri+1pE+J5BsJH0Oa8ejWC55RFBxdywhJPOqH0EnFTBJNWAGIH0VwcYSAUgDUmlyynttxxxAPqyPV0ZkUwwD0PvBavdDheKdEHeW1HsDUssAzqyqiO84SLg1YN4Mw9XPUwkRxmEsMAij2w5iNDxrvYCubgMvX97hj/4wge/+8IINvW9i6qegviKP2qp8GUBSwGYF1S15VHUo9wHsN3E2FgWm/bCmjhiABJ89c8wMs0eYWbjGs1UTb9dUvNnI4+WWghc7eTzby+MJAXiQw2NflkH4+CiDx8d3AsBbPDq7YwBSHPgodINHYYLvGo8iV3j0EMBkGo9TZfV7mkqwhmcC8GU6jleXCby+SjIA398kGYAfCD4B4KcMARhDRTaKqryAj9yvQuoXQqNygWYlhJZ8CG15AjCIdiWIDuUcPeo5hpQARtVzjOVPMK2cYNUIYa8YQwjXuEIeWd1ALlXA9WkBqQMbKVK0Q6rdCjdMSsfUjitf0m8z6BiIftqXYsACU8ANv4XFi/sKWAZQjiugWjGPB9nL6Q8/1yrfC/4CQGZSUstdcbNnVAvWXADjBw5iEkChhFwFhRru2Yjt2azWnKbG6wMHqysOWrotfKpU8eZtDk+e3OJ3fhDGsz+Ks6H39Z/zqKtQUFuloKZaQXWtBFBFFQHYnkdlp4LKHhWVfSre9RlYG00zAEn5TKZ8R7BmjlCcOUJh9hSNizm8XNHxZk3Fq40cXmzm8Gy7DOAjAvAgi8e+Ozw+vMOj4zt8LxWQVULu8Ch4ew/AxxQDMgC5CyYAnzwAkLtf7oJl5cPrfpn63Ur1i+PjPQCjqCEIFQFgPoxGaoIhBcyH0EoAKgRgAJ3qOfq1IMb1EGbMMBasC6xYEWzYUWwXYtgtxnBQiuMcl0ghiztHx921gasTA8kDA0kC7lAont9Eyke/CVDq9SgwFWQgMgUs4Jo+SuQz2eREBKDsB6Y5Al0XLAEk+NhHqx98sJo1ROfuf6qVQ3dfATmARWwQgNQOuKYjvltA0ldC/IC74di+jdi+hdiehTjZron4Lv1P8Nm4oRG3+w5Gpx3UtRdQ1WCiotbA+88qXr7N4dvvrvEbvxbAi2+TaK5WUVuhoKYqj+oaAlBBdb2CqiYVlS15VLTlUdGZR0W3iooeFR9YU4yCq8kAq4AUpg9hzxwBM4fA9DEW5i7xfMnAmxUNr9ZUvNjI4zkDMIunOzk83svi+/0MHh0I82fw6IhDyF3wHb4P3N4HkFVAvABSJYQDSO6XAZhO4Rmr/fL2P14BITccx9srApC73ne3BGECH10FjDMAK3NRVDMVvEBtPozafAgN+TCa8mE050gFg2hj8AXQr4UwpocxbVxg3opgyYpi1Y5ioxDDViHGINxxYth1YtgvxnGMNGLIIGvruIsRhELhhNIlfcJcCG2khBqmCEBfEWsHOm+IFsOx+ASV8uNGYoq/B9NzEID3R8OIT3W5vSAP4j9Zu9mhuWHYa5k2Ztd1JPYcJD0KSADG9y3E920k9sgEiHs2rg9s+LcK6BiyUdtmoa61gOqmAj7XWfhYbeDtJxXPXmfww58k8X/+yjGefZdEY7WGmkoFVUwBVVTVK6hsVFDRrOBzm4JPHXl87srjY4+KT30q3vbrqBvM4Xg8AmXqDMb0Ga6ngpiYvsbLBR1vljS8XlHxcl3F8w0FTzdzzB5vZfBoO4Pvdu/w/d4dB9CXxfeHd/iOqWAG359l8N35Hb4PZfAofIfHFzd4FL3BY2mxa7cW/IQqH0keA3oBpCYY6oZjMeBlggN4k8AbqnjcxvDpNo63txG8u6PKBwEYYwBSDFjNKiJh1OZCqMuFUJ8LoDEXQHP+nKlfnxbEmH6BKSOCOTOCRSuKZSuKNSuGdTuOTQkggzDKbNeJYt+J4wyXuIGC7LWJ1D4BSO6WW4riReGG+XruglNHNq7pM2wHBuZDNuukoAkqJYB8QIsYWeVOzUFtgZy1r/SE8DH75blgPADKzzQkaYbU+wCmaGSEiAMZePs2kmzpILlXQGK/gKsDG0ebBbT2k/JZaOggCG2099voH7NR12rhfZWB15/yePLqFr/zwzj+xS8f4rs/iqCuSkVVdR4VNXlU1CmoaMjjc5OCj615fGzP4UNnDh+68/jAVFDF6wEVrwZV1IzkUD+WxYcJBc9nNLyZU/B6UcGLFQXPVxU8Xc/jyUYWjzfu8P3mLb7bvMN323f4dvcO3+1l8P1+Ft8ThEcZfHecwXenWXxznsG3oQy+D9/hUeQWj6O3eCTa/76PXeORUEGqhDxhAMoYMCkg5I3Qshnm1VUM767iGLq9wX5eQUjXcGzk0Z1NMQgrcjFU5Kgp5gJV2RCqs0FUZwOoyZ6jLnuOptw52vMB9KlBjBphTJkRzJoRV/1WSAEZgDFsfA3CQoRBuOfEcFhK4hI53KV1JAlCUjx/AWkfhzDls7j5LaT9NtL+AgfQR5MTFbApAOQjoj3Ts7HYj3+0Wr4b7FZC3CH5HgDlWK6HAMoYcCNewhx95XFdR5JiusOSGwcyAA/IHGbJfQfpAz4apmekiIYuB41dBdR12OgesbC0XsT8ahHNPRY+1Jl4V63jxacsvn15gx/8KIZ/+i99+L3fC+LTpywqahR8qsnjU30OHxvz+NCcx/vWPN51KHjfpeB9t4J3vQreDuTxdjiPN6N5vB5X8GYyjzf0Yb+5HF4u5PB8KYenKzk8Wc3i8VoWj9Yy+G79Dt9u3uGbrQy+3eIgPtrN4ul+Di8O83hNA1LPFbwM5PFN4A4/Cd5yCC9u8H3kmlVCvotd4fvYJR7F0ngUT+H7ZAKPkwlRARFxoOiCo5ow9YK8SEYwfXmHUNZELG8ipZlQbBuGU0B/NoW3d2F8ylzg810QlZlzVDE7Q132DM05qvEGMaiGMa5HMEWDEMwY5q0YFu0Ylu0YVqwYA3DNjmLNjmG9EOPumMWEpIIEYAx7TpzZUSmFK+RwFdSRYrVkDqA0ApGWl2SHBdzQJOhsQGrhXiWEAchmyS+PByzPlP9gSL47Q6rbFSf89z0XDE8lpIjZQAHz6zrSDMAiq9InfAXED2zED0j1HAYkLdP7BczOFFDf7aCpp4iGbgf1nTa6R21MLjhoHbTwqdXAx2YD7xo0vKxV8ORzBj99c43f+S6Gf/av/fiV3/Dj0dM0Plbl8bE2h/f1WbxryuJtaw5v2vJ425HH2+48Xvfm8Lo/h9eDWbwZzuHVWA6vJrJ4NZXBi9ksns9l8WwhgyeLGTxayeA7Zrf4du0W36zd4qfrd/hmI4PvNjN4tpnHqx0F7w9oHkADzQEL3VEb3QkLr0I5/Oj8Ft+GbvDtxQ2+i1wy+zZ6ie+iaXwXS+E7gjCR5BAmEngqYUzG8TwZw/fxMJqjcfivdPhvdRxldJzlNIQUA3emhbCu4O11AO9uA/h0F2AA1mTO0Jg9R3suiD4ljBEtikkjjmkjjhkzjlkrjgUrjqVCAstkdtyFkGLBtUIU6xQTWlFsWRFs2RHs2BHsUgXFiWPfSTB3fKnkkTygwQZFoYSkeML1UgXEZ+PK7+D2sIBNH80RXWDe0R2M6r4TIlwv65IjAMtTc9wHUMSA5UoIfWjkPoS8GYYDOBOwML+mMQCv6CZ9BSQPCsL1ShfM3e/pmo22fgcNvUU09Tlo7C2gvtdGbbeFqk4DnzvITHxsM/ChRcfbJhUv6nN4XH2Hbz5e4fdfJfArPznFP/nNffyr3z/F9y/TeFuVxdv6LF435fCqNYfX7Vm86sziVU8WL/syeDmQwYuhLJ6P5PB8LIsXExk8m8rg6UwGj+cyeDR/i+8W7/DN8i1+unzHbeUWP1m9wzerpIp5vKCmmk0V73dVVPg01J4YaAsWMJYoYubKwbPAHX7//Bp/FLrGTy6u8NOLNH4aSeMbsmgSP40l8G08ge/jcTxOxPGEWYzZ40QU31wEMHxxid2Uit0rFXs3Kvy3Ko4zGoJ5DUlNQ+1NCG9vSfWCaMwG0UFdbPkwhtQIxrUopnSCL4EZg+CLYd6OY5EZwUcQCgBNcsWkghQTRrFONWMrgk2C0IowNdwtRLFXSOCgmMRF6Q7JExNpX4mNeGHQEYBHHMBLv42rwwJu6QvqPj5Fr6uA7H1gCaDogqOhWKwWLIZk3Xq64ojEe1P0ShfM7AGAbG4YBzPnFubWVAbgpb+INMk1A9Bk8YML4F4Ba9MW6ruLaOwroolA7LdR12ehttdGVY+Fym4Tn7sMfOo08KFDw7t2Fa/a8njeksPjhjt8U3ONH1Uk8YM3F/jnPznCP/5dH37lj07xoxdJPK64wfP6DJ63ZPG8LYvnnRk8687gae8dng5k8GQ4iyejGTwZy+DxxB2+n7rDtzO3+GbuBj+Zv8FPFm/x46U7ZvT7JwTlUgaPF3N4saSw5pr32yo+79N0vDoazyx0XxQwnSqiJ27gt49S+P1AGn8YSuNH4RT+KJzEjy+S+EkkgR9H4vhpNIZvY6R2MTxKxPAoHsWjeATfxcL4UeAEg8EUNuI5bKby2L5UsHut4uA2j5M7BWfZHBpugqjPhNCZj6BfjWJYi2FUi2Jcj2FKj2Jaj2HaiGHWTGDOjmNBALhQiGGJ4CvEsWrHWUWEAUjumGJCM8Ig3GRKGMW2TfEgxYIJ7DtJHOESkZDCmsyowZkgTDP14xBeHkoAKQY0sBASMyMIF+wT/b4cPs8I6YezY5U/VigU0DMYlYNXnh2BXsnkfcFFNhpmdk1BercgACT4CDyDLamPmNr84lsWpkYM1HYRgCU0DjioH7BRN2Chtt9Edb+Bqj4dFb0aPlElolvF+6483nTm8aozj+cdOTxpy+D75hv8tPESP6xJ4Tc/x/DPnwfwT749xi/99AT/6kkQv/Mmhh9VpPFN/TW+bbnBtx3X+K7nGt/13+G7oQy+HbnFt6O3+OnYLX48cYc/mr7FD2dv8aO5W/xw7gY/nL/FH87d4EezN/jp7B2ezmbxej6PtysK3m8q+Lyrsql56+g7cOcWBqM2RmIWfs+XwG8ex/F75wn8fjCOPwjF8cNwHD+6iDH7cSSKn8Zi+C4WxfcCvu9jYXwXCeB3T/2oOQ5iNXKH5dgd1hNZbKZy2L7M4PAqi/l0DHU3Z+hT4hjS4hjRExjV4xjT45ggAA0BoYj95qw45m0e/y26ACawIgBcsyJYtS6wZkaxYUZd+DiAMewWyAUnsU8qWIrjLJTB5W4Rl0cSQqoFW0gfktm4OnI4gOK1TKmAsgJCI18khPIDmAxI72AE2Q5IkxO5AAr4+CiY8gRF9I0Q5oLjRTYgdXY1LwB0uAtmqmcyo8oIDVa9WDcwNqCgsstGfX8RDYMO6ods1A9aqBswUTNgsJEsn/uoGUXBxz4FH/ryeNebw5veHF715vCiJ8tU7VHXHb7tuMVP2m7wo5Yr/G5DGr9eHcf/8eECv/Q6iF96eY5//jKIf/kmhF/9cIFfq7zAv66L4QfNSfxWexK/1ZXCb/em8VsDl/itoSv8YPQKPxi/wm+NXeIHY2n85mgKPxhJ4cejN3g2mWWVlvdLCj6tK/i8raJyT0WNX0PTiY6eAP/k6q9vh/Brvgv8zkkMv3cewx8GYvhhKI4/Ckfxk4sYvoly9Xscj+FJPMrsUTSMby/O8ftnfvxgbwOdR2Eshm6wdHGD1cgtNqO3mInEURXzoT0XxqCewLCeEAAmMGrEMW5EMWFEMGlEMWVEMW3FMGfHmAISeGTkfsmkApLrXTUjWGPqR+DFsG1FsSPg2yskceCksGcnmBoeHd3hcqeIq2OCkCtg2m9yO7RwdcQrIWs0S/5FgSmgWwHxfCfEO1fMF6Nhyt8LLgMo1Y/Bl+YzI8iuODk/4PQZAajgcpdcMLlfGfeR8Xa/CA08WNUw3nuHCmp2odhvyEHDsI36IRN1QyZqafzeoI7KARUV/So+DSj4MKDg/WAebwdyeD2QxcuBLF4MZPF0IIvH/Rl813eHb/tu8U3vLX7Sd4sf9d3gD3qv8bs9V/jXHWn8alMcv1x7gX9aHcQv1gTwT6rP8Qs1Z/iFunP848Yg/lFTEL/QHMQvtAXxC+1k5/iF9jP8b22n+IfNp/jl1iC+G7zG6+kc3i0o+LSi4vOmisodFTX7Kur9KjqODbzdv8Y/Wz3Br/vC+N3jC/zhWRQ/Csbw43Ac34Sj+DYSw/dRAo/Hfk+TMTxLRPA0foHH0RC+DZ/id4/38JvbK3izt48m/zmaj85RfXKIN6F9NNxSw3IcQ0aC2YgRZ/C5AOoEYATTRgQzVgyzHuVbdgi+GDNW+WCxH3e/MgbcsmNM+XYYfAkG30EhzYDc0CI4XL3F5T7F+A5zuUz5BIDkiglKBiC5YALQbYK5D6H86oI7NyC9E3JXvN8X7AIoPs0gxwDKqTnYrAiXHMC1aBFTAkCugLw/kWpNDMI93hNysW0huKphsTuNqhYFVT3kem0O4IiJ+hEDdSMme4+jakhHxZCGT0MKPg7nmb0fyeHtcBavh7N4NZLDy5EcnlE8N5LB49EMvh+9w3djGXw3nsG343f4ZiKDn05k8JOJDH40fos/GLvB743f4HfHr/CDiTR+czyJ3xhP4NfGE/hXE3H86kQcvzIRw69MRPArYxH8i9Ew/veBc/z91gP848ZjfNt/jfczCj4sKvi4qrDpOiq38qjbUVG9k8WvLp3iV3cC+P3jCH4SiOHbUBzfRRJ4HE3gSSyBp/EEXiQSeJlK4nU6ibdXSdbm9/4yhg/pKN6nIngTD+JJ5Bg/Cezh+8A+nl/48T55jOZMBH1qEoMawZfEiEHKl8CYGce4GcMEuV96A44BGMWcFWUVEBc+J44VJ45VZgRghEFI4K3bomvOjjP49p0U/MVL+JxLbFtxrJeiWA5e4HQmx2q61NzC4ZMAGtwds4boQhnAr86OVW6Q5hUSXs+41xfMARTDsTzxn3S9/LccjFDCatTBFA1GWMkjvVNgDZK8FuwBkAYibJkIrunYGbpEc1Ucn7os1PRZTPkaRi00jFuoH7dQN26iekxH5ZiGz2MqPo8p+DSm4MO4gvfjebwdz+H1RJ7Zy8ksXkxlmIt8MpXFkxluj2cyeDSTwfdzWXw/n8O381l8s5DDN4s5/GQpix8vZfDj5Vv8aOUGP1q/wY82bvGjzVv8UNrGDf5g/Qa/u3qJfzUXxf86cIT/pdmH3+i8wPej13g1k8Xb+SxeL9zgu/kk/o/ZE/zq1jl+ep7E44sUnscu8TKRxqtkGq9TKbxNp/DuMokPl0l8vE7i800KlbfC7pKovk2g+jaO6tsYam+jqL+LoikbQ3s+wb5e1KcmMEDw6UmMGimMGUmMmUlMGGRxTLoAUgUkjnmL13xZ80uR20qRA7hGEBZkG2AUm4U4tinWI/CcSxwXrxl8G2YMy04EczchLA9FEF83WXsfA481Qhusb5gZiwV51+raAQfQ/VacBE98M4R/NZO/nCTbAe+NhnF7QmQTjDtDlpwliwPIJqhko2EcTJ0amCUAdwlAWQPmACap623HRHTbRGhdx8mCgvG6ID5WJFHRa7O4j1xv/ZiFhkkbDVM2aicNNo9LxYSOz5MaPk0q+Dil4MOUivfTGt5OK3gzo+DNbB6vZvN4OZfDc7L5HJ4v5PF0IYsnC1k8XczhyXIOj1ZyeLSax/dreXxHtp5j7XvfUGPzzh2+2c3gp3t3+Ol+Fj894PZjsr07/HD7Br+9nsK/mA3hH/T78Q86ffjfu4/wS/3H+MURP35x9hD/ejeE74ME3hVeJWmelyu8TV/h3WUaHy5T+HCVxMerJD5dJ1Fxk0TlXQpVdylU3yVQm+FWn02gKZtESy7BvlrEZrJXU+jVksz1Uuw3YhCASQ6gkcCEkWLtfqwCwgCMY85MYMFKYMlKYKWQxKqTxJqTxIawLbJCEjuFJPYKKewX0jhwLnFQuMSulcY6vcxuRLDgRDB+FcBE/ynOJjNI71MzDIFnInVA4GlI+aiBmoN46bdwLQDklRDuKXllQ/SEPHgxSQ5G+GpD9NcBlCZiQHopKcIVcG6VN8MQgLINkNmujcSOhdi2hYtNE8FVHQfjd+j7dIZ372P42G2gashG9bCJWoJwykbbfAHtizaaFyw0zJuomzdQu2Cw+VwqFwxU0KRCCzoqlgxULBuoWNFRsarh85qOz+saPqyreLum4BVrv1PwlPp5hT3eVPD9dg7f72Tx/V4O3+/n8P1BhnWzfXeYw/dHeXx/nMd3xzl8e5jFN/47/MR3jR/tX+H3d9P4wVYcv7ERxW9uRfD7vji+D1zhxcU1XsWv8CZ5zWY6fXd1jffX1/hwfYlP1ykG3ufrBCpuCb4kqu9SqMkkUMfAi6MhG0dTPolWJYl2JYlONYVuLYUegk9PYkAn9eMVD1n54AAmMCUbnkn9jDgWrSRWrTQ27DQ27TTW7RTWmCWwZiWwasVdWzG5LRkxzOtRzGoRzJgXmNTDGPCfYKT1GCfjt0jt6EjvG0gfmEgf6Ejta0gdqEgdSAg5gDc0qmlfAEhdcexdEOGGKf6jJhl6GYm+G3xp8/dCHs6Sz0ZEewEUg1F3LullJDlbqqyEOFiNFJgCzlElRLQDkgtO0fB8oYAJGgGzYyGyaSG8buB8WcPBRBZDn8/x7tkZXjdk2ADSilEblWM2qids1M3YaJy30bJko221gI71Ajo2bLSTbZJZaNuy0bpdQAszm327t2HHQv2OxT4mSF80qtiht910vNzhg02f7uT/f41991sUSRvtP3732/Ctq2t2RRTMmSgoKIqCkvMwwxAkDzA5wOSEeu5z3requ2fw23t/OE91V1dXV8+cflMlXPTn8XeAw63yuBDM428OPF3L4e/1HC58zeHCZhZ/b+Xw91YWFzj/g6NfmG4dyyhoTkK6sn+MawcZXD86xo1wRsjXEk/L8mqtabvOcwpt6YSoXEq+dpLvJIqHJ1E8ykZF6j2l5MtH8KIQRUeBS6xF0VuK4lUpjr5yHG/KMZF+JKDj/VbCeF8JGwJGpNdjvBrGXC2GhVoSs7U4xqtRjJaP8KF8iCHODy7tCYbKexiq7GGoSuzjfS2E97UDGTUzmNxGj38DXb2rGHmyh63RLGLLZcT8JB0JSPCY/cNFRElCjwRMB+tCQO4bsxA5hT+uq2g4TogMzeIgBM/EpIbVsbKevmBDQLsouXrBFrpPHGc+KQHLqoKlJ+SHBKIZC2S3mxCRw684AtpIQUvCtZEcPj8/wuPL27h6cR9X2lP4p7uEW29P0fr+FK0f6mgZruHWxxpaR2q4PVrF7S8VxVgZreNltBjcnCjp6JapMq5PF3F9uoDrM3ncmCvixkIRN3wlme3GyUZXZah9ARfXDNZzuCQz3nK4uJXDxe0cLu3kcWmHaQ6XdnO4vJfDlb0sru6f4BpXvRLiHeNm9Bg3YxmXfFxml8TLpNCeSaL9OCEqVyTfCSVfDI+yMTzORfEkFxXyPS9E8LIQQUcxgu5SBL3lKPoqMbyuxDFQcQmo5FMVLOSrRvGlSokXw2I9gYVaAmOViPSKDFZCeFMJoZ+Tk7I76E5toSuxha7YJjqPvqJjbx0v1lfxYnEVL74E8aJvBT1PNzD8+ACBgQwO59m3r1AClhoQ9RcRZUpCWgKukoBlfNnl0hynOinJOxpGBqfqygi2W65RBWeNBPR2w5kANIlHRisZdWk22oCWgKOTecR82hVHKZggCVdOEfMTSsCwr46jxRoO5qvYmy1je7KIr2M5LA+dYORJDC+u7KDlz6+4dGEH568f4q+7SZx/zphfHn+/LuHSYBEXh0q4+L6MS8MVXPpYxMUPBVx4n8f5oRz+Gsri3Pss/hzO4txIFufGczg/XcCFuSIuLxRwzVfQGW+c67tewrWNIq5+zeMysZnDZc713cnj8m4el/eIHC7vZ3FlP4urXOvvkAtNmlXuwydoiZ6gRbZYOJYtFm4n02gzC4xzjee7x0m0nyRwPxvHg2wcj7JxPM4l8DgXw9N8FE8LUTwrRJWARbOwkFnfjwTklloDhCWgeL5RDFdj+FiNYqwWx2IticC3Y8zVEvhY5hYMh3iV38OzjVXc/7yI9r553H2xgPuPF/Dw/hwe3ZvDk/Z5vLjjQ/edIAbubWLkWQjz/Ql8/VzA4UIFEUM8h4ABQ0CSrhkk4GpVQjPp1VNMGgJyH2nyRIbu2Z40TlA3q2M5TkjqG9bSdmJ69rujgu18EPV6VfU6A1FllfzvMuRm5qCOj19LGJ7IIbJ0aiSgdsepBKwh5q+pM8JZ+IaEofmKxAV3pgrYmshhczyHtdEsFgZS+PjkCN03d/Dw4lfcPreB6/9dw8X/ruKvP1fx33Nr+OOvNfxxYQ3/vbCKc38Hcf7CCi6cD+D8OT/OnfPhv3/58MffAfz+zzp+fbCLX/ui+IMOia+IK8sFXOV0y3Vd3++frQKubeVxbTuPa7t5XN0r4Op+HteIUA5XQ7ri1fVDLjKp5OP+HreiObTGs7id4AYzx7LBTHuKm8so+e6dZHCf2yxkE3iQTeg+H7kknuQSeJqLic33rBARAr4oRmXjQJV+XOE0hv5qDK+rCQxUYyb0opLvQzWKT7U4xsTGS2H1WxaLp2l8qkbwtn6Ezo11PH65iK42P4YebmGs4wCzfREsDsbgG4oj8D6B1Y8pbHxOY3syi/25PA4WCzjylRBe5pC6KiL+ipKPPVkOEYuILhMFxJYLkjIvtlJGPFhFkr0hwTo++wpKwCNO3bVLtOngFeUPQ3mcE6JzhO2WrSIB15okoB2KLwT02H9Uv1wD2BLw09cSBsaPEZqvIrX+AwkScEUlYHylhhj7hGVAKiVhDeGlGg4XK9ifL4sk3J0pYme6gO3pvBJyuoCNiSJWPxew/D6LuddpTPUkMNYRw8jzCD49CwtGXkTwpTOO8Z4Epl6lMNWXxGRfEuO9CYy+jOLdw0N03trGnctBnL8axO9dBzi/UMCllRKuBrnYUAkt2yW07pbQsleSxSVv7OdxI5SXVU6vHyrsMrs3w1nZ2ag1lsPteA53ElmztdYx7qWO8TBzgqfc1ZLL6ua5q+UJegpcWu0Y3YUMOgu6xdbLQgIvC7q4+AtZ24/rO8fRW0mgrxLH62ocA7Uk3laTeFdLyHrPH6pxfKwlMFJPYqqexvLpCda+5bF4msFINYahegSd06t4c38DiwNJbM0UsLdYREhQEJIJFvI4XMjjaDGPo6UCwr4iIsslRPyEIZ0HEdp7/jIiy1qOJIyRiCRfoIR4sCLxwBQHJvjrGPYVMGYkIAnIFTQ0fGe0qcyMMwSkNEzphoUOAbljDQnoOCFG/YoDYtIlWRnBEvAUo5tl9I6lsDFZRGYdSFIFG/IpASkF6+KMMCQTXqriaLGMgwWigtBcCftzZexzofPZEnYoGadL2J4uYnuqiK3JArZIzKkiNqdK2GSeXDdlzPHWdBGb0yXB18kS1idKWBsvYnkkiy/dUTy9uYaLrav4cziOiwGueFDCjY0yWrbLaAtVce+oirtHZbSFS2gN67Za3F7hZiSPW5E8WqN53JGNBbmlag6PUnk8TefReVzEq5MS+rIl9OeK6MsV0J3LoyOblS1WX+a4yyWRFhL2FDPoLaVli61X3FqB4G5H1STe1FIYrJF4KQzVUvhQTeBjLYnRehqTpxksfMsi+D2P1W95zNXTsvrV229RdE+vY+TxDnamijj0lXGwXMKhjyjiaKmEoyWmBQdhX8ElVZPKbYA4HARtP2sLGrVMp8Taf+t17C9W8M5XkAUq58PkiO6q6k7rdScl6bwQYwNmTE+IQ0Crgo30I+kUrJRRbmW3JeCXrQp6ptJY/JzF8doPJIO0AS0BdVg3JWB0uYaIELAiOCQWymJ3HMyXEFooITRfxv58SSSjxe5sSXpRSE4Gs3dI0tkidokZguclbHsxU5Z0a7aEzdkiNqYLCHzJYqTzEA9agvjryZaM/buyUcbVzRKub5dxa7+Ce4dVPIpU8SxWxYt4Fc/jVbxIVNGRrKIzXUVXuoqedAWvMkQZPekSOtIFPE3pRtN341ncEZvwGLcYjkkm0ZJMoCWVQGs6gfZMAvdPEniaTaIjl0RvIYnX3DarksFQ5RjD1RN8qmXxuU6cYKx+gul6FgunlHY5LJzmMF3PYLQaw/taFAPVMHqmNjH28hAhmRhGVdqIo+UijnyWfJR8eYSX8ogsFRDxUa2WXfhpA1pJR7tPPWCXfEpAesOUfiQf7b/jde77UsLbQAGTobqRgFb9qiA7Q0AZJePZqGYt50pA3aSG4RZWRNQN7DnXhqEXXMeXrRL65o8x+jGNdOA7UmZIVpyDGB0VXBMCRn2GhL6KYqki0vCQEnGxhIMFRUikY1nSn2FfypSErJSee1TnC0wrgl2DHe5fMqek3ZwuYH0yi6WPaQw83kFrSxAXunZwYTaDy1slXNuv4jp3ONovyz5vrYdltB2VcTdSxv1oCfdjZdyLl9AeK4gkvBOjOs7KRoP/xLnr0QmuhzO4tpfA1bUori4f4upiCJfn93FpKYQrqwe4sR9GazKOdmsbnsTxJJuQhce7C0n0k4zljOx+OVQ9xnuC5OSOmOUEBsoxDNZiGKxH8Cq+h67BVUx1hXEwXxEbjoQTdcpUCMjpsnnB0VLOQI/DSwVERQVb9UqUJfTC47h4wJZ8jZ6wEpC23ynSG99xvPoDk9MFDK0WMSUSUIWUo3odAmovCAloR8lQBSsBjQ3oXZZDJJ8h31IDCbk61ilmD+sY365gcDmLvg9xHM3XkHZCMSShqmA1aEnCKiIC2hUVh4xHS2XBIbFojklMm+fFYknSAyFtGaFFJWxIjiuC/YWKIaRFRYi4PUNVnsfaRBYL7xIYeLCFuy0ruPxgHedf7+LCVByXglz5qogreyVcPSjh2lEJ18IFXIkUcDWSx9VIDlfC9IyPcXU7hUvLEZwf2cFfr1Zx8YkP/7T7cPfOMp60BfG8bRVPb6/h4a0g2m8FcOuOHzcer+Bq/ypuTG7i1kYI7dEoHhzH8ZR2YSmJDmf7rSS6ywl0lHUR8o5yBC9PDvBsewuPP67g9fMN+N4k5Hei88DxlxHabWKzWRKSXFS5KvlcEuYkL+LLI7qclzJEzF8ykk+JpxqM5KPN5xKRMcFEsIbU2imOv35HLPAN76az+Pi1jClHArrjR11YCejululKQI8TYgm4FLeEIwFrDgGX7OpYBzVM7FQwHMzhxacolj9nkVmjI2IJyIA0Y4GUghVDwIohII8pESkNqT7Kjnp2pKRM5fRITJLVA5eYFXFsmDrEtBKTap3SkpJzvojduSJ25grYns1jgxJxKIlPT/fQeTOI9ivL+OefAC7dXcP5Jxv48+Um/uzZxp+vDLo3ce7FBs4/CuJyWwAtLX7c+8ePF7eCGLi/ibGuAyy8iyE4msHGRBYbkzmsT5xgbTyL4CiflcJkbxTvH++hu20dj277cfvuIlpe+nBrYAW3R9fRNr2JtvkttC1soW1uE3em1tH6MYC2V0t4/GQJ/Q9XMd1ziL1JeqMkX8k4DSSLeq7qVNC+sxLxLAlJPiWokjTqVwLGST4hoIK9IM1xQEpAEjC5WkN24zvW58rom8/i83ZVzLIFsQGbJaDrgOgCRbqTprs40Rkv2PaAWAlYc6Vg9BRLsjxbDZO7FXxay6NjIoGBgSiSnPkmUpB2YF1Hx9C2EOJZUMy7hBT14VPiCZhvelEkNeEBKWul5v8koysplYiUkEVV8YtMi5K3R5CMs3mRjBuTeayMnmDhbQoT3REMP93HwL0dvLqzhd7bm+i98xWv27fw9sG2xM5mXsWw/CGD9bGc2Jv7JD4dAF8JoaUi9pe49koB+4tEUdI9YqGA3QV+BEWsj2Wx9C6Byd4DfHy2g8H7G+htC6KrNYDO2ysSq+u/u4ahh5uY6DxAcDiN0HxBHAM6Aa7Hqh6sENA4DdJbIV6sRwpSHYsNmEOUdqCP5FSJSXvPCb+IpHMJGHdUsHq/DL8kglWkVmvIcAPE8SwGAgWM7dRkfIAuz/YT6WfWCfQSkD7HT/qCddQqPRhVw00gAcN1zB/WML1XweeNAt4sZPB4ICwDDjIbMLFA7Y5T6aeGrrywxJoUlpRCLCPxSEC9T8GBrRIWEPVCwqrUPPKVhXw8FxL6/rfK1mObTzIqSE5iX0Bi0p4sYW++hN35Anbm8tieK2CH0nNBwbKhJXqZZeNt0tgnygZsWwmHy/RKC4IDg9BSASGmyzxmPUU9N6TdJUHnFXt8jrRf6w9TmpEM7AJbqcoKBjyPeL1Tx2kwxyIBuXYP7UETevHR/lNP2A04u1LvLJqdEI6OqeF4/VQiE11f0hheK2Fyr465MJfm8GzTwJWx2C0ngWjOB2EAWvuHKewa1ge0BNTR0MpcGwd07UFOuzvFYvgU80c1zOxXMbZZxHt/Fk9G4ng7GBdnhOPHSMAY1a9IO0NCIZ4hmDgoJKC1Dc9KP0d9m5TkVfVMo5swhDSqmqTkH6awxz8h5hnYchUc0MYUlEwszRJF04OlIg6FcCaA6/mo+JGECeuBLpOAeYeIDI0I/NZDVWKF/Sxr6zR53mMDks2VdnymqlqF12GwBFTHwrULDYwDov/JWQKq6vWSWW0/JR+lXx0p/yneD6fQO38s0ZDpUB0LtP/MTklWBQv5zDoxdqCqMyLa3a7V9IQ4YwEt+epnnJGlKGe/1zF/VMfsQRUTO2V8Ws3j1UwG994cIjCaw8k6wzF14wV7yWftFY6YMQSjxKOX7KhbEtDk+1lWJzhZj1pWWbCq25LQQ8pGErpkdBwdb55IUSWSJfIRJaohNq+JNBOJpqShZHOIIn+oElAktCGOkk9DIEK8JcKQj+fmupVqQlxTH71QGyAO+7n4ZwFhqlGRZPaaS6rG+B3VqZVWhkzi3VpPl46GkpJILHNKrTvowBK7gZAO8Wpq+wVryK5/w8qXPJ5/iuJ9MI+J3SrmDskLdUBUAroq2BkhzcnohnxnBiNYL9hZls3E/rwhGBJwMcoRD3S365g7qGJK1HAJ75ZyeDoSx7PeQxzOVmSiSlwC0Uo8SkNLJh2yZdSsdUgMubzSUAgq5ZWsSlCFl4DWdhQCiWfNAKxLQCGS5CkJxfOm42MlGOuwtqagijClrX0GicoAr0iqRgJS4llbyoY1bFjEltXnMyBs4nLNBPR6rk54xKhOseE0bqd1a4jFIaCRdkrAovTbWpuOJCMBz8BfESSY2vCLIbAVFOqMcBiWh3yrdRxvfENkvorOt1H0zKUwumHCL0fqG1BALcc8W/xyaq/MiuN2rUpA2SfObNXV4IS4m1XrzV7VSyzGuPgMQXFbF0dkimp4u4zhYB79sxm0Dx6hvzeCpI+L1tSNZ6Xki9neEUsqsRMJl1iqyjy2oJTzkkNVsnjQHk9Z7UOPk+IhWgPobRvbUYmnBNQ2uM8QdS+SSdWqqkgvAe0H4CWgtbm8ZT1g7wQJyNQQrEE1Gq+UZKO9pnZbAZElJaaQT5wHTwzPqF9LwIZzE9fzEpHSkFJP/xdKP+OENLRDiajqWEdEk3zpjW84Xvkmptbj0Qjer2Tlv58O1UT9culmyxVnn2mJ/+mq+c40TSMBnWmZznhAu0kN54SIF0zvVz1gC5JvMco1QGgH1jFzUMMkpeBmEUPLWXRNJHGrdx8fXyeR9n1DwgSkSTqJDdpzrsBECOk0lqVq1qhakk5sQi8xjL1lVLRKPWsHWkK6YZuwENBKIOO0iMdty1ryNJoIZ0i4QmOfRFRiKcEa7TX54yT0QcnmEszeQ9KRVCSgkMshnJF2Eo5ivgaPIwyXsMdCgsYaq7OkayCryXdVsOlCk9+K0MEEEuMz97nnhpQkpNdR9JnAtIwFrMkEdAad8+s/MPnhBHffhvFmMS3Sj/89BRG9X3ZSOASULlyGXtwgtBBRJKLriDgE9A7JdwgoatcQUIinEEckauKBR3X5AsZ3GJIpYHDhGM9GYrjxchefB9JI+41TIr0jLhwiWjiBa6OaSUYbOyQZpIPcSxI3RGMJqGEZDesoEV07z0pAKy3dmKRCyOj10OWZxqlgGigpxDZrlIiWRBL2ELhkFEKK5DKSz3iiLqFcaaYSzxMoNuRjwFhGodjnmMEB3vulB0PIpBJQbVOrVt3BBFKe3XCse6mImM8loiWgSk4j/VY06Jxb/4H54TzaX0fQM52S+C+l30yoKtqQ0s/OoCTxBJ6NzoWAsm2DWbDcTEw64wW7gxE49KqJgJSAoor1gWQ9A4/sFZkK1TDG/YNXCuifOcbjD1Fcf7mL4f4kUsvfkRHHhPFBAydWaKSiRzq63q9H6on96OY7YRohkqt6VfpRKtljks72lRqv26nDIymcP8wjBT0OgrXZHPvNSUkk7VFw4m4N9puJv5luMZLM7YEwAWMjzdwyRgou5xD1EXkl4lJRutCs9HLvtaS0vRn2fdygNMmnzojWIXUJATmrUclrnUUrFCj9UuunyK5+x9S7E9zqPsLL8ZRous9fS2J+qfSjmaYSUKMmNSwL6vA7g5ldYioJtT+YXcANQ/LtgFRdEd8NQiv5FByUID0iRPibGKBCwv06vmxW8N6fQ990Rkh4+ek2ejsiiCyc4uQrR8x801WVDBFJOjt6xu0/NuTzqkbH/rOwYRzjRAjRDDySTaSbIaD+KRoW8qpe77FDdBt7FBWrEs+SjuEVkoupPXbVoZtnCeiQSIjndn85YRDH+7UE1vtY1t4baRhEoCEU7elQ8jmkNCq2wZ5bLiIu4/nMvazDQMjnL6tD4u0FWamKI5nxn2K4P4HrL/fx/EsS75ZzGP1akE4IRkEWjlQ4NcaLyZEqfLGqEjFWhz/GtCZpIO6uEx3RwQjfZTCCLFBuVkWgESkVRatYFNTUCXGISEmoapgGKPsAZw5PMblXk6+DX0nfVBpPhqO49Gwb7Y92EfiURyb4AxnOsudEZ8/IGSc1nlkDKSwxvMdOHLFRlQrhms4bYeKSDWRWsjUSkPUrQRpie44DYYmXP0NASySHaE7wVwd0uiq70WFoVMmu6pWuM5/tQvOoYvF4NfRiHQslsvGaxabUujiYlHDbp88X+y9QQYLqVlRuFam1Ok5WT7HFUMvLA1zt3MOzzwm89Z3g03pBQm8z+xXpjNDQSyNIPvKGsKRTVB1wrUAPAXU0DAkYSJuFKO0QLBIvwn1g1QNeECJ6SUh78BTzHnuQcaHRDUPCmTSef4zhRtcuLt1bR39HGDvjZaSDP5Be/y6jKujiKwmrOg1QSOGNTXlsRQ+UJJaYHpJZMhkwpNBMaNfu9NTVULfp2jLepdhoxulwbDyHUI1/rEsgK3VsHK5JOnnigEpG95odgayqk7CS05DO6Z3gu3iOjefr2olmBLNfpZ0TE7QTjgz5Uis1ZFZPccK9XmZK+NQXxbWHX3GjNyRqd2DpBJ9WC2L3MfQ2e0DPV/2BRgLW4ItW4ItUsRwl2Tzki1bgj1Xgj1d1VEyzBPSOB2RfsKpa1/lwCOjYg4aExiGhJKQqng5pgHr0q/aSvJ5JoWMkhrbXIVx4soGr9zbQ3xnG6mgBcV8dx6unssYcjV0ZZxbkXFSNuksMqkFNq7TUPJcwNqygfaX6Jbv3sYwb1xJIbIuLLOqEa68Z4H4MtjdAJ+EIIZmyL3ZFr8mATSf+5u0WU4cgYdSbqjjrJBjJJ32r5hmmJ8P27cp7ONKthLjt4TCDQZ3fh/MyOD6Po1QkaKzq0xtUliFU7MMNECQcy1aRYpeaSLs6MoEa9iaL+PgqitsPt3Dx2Sbuvj1C92QKb305fFwrYWyLXW4VzIYqEgHhf+4loA5aqcAXpfol6WgDqvp1CVjVgQlm10yxAUlAcUKyP7BigtFCwLg6HAuiekk+JaJLQpWA1iumQyL24EEN0/uGhBsFfPBnMTCXQfd4Ck+HY7jZu49zD9Zw4c4qHtzfxsfuMFY/ZXDIpd58VSQDnGuqM+5dfEMm+E3S9MqpzEVlyjWn0wGihpS/KmmaX3OQ99e1HoMU7zN1NdedDn5HhostEsyTemtIESs1JA14TEjd/OOCfF5VkPIiUEWG7fHXkHZScxyoIE2pEzB1BupIBurOsySf8FeQ9JcF+owaMit8Zh3HwVMcr37DMYdF8QM278vYq0De19TPNjKUYtrKtiV9VcQ4bnK8gJnBJLqfh3Dt7gb+evgVN1/t4/lIHH1zGQz5cxhZL7uSL1TF/CE9X/3f3aF6preMajdK0pF86vn6Y0TNSMSqkJJL9dLhFQnoLlCpS3NQBdvRMJSCQkJLOiGgK/2sQyJOCSWh9BOzl0T7iid3yvjytSjddVTJr2eP0T2WwuMPEbT27uHCow38fnsF524GcKM1iAf3NtH5dBf9Lw8x2BXGYFcUg91RDHRF8KYzgjcdEcl7y/zOKAY6mEYw0BHGwMsjDHQcYrDzCG+7wnjXFcFbi04tpwhjgJB7WVcM77rjeNcVx2BnDIMdBizbZRGW+6Te7oiA9dpnvzEY6DjSdrw8whsB86OCAfP8d11RvOs27yB1M41hwLzPAN+RbeuIYID3v2S95jlyzmO2nffoffLb8B27oxjsYWre1bw/fwuCv0/Ps308e7iDO/c2caVtA3/dXcPfT7bQ+iqEp8NR9E6mMLh0guFgQez5id2KCBQKFo4BoOptln4OCePW0dC5HxJ6MVKQ9qDYhCSm2TVTvWDPXnF2UpJXAioB+VBVwS4BXY9Y9pATEupgBXpH7B9knGhqt4LxrSJGN/IYXslLtx17TbrHkmIfPhg8wq2eXVx+uoG/7gfxZ3sQf7QF8VtrAL/e8uM/gmX80rKMX3jcEjBYwS9Mb/rxiwGPf7sVwB+tK/jjThC/t67I+a83A/i1xYDnt1bwa8sKfiPM8X9urmg5Kat1ad3L+OUfH375Z1nOpWxLQJ73f26uCH65GdC2tKxI3XKddTDvFt9lFb8Kgvi1lWX4jGX8p2VZj5l/i9D7id9ag/jNyWMdQfx2m/cr/tO6quDzbvE55h4PfrfHci2A3++s4M+7qzj/aB1XXmxKp8GjdxG8HI2jdyqFgcUMPgSyGFkvYmyzLN7uDFXuYU3+038jn6hgIWC9iYCuIyJeMfPMGoE/DcPYEdFCPJJOYI85+di1BUlSd96IISJJSJvw6BTzh3XMhmoivie2S/iyWcToegEfgyoRGbjum8mgZyKNjtEEnn4I4+G7Q9wfDOHum3209e/h9qtd3OnbRXv/PtpfhwR3Xx94wPN93CP6FfffhHD/zYGkkv96X8pIOXONqUDuN8dvtK72/j209+2hrU/T9j7mmfz+PS3zWo8FUjfbzHq9bTuQPKK9P+TUwXrb+nbR1rejz5B307Yp9nGXbbGQ9h3g3oABy5jj+4MHuM/UeyzvrscPBg5xf+AQDwYP8OjdIZ4OH+HFSASdXxLonUzjzdwx3vmO8WGFXm5eerUmtouY2tNAM/9Dko/xPlG7DXafDdUR1su1ElBjfmIHkoQ2NshhWoaAqoK9A1LNFg2UgCLlxAP2ks9AQjMqAYV8JuAo27l6wzNHHLyqJKQYn9wti21Ig5ZjCdl7wn7kIX8Wb5eO8WYuhb6ZJF5NJdEzmUD3RAJdY3F0fYmhayyG7vG45HVPJDUdT6BHEPekcfRMJBTMk+Okk/ZOupBzQUrzJhICe6+tn6k8e5xtiGo6GUcPMcE26TO1bbZ9REoM+R6m4wl0fUmg80tc3qlbYOqSugnbZrYthZ5xbaPT/kmShtDf6NV0Cq+mCHPeBIbC+qYtUuifTePNfBpvF9MYIukCOXxczYt2GtssiJCY2ither+szoZIPu6EbuN9trtNhY2N+WnopYJlISCdDSWhOBwSgLYSsJGA6oR4pmVaFUzJ5njAEVW/DTBq2GmMnb5p7UIrBS0RD3XwAoOXopb3Kd7LGBcylsXWGKFkXM3hw0oW7wMnGFom9OsULGXwbonHJwL+gMx/u5SRH5SQMsznfYITBe+R+k7w3n+sdfuz4qW/9zMvKxJZn6nPZf2SShsyeOtj3XxGGm+Z8nw547l+rPA+1581yOHdsn5k0l6+hyCDIXknzdd31HcYYpuX9D0dSHvY3hP5jd4HcvoOts3Lx3IscN7NxYfACYZXsvi0msPoeh5fvhYwtsXYXhFTuyXMGOLNHZJ8dDb0/2Y4zh2YYofpkYAUOLzO0IuCzkZj/E9Vr6TSPUcCKtfOBqI9Q/KtA6L9v3YsoMYFJT4oX0RzFFwJqY6JklGlodoP4qCQjAdV8ahIxun9iqpoEnKb7n5RfpjPG/plNmC9ICnJSg+bGJHzHEbW6LHpNbm+bsuzjIKhoc+sW1AUdUMniamcO/klSRn1t8+WZ0j9/PP0D9RrOYxu0G7S69Iu3meg9dAGZrvcNmn7LNj+rIPGa+YZVI/mmfxtBFK/Httynw1G17P4vEHo+Rfiax5fNvNKuu0iJondoki8uYOKYJ7kO+Ikc+1mEwJKiMW1+di74f7Xqn7JCXrBGgesSB6JKD0iRjWLOiYBOUYw/QPhnxOw2QnRhzMOKA9xIt12pEwzAa2I1mMrDVUiWiLWRCJSxM8d0sNSKBlLmNwtYXKnJF8mf6jxnRLGjcRUlCSlOqenTUxIeU3HnfvMvSaV8rtliWc52CVMvnO9aq7ZehWsY2y7iLHtQlPdBrv0GsuYkFTfwx7rO9i6PPVum7ayTostPZdr5l0mzLktM7Gjkmtyp4BJlrGQcgZShte1jGBXpR1JR4k3EypjVojHpTUqWAhT8pnOB0f6eSRgXJ0Nd8qGVxBx3lBNpWG0ojwxKlr7iDlIoZmAWUNAOx7QDEp1SGjUsTLcGpyeiUp8cILLd6gqbiajE9AWaWq/KtqVnMbHwa0G/OqO2MGtEFKG1AsTYu5TdTPVcwa8Zw4q0i3EMpSmCuaV5QdWmPJyTwUzrNeYAwwtUBILxDzQupw8Wx/bEOLYtzKm9tkRT9i6zXPkun2GB9Ie20ZzbP58uW+viGnaXcb2mmbdclzEzL6qxek9+y7MZ1lKLb1GAmnd5tgSy1N+JkQYsgnhyqJm+TtTCPB395JOiCfks7af9unaldJ0wpqS0vJByUnoNVXN2ieswWlKTjNWsJGApivu+LuHgCYW6JGEzcRyvwhWaueRqEPCPPGQTVkJ2Vg17vSgWPvSSkbGmNTuECkppFRQWooNyZTnApWkAvkRTWrKWiIr1K6ZE5JrSIHmgOBQJ1k5dZ2B+5y5I9ZTxuxhBbMN9VdNm5jqcXPbHcgHQJWnRJg9KBm4pHDbfPaY0krOD6oSb9V31gCx8zz5kLWtFpRu2iaVdPP2txbt5AqGRvK5/7VLQEZJzFgBM+jAGXhgpJxISKN+tYxV4SoBGwlo+4IpAb27pRsCWhLakItINCf8otLPZxa01Nl05r643seHasxQvwwbQ7T2pR3m7zgtRk3L0H8vhJR1zFNyGgnqqHZjYzr3CjRfpGpY7ZrGMuog6bElvaKhPseZYhmSVyV1g/S291uy2naawLwSXp0xgRDFJcj8EWHaR0jA136MfJYhjYfYNi5n26+Ecs8XpLxBuKLRC6NeBXw307lgHUerrYR8TQKH8T1KMD23BFQpKJKNuylQxZqAtI6EUftP4cYBZaj+GQLKYAQPAZtgyWghZKPU+5cyDeS1Ktqcc/L7ImHsTKenxRDTiUGaPmj+WAuxUyxwRLYpK4Fv2y0ox/bcJbjcZ0iu9TXeq9dNGU/dTsDdOF/NYaiGOhvipbYu77khshBeiUxSzIfLAks2/aDcZ6rJYn4bj+mikstILVvWozqts7gQrjiDSdhuTZWMcq9xGO14vrNaTkGCaZfaN0lJMlf1Guno5BuJaFKNDWo/sG754a6O8D+84LMkbMz7pqmnDCWgwBLv/0FKHxc/Slgiuj0uP0eT1LTeuedcw0YedU+IBP4mNqwt6/Zje+tsrr8JQkjGPStYjNkYqBLQDtCwhJyXj8T70di6Tep8DCQyiUCUsRgta72m370BIo1UIjmmi3k222PLaWTCGv3GWYxVtN2mjQ5R5VlWylnBoOpVFyNVzWVhiWNXTRNJKCra+zyPg8pBCTH1hNUbZh8wJaBu+dEQhnF6QsxgBBmSxUXKU2cJaEnoHNsyDN0YEnqJ20zCs3lGMhoyqsS0UtOVng2SkqkjRc2ycUa6Uqo60tZKYOeaCQuZOpSkHtg8yXdDUBbqhNlzVyp5pZ6S27bTJbbjhDl1WiKRCBZuOds259j5oNjlqbPPWIerLi1+5hC411ziNppRQiqx483KViSiHc3cRECucuAlqIwZZfvtRyreb5MHbGOBxv6zQ/Ibu+Ky3x1PWFSxhYd8SjqFnHMtGU9ewzXjzMixXa61qS5LaC/RG+pqkq4kkxDKkNmpu0kau3W61xxCCkFd4vuStj6vdHadKS+cifrywTQSq8Fmcp5hUTcw5yRTwpJfrzuEOKMhbBl9H+djc0hm2m8cA5VYJk/MJEtEa+O5H63dhkNnsLkTyHVpXXd9F92syE63NEs3O7Yg6zRS1QxetqS3HrE6J3alLLOF108JSDVs14rO6BQ6S8hmYjp5Uta95i1r75d8Tzmb8rrzjIbr351zP9H8Mdj6bR3m/p+Vkec7hLfS3XMu28mrWmCe3GOuCckbYD+mRidNV5G1sBEB74egBHfRqCG8cOpO6i5Vbj2mzRwwLB+ULe/5AO2CQM7H2VS/bZd9V7MrqqR2UXH7u9prXtjfzfwGSlIzhcNKTPsbWHVuFygybWX9Oi3zuxKwYauu7A+HiJSGAkMSJaV7bIlKyE7rPDep3N8Et27dFnaVqXmmW06fLSv2m2NvO7xt4bMartvnes+lTY1ttedyzWn/2fY6170flAfOh2b+SN2eypx7yzbUod6fpE0fd0PdDcRoLNdwj/e/+Ume5P9EiEg57+9kftufwbapIc+Tb9vrJa+k9jfxlJP7j/X/ddaG2Sn+uPkDkBXLmUFWWtBIJOguN8Ne+xm8dbDOn4FTQZvzmp//M/yv5/z/4N/u+19taH63f0Nznf9WT3Nec9mf/dbNdTXX0VyfrefIA1tfc/u88P4GzfX92zObyzbn2brt//8NwP8F5AnrRKzLuowAAAAASUVORK5CYII=" alt="feide" /></div>
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
