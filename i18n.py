"""双语人话层：把 SKILL.md 原文归一化成中/英「一句话 + 亮点」，结果持久缓存。

为什么需要这一层：SKILL.md 的 description 是写给 agent 做路由判断的
（清一色 "Use when users ask about..."），直接截断展示等于把机器可读文本
当人类文案用。这里用模型重写成人话，并同时产出中英两份，前端切换语言不发请求。

缓存键 = full_name + skill_path，命中还要同时满足两个指纹：content_hash（输入
内容没变）和 contract_hash（prompt / 模型 / 温度 / 正文截断长度没变）。只看内容
指纹的话，换模型或改 prompt 都不会触发重译，缓存里就会攒下同一份输入对应好几份
不同文案、而生效的只是最后落盘那行的局面。GitHub Actions 每 6 小时跑一次，正常
情况下只翻新增条目。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

I18N_DIRNAME = "i18n"
CACHE_NAME = "cards.jsonl"

DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_MODEL = "qwen-plus"
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT = 60

BODY_LIMIT = 1800
TEMPERATURE = 0.2

# 一条产出不合格时最多调几次模型（含首次）。失败率实测 <1%，设 2 只给这不到 1%
# 加一次成本；再高就是拿钱换边际收益。
DEFAULT_ATTEMPTS = 2

# 手动版本号：改了 prompt 语义但想强制重译时 +1。prompt 正文本身也进指纹，
# 所以只改措辞不用动这里；这个号是留给「文本没变但要求变了」的场景。
PROMPT_VERSION = "2"

# NOTE: 下面这几组阈值本该进 config_defaults.json，因该文件正被其它改动占用，
# 暂放此处。挪走时记得同步 contract_hash 的输入。

# 卡片正文宽度实测：容器 --phone 470px，highlights li 扣掉左右 padding 后
# 约 404px，字号 .8rem(12.8px)。半角字符约 6.4px，所以单行放得下约 63 个
# 「显示宽度单位」（1 单位 = 半角字符宽，汉字算 2）。目标值按「一行装得下」定。
_TARGET_WIDTH = {
    "one_liner_zh": 80,    # 40 汉字
    "one_liner_en": 105,
    "highlights_zh": 40,   # 20 汉字
    "highlights_en": 60,
    "who_for_zh": 28,      # 14 汉字
    "who_for_en": 42,
}

# 校验用的硬上限，比目标值宽松：目标写进 prompt 引导模型，硬上限只拦真正撑爆
# 版面的离群值。按现有缓存语料模拟，这组值的整条判废率 9.0%（且那批语料是旧
# 宽松 prompt 产的，新 prompt 下实际会低得多）；再收紧到 118/64/48 就跳到 30.6%，
# 那是拿重试成本换排版，不划算。
_MAX_WIDTH = {
    "one_liner_zh": 88,
    "one_liner_en": 130,
    "highlights_zh": 48,
    "highlights_en": 72,
    "who_for_zh": 36,
    "who_for_en": 56,
}

# 模型产出的字段；缺任何一个都视为该条失败，降级用原文
FIELDS = (
    "one_liner_zh",
    "one_liner_en",
    "highlights_zh",
    "highlights_en",
    "who_for_zh",
    "who_for_en",
)

_SCALAR_FIELDS = ("one_liner_zh", "one_liner_en", "who_for_zh", "who_for_en")
_LIST_FIELDS = ("highlights_zh", "highlights_en")

SYSTEM_PROMPT = (
    "你是 skill-feed 的内容编辑。读者是不想读 SKILL.md、只想三秒钟判断"
    "「这个 agent skill 值不值得装」的人。你的产出必须是人话，不是文档摘录。"
    "严格只输出一个 JSON 对象。"
)

USER_TEMPLATE = """仓库：{full_name}
名称：{name}
原始描述：{description}

SKILL.md / README 片段：
---
{body}
---

产出 JSON，字段与要求：

one_liner_zh  一句话讲清「用它能做成什么」。动词开头，≤40 汉字。
              禁止以「当你…」「用于…时」「这是一个…」开头。
one_liner_en  同义英文，动词开头，≤105 个字符（含空格，约 16 词）。
highlights_zh 恰好 3 条能力点，每条 ≤20 汉字，讲产出与效果。
highlights_en 对应的 3 条英文，每条 ≤60 个字符（含空格，约 9 词），与中文一一对应同义。
who_for_zh    适合谁用，≤14 汉字。
who_for_en    对应英文，≤42 个字符（含空格，约 6 词）。

关于英文长度：卡片一行只放得下约 60 个英文字符，超了就折行、把按钮挤出屏幕。
英文按字符数算，别按词数算——同样信息量的英文比中文占宽得多。压缩的办法是换更短的
词、砍掉从句和修饰语，不是省略主语或写成电报体；读者是海外开发者，可读性优先。

硬禁止（出现即视为错误产出）：
- URL
- 你正在读的源文件名：SKILL.md / README.md / AGENTS.md / CLAUDE.md 等
- 带目录的文件路径：references/style.md、scripts/build.sh、./config/x.yaml
- 安装与配置命令（pip install、npm install、npx …）、依赖版本号、Prerequisites 清单
- 写给 agent 的指令（例如「先读取…」「执行前先…」）
- 仅重复仓库名或标题当作亮点

允许且鼓励：如果这个 skill 的产出物本身就是某个文件（例如生成 DESIGN.md、
写出 ADR.md、导出 report.html），照实写出这个产出文件名——那是它的能力，
不是文件引用。区别在于：源文件是它读的，产出物是它给你的。

中英两份必须语义一致。只输出 JSON，不要任何解释或代码围栏。"""


def i18n_root(data_dir: Path) -> Path:
    return data_dir / I18N_DIRNAME


def cache_path(data_dir: Path) -> Path:
    return i18n_root(data_dir) / CACHE_NAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_hash(item: dict) -> str:
    """内容指纹：描述或正文变了才需要重译。"""
    raw = "\n".join(
        [
            str(item.get("name") or ""),
            str(item.get("description") or ""),
            str(item.get("body_preview") or "")[:BODY_LIMIT],
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def contract_hash(
    *,
    model: str = DEFAULT_MODEL,
    temperature: float = TEMPERATURE,
    body_limit: int = BODY_LIMIT,
) -> str:
    """产出契约指纹：任何会改变模型产出的参数变了，缓存就该失效。

    content_hash 只管输入内容，管不住 prompt/模型/温度/截断长度。少了这层，换模型
    或改 prompt 都不会触发任何重译，缓存里就会攒下「同一个 content_hash 对应好几份
    不同文案」的行（实测 432 个键里 34 个是这样），而最终生效的只是 cards.jsonl 里
    最后落盘的那一行——哪份文案生效取决于写入顺序，不取决于代码。

    校验用的 _MAX_WIDTH / _BANNED_RULES 故意不进指纹：它们只决定「收不收」，不决定
    「生成什么」。调排版阈值不该引发重译。
    """
    raw = "\n".join(
        [
            PROMPT_VERSION,
            SYSTEM_PROMPT,
            USER_TEMPLATE,
            str(model),
            f"{float(temperature):.4f}",
            str(int(body_limit)),
            ",".join(FIELDS),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def cache_key(item: dict) -> str:
    """缓存键 = full_name + skill_path。

    monorepo 一个仓库能展开出十几条 skill，它们 full_name 相同。只用 full_name
    做键会让同仓库的条目互相覆盖，每次构建都要重译一大批（实测 212 条里 150
    条在空烧），所以必须带上 skill_path 区分。
    """
    fn = str(item.get("full_name") or "")
    path = str(item.get("skill_path") or "")
    return f"{fn}#{path}" if path else fn


def load_cache(data_dir: Path) -> dict[str, dict]:
    """读缓存。同一键后写的覆盖先写的。"""
    path = cache_path(data_dir)
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not row.get("full_name"):
                continue
            out[cache_key(row)] = row
    except OSError:
        pass
    return out


def _append_cache(data_dir: Path, rows: Iterable[dict]) -> int:
    path = cache_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def _strip_fence(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


def _clean_one(s: Any) -> str:
    out = re.sub(r"\s+", " ", str(s or "")).strip()
    out = out.strip("`*_ ")
    return out


# 违禁词表。每条都带名字，失败时能说清是哪条拦的——排查时「banned:path」比
# 一个大正则的布尔值有用得多。
#
# 这里要拦的只有一件事：模型在描述它读到的文件，而不是描述这个 skill 的能力。
# 所以判据是「这个文件名是它读的输入，还是它给你的产出」，不是「有没有出现文件名」。
# 旧表里的裸 `\.md\b` 就是把两者混为一谈：stitch-design-taste 的功能本身就是
# 生成 DESIGN.md，任何忠实的摘要都必然提到它，于是永远不可能通过——这是逻辑上
# 不可满足的约束，不是模型写得不好。
_BANNED_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"https?://|\bwww\.[a-z0-9-]+\.[a-z]{2,}", re.I)),
    # 源文件白名单式点名：只拦 agent 生态里公认的「输入文件」，产出物文件名放行
    (
        "source_file",
        re.compile(
            r"\b(?:SKILL|README|AGENTS|CLAUDE|GEMINI|CODEX|CURSOR|CHANGELOG"
            r"|CONTRIBUTING|LICENSE)\.(?:md|markdown|mdx|txt)\b",
            re.I,
        ),
    ),
    # 带目录的路径。目录段必须全小写，否则 "React/Next.js"、"WCAG 2.1/2.2" 会误伤
    # （实测旧的宽松写法在 4304 条已生效译文上误伤 3 条，收窄后 0 条）。
    (
        "path",
        re.compile(
            r"(?:^|[\s(\[（「'\"`])(?:\./|\.\./)?[a-z0-9_-]+(?:/[a-z0-9_.-]+)+"
            r"\.(?:md|markdown|mdx|py|js|mjs|cjs|ts|tsx|jsx|json|ya?ml|toml|ini"
            r"|cfg|sh|bash|ps1|txt|csv|sql|rb|go|rs|java|php)\b"
        ),
    ),
    (
        "install_cmd",
        re.compile(
            r"\b(?:pip|pipx|uv|npm|pnpm|yarn|brew|cargo|apt|gem)\s+(?:install|add)\b"
            r"|\bnpx\s+\S",
            re.I,
        ),
    ),
    # 依赖清单/版本钉死。旧表用的是裸 `Requires\b`，那个太宽：requires 是普通英文
    # 动词，实测 388 条源描述里 8 条含它，其中 4 条是正当用法（"requires running
    # verification commands"、"explicitly requires Options API"），照抄进摘要完全
    # 合理却会被判违规。改成只拦真正的依赖声明形态。
    (
        "dependency",
        re.compile(
            r"\b(?:requirements\.txt|package\.json|pyproject\.toml|Pipfile)\b"
            r"|\b(?:requires?|依赖|需要)\s*[:：]?\s*[\w.+-]*\s*v?\d+(?:\.\d+)+"
            r"|\bOptional\s+extras?\b|\bPrerequisites?\s*[:：]|前置(?:条件|要求)\s*[:：]",
            re.I,
        ),
    ),
)


def _banned_reason(text: str) -> str:
    """命中返回规则名，没命中返回空串。"""
    for name, pat in _BANNED_RULES:
        if pat.search(text):
            return name
    return ""


def _display_width(text: str) -> int:
    """显示宽度：东亚全角/宽字符算 2，其余算 1。

    中英不能共用一个字符数上限——一个汉字的渲染宽度约等于两个英文字符，按字符数
    卡会让英文实际占宽是中文的近两倍（实测 highlights 中位显示宽度 zh 31 / en 51）。
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _check_fields(obj: Any, *, enforce_length: bool) -> tuple[Optional[dict], str]:
    """校验产出，返回 (字段表, 失败原因)。失败时字段表为 None。

    enforce_length 只对新鲜的模型产出开。缓存行和人工审校稿走 False：长度上限是
    后加的，对存量译稿开会一次性判废 38.4%，等于用一次全量重译换排版。
    """
    if not isinstance(obj, dict):
        return None, "not_object"
    out: dict[str, Any] = {}
    for key in _SCALAR_FIELDS:
        val = _clean_one(obj.get(key))
        if not val:
            return None, f"missing:{key}"
        rule = _banned_reason(val)
        if rule:
            return None, f"banned:{rule}:{key}"
        if enforce_length:
            w = _display_width(val)
            if w > _MAX_WIDTH[key]:
                return None, f"too_long:{key}:{w}>{_MAX_WIDTH[key]}"
        out[key] = val
    for key in _LIST_FIELDS:
        raw = obj.get(key)
        if not isinstance(raw, list):
            return None, f"not_list:{key}"
        items = [_clean_one(x) for x in raw]
        items = [x for x in items if x and not _banned_reason(x)]
        if enforce_length:
            items = [x for x in items if _display_width(x) <= _MAX_WIDTH[key]]
        # 3 条里废掉 1 条还能看，废掉 2 条就不是「亮点」了
        if len(items) < 2:
            return None, f"too_few:{key}"
        out[key] = items[:3]
    return out, ""


def _valid_fields(obj: dict) -> Optional[dict]:
    """结构校验：字段齐全、不含违禁内容。不含长度门槛。

    bitable_store 用同一个函数校验人工审校过的译稿，缓存命中判定也走它。这两处
    都不能受长度上限影响，否则改一次排版阈值就会把已验收的稿子和几百条存量缓存
    一起判废。长度只在 _check_fields(enforce_length=True) 里对新产出生效。
    """
    fields, _ = _check_fields(obj, enforce_length=False)
    return fields


def _retry_hint(reason: str) -> str:
    """把校验失败原因翻译成给模型看的整改要求。"""
    kind, _, rest = reason.partition(":")
    if kind == "too_long":
        field, _, sizes = rest.partition(":")
        return (
            f"上一次产出不合格：{field} 的显示宽度 {sizes}，超了。"
            "请把这个字段改短，用更短的词、砍掉从句，不要写成电报体，其余字段保持同样质量。"
        )
    if kind == "banned":
        rule, _, field = rest.partition(":")
        detail = {
            "url": "不要写 URL。",
            "source_file": "不要提你读的源文件名（SKILL.md / README.md 等）；"
                           "如果这个 skill 的产出物就是某个文件，写产出物的名字是允许的。",
            "path": "不要写带目录的文件路径。",
            "install_cmd": "不要写安装或配置命令。",
            "dependency": "不要写依赖清单或版本号。",
        }.get(rule, "去掉违规内容。")
        return f"上一次产出不合格：{field} 命中禁止项（{rule}）。{detail}"
    if kind == "too_few":
        return f"上一次产出不合格：{rest} 有效条目不足 3 条，请补齐并保证每条都合规。"
    return "上一次产出不合格：JSON 字段缺失或结构不对，请严格按要求重出。"


def _chat(
    item: dict,
    *,
    api_key: str,
    model: str,
    base_url: str,
    timeout: int,
    hint: str = "",
) -> tuple[Optional[Any], str]:
    """调一次模型，返回 (解析出的 JSON 对象, 失败原因)。"""
    body = str(item.get("body_preview") or "")[:BODY_LIMIT]
    if not body:
        body = str(item.get("description") or "")
    user = USER_TEMPLATE.format(
        full_name=item.get("full_name") or "",
        name=item.get("name") or "",
        description=str(item.get("description") or "")[:600],
        body=body,
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    if hint:
        messages.append({"role": "user", "content": hint})
    payload = {
        "model": model,
        "temperature": TEMPERATURE,
        "response_format": {"type": "json_object"},
        "messages": messages,
    }
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None, "api_error"
    try:
        data = json.loads(raw)
        text = data["choices"][0]["message"]["content"]
        obj = json.loads(_strip_fence(text))
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None, "bad_json"
    return obj, ""


def _call_model(
    item: dict,
    *,
    api_key: str,
    model: str,
    base_url: str,
    timeout: int,
    attempts: int = DEFAULT_ATTEMPTS,
) -> tuple[Optional[dict], str, int]:
    """要一份合格产出，返回 (字段表, 失败原因, 实际调用次数)。

    不合格就把具体原因回喂给模型再要一次。原来是一次不过直接放弃，那条目既拿不到
    译文、下一轮又会重来——每轮烧一次调用且必定失败。
    """
    reason = "api_error"
    hint = ""
    used = 0
    for _ in range(max(1, attempts)):
        used += 1
        obj, err = _chat(
            item,
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout,
            hint=hint,
        )
        if err:
            reason, hint = err, ""
            continue
        fields, reason = _check_fields(obj, enforce_length=True)
        if fields:
            return fields, "", used
        hint = _retry_hint(reason)
    return None, reason, used


def attach(item: dict, fields: dict) -> dict:
    """把双语字段贴到条目上，同时保留原文作兜底。"""
    for key in FIELDS:
        if key in fields:
            item[key] = fields[key]
    item["i18n_ready"] = True
    return item


def enrich_items(
    data_dir: Path,
    items: list[dict],
    *,
    api_key: str = "",
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    force: bool = False,
    limit: int = 0,
    attempts: int = DEFAULT_ATTEMPTS,
    strict_contract: Optional[bool] = None,
) -> dict:
    """就地给 items 补双语字段。返回统计。

    没有 api_key 时不报错：命中缓存的照样贴上，未命中的保持原文由前端兜底。
    """
    api_key = api_key or os.environ.get("DASHSCOPE_API_KEY", "")
    # 工作空间维度的 key（sk-ws-…）必须走该工作空间的专属域名，不能用通用 dashscope 域名。
    # CI 里 SKILLFEED_HOME 指向仓库内路径，读不到本机 config，所以留一个环境变量出口。
    base_url = os.environ.get("DASHSCOPE_BASE_URL", "") or base_url
    if strict_contract is None:
        strict_contract = os.environ.get("SKILLFEED_I18N_STRICT_CONTRACT", "") == "1"
    contract = contract_hash(model=model)
    cache = load_cache(data_dir)
    stats = {
        "total": len(items),
        "cached": 0,
        "locked": 0,
        "translated": 0,
        "failed": 0,
        "degraded": 0,
        "calls": 0,
        "skipped": 0,
    }

    def contract_ok(row: dict) -> bool:
        """老缓存行没有 contract 字段，一律当命中放行（grandfathering）。

        不放行的话，这次加指纹会把缓存里几百条有效译稿一次性作废、全量重烧一遍，
        而这个缓存存在的全部意义就是省这笔钱。代价是这批老行被永久钉在「产它们的
        那版 prompt」上，直到内容自己变——想主动清掉就开 strict_contract。
        新写的行都带 contract，所以下一次改 prompt/换模型能正确失效。
        """
        got = str(row.get("contract") or "")
        if not got:
            return not strict_contract
        return got == contract

    todo: list[dict] = []
    for it in items:
        fn = str(it.get("full_name") or "")
        if not fn:
            stats["skipped"] += 1
            continue
        h = content_hash(it)
        hit = cache.get(cache_key(it))
        if hit is None:
            # 换键之前写的缓存行没有 skill_path。回退到裸 full_name 查一次，
            # 命中与否仍由下面的 hash 比对决定，所以不会把译文错贴给同仓库兄弟。
            hit = cache.get(fn)
        if hit and not force:
            # locked = 多维表格里人工标了「已验收」。这种行锁定译稿，上游
            # SKILL.md 再改也不重译：既省 token，也保证看板文案不会自己变。
            # 必须排在 hash / contract 之前——人工审校过的稿子不该因为我们改了
            # prompt 就被冲掉。
            if hit.get("locked") and _valid_fields(hit.get("fields") or {}):
                attach(it, hit["fields"])
                stats["cached"] += 1
                stats["locked"] += 1
                continue
            if hit.get("hash") == h and contract_ok(hit):
                if _valid_fields(hit.get("fields") or {}):
                    attach(it, hit["fields"])
                    stats["cached"] += 1
                    continue
                if hit.get("degraded"):
                    # 上一轮重试到底也没要出合格产出。同样的输入 + 同样的契约，
                    # 再调一次还是同样的结果，所以记一笔别再烧钱；条目保持原文，
                    # 前端走它本来就有的兜底。等 prompt/模型/内容任一变了自然重试。
                    stats["degraded"] += 1
                    continue
        it["_i18n_hash"] = h
        todo.append(it)

    if limit > 0:
        todo = todo[:limit]

    if not todo:
        return stats
    if not api_key:
        stats["skipped"] += len(todo)
        for it in todo:
            it.pop("_i18n_hash", None)
        return stats

    def work(it: dict) -> tuple[dict, Optional[dict], str, int]:
        fields, reason, used = _call_model(
            it,
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout,
            attempts=attempts,
        )
        return it, fields, reason, used

    new_rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for it, fields, reason, used in pool.map(work, todo):
            h = it.pop("_i18n_hash", "") or content_hash(it)
            stats["calls"] += used
            row = {
                "full_name": it.get("full_name"),
                "skill_path": it.get("skill_path") or "",
                "hash": h,
                "contract": contract,
                "model": model,
                "at": _now(),
            }
            if not fields:
                stats["failed"] += 1
                # 网络类失败不落盘：那是环境问题，下一轮该重试。只有模型确实产不出
                # 合格内容才记 degraded，否则一次断网就把条目钉死。
                if reason not in ("api_error", "bad_json"):
                    stats["degraded"] += 1
                    row.update({"fields": {}, "degraded": True, "fail_reason": reason,
                                "attempts": used})
                    new_rows.append(row)
                continue
            attach(it, fields)
            stats["translated"] += 1
            row["fields"] = fields
            new_rows.append(row)

    if new_rows:
        _append_cache(data_dir, new_rows)
    return stats


def compact_cache(data_dir: Path, *, backup: bool = True) -> dict:
    """重写 cards.jsonl，每个键只留最后一行。

    load_cache 的语义就是「同键后写覆盖先写」，所以丢掉被覆盖的行对读取方完全等价。
    实测 2072 行只对应 432 个有效键，79.2% 是死数据。
    不在 enrich_items 里自动调：构建过程中重写一个别的进程正在读的文件不值当，
    要压缩就显式调一次。
    """
    path = cache_path(data_dir)
    stats = {"before": 0, "after": 0, "dropped": 0}
    if not path.exists():
        return stats
    keep: dict[str, str] = {}
    order: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not row.get("full_name"):
            continue
        stats["before"] += 1
        k = cache_key(row)
        if k not in keep:
            order.append(k)
        keep[k] = line
    stats["after"] = len(keep)
    stats["dropped"] = stats["before"] - stats["after"]
    if backup:
        path.with_suffix(path.suffix + ".bak").write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(keep[k] + "\n" for k in order), encoding="utf-8")
    tmp.replace(path)
    return stats


def enrich_feed(
    data_dir: Path,
    feed: dict,
    *,
    api_key: str = "",
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    workers: int = DEFAULT_WORKERS,
    force: bool = False,
    limit: int = 0,
    attempts: int = DEFAULT_ATTEMPTS,
) -> dict:
    """给 feed['items'] 补双语字段（只处理入流条目，corpus 兜底池不翻）。"""
    items = feed.get("items") or []
    stats = enrich_items(
        data_dir,
        items,
        api_key=api_key,
        model=model,
        base_url=base_url,
        workers=workers,
        force=force,
        limit=limit,
        attempts=attempts,
    )
    feed["i18n"] = {
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "contract": contract_hash(model=model),
        "updated_at": _now(),
        "stats": stats,
        "languages": ["zh", "en"],
        "default": "zh",
    }
    return stats
