"""GitHub full_name 白名单校验。

所有外部来源（飞书底表、小红书 CSV 等）的 full_name 进 subprocess/URL 前必须过这里，
防止路径操纵（../）、查询参数注入（?per_page=）等 SSRF 攻击。
"""

from __future__ import annotations

import re

# owner/repo：owner 1-39 字母数字连字符，repo 1-100，禁两点、禁斜杠嵌套
_FULL_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}$"
)


class InvalidFullName(ValueError):
    """full_name 不符合 owner/repo 格式或含路径操纵字符。"""


def validate_github_full_name(full_name: str, *, max_len: int = 120) -> str:
    """校验并返回规范化后的 full_name。不合法抛 InvalidFullName。

    规则：
    - 必须形如 owner/repo，恰好一个斜杠
    - 只允许 [A-Za-z0-9._-]，禁止 .. / ~ / \\ / 空格 / 控制字符
    - owner ≤ 39 字符（GitHub 限制），repo ≤ 100
    - 总长 ≤ max_len
    """
    if not isinstance(full_name, str):
        raise InvalidFullName(f"full_name 不是字符串: {type(full_name)!r}")
    s = full_name.strip()
    if not s:
        raise InvalidFullName("full_name 为空")
    if len(s) > max_len:
        raise InvalidFullName(f"full_name 过长: {len(s)} > {max_len}")
    if s.count("/") != 1:
        raise InvalidFullName(f"full_name 必须恰好一个斜杠: {s!r}")
    if ".." in s or "~" in s or "\\" in s:
        raise InvalidFullName(f"full_name 含路径操纵字符: {s!r}")
    if not _FULL_NAME_RE.match(s):
        raise InvalidFullName(f"full_name 不匹配 owner/repo 格式: {s!r}")
    return s
