"""CI 里把单测进程的出网调用变成异常。

放在 PYTHONPATH 上，CPython 启动时自动 import（不需要任何测试改动）。
目的不是「安全隔离」，而是把「某个单测偷偷打真实 API」变成一条明确的报错，
而不是一次偶发超时——后者会被当成环境抖动重跑掉，前者跑不掉。
loopback 放行：FastAPI 的 TestClient 走 ASGI 不开 socket，但留着 127.0.0.1，
以免将来有人起本地 http.server 做端到端测试时被误伤。
"""

from __future__ import annotations

import socket

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", ""})

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_create_connection = socket.create_connection


def _host_of(address: object) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return ""


def _deny(host: str) -> None:
    raise OSError(
        f"单测进程被禁止出网（目标 {host!r}）。"
        "单测不应依赖网络或外部凭据；需要外部响应请改成 fixture 或打桩。"
    )


def _connect(sock: socket.socket, address: object) -> object:
    host = _host_of(address)
    if host not in _LOOPBACK:
        _deny(host)
    return _real_connect(sock, address)


def _connect_ex(sock: socket.socket, address: object) -> object:
    host = _host_of(address)
    if host not in _LOOPBACK:
        _deny(host)
    return _real_connect_ex(sock, address)


def _create_connection(address: object, *args: object, **kwargs: object) -> object:
    host = _host_of(address)
    if host not in _LOOPBACK:
        _deny(host)
    return _real_create_connection(address, *args, **kwargs)


socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
socket.create_connection = _create_connection
