# coding: utf-8
"""kgg 密钥映射全局管理（来源：KGMusicV3.db / 导出的 kgg.key）。

keymap 为 {audioHash: ekey} 字符串映射。加载来源优先级：
  1. configure() 显式指定（CLI --kgg-db / WebUI 上传或配置路径）
  2. 环境变量 KGG_DB（指向 KGMusicV3.db）或 KGG_KEY（指向 kgg.key）
  3. 项目 assets/kgg.key（用户手动部署的静态映射）
  4. 常见酷狗客户端安装路径（Windows APPDATA/LOCALAPPDATA）
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from .crypto.kgg_db import (
    load_key_file,
    load_key_map,
)

_lock = threading.Lock()
_KEY_MAP: dict[str, str] | None = None
_SOURCE = ""


class KggKeyError(Exception):
    """kgg 密钥映射不可用。"""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


def _auto_candidates() -> list[str]:
    env_db = os.environ.get("KGG_DB", "").strip()
    env_key = os.environ.get("KGG_KEY", "").strip()
    candidates = []
    if env_key:
        candidates.append(("key", env_key))
    if env_db:
        candidates.append(("db", env_db))
    assets = Path(__file__).resolve().parent / "assets" / "kgg.key"
    if assets.is_file():
        candidates.append(("key", str(assets)))
    for k in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(k)
        if not base:
            continue
        for sub in ("KuGou", "KuGou8"):
            p = Path(base) / sub / "KGMusicV3.db"
            if p.is_file():
                candidates.append(("db", str(p)))
    home = Path.home() / "AppData" / "Roaming"
    for sub in ("KuGou", "KuGou8"):
        p = home / sub / "KGMusicV3.db"
        if p.is_file():
            candidates.append(("db", str(p)))
    return [c for c in candidates if c]  # noqa: RUF005


def configure(db_path: str | None = None, key_path: str | None = None) -> int:
    """加载密钥映射并设为全局可用。返回条目数（0 表示无映射/覆盖为空表）。

    不抛异常时表示成功；db 解密失败或文件不存在时抛出 KggKeyError。
    """
    global _KEY_MAP, _SOURCE
    if db_path:
        try:
            key_map = load_key_map(db_path)
        except OSError as e:
            raise KggKeyError(f"无法读取密钥库: {db_path} ({e})") from e
        except ValueError as e:
            raise KggKeyError(f"密钥库解密失败: {e}",
                              hint="确认是 KGMusicV3.db（SQLCipher），或 master key 已更新") from e
        _SOURCE = f"db:{db_path}"
    elif key_path:
        try:
            key_map = load_key_file(key_path)
        except OSError as e:
            raise KggKeyError(f"无法读取 kgg.key: {key_path} ({e})") from e
        _SOURCE = f"key:{key_path}"
    else:
        for kind, path in _auto_candidates():
            try:
                return configure(db_path=path if kind == "db" else None,
                                 key_path=path if kind == "key" else None)
            except KggKeyError:
                continue
        raise KggKeyError("未找到酷狗密钥库 KGMusicV3.db 或 kgg.key",
                          hint="上传酷狗客户端的 KGMusicV3.db，或先导出 kgg.key")
    with _lock:
        _KEY_MAP = key_map
    return len(key_map)


def set_key_map(key_map: dict[str, str], source: str = "") -> None:
    """运行时注入 keymap（webui 上传后缓存用），不落盘。"""
    global _KEY_MAP, _SOURCE
    with _lock:
        _KEY_MAP = dict(key_map)
        _SOURCE = source or _SOURCE


def get() -> dict[str, str] | None:
    with _lock:
        return _KEY_MAP


def source() -> str:
    with _lock:
        return _SOURCE


def ensure_loaded() -> dict[str, str]:
    """惰性加载并返回全局映射；失败抛出 KggKeyError（带解决提示）。"""
    key_map = get()
    if key_map is None:
        configure()
        key_map = get()
    assert key_map is not None
    return key_map