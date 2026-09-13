#!/usr/bin/env python3
"""音乐加密文件解锁工具（统一入口）。

用法：
  python unlock.py <文件或目录>
  python unlock.py -r -o outdir 歌曲目录
  python unlock.py --selftest
"""
from __future__ import annotations

from music_unlock.cli import main

if __name__ == "__main__":
    raise SystemExit(main())