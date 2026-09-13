# coding: utf-8
"""命令行入口。"""
from __future__ import annotations

import argparse
from pathlib import Path

from .core import collect_files, decrypt_file, selftest


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="unlock",
        description="音乐加密文件解锁工具：KGM/KGMA/VPR(K酷狗) · KWM(酷我) · QMC(QQ音乐) · NCM(网易云)",
    )
    p.add_argument("target", nargs="?", help="文件或目录")
    p.add_argument("-r", "--recursive", action="store_true", help="递归处理子目录")
    p.add_argument("-o", "--outdir", help="输出目录（默认与源文件相同）")
    p.add_argument("-f", "--force", action="store_true", help="覆盖已存在的输出文件")
    p.add_argument("-d", "--delete", action="store_true", help="解密成功后删除原文件")
    p.add_argument("-v", "--verbose", action="store_true", help="显示未识别格式的文件")
    p.add_argument("-t", "--selftest", action="store_true", help="运行自检后退出")
    p.add_argument("--list-formats", action="store_true", help="列出支持的加密格式")
    p.add_argument("--kgg-db", metavar="PATH", help="酷狗 KGMusicV3.db 路径（解 .kgg 需要）")
    p.add_argument("--kgg-key", metavar="PATH", help="导出的 kgg.key 密钥映射文件路径")
    return p


def main() -> int:
    from . import kgg_keys
    args = build_parser().parse_args()

    if args.selftest:
        return selftest()
    if args.list_formats:
        from .formats import FORMATS
        print("支持的加密格式:")
        for f in FORMATS:
            print(f"  - {f.name}")
        return 0
    if not args.target:
        build_parser().error("缺少目标文件/目录")
        return 2

    if args.kgg_db or args.kgg_key:
        try:
            count = kgg_keys.configure(db_path=args.kgg_db, key_path=args.kgg_key)
            print(f"已加载 {count} 条酷狗密钥映射（{kgg_keys.source()}）")
        except kgg_keys.KggKeyError as e:
            print(f"密钥映射加载失败: {e}")
            if e.hint:
                print(f"提示: {e.hint}")
            return 1

    outdir = Path(args.outdir) if args.outdir else None
    files = collect_files(Path(args.target), args.recursive)
    if not files:
        print("未找到需要处理的文件。")
        return 0

    ok = 0
    total = 0
    for src in files:
        msg = decrypt_file(src, outdir, args.force, args.delete, args.verbose)
        if not msg:
            continue
        print(msg)
        total += 1
        if not msg.startswith(("跳过", "失败")):
            ok += 1
    print(f"完成 {ok}/{total}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())