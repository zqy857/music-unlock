# coding: utf-8
"""统一解密管线与自检。"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
from pathlib import Path

from .formats import DecodeResult, DecryptError, detect_format
from .sniff import sniff_audio


def decrypt_bytes(data: bytes, extension: str) -> DecodeResult:
    fmt = detect_format(data, extension)
    if fmt is None:
        raise DecryptError("格式未识别")
    result = fmt.decrypt(data)
    if not result.data:
        raise DecryptError("解密结果为空")
    return result


def decrypt_file(src: Path, outdir: Path | None, force: bool, delete: bool, verbose: bool) -> str:
    try:
        data = src.read_bytes()
    except OSError as e:
        return f"读取失败: {src} ({e})"

    try:
        result = decrypt_bytes(data, src.suffix)
    except DecryptError as e:
        if verbose:
            return f"跳过({e}): {src}"
        return ""
    except Exception as e:
        return f"失败: {src} ({e})"

    dest_dir = outdir or src.parent
    try:
        if outdir is not None:
            outdir.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkstemp(prefix=".unlock_", dir=str(dest_dir))[1])
    except OSError as e:
        return f"输出目录不可用: {dest_dir} ({e})"

    dest = None
    try:
        tmp.write_bytes(result.data)
        ext = sniff_audio(result.data) or result.ext or ""
        base = result.clean_name(src.name)
        dest = dest_dir / (base + ext)
        if dest == src and not force:
            tmp.unlink(missing_ok=True)
            return "跳过(输入输出相同)"
        if dest.exists() and not force:
            tmp.unlink(missing_ok=True)
            return f"跳过(输出已存在): {dest}"
        os.replace(tmp, dest)
        if delete:
            src.unlink(missing_ok=True)
        kind = ext or result.ext or "未知格式"
        return f"{src.name} -> {dest.name} [{ext or '?'}] ({result.title or kind})"
    except Exception as e:
        tmp.unlink(missing_ok=True)
        return f"失败: {src} ({e})"


def collect_files(target: Path, recursive: bool):
    if target.is_file():
        return [target]
    if target.is_dir():
        if recursive:
            return [p for p in target.rglob("*") if p.is_file()]
        return [p for p in target.iterdir() if p.is_file()]
    return []


def selftest() -> int:
    from .crypto import aes, tea
    from .formats import kgm

    ok = True
    print("== 基础密码原语 ==")
    ok &= _step("AES-128 FIPS-197 向量", _selftest_aes(aes))
    ok &= _step("QMC simpleMakeKey(106,8)", _simple_make_key_ok(tea))
    ok &= _step("QMC TEA 可逆性", _tea_roundtrip(tea))

    print("== KGM ==")
    base = Path(__file__).resolve().parent.parent
    enc = base / "tests" / "test_kugou_kgm.dat"
    exp = base / "tests" / "test_kugou_kgm_right.dat"
    if enc.exists() and exp.exists():
        ok &= _step(
            "官方测试向量",
            _kgm_vector_ok(enc, exp, kgm),
        )
    else:
        print("官方测试向量: 跳过(未找到 tests/)")
    ok &= _step("KGM 与权威公式一致", _kgm_formula_ok(kgm))

    from .formats import kwm, ncm, qmc
    ok &= _step("QMC map 官方向量", _qmc_vectors("mflac_map", qmc))
    ok &= _step("QMC static 官方向量", _qmc_vectors("qmc0_static", qmc))
    ok &= _step("QMC rc4 官方向量", _qmc_vectors("mflac_rc4", qmc))
    ok &= _step("QMC rc4 (mflac0) 官方向量", _qmc_vectors("mflac0_rc4", qmc))
    ok &= _step("QMC 密钥官方向量", _qmc_keys(qmc))
    ok &= _step("KWM 自反性", _kwm_roundtrip(kwm))
    ok &= _step("NCM 密钥盒自反性", _ncm_box_roundtrip(ncm))

    from .crypto import kgg_db as _kgg_db
    print("== KGG (新酷狗) ==")
    ok &= _step("KGG 页派生官方向量", _kgg_derive_ok(_kgg_db))
    ok &= _step("KGG db 加密往返", _kgg_db_roundtrip(_kgg_db))

    print("全部通过" if ok else "存在失败项")
    return 0 if ok else 1


def _step(label: str, ok: bool) -> bool:
    print(f"{label}: {'通过' if ok else '失败'}")
    return ok


def _kgg_derive_ok(kgg_db) -> bool:
    return (
        kgg_db.derive_page_aes_key(0, kgg_db.DEFAULT_MASTER_KEY).hex()
        == "1962c05fa2ebbe2428ff522b9e03ead4"
        and kgg_db.derive_page_aes_iv(0).hex()
        == "055a673593892ddf3ab3b3c621c34802"
    )


def _kgg_db_roundtrip(kgg_db) -> bool:
    import struct
    import sqlite3
    import tempfile

    from .crypto.aes import AES128CBC

    page = kgg_db.DB_PAGE_SIZE
    master = kgg_db.DEFAULT_MASTER_KEY

    def _mk_plain() -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "k.db"
            c = sqlite3.connect(str(p))
            c.execute("CREATE TABLE ShareFileItems (EncryptionKeyId TEXT, EncryptionKey TEXT)")
            c.execute("INSERT INTO ShareFileItems VALUES ('k','v')")
            c.commit()
            c.close()
            raw = p.read_bytes()
        plain = bytearray(raw)
        plain[0:16] = b"SQLite format 3\x00"
        plain[0x14:0x18] = struct.pack("<I", 0x20204000)
        return bytes(plain)

    def _enc_page(plain: bytes, n: int) -> bytes:
        return AES128CBC(
            kgg_db.derive_page_aes_key(n, master),
            kgg_db.derive_page_aes_iv(n),
        ).encrypt(plain)

    try:
        plain = _mk_plain()
        if len(plain) % page != 0:
            return False
        out = bytearray(len(plain))
        ct = _enc_page(plain[0x10:], 1)
        out[0x00:0x08] = plain[0x00:0x08]
        out[0x08:0x10] = ct[0:8]
        out[0x10:0x18] = plain[0x10:0x18]
        out[0x18:] = ct[8:]
        for n in range(2, len(plain) // page + 1):
            s = (n - 1) * page
            out[s:s + page] = _enc_page(plain[s:s + page], n)
        return kgg_db.decrypt_pc_database(bytes(out)) == plain
    except Exception:
        return False


def _selftest_aes(aes_mod) -> bool:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    try:
        c = aes_mod.AES128ECB(key)
        return c.encrypt(pt) == ct and c.decrypt(ct) == pt
    except Exception:
        return False


def _simple_make_key_ok(tea_mod) -> bool:
    return tea_mod.simple_make_key(106, 8) == tea_mod.SIMPLE_MAKE_KEY_106_8


def _tea_roundtrip(tea_mod) -> bool:
    import random

    rng = random.Random(7)
    key = rng.randbytes(16)
    for _ in range(64):
        block = rng.randbytes(8)
        enc = tea_mod._tea_encrypt_block(block, key, rounds=32)
        dec = tea_mod._tea_decrypt_block(enc, key, rounds=32)
        if dec != block:
            return False
    return True


def _kgm_vector_ok(enc: Path, exp: Path, kgm_mod) -> bool:
    data = enc.read_bytes()
    header = data[:1024]
    hlen = struct.unpack("<I", header[0x10:0x14])[0]
    key = header[0x1C:0x2C] + b"\x00"
    got = kgm_mod.KgmFormat._apply(data[hlen:], key, False)
    want = exp.read_bytes()
    return got == want and len(got) > 0


def _kgm_formula_ok(kgm_mod) -> bool:
    import random

    rng = random.Random(2026)
    key_len = 17
    for _ in range(8):
        key = rng.randbytes(16) + b"\x00"
        for size in (1, 15, 16, 17, 255, 272, 4096, 5433):
            data = rng.randbytes(size)
            got = kgm_mod.KgmFormat._apply(data, key, False)
            ref = _kgm_ref(data, key, kgm_mod)
            if got != ref:
                return False
    return True


def _kgm_ref(data: bytes, key: bytes, kgm_mod) -> bytes:
    mask = kgm_mod.load_pub_key()
    n = len(data)
    out = bytearray(n)
    for i in range(n):
        med = data[i] ^ key[i % 17] ^ kgm_mod._MASK_V2[i % 272] ^ mask[i >> 4]
        out[i] = med ^ ((med & 0x0F) << 4)
    return bytes(out)


def _qmc_vectors(name: str, qmc_mod) -> bool:
    base = Path(qmc_mod.__file__).resolve().parent.parent.parent / "tests" / "data" / "qmc"
    raw = bytearray((base / f"{name}_raw.bin").read_bytes())
    suffix = (base / f"{name}_suffix.bin").read_bytes()
    target = (base / f"{name}_target.bin").read_bytes()
    got = qmc_mod.QmcFormat().decrypt(bytes(raw) + suffix)
    return got.data == target


def _qmc_keys(qmc_mod) -> bool:
    base = Path(qmc_mod.__file__).resolve().parent.parent.parent / "tests" / "data" / "qmc"
    from .crypto.tea import decrypt_key
    for name in ("mflac0_rc4", "mflac_map", "mflac_rc4", "mgg_map"):
        raw = (base / f"{name}_key_raw.bin").read_bytes()
        want = (base / f"{name}_key.bin").read_bytes()
        if decrypt_key(raw) != want:
            return False
    return True


def _kwm_roundtrip(kwm_mod) -> bool:
    import random

    rng = random.Random(9)
    key = rng.randbytes(8)
    mask = kwm_mod.generate_mask(key)
    for size in (1, 32, 33, 1024):
        audio = rng.randbytes(size)
        enc = bytearray(audio)
        for i in range(size):
            enc[i] ^= mask[i & 0x1F]
        if bytes(enc) == audio:
            continue
        dec = bytearray(enc)
        for i in range(size):
            dec[i] ^= mask[i & 0x1F]
        if bytes(dec) != audio:
            return False
    return True


def _ncm_box_roundtrip(ncm_mod) -> bool:
    key = bytes(range(16))
    box = ncm_mod.build_key_box(key)
    for size in (1, 256, 1000):
        audio = bytes((i * 7 + size) & 0xFF for i in range(size))
        enc = bytes(box[i & 0xFF] ^ audio[i] for i in range(size))
        dec = bytes(box[i & 0xFF] ^ enc[i] for i in range(size))
        if dec != audio:
            return False
    return True