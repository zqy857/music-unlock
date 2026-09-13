# coding: utf-8
"""酷狗 KGMusicV3.db（SQLCipher）解密与 ekey 映射提取。

忠实移植 unlock-music.dev/cli/algo/kgm/pc_kugou_db（Go）与社区 Python
实现对等逻辑：
  - 每页 0x400 字节，AES-128-CBC 按页独立解密（无 HMAC 模式）
  - 页 AES 密钥 = MD5(master(16B) + pageNoLE + "sAlT"LE(0x546C4173))
  - 页 IV     = MD5(由 seed = pageNo+1 经 LCG 递推出的 4 个 uint32 LE)
  - 页 1 有 header 完整性校验（用于确认 master key 正确）
解密后的库为标准 SQLite，从 ShareFileItems 表提取
EncryptionKeyId(audioHash) -> EncryptionKey(ekey) 映射，可导出为 kgg.key。
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import tempfile
import warnings

from .aes import AES128CBC

DB_PAGE_SIZE = 0x400
SQLITE_HEADER = b"SQLite format 3\x00"

DEFAULT_MASTER_KEY = bytes.fromhex("1d613145b247bf7f3d189672144fe4bf")

_QUERY_EKEY = (
    "SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems "
    "WHERE EncryptionKeyId IS NOT NULL AND EncryptionKeyId != '' "
    "AND EncryptionKey IS NOT NULL AND EncryptionKey != ''"
)


def _master_key_candidates() -> list[bytes]:
    """返回待尝试的 master key：环境变量 KGG_DB_MASTER_KEY（hex）优先。"""
    env = os.environ.get("KGG_DB_MASTER_KEY", "").strip()
    if env:
        try:
            raw = bytes.fromhex(env)
            if len(raw) == 16:
                return [raw, DEFAULT_MASTER_KEY]
        except ValueError:
            pass
    return [DEFAULT_MASTER_KEY]


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def next_page_iv(seed: int) -> int:
    left = _u32(seed * 0x9EF4)
    right = _u32((seed // 0xCE26) * 0x7FFFFF07)
    value = _u32(left - right)
    if (value & 0x80000000) == 0:
        return _u32(value)
    return _u32(value + 0x7FFFFF07)


def derive_page_aes_key(seed: int, master: bytes) -> bytes:
    buf = master + struct.pack("<I", seed) + struct.pack("<I", 0x546C4173)
    return hashlib.md5(buf).digest()


def derive_page_aes_iv(seed: int) -> bytes:
    iv = bytearray(0x10)
    seed = _u32(seed + 1)
    for i in range(0, 0x10, 4):
        seed = next_page_iv(seed)
        struct.pack_into("<I", iv, i, seed)
    return hashlib.md5(bytes(iv)).digest()


def decrypt_page(buffer: bytes, page_number: int, master: bytes) -> bytes:
    key = derive_page_aes_key(page_number, master)
    iv = derive_page_aes_iv(page_number)
    return AES128CBC(key, iv).decrypt(buffer)


def validate_page1_header(header: bytes) -> bool:
    if len(header) < 0x18:
        return False
    o10 = struct.unpack_from("<I", header, 0x10)[0]
    o14 = struct.unpack_from("<I", header, 0x14)[0]
    v6 = ((o10 & 0xFF) << 8) | ((o10 & 0xFF00) << 16)
    return (o14 == 0x20204000
            and (v6 - 0x200) <= 0xFE00
            and (v6 & (v6 - 1)) == 0)


def decrypt_page1(page: bytes, master: bytes) -> bytes:
    if not validate_page1_header(page):
        raise ValueError("kgg db: invalid page 1 header")
    buf = bytearray(page)
    expected_hdr = bytes(buf[0x10:0x18])
    # swap trick：把头部 [0x08:0x10] 挪到 [0x10:0x18] 再解密，解后校验
    buf[0x10:0x18] = buf[0x08:0x10]
    buf[0x10:] = decrypt_page(bytes(buf[0x10:]), 1, master)
    if bytes(buf[0x10:0x18]) != expected_hdr:
        raise ValueError("kgg db: page 1 integrity check failed")
    return bytes(buf)


def decrypt_pc_database(buffer: bytes) -> bytes:
    """把整个密钥库解密成可直接由 sqlite3 打开的 SQLite 字节。"""
    if buffer[:len(SQLITE_HEADER)] == SQLITE_HEADER:
        return buffer  # 未加密
    if len(buffer) == 0 or len(buffer) % DB_PAGE_SIZE != 0:
        raise ValueError(f"kgg db: invalid database size: {len(buffer)}")

    last_err = None
    for master in _master_key_candidates():
        try:
            first = decrypt_page1(buffer[:DB_PAGE_SIZE], master)
            chosen = master
            break
        except ValueError as e:
            last_err = e
            continue
    else:
        raise ValueError(f"kgg db: page 1 decrypt failed for all master keys: {last_err}")

    buf = bytearray(buffer)
    buf[0:len(SQLITE_HEADER)] = SQLITE_HEADER
    buf[len(SQLITE_HEADER):DB_PAGE_SIZE] = first[0x10:]
    for page_no in range(2, len(buf) // DB_PAGE_SIZE + 1):
        start = (page_no - 1) * DB_PAGE_SIZE
        buf[start:start + DB_PAGE_SIZE] = decrypt_page(
            buffer[start:start + DB_PAGE_SIZE], page_no, chosen)
    return bytes(buf)


def _query_key_map(decrypted: bytes) -> dict[str, str]:
    key_map: dict[str, str] = {}

    def collect(conn: sqlite3.Connection):
        for row in conn.execute(_QUERY_EKEY):
            key_map[str(row[0])] = str(row[1])

    try:
        # 优先内存库（不落盘明文）；3.13+ 该 API 已过时，失败则回退临时文件
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            conn = sqlite3.connect(":memory:")
            conn.deserialize(decrypted)
        try:
            collect(conn)
        finally:
            conn.close()
        return key_map
    except (AttributeError, TypeError, sqlite3.Error):

        fd, tmp = tempfile.mkstemp(suffix=".db")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(decrypted)
            conn = sqlite3.connect(tmp)
            try:
                collect(conn)
            finally:
                conn.close()
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return key_map


def load_key_map(db_path: str) -> dict[str, str]:
    """读取 KGMusicV3.db，返回 {audioHash: ekey} 映射。"""
    with open(db_path, "rb") as f:
        raw = f.read()
    decrypted = decrypt_pc_database(raw)
    return _query_key_map(decrypted)


def export_key_file(key_map: dict[str, str], path: str) -> None:
    """导出为 kgg.key（格式: <id>$<ekey>\\n），与社区工具兼容且不受 db 时效影响。"""
    with open(path, "w", encoding="utf-8") as f:
        for key_id, ekey in key_map.items():
            f.write(f"{key_id}${ekey}\n")


def load_key_file(path: str) -> dict[str, str]:
    """解析 kgg.key（格式: <id>$<ekey>\\n）。"""
    key_map: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "$" in line:
                key_id, _, ekey = line.partition("$")
                if key_id and ekey:
                    key_map[key_id] = ekey
    return key_map