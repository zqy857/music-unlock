# coding: utf-8
"""kgg v5 解密单元测试。

覆盖：
  - 官方（unlock-music v0.2.12）页派生向量（page 0 key/iv）
  - KGMusicV3.db 加密库构造 -> 解密往返（含页1 header 校验路径）
  - load_key_map / kgg.key 导出导入
  - KggFormat 检测与 QMC2（MAP/RC4）音区加密往返
  - 真实 花海 kgg 样本的 detect / 缺密钥报错
"""
from __future__ import annotations

import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from music_unlock import kgg_keys  # noqa: E402
from music_unlock.crypto import kgg_db  # noqa: E402
from music_unlock.crypto.aes import AES128CBC  # noqa: E402
from music_unlock.crypto.tea import decrypt_key  # noqa: E402
from music_unlock.formats import DecryptError, kgg, kgm, qmc  # noqa: E402
from music_unlock.formats.kgg import KggFormat, _KGG_MAGIC  # noqa: E402

_BASE = Path(__file__).resolve().parent
_QMC = _BASE / "data" / "qmc"
_MASTER = kgg_db.DEFAULT_MASTER_KEY
_PAGE = kgg_db.DB_PAGE_SIZE

ROWS = [("267eb9d6d754e803ffffffffffffffff", "ec5f31...fake ekey...AAAA"),
        ("deadbeef000000000000000000000000", "ubL0FUGUQn0PVIbM4T0PVA==")]


def _build_sqlite_db(rows: list[tuple[str, str]]) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "plain.db"
        conn = sqlite3.connect(str(p))
        conn.execute(
            "CREATE TABLE ShareFileItems (EncryptionKeyId TEXT, EncryptionKey TEXT)")
        conn.executemany("INSERT INTO ShareFileItems VALUES (?, ?)", rows)
        conn.commit()
        conn.close()
        return p.read_bytes()


def _enc_page(plain: bytes, page_no: int, master: bytes = _MASTER) -> bytes:
    key = kgg_db.derive_page_aes_key(page_no, master)
    iv = kgg_db.derive_page_aes_iv(page_no)
    return AES128CBC(key, iv).encrypt(plain)


def _enc_page1(plain_page: bytes, master: bytes = _MASTER) -> bytes:
    key = kgg_db.derive_page_aes_key(1, master)
    iv = kgg_db.derive_page_aes_iv(1)
    ct = AES128CBC(key, iv).encrypt(plain_page[0x10:])
    e = bytearray(_PAGE)
    e[0x00:0x08] = plain_page[0x00:0x08]
    e[0x08:0x10] = ct[0:8]                  # 解密时被复制到 [0x10:0x18]，补齐首个密文块
    e[0x10:0x18] = bytes(plain_page[0x10:0x18])  # 校验期望 == 解密后内容
    e[0x18:] = ct[8:]
    return bytes(e)


def _enc_db(plain_page1_plain: bytes, rest: bytes, master: bytes = _MASTER) -> bytes:
    plain = bytearray(plain_page1_plain + rest)
    assert len(plain) % _PAGE == 0
    out = bytearray(len(plain))
    out[0:_PAGE] = _enc_page1(bytes(plain[:_PAGE]), master)
    for n in range(2, len(plain) // _PAGE + 1):
        s = (n - 1) * _PAGE
        out[s:s + _PAGE] = _enc_page(plain[s:s + _PAGE], n, master)
    return bytes(out)


def _decryptable_db(db_bytes: bytes) -> bytes:
    """把 sqlite 库改成解密后形态（[0:16] 魔数、[0x14:0x18]=0x20204000）。"""
    out = bytearray(db_bytes)
    out[0:16] = kgg_db.SQLITE_HEADER
    out[0x14:0x18] = struct.pack("<I", 0x20204000)
    return bytes(out)


def _mk_kgg(audio_plain: bytes, hash_str: str, raw_ekey: str) -> bytes:
    hlen = 0x200
    header = bytearray(hlen)
    header[0:16] = _KGG_MAGIC
    struct.pack_into("<I", header, 0x10, hlen)
    struct.pack_into("<I", header, 0x14, 5)
    struct.pack_into("<I", header, 0x18, 0)
    hb = hash_str.encode("utf-8")
    struct.pack_into("<I", header, 0x44, len(hb))
    header[0x48:0x48 + len(hb)] = hb
    key = decrypt_key(raw_ekey.encode("utf-8"))
    cipher = qmc.Rc4Cipher(key) if len(key) > 300 else qmc.MapCipher(key)
    enc = bytearray(audio_plain)
    cipher.decrypt(enc, 0)
    return bytes(header) + bytes(enc)


class TestDbPrimitives(unittest.TestCase):
    def test_official_page_key_vector(self):
        self.assertEqual(
            kgg_db.derive_page_aes_key(0, _MASTER).hex(),
            "1962c05fa2ebbe2428ff522b9e03ead4")

    def test_official_page_iv_vector(self):
        self.assertEqual(
            kgg_db.derive_page_aes_iv(0).hex(),
            "055a673593892ddf3ab3b3c621c34802")

    def test_plaintext_passthrough(self):
        db = _build_sqlite_db(ROWS)
        self.assertEqual(kgg_db.decrypt_pc_database(db), db)

    def test_bad_sizes(self):
        for bad in (b"", b"x" * 3, b"x" * (_PAGE + 1)):
            with self.assertRaises(ValueError):
                kgg_db.decrypt_pc_database(bad)


class TestDbRoundtrip(unittest.TestCase):
    def _enc(self, db_bytes: bytes, master: bytes = _MASTER) -> bytes:
        patched = _decryptable_db(db_bytes)
        return _enc_db(patched[:_PAGE], patched[_PAGE:], master)

    def test_crypto_roundtrip(self):
        plain = _build_sqlite_db(ROWS)
        enc = self._enc(plain)
        self.assertNotEqual(enc, plain)
        got = kgg_db.decrypt_pc_database(enc)
        self.assertEqual(got, _decryptable_db(plain))

    def test_wrong_master_rejected(self):
        plain = _build_sqlite_db(ROWS)
        enc = self._enc(plain, master=bytes(16))
        with self.assertRaises(ValueError):
            kgg_db.decrypt_pc_database(enc)

    def test_load_key_map_end_to_end(self):
        plain = _build_sqlite_db(ROWS)
        expected = dict(ROWS)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "KGMusicV3.db"
            p.write_bytes(self._enc(plain))
            self.assertEqual(kgg_db.load_key_map(str(p)), expected)

    def test_decrypted_db_parseable(self):
        plain = _build_sqlite_db(ROWS)
        dec = kgg_db.decrypt_pc_database(self._enc(plain))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "out.db"
            p.write_bytes(dec)
            conn = sqlite3.connect(str(p))
            got = dict(conn.execute(
                "SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems"))
            conn.close()
            self.assertEqual(got, dict(ROWS))


class TestKeyFile(unittest.TestCase):
    def test_export_import(self):
        m = {"a": "AA==", "b": "BBBB"}
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "kgg.key"
            kgg_db.export_key_file(m, str(p))
            self.assertEqual(kgg_db.load_key_file(str(p)), m)

    def test_load_key_file_ignores_garbage(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "kgg.key"
            p.write_text("a$AA==\n\nno-dollar-line\nc$\n", encoding="utf-8")
            self.assertEqual(kgg_db.load_key_file(str(p)), {"a": "AA=="})


class TestKggFormat(unittest.TestCase):
    _saved: dict | None = None

    def setUp(self):
        self._saved = kgg_keys.get()
        kgg_keys.set_key_map({})

    def tearDown(self):
        kgg_keys.set_key_map(self._saved if self._saved is not None else {})

    def _valid_ekey(self) -> str | None:
        p = _QMC / "mflac_map_key_raw.bin"
        if not p.exists():
            return None
        return p.read_text(encoding="utf-8")

    def test_map_roundtrip(self):
        raw_ekey = self._valid_ekey()
        if raw_ekey is None:
            self.skipTest("qmc vectors missing")
        audio = (b"fLaC\x00\x01\x02" * 300) + b"\x0a\x0d" * 100
        blob = _mk_kgg(audio, "hash_map", raw_ekey)
        self.assertTrue(KggFormat().detect(blob[:1024], ".kgg"))
        kgg_keys.set_key_map({"hash_map": raw_ekey})
        got = KggFormat().decrypt(blob)
        self.assertEqual(got.data, audio)

    def test_rc4_roundtrip(self):
        p = _QMC / "mflac_rc4_key_raw.bin"
        if not p.exists():
            self.skipTest("qmc vectors missing")
        raw_ekey = p.read_text(encoding="utf-8")
        audio = bytes(range(256)) * 40  # 10240B，跨 RC4 分段
        blob = _mk_kgg(audio, "hash_rc4", raw_ekey)
        self.assertTrue(KggFormat().detect(blob[:1024], ".kgg"))
        kgg_keys.set_key_map({"hash_rc4": raw_ekey})
        got = KggFormat().decrypt(blob)
        self.assertEqual(got.data, audio)

    def test_missing_hash_in_map(self):
        raw_ekey = self._valid_ekey()
        if raw_ekey is None:
            self.skipTest("qmc vectors missing")
        blob = _mk_kgg(b"x" * 512, "hash_unknown", raw_ekey)
        with self.assertRaises(DecryptError):
            KggFormat().decrypt(blob)

    def test_no_key_source(self):
        raw_ekey = self._valid_ekey()
        if raw_ekey is None:
            self.skipTest("qmc vectors missing")
        blob = _mk_kgg(b"x" * 512, "hash_none", raw_ekey)
        with mock.patch.object(kgg_keys, "_auto_candidates", return_value=[]):
            with self.assertRaises(DecryptError):
                KggFormat().decrypt(blob)

    def test_classify_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "v3.kgg"
            p.write_bytes(b"\x00" * 1024)
            # 构造 v3 头（走 KGM）
            hdr = bytearray(1024)
            hdr[0:16] = _KGG_MAGIC
            struct.pack_into("<I", hdr, 0x14, 3)
            self.assertEqual(kgg.classify(bytes(hdr)), None)
            self.assertEqual(kgm.classify(bytes(hdr)), "kgm")
            # v5 头（走 KGG）
            struct.pack_into("<I", hdr, 0x14, 5)
            self.assertEqual(kgg.classify(bytes(hdr)), "kgg")
            self.assertEqual(kgm.classify(bytes(hdr)), "kgg")

    def test_real_snake_head_detect(self):
        p = _BASE.parent / "周杰伦 - 花海_SQ.kgg.flac"
        if not p.exists():
            self.skipTest("real sample missing")
        hdr = p.read_bytes()[:1024]
        self.assertEqual(kgg.classify(hdr), "kgg")
        self.assertTrue(KggFormat().detect(hdr, ".kgg"))
        self.assertFalse(kgm.KgmFormat().detect(hdr, ".kgg"))


if __name__ == "__main__":
    unittest.main(verbosity=2)