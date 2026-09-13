# coding: utf-8
"""格式解密单元测试（含 unlock-music 官方向量）。"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from music_unlock.core import decrypt_bytes, decrypt_file  # noqa: E402
from music_unlock.formats import kgm, kwm, ncm, qmc  # noqa: E402
from music_unlock.sniff import sniff_audio  # noqa: E402

_BASE = Path(__file__).resolve().parent
_QMC = _BASE / "data" / "qmc"


def _kgm_ref(data: bytes, key: bytes) -> bytes:
    mask = kgm.load_pub_key()
    out = bytearray(len(data))
    for i in range(len(data)):
        med = data[i] ^ key[i % 17] ^ kgm._MASK_V2[i % 272] ^ mask[i >> 4]
        out[i] = med ^ ((med & 0x0F) << 4)
    return bytes(out)


class TestKgm(unittest.TestCase):
    def test_official_vector(self):
        enc = _BASE / "test_kugou_kgm.dat"
        exp = _BASE / "test_kugou_kgm_right.dat"
        if not (enc.exists() and exp.exists()):
            self.skipTest("tampering vectors missing")
        data = enc.read_bytes()
        header = data[:1024]
        hlen = struct.unpack("<I", header[0x10:0x14])[0]
        key = header[0x1C:0x2C] + b"\x00"
        got = kgm.KgmFormat._apply(data[hlen:], key, False)
        self.assertEqual(got, exp.read_bytes())

    def test_across_chunk_sizes(self):
        rng = stable_rng()
        for size in (1, 15, 16, 17, 255, 272, 4096, 5433, 1 << 20, (1 << 20) + 17):
            key = rng.randbytes(16) + b"\x00"
            data = rng.randbytes(size)
            got = kgm.KgmFormat._apply(data, key, False)
            self.assertEqual(got, _kgm_ref(data, key))

    def test_detect(self):
        header = bytes.fromhex("7cd532eb86027f4ba8afa68e0fff9914000400000300000001000000") + b"\x00" * 996
        self.assertTrue(kgm.KgmFormat().detect(header, ".mp3"))


def stable_rng():
    return random_mod()


class TestKwm(unittest.TestCase):
    def test_magic(self):
        fm = kwm.KwmFormat()
        self.assertTrue(fm.detect(bytes.fromhex("7965656c696f6e2d6b75776f2d746d65") + b"\x00" * 16, ".kwm"))
        self.assertFalse(fm.detect(b"\x00" * 32, ".kwm"))


class TestQmc(unittest.TestCase):
    def _run(self, name):
        raw = bytearray((_QMC / f"{name}_raw.bin").read_bytes())
        suffix = (_QMC / f"{name}_suffix.bin").read_bytes()
        target = (_QMC / f"{name}_target.bin").read_bytes()
        return qmc.QmcFormat().decrypt(bytes(raw) + suffix), target

    def test_map(self):
        got, target = self._run("mflac_map")
        self.assertEqual(got.data, target)

    def test_map_ogg(self):
        got, target = self._run("mgg_map")
        self.assertEqual(got.data, target)

    def test_static(self):
        got, target = self._run("qmc0_static")
        self.assertEqual(got.data, target)

    def test_rc4(self):
        got, target = self._run("mflac_rc4")
        self.assertEqual(got.data, target)

    def test_rc4_mflac0(self):
        got, target = self._run("mflac0_rc4")
        self.assertEqual(got.data, target)

    def test_detect_via_ext(self):
        self.assertTrue(qmc.QmcFormat().detect(b"\x00" * 32, ".mflac"))
        self.assertTrue(qmc.QmcFormat().detect(b"\x00" * 32, ".qmcflac"))


class TestNcm(unittest.TestCase):
    def test_detect_magic(self):
        fm = ncm.NcmFormat()
        self.assertTrue(fm.detect(b"CTENFDAM", ".ncm"))
        self.assertFalse(fm.detect(b"notncm!!", ".ncm"))

    def test_sniff(self):
        for magic, ext in ((b"ID3", ".mp3"), (b"fLaC", ".flac"), (b"OggS", ".ogg"),
                           (b"\xff\xfb\x90\x44" + b"\x00" * 28, ".mp3"), (b"", None)):
            self.assertEqual(sniff_audio(magic), ext)


class TestPipeline(unittest.TestCase):
    def test_kgm_pipeline(self):
        enc = _BASE / "test_kugou_kgm.dat"
        if not enc.exists():
            self.skipTest("vector missing")
        with tempfile.TemporaryDirectory() as tmp:
            msg = decrypt_file(enc, Path(tmp), force=True, delete=False, verbose=False)
            out = sorted(Path(tmp).iterdir())
            self.assertEqual(len(out), 1)
            self.assertIn("->", msg)
            self.assertNotEqual(enc.read_bytes(), out[0].read_bytes())

    def test_bad_data(self):
        from music_unlock.formats import DecryptError
        with self.assertRaises(DecryptError):
            decrypt_bytes(b"\x00" * 2000, ".mp3")


def random_mod():
    import random
    return random.Random(2026)


if __name__ == "__main__":
    unittest.main(verbosity=2)