# coding: utf-8
"""密码原语单元测试。"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from music_unlock.crypto import aes, tea  # noqa: E402
from music_unlock.formats import kwm, ncm  # noqa: E402


class TestAES(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_fips197_c1(self):
        c = aes.AES128ECB(self.KEY)
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            c.encrypt(pt),
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
        )

    def test_fips197_decrypt(self):
        c = aes.AES128ECB(self.KEY)
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(
            c.decrypt(ct),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )

    def test_roundtrip(self):
        c = aes.AES128ECB(self.KEY)
        rng = random.Random(1)
        for _ in range(16):
            block = rng.randbytes(16)
            self.assertEqual(c.decrypt(c.encrypt(block)), block)

    def test_multiblock(self):
        key = bytes(range(16))
        data = bytes((i * 13 + 7) & 0xFF for i in range(80))
        c = aes.AES128ECB(key)
        self.assertEqual(c.decrypt(c.encrypt(data)), data)


class TestTea(unittest.TestCase):
    def test_simple_make_key(self):
        self.assertEqual(tea.simple_make_key(106, 8), tea.SIMPLE_MAKE_KEY_106_8)

    def test_block_roundtrip(self):
        rng = random.Random(2)
        for _ in range(32):
            key = rng.randbytes(16)
            block = rng.randbytes(8)
            enc = tea._tea_encrypt_block(block, key, 32)
            self.assertEqual(tea._tea_decrypt_block(enc, key, 32), block)

    def test_decrypt_key_official(self):
        base = Path(__file__).resolve().parent / "data" / "qmc"
        for name in ("mflac0_rc4", "mflac_map", "mflac_rc4", "mgg_map"):
            with self.subTest(name=name):
                raw = (base / f"{name}_key_raw.bin").read_bytes()
                want = (base / f"{name}_key.bin").read_bytes()
                self.assertEqual(tea.decrypt_key(raw), want)


class TestKwmMask(unittest.TestCase):
    def test_mask_involutive(self):
        rng = random.Random(3)
        for _ in range(4):
            key = rng.randbytes(8)
            mask = kwm.generate_mask(key)
            audio = rng.randbytes(500)
            enc = bytes(mask[i & 0x1F] ^ audio[i] for i in range(len(audio)))
            dec = bytes(mask[i & 0x1F] ^ enc[i] for i in range(len(enc)))
            self.assertEqual(dec, audio)

    def test_mask_repeat_cycle(self):
        mask = kwm.generate_mask(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(
            bytes(mask[i & 0x1F] for i in range(96)),
            mask * 3,
        )


class TestNcmBox(unittest.TestCase):
    def test_box_involutive(self):
        for key_len in (8, 16, 32):
            key = bytes(range(key_len))
            box = ncm.build_key_box(key)
            self.assertEqual(len(box), 256)
            for size in (1, 255, 300):
                audio = bytes((i * 11 + size) & 0xFF for i in range(size))
                enc = bytes(box[i & 0xFF] ^ audio[i] for i in range(size))
                dec = bytes(box[i & 0xFF] ^ enc[i] for i in range(size))
                self.assertEqual(dec, audio)


if __name__ == "__main__":
    unittest.main(verbosity=2)