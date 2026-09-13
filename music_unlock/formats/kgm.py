# coding: utf-8
"""酷狗 KGM / KGMA / VPR 解密。"""
from __future__ import annotations

import lzma
import struct
from pathlib import Path

from . import BaseFormat, DecodeResult, DecryptError

_MAGIC_NEW = bytes.fromhex("7cd532eb86027f4ba8afa68e0fff9914000400000300000001000000")
_MAGIC_KGM = bytes.fromhex("7cd532eb86027f4ba8afa68e0fff9914")
_MAGIC_VPR = bytes.fromhex("0528bc96e9e45a4391aabdd07af53631")

_MASK_V2 = bytes.fromhex(
    "b8d53db2e9af788c8333715176a0cd372f3e358da9be98b7e78c22ce5a61df68"
    "6989fea5b6dea977fcc8bdbde56d3e5a36ef694ebee1e9661cf3d902b6f2129b"
    "44d06fb93589b6466d73820669c1edd785c230dfa262be792d62623d0d7ebe48"
    "892302a0e4d57551320253fd163a213b160fc3b2bbb3e2ba3a3d13ecf6014584"
    "a5700f93490c64cd31d5cc4c07019e001a2390bf881e3baba63ec47347107e3b"
    "5ebce30084ff09d4e0890f5b58704ffb65d85c531bd3c8c6bfef98b0504f0fea"
    "e583588c282c8467cdd09e47db2750caf46363e8977f1b4b0cc2c1214ccc58f5"
    "9452a3f3d3e068f40023f35e0a7b93ddab12b213e884d7a79f0f324c551d0436"
    "52dc03f3f94e42e93d61ef7cb6b39350"
)
_VPR_DIFF = bytes.fromhex("25dfe8a6751e750e2f80f32db8b6e31100")
_G = bytes((x ^ ((x & 0x0F) << 4)) for x in range(256))

_KEY_PATH = Path(__file__).resolve().parent.parent / "assets" / "kugou_key.xz"
_pub_key = None


def load_pub_key() -> bytes:
    global _pub_key
    if _pub_key is None:
        try:
            with lzma.open(_KEY_PATH, "rb") as f:
                _pub_key = f.read()
        except FileNotFoundError:
            raise DecryptError(f"缺少密钥文件: {_KEY_PATH}")
    return _pub_key


def classify(header: bytes):
    if header[:28] == _MAGIC_NEW:
        return "kgma"
    if header[:16] == _MAGIC_KGM or header[:16] == _MAGIC_VPR:
        if len(header) >= 0x18:
            version = struct.unpack("<I", header[0x14:0x18])[0]
            if version >= 4:
                return "kgg"
        return "kgm" if header[:16] == _MAGIC_KGM else "vpr"
    return None


class KgmFormat(BaseFormat):
    name = "kgm"
    suffixes = ("kgm", "kgma", "vpr", "kgg", "vgm")

    def detect(self, header: bytes, extension: str) -> bool:
        return classify(header) not in (None, "kgg")

    def decrypt(self, data: bytes) -> DecodeResult:
        kind = classify(data[:1024])
        if kind is None:
            raise DecryptError("KGM 魔数不匹配")
        hlen = struct.unpack("<I", data[0x10:0x14])[0]
        if hlen < 0x2C or hlen >= len(data):
            raise DecryptError("头部长度异常")
        key = data[0x1C:0x2C] + b"\x00"
        audio = self._apply(data[hlen:], key, kind == "vpr")
        return DecodeResult(data=audio)

    @staticmethod
    def _apply(chunk, key, is_vpr: bool) -> bytes:
        pub = load_pub_key()
        n = len(chunk)
        data = chunk if isinstance(chunk, bytearray) else bytearray(chunk)
        kl = len(key)
        pk = bytes(key[i % kl] ^ _MASK_V2[i % 272] for i in range(272))
        ks_int = [
            int.from_bytes(pk[16 * r:16 * r + 16], "big")
            for r in range(17)
        ]
        rep16 = [int.from_bytes(bytes([v]) * 16, "big") for v in range(256)]
        nblk = (n + 15) // 16
        for r in range(nblk):
            start = r * 16
            step = min(16, n - start)
            xors = ks_int[r % 17] ^ rep16[pub[r]]
            if step == 16:
                data[start:start + 16] = (
                    int.from_bytes(data[start:start + 16], "big") ^ xors
                ).to_bytes(16, "big").translate(_G)
            else:
                out = (int.from_bytes(data[start:start + step], "big") ^ (xors >> (128 - 8 * step))).to_bytes(step, "big")
                data[start:start + step] = out.translate(_G)
        if is_vpr:
            vd = _VPR_DIFF
            for i in range(n):
                data[i] ^= vd[i % 17]
        return data if isinstance(chunk, bytearray) else bytes(data)