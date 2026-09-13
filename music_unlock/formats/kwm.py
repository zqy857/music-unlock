# coding: utf-8
"""酷我 KWM 解密。"""
from __future__ import annotations

from . import BaseFormat, DecodeResult, DecryptError

_MAGIC = bytes.fromhex("7965656c696f6e2d6b75776f2d746d65")
_KEY_PREDEFINED = "MoOtOiTvINGwd2E6n0E1i7L5t2IoOoNk"


def _pad_or_truncate(raw: str, length: int) -> str:
    n = len(raw)
    if n == 0:
        return "\x00" * length
    if n > length:
        return raw[:length]
    out = []
    for i in range(length):
        out.append(raw[i % n])
    return "".join(out)


def generate_mask(key: bytes) -> bytes:
    key_int = int.from_bytes(key[:8], "little")
    key_str = str(key_int)
    key_str_trim = _pad_or_truncate(key_str, 32)
    return bytes(ord(a) ^ ord(b) for a, b in zip(_KEY_PREDEFINED, key_str_trim))


class KwmFormat(BaseFormat):
    name = "kwm"
    suffixes = ("kwm",)

    def detect(self, header: bytes, extension: str) -> bool:
        return header[:16] == _MAGIC

    def decrypt(self, data: bytes) -> DecodeResult:
        if len(data) < 1024:
            raise DecryptError("KWM 文件过小")
        if data[:16] != _MAGIC:
            raise DecryptError("KWM 魔数不匹配")
        mask = generate_mask(data[0x18:0x20])
        audio = bytearray(data[1024:])
        n = len(audio)
        for i in range(n):
            audio[i] ^= mask[i & 0x1F]
        return DecodeResult(data=bytes(audio))