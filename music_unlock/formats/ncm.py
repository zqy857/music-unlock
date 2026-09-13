# coding: utf-8
"""网易云 NCM 解密。"""
from __future__ import annotations

import json

from ..crypto.aes import AES128ECB, pkcs7_unpad
from . import BaseFormat, DecodeResult, DecryptError

_MAGIC = bytes.fromhex("4354454e4644414d")  # CTENFDAM
_KEY_CORE = bytes.fromhex("687a4852416d736f356b496e62617857")  # hzHRAmso5kInbaxW
_KEY_META = bytes.fromhex("2331346c6a6b5f215c5d2630553c2728")  # #314lJk_!\]&0U<'(
_XOR_KEY = 0x64
_XOR_META = 0x63


def build_key_box(key: bytes) -> bytes:
    box = list(range(256))
    key_len = len(key)
    j = 0
    for i in range(256):
        j = (box[i] + j + key[i % key_len]) & 0xFF
        box[i], box[j] = box[j], box[i]
    box2 = [0] * 256
    for i in range(256):
        _i = (i + 1) & 0xFF
        si = box[_i]
        sj = box[(_i + si) & 0xFF]
        box2[i] = box[(si + sj) & 0xFF]
    return bytes(box2)


def _fmt_title(meta: dict) -> tuple:
    fmt = meta.get("format") or ""
    title = meta.get("musicName") or "%s" % (meta.get("programName") or "")
    album = meta.get("album") or meta.get("brand") or meta.get("radioName") or ""
    artists = []
    for item in meta.get("artist") or []:
        if isinstance(item, list):
            for sub in item:
                if isinstance(sub, str):
                    artists.append(sub)
    main = meta.get("mainMusic") or {}
    if main:
        artists = artists or [str(main.get("musicName", ""))]
        title = title or main.get("musicName", "")
        album = album or main.get("album", "")
        if not fmt:
            fmt = main.get("format", "")
    dj = meta.get("djName") or ""
    artist = dj if dj else " / ".join(a for a in artists if a)
    return fmt, title, artist, album


class NcmFormat(BaseFormat):
    name = "ncm"
    suffixes = ("ncm",)

    def detect(self, header: bytes, extension: str) -> bool:
        return header[:8] == _MAGIC

    def decrypt(self, data: bytes) -> DecodeResult:
        n = len(data)
        if data[:8] != _MAGIC:
            raise DecryptError("NCM 魔数不匹配")
        offset = 8 + 2

        key_block_end = offset + 4
        if key_block_end > n:
            raise DecryptError("NCM 密钥长度位置越界")
        key_len = int.from_bytes(data[offset:key_block_end], "little")
        if key_block_end + key_len > n:
            raise DecryptError("NCM 密钥块越界")
        key_raw = bytes(b ^ _XOR_KEY for b in data[key_block_end:key_block_end + key_len])
        if not key_raw:
            raise DecryptError("NCM 密钥块为空")
        try:
            cur = pkcs7_unpad(AES128ECB(_KEY_CORE).decrypt(key_raw))
        except Exception as e:
            raise DecryptError(f"NCM 密钥解密失败: {e}")
        key = cur[17:]

        offset_meta = key_block_end + key_len
        meta_len = int.from_bytes(data[offset_meta:offset_meta + 4], "little")
        offset_cover = offset_meta + 4 + meta_len

        ext = ""
        title = artist = album = ""
        if meta_len > 22 and offset_cover <= n:
            begin = offset_meta + 4 + 22
            end = offset_meta + 4 + meta_len
            meta_block = bytes(b ^ _XOR_META for b in data[begin:end])
            try:
                meta_plain = pkcs7_unpad(AES128ECB(_KEY_META).decrypt(meta_block))
            except Exception:
                meta_plain = b""
            sep = meta_plain.find(b":")
            if sep != -1:
                meta_type = meta_plain[:sep]
                meta_raw = meta_plain[sep + 1:]
                if meta_type == b"music" or meta_type == b"dj":
                    try:
                        meta = json.loads(meta_raw.decode("utf-8"))
                        ext, title, artist, album = _fmt_title(meta)
                    except Exception:
                        pass

        cover = None
        audio_offset = offset_cover
        if offset_cover + 13 <= n:
            cover_len_start = offset_cover + 9
            cover_len = int.from_bytes(data[cover_len_start:cover_len_start + 4], "little")
            audio_offset = cover_len_start + 4 + cover_len
            if cover_len and audio_offset <= n + 1:
                cover_start = cover_len_start + 4
                if cover_start + cover_len <= n:
                    cover = data[cover_start:cover_start + cover_len]
            else:
                audio_offset = offset_cover
        if audio_offset > n:
            raise DecryptError("NCM 音频偏移越界")

        box = build_key_box(key)
        audio = bytearray(n - audio_offset)
        for i in range(len(audio)):
            audio[i] = box[i & 0xFF] ^ data[audio_offset + i]
        return DecodeResult(data=bytes(audio), ext=("." + ext if ext else None),
                            title=title, artist=artist, album=album, cover=cover)