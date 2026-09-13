# coding: utf-8
"""酷狗 KGG（新格式 v5）解密。

新格式 .kgg 头部在明文处记录 audioHash，密钥 ekey 不在文件中，需要从酷狗
客户端 KGMusicV3.db 中按 audioHash 查询（见 crypto/kgg_db / kgg_keys），或
使用导出的静态 kgg.key。流程：
  audioHash -> ekey -> TEA(base64/双层) 解出 QMC2 原始密钥
  -> len>300 用分段 RC4（Rc4Cipher），否则查表 MAP（MapCipher）-> 流式解密音频区
"""
from __future__ import annotations

import struct

from .. import kgg_keys
from ..crypto.tea import decrypt_key
from . import BaseFormat, DecodeResult, DecryptError
from .qmc import MapCipher, Rc4Cipher

_KGG_MAGIC = bytes.fromhex("7cd532eb86027f4ba8afa68e0fff9914")
_VPR_MAGIC = bytes.fromhex("0528bc96e9e45a4391aabdd07af53631")
_MIN_HEADER = 0x4C


def classify(header: bytes) -> str | None:
    if len(header) < 0x18:
        return None
    if header[:16] != _KGG_MAGIC and header[:16] != _VPR_MAGIC:
        return None
    version = struct.unpack("<I", header[0x14:0x18])[0]
    if version >= 4:
        return "kgg"
    return None


class KggFormat(BaseFormat):
    name = "kgg"
    suffixes = ("kgg", "vgm")

    def detect(self, header: bytes, extension: str) -> bool:
        return classify(header) == "kgg"

    def decrypt(self, data: bytes) -> DecodeResult:
        if classify(data[:1024]) != "kgg":
            raise DecryptError("KGG 魔数/版本不匹配")
        hlen = struct.unpack("<I", data[0x10:0x14])[0]
        if hlen < _MIN_HEADER or hlen >= len(data):
            raise DecryptError("KGG 头部长度异常")
        hash_len = struct.unpack("<I", data[0x44:0x48])[0]
        if hash_len <= 0 or hash_len > 256:
            raise DecryptError("KGG audioHash 长度异常")
        audio_hash = data[0x48:0x48 + hash_len].decode("utf-8", errors="replace")

        key_map = kgg_keys.get()
        if not key_map:
            try:
                key_map = kgg_keys.ensure_loaded()
            except kgg_keys.KggKeyError as e:
                raise DecryptError(f"KGG {audio_hash[:16]}... 密钥不可用: {e}") from e
        ekey = key_map.get(audio_hash)
        if not ekey:
            raise DecryptError(
                f"{audio_hash[:16]}... 未入库：请先在酷狗客户端播放该歌曲，"
                "再更新 KGMusicV3.db 或导入 kgg.key"
            )

        try:
            key = decrypt_key(ekey.encode("utf-8"))
        except (ValueError, TypeError) as e:
            raise DecryptError(f"KGG ekey 解密失败: {e}") from e
        if not key:
            raise DecryptError("KGG ekey 解密结果为空")

        cipher = Rc4Cipher(key) if len(key) > 300 else MapCipher(key)
        audio = bytearray(data[hlen:])
        cipher.decrypt(audio, 0)
        return DecodeResult(data=bytes(audio))