# coding: utf-8
"""QQ音乐 QMC 解密（map / static / rc4 三种流密码 + TEA 密钥）。

移植自 unlock-music/cli v0.1.1 algo/qmc。
"""
from __future__ import annotations

from ..crypto.tea import decrypt_key
from . import BaseFormat, DecodeResult, DecryptError

_RC4_SEGMENT_SIZE = 5120
_RC4_FIRST_SEGMENT_SIZE = 128

_STATIC_BOX = bytes.fromhex(
    "77483273def2c0c895ec30b251c3e1a09ee69dcffa7f14d1"
    "ceb8dcc34a6793d628c29170ca8da2a4f00861907e6fa2e0"
    "ebae3eb667c792f491b5f66c5e8440f7f31b027fd5ab4189"
    "28f425cc5211ad4368a6418b84b5ff2c924a26d8476a7c95"
    "61cce6cbbb3f47588975c375a1d9afcc087317dcaa9aa216"
    "41d8a206c68bfc66349fcf1823a00a74e72b277092e9af37"
    "e68ca7bc62659cc208c988b3f343ac742c0fd4afa1c30164"
    "954e489ff43578957a39d66aa06d40e84fa8ef111df31b3f"
    "3f07dd6f5b193019fbef0e37f00ecd1649fe5347131abda4"
    "f14019600eed6809065f4dcf3d1afe2077e4d9daf9a42b76"
    "1c71db00bcfd0c6ca547f7f600794a11"
)

_QMC_EXTS = set("qmc0 qmc3 qmc2 qmc4 qmc6 qmc8 qmcflac qmcogg tkm "
                "bkcmp3 bkcm4a bkcflac bkcwav bkcape bkcogg bkcwma "
                "666c6163 6d7033 6f6767 6d3461 776176 "
                "mgg mgg1 mggl mflac mflac0".split())


def _trunc_divmod(a: int, b: int) -> int:
    r = a % b
    return r if a >= 0 or r == 0 else r - b


class MapCipher:
    def __init__(self, key: bytes):
        if not key:
            raise DecryptError("qmc/cipher_map: invalid key size")
        self.key = key
        self.size = len(key)

    @staticmethod
    def _rotate(value: int, bits: int) -> int:
        rotate = (bits + 4) % 8
        left = value << rotate
        right = value >> rotate
        return (left | right) & 0xFF

    def get_mask(self, offset: int) -> int:
        if offset > 0x7FFF:
            offset %= 0x7FFF
        idx = (offset * offset + 71214) % self.size
        return self._rotate(self.key[idx], idx & 0x7)

    def decrypt(self, buf: bytearray, offset: int):
        for i in range(len(buf)):
            buf[i] ^= self.get_mask(offset + i)


class StaticCipher:
    def get_mask(self, offset: int) -> int:
        if offset > 0x7FFF:
            offset %= 0x7FFF
        idx = (offset * offset + 27) & 0xFF
        return _STATIC_BOX[idx]

    def decrypt(self, buf: bytearray, offset: int):
        for i in range(len(buf)):
            buf[i] ^= self.get_mask(offset + i)


class Rc4Cipher:
    def __init__(self, key: bytes):
        n = len(key)
        if n == 0:
            raise DecryptError("qmc/cipher_rc4: invalid key size")
        self.key = key
        self.n = n
        box = [i & 0xFF for i in range(n)]
        j = 0
        for i in range(n):
            j = (j + box[i] + key[i % n]) % n
            box[i], box[j] = box[j], box[i]
        self.box = box
        h = 1
        for i in range(n):
            v = key[i]
            if v == 0:
                continue
            nh = (h * v) & 0xFFFFFFFF
            if nh == 0 or nh <= h:
                break
            h = nh
        self.hash = h

    def get_segment_skip(self, seg_id: int) -> int:
        n = self.n
        seed = self.key[seg_id % n]
        div = float((seg_id + 1) * seed)
        if div == 0.0:
            idx = -(1 << 63)
        else:
            idx = int(float(self.hash) / div * 100.0)
        return _trunc_divmod(idx, n)

    def enc_first_segment(self, src: bytearray, start: int, length: int, offset: int):
        for i in range(length):
            src[start + i] ^= self.key[self.get_segment_skip(offset + i)]

    def enc_a_segment(self, src: bytearray, start: int, length: int, offset: int):
        n = self.n
        box = list(self.box)
        j = k = 0
        skip_len = (offset % _RC4_SEGMENT_SIZE) + self.get_segment_skip(offset // _RC4_SEGMENT_SIZE)
        for t in range(-skip_len, length):
            j = (j + 1) % n
            k = (box[j] + k) % n
            box[j], box[k] = box[k], box[j]
            if t >= 0:
                src[start + t] ^= box[(box[j] + box[k]) % n]

    def decrypt(self, src: bytearray, offset: int):
        to_process = len(src)
        processed = 0

        def mark(inc: int) -> bool:
            nonlocal offset, to_process, processed
            offset += inc
            to_process -= inc
            processed += inc
            return to_process == 0

        if offset < _RC4_FIRST_SEGMENT_SIZE:
            block = to_process
            if block > _RC4_FIRST_SEGMENT_SIZE - offset:
                block = _RC4_FIRST_SEGMENT_SIZE - offset
            self.enc_first_segment(src, processed, block, offset)
            if mark(block):
                return

        if offset % _RC4_SEGMENT_SIZE != 0:
            block = to_process
            if block > _RC4_SEGMENT_SIZE - offset % _RC4_SEGMENT_SIZE:
                block = _RC4_SEGMENT_SIZE - offset % _RC4_SEGMENT_SIZE
            self.enc_a_segment(src, processed, block, offset)
            if mark(block):
                return

        while to_process > _RC4_SEGMENT_SIZE:
            self.enc_a_segment(src, processed, _RC4_SEGMENT_SIZE, offset)
            mark(_RC4_SEGMENT_SIZE)

        if to_process > 0:
            self.enc_a_segment(src, processed, to_process, offset)


def _search_key(data: bytes):
    n = len(data)
    if n < 8:
        raise DecryptError("QMC 文件过小")
    tail = data[-4:]
    if tail == b"QTag":
        meta_len = int.from_bytes(data[-8:-4], "big")
        if meta_len < 0 or 8 + meta_len > n:
            raise DecryptError("QTag 元数据长度异常")
        audio_len = n - 8 - meta_len
        raw_meta = data[n - 8 - meta_len:n - 8].decode("utf-8", errors="replace")
        items = raw_meta.split(",")
        if len(items) != 3:
            raise DecryptError("无效 QTag 元数据")
        return decrypt_key(items[0].encode("utf-8")), audio_len
    size = int.from_bytes(tail, "little")
    if size < 0x300 and size != 0:
        if 4 + size > n:
            raise DecryptError("QMC 尾部密钥长度异常")
        audio_len = n - 4 - size
        raw_key = data[n - 4 - size:n - 4]
        return decrypt_key(raw_key), audio_len
    return b"", n


class QmcFormat(BaseFormat):
    name = "qmc"
    suffixes = ("qmc0", "qmc2", "qmc3", "qmc4", "qmc6", "qmc8",
                "qmcflac", "qmcogg", "tkm", "mflac", "mflac0", "mflac1",
                "mgg", "mgg0", "mgg1", "mgg2", "mgg3", "mggl", "mma3")

    def detect(self, header: bytes, extension: str) -> bool:
        clean = extension.lstrip(".").lower()
        return clean in _QMC_EXTS

    def decrypt(self, data: bytes) -> DecodeResult:
        decoded_key, audio_len = _search_key(data)
        audio = bytearray(data[:audio_len])
        if len(decoded_key) > 300:
            Rc4Cipher(decoded_key).decrypt(audio, 0)
        elif decoded_key:
            MapCipher(decoded_key).decrypt(audio, 0)
        else:
            StaticCipher().decrypt(audio, 0)
        return DecodeResult(data=bytes(audio))