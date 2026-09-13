# coding: utf-8
"""音频加密格式注册表与检测。"""
from __future__ import annotations

from dataclasses import dataclass, field

_ENCRYPTED_SUFFIXES = tuple(".kgm .kgma .vpr .kgg .vgm .kwm .ncm .qmc0 .qmc2 .qmc3 "
                            ".qmc6 .qmc8 .qmcflac .qmcogg .qmcflac1 .qmcogg1 "
                            ".tkm .mflac .mflac0 .mflac1 .mgg .mgg0 .mgg1 .mgg2 "
                            ".mma3 .mgg3".split())


class DecryptError(Exception):
    """解密失败。"""


@dataclass
class DecodeResult:
    data: bytes
    ext: str | None = None
    title: str = ""
    artist: str = ""
    album: str = ""
    cover: bytes | None = None

    def clean_name(self, original: str) -> str:
        base = original
        dot = base.rfind(".")
        if dot > 0:
            base = base[:dot]
        changed = True
        while changed:
            changed = False
            low = base.lower()
            for s in _ENCRYPTED_SUFFIXES:
                if low.endswith(s):
                    base = base[:-len(s)]
                    changed = True
                    break
        return base


class BaseFormat:
    name = ""

    def detect(self, header: bytes, extension: str) -> bool:
        raise NotImplementedError

    def decrypt(self, data: bytes) -> DecodeResult:
        raise NotImplementedError


def strip_encrypted_suffix(name: str) -> str:
    return DecodeResult(b"").clean_name(name)


from .kgm import KgmFormat
from .kwm import KwmFormat
from .ncm import NcmFormat
from .qmc import QmcFormat

FORMATS = (KgmFormat(), KwmFormat(), NcmFormat(), QmcFormat())


def detect_format(data: bytes, extension: str) -> BaseFormat | None:
    header = data[:1024]
    for fmt in FORMATS:
        if fmt.detect(header, extension):
            return fmt
    return None