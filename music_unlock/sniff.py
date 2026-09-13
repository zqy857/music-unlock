# coding: utf-8
"""音频真实格式嗅探：根据解密后数据的魔数返回扩展名。"""
from __future__ import annotations


def sniff_audio(data: bytes):
    if not data:
        return None
    head = data[:32]
    if head[:3] == b"ID3":
        return ".mp3"
    if head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        return ".mp3"
    if head[:4] == b"fLaC":
        return ".flac"
    if head[:4] == b"OggS":
        return ".ogg"
    if head[:4] == b"ftyp":
        return ".m4a"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return ".wav"
    if head[:5] == b"#!AMR":
        return ".amr"
    if head[:4] == b"MAC " or head[:7] == b"APETAGEX":
        return ".ape"
    if head[:4] == b"wvpk":
        return ".wv"
    if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        return ".aiff"
    return None