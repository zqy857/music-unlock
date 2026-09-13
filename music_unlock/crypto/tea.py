# coding: utf-8
"""QQ 音乐 (QMC) 密钥解密所需 TEA 算法移植。

参考 golang.org/x/crypto/tea (32 轮 TEA) 与 unlock-music/cli 的
algo/qmc/key_dec.go 中的 decryptTencentTea 流程。
"""
from __future__ import annotations

import base64
import math

_DELTA = 0x9E3779B9
_M32 = 0xFFFFFFFF


def _tea_encrypt_block(block: bytes, key: bytes, rounds: int = 32) -> bytes:
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]
    k0, k1, k2, k3 = k
    s = 0
    for _ in range(rounds // 2):
        s = (s + _DELTA) & _M32
        v0 = (v0 + ((((v1 << 4) + k0) & _M32) ^ ((v1 + s) & _M32) ^ (((v1 >> 5) + k1) & _M32))) & _M32
        v1 = (v1 + ((((v0 << 4) + k2) & _M32) ^ ((v0 + s) & _M32) ^ (((v0 >> 5) + k3) & _M32))) & _M32
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def _tea_decrypt_block(block: bytes, key: bytes, rounds: int = 32) -> bytes:
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]
    k0, k1, k2, k3 = k
    s = (_DELTA * (rounds // 2)) & _M32
    for _ in range(rounds // 2):
        v1 = (v1 - ((((v0 << 4) + k2) & _M32) ^ ((v0 + s) & _M32) ^ (((v0 >> 5) + k3) & _M32))) & _M32
        v0 = (v0 - ((((v1 << 4) + k0) & _M32) ^ ((v1 + s) & _M32) ^ (((v1 >> 5) + k1) & _M32))) & _M32
        s = (s - _DELTA) & _M32
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def simple_make_key(salt: int, length: int) -> bytes:
    out = bytearray(length)
    for i in range(length):
        tmp = math.tan(salt + i * 0.1)
        out[i] = int(math.fabs(tmp) * 100.0) & 0xFF
    return bytes(out)


def _xor8(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt_tencent_tea(in_buf: bytes, key: bytes) -> bytes:
    salt_len = 2
    zero_len = 7
    if len(in_buf) % 8 != 0:
        raise ValueError("inBuf size not a multiple of the block size")
    if len(in_buf) < 16:
        raise ValueError("inBuf size too small")

    dest = _tea_decrypt_block(in_buf[:8], key, 32)
    pad_len = dest[0] & 0x7
    out_len = len(in_buf) - 1 - pad_len - salt_len - zero_len
    if pad_len + salt_len != 8:
        raise ValueError("invalid pad len")
    out = bytearray(out_len)

    iv_prev = bytearray(8)
    iv_cur = in_buf[:8]
    pos = 8
    dest_idx = 1 + pad_len

    def crypt_block():
        nonlocal iv_prev, iv_cur, pos, dest_idx, dest
        iv_prev = iv_cur
        iv_cur = in_buf[pos:pos + 8]
        dest = _tea_decrypt_block(_xor8(dest, iv_cur), key, 32)
        pos += 8
        dest_idx = 0

    i = 1
    while i <= salt_len:
        if dest_idx < 8:
            dest_idx += 1
            i += 1
        elif dest_idx == 8:
            crypt_block()

    out_pos = 0
    while out_pos < out_len:
        if dest_idx < 8:
            out[out_pos] = dest[dest_idx] ^ iv_prev[dest_idx]
            dest_idx += 1
            out_pos += 1
        elif dest_idx == 8:
            crypt_block()

    for _ in range(1, zero_len + 1):
        if dest_idx < 8 and dest[dest_idx] != iv_prev[dest_idx]:
            raise ValueError("zero check failed")

    return bytes(out)


def decrypt_key(raw_key: bytes) -> bytes:
    raw = base64.b64decode(raw_key, validate=False)
    if len(raw) < 16:
        raise ValueError("key length is too short")

    if raw.startswith(_RAW_KEY_PREFIX_V2):
        raw = _derive_key_v2(raw[len(_RAW_KEY_PREFIX_V2):])

    simple_key = simple_make_key(106, 8)
    tea_key = bytearray(16)
    for i in range(8):
        tea_key[i << 1] = simple_key[i]
        tea_key[i << 1 | 1] = raw[i]

    rs = decrypt_tencent_tea(raw[8:], bytes(tea_key))
    return raw[:8] + rs


_RAW_KEY_PREFIX_V2 = b"QQMusic EncV2,Key:"

_DERIVE_V2_KEY1 = bytes([
    0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
    0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28,
])
_DERIVE_V2_KEY2 = bytes([
    0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
    0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54,
])


def _derive_key_v2(raw: bytes) -> bytes:
    buf = decrypt_tencent_tea(raw, _DERIVE_V2_KEY1)
    buf = decrypt_tencent_tea(buf, _DERIVE_V2_KEY2)
    return base64.b64decode(buf, validate=False)


SIMPLE_MAKE_KEY_106_8 = bytes([0x69, 0x56, 0x46, 0x38, 0x2B, 0x20, 0x15, 0x0B])