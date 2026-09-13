# coding: utf-8
"""网易云音乐 (NCM) 需要的 AES-128-ECB 纯 Python 实现。

优先使用 pycryptodome（若已安装），否则回退到内置实现。
内置实现通过 FIPS-197 测试向量验证（见 tests/test_aes.py）。
"""
from __future__ import annotations

try:
    from Crypto.Cipher import AES as _PyCryptodomeAES
    _HAVE_PYCRYPTODOME = True
except ImportError:
    _PyCryptodomeAES = None
    _HAVE_PYCRYPTODOME = False


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        v = inv
        r = v
        for _ in range(4):
            v = ((v << 1) | (v >> 7)) & 0xFF
            r ^= v
        sbox[x] = r ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _build_sbox()


def _key_expansion(key: bytes):
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _add_round_key(state, words):
    # state 为行优先 [row][col]，列 c 与密钥字 words[c] 逐字节异或
    for c in range(4):
        xk = words[c]
        for r in range(4):
            state[r][c] ^= xk[r]


def _sub_bytes(state, sbox):
    for r in range(4):
        for c in range(4):
            state[r][c] = sbox[state[r][c]]


def _shift_rows(state, inv=False):
    for r in range(1, 4):
        row = state[r]
        if inv:
            row[:] = row[-r:] + row[:-r]
        else:
            row[:] = row[r:] + row[:r]


def _mix_columns(state, inv=False):
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        if not inv:
            b0 = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
            b1 = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
            b2 = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
            b3 = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
        else:
            b0 = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
            b1 = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
            b2 = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
            b3 = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
        state[0][c], state[1][c], state[2][c], state[3][c] = b0, b1, b2, b3


def _to_state(block: bytes):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(s) -> bytes:
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _encrypt_block(block: bytes, w) -> bytes:
    s = _to_state(block)
    _add_round_key(s, w[0:4])
    for rnd in range(1, 10):
        _sub_bytes(s, _SBOX)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w[4 * rnd:4 * rnd + 4])
    _sub_bytes(s, _SBOX)
    _shift_rows(s)
    _add_round_key(s, w[40:44])
    return _from_state(s)


def _decrypt_block(block: bytes, w) -> bytes:
    s = _to_state(block)
    _add_round_key(s, w[40:44])
    for rnd in range(9, 0, -1):
        _shift_rows(s, inv=True)
        _sub_bytes(s, _INV_SBOX)
        _add_round_key(s, w[4 * rnd:4 * rnd + 4])
        _mix_columns(s, inv=True)
    _shift_rows(s, inv=True)
    _sub_bytes(s, _INV_SBOX)
    _add_round_key(s, w[0:4])
    return _from_state(s)


class _PureAES128ECB:
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 要求 16 字节密钥")
        self._w = _key_expansion(key)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % 16:
            raise ValueError("数据长度必须为 16 的倍数")
        out = bytearray()
        for off in range(0, len(data), 16):
            out += _decrypt_block(data[off:off + 16], self._w)
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % 16:
            raise ValueError("数据长度必须为 16 的倍数")
        out = bytearray()
        for off in range(0, len(data), 16):
            out += _encrypt_block(data[off:off + 16], self._w)
        return bytes(out)


class AES128ECB:
    __slots__ = ("_impl",)

    def __init__(self, key: bytes):
        self._impl = _PyCryptodomeAES.new(key, _PyCryptodomeAES.MODE_ECB) if _HAVE_PYCRYPTODOME else _PureAES128ECB(key)

    def decrypt(self, data: bytes) -> bytes:
        return self._impl.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        return self._impl.encrypt(data)


class _PureAES128CBC:
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 16 or len(iv) != 16:
            raise ValueError("AES-128-CBC 要求 16 字节密钥与 IV")
        self._ecb = _PureAES128ECB(key)
        self._iv = bytes(iv)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % 16:
            raise ValueError("数据长度必须为 16 的倍数")
        out = bytearray(len(data))
        prev = self._iv
        for off in range(0, len(data), 16):
            cur = data[off:off + 16]
            d = self._ecb.decrypt(cur)
            for i in range(16):
                out[off + i] = d[i] ^ prev[i]
            prev = cur
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % 16:
            raise ValueError("数据长度必须为 16 的倍数")
        out = bytearray(len(data))
        prev = self._iv
        for off in range(0, len(data), 16):
            cur = data[off:off + 16]
            e = self._ecb.encrypt(bytes(a ^ b for a, b in zip(cur, prev)))
            out[off:off + 16] = e
            prev = bytes(e)
        return bytes(out)


class AES128CBC:
    __slots__ = ("_impl",)

    def __init__(self, key: bytes, iv: bytes):
        if _HAVE_PYCRYPTODOME:
            self._impl = _PyCryptodomeAES.new(key, _PyCryptodomeAES.MODE_CBC, iv)
        else:
            self._impl = _PureAES128CBC(key, iv)

    def decrypt(self, data: bytes) -> bytes:
        return self._impl.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        return self._impl.encrypt(data)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data[: -data[-1]] if data[-1] < len(data) else b""