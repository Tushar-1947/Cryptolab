"""SHA-256 and SHA-512 (FIPS 180-4), HMAC (RFC 2104) and PBKDF2 (RFC 8018).

The round constants are *derived* (fractional parts of square / cube roots of the first
primes) instead of pasted in, which both documents where they come from and avoids typos.
"""
from typing import Callable


def _primes(n: int):
    out, c = [], 2
    while len(out) < n:
        if all(c % p for p in out if p * p <= c):
            out.append(c)
        c += 1
    return out


def _iroot(n: int, k: int) -> int:
    """Integer k-th root by binary search."""
    lo, hi = 0, 1 << ((n.bit_length() // k) + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _consts(word_bits: int, rounds: int, count_h: int = 8):
    mask = (1 << word_bits) - 1
    ps = _primes(rounds)
    k = [_iroot(p << (3 * word_bits), 3) & mask for p in ps]           # frac(cbrt(p)) * 2^w
    h = [_iroot(p << (2 * word_bits), 2) & mask for p in ps[:count_h]]  # frac(sqrt(p)) * 2^w
    return k, h


class _SHA2:
    WORD = BLOCK = ROUNDS = LEN_BYTES = 0
    S0 = S1 = s0 = s1 = ()  # rotation / shift amounts
    DIGEST_SIZE = 0
    _K = _H0 = ()

    def __init__(self, data: bytes = b""):
        self._h = list(self._H0)
        self._buf = b""
        self._len = 0
        self.update(data)

    @classmethod
    def _rotr(cls, x, n):
        m = (1 << cls.WORD) - 1
        return ((x >> n) | (x << (cls.WORD - n))) & m

    def _compress(self, block: bytes):
        w_bytes, mask, c = self.WORD // 8, (1 << self.WORD) - 1, type(self)
        w = [int.from_bytes(block[i:i + w_bytes], "big") for i in range(0, self.BLOCK, w_bytes)]
        for t in range(16, self.ROUNDS):
            s0 = c._rotr(w[t - 15], c.s0[0]) ^ c._rotr(w[t - 15], c.s0[1]) ^ (w[t - 15] >> c.s0[2])
            s1 = c._rotr(w[t - 2], c.s1[0]) ^ c._rotr(w[t - 2], c.s1[1]) ^ (w[t - 2] >> c.s1[2])
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & mask)
        a, b, cc, d, e, f, g, h = self._h
        for t in range(self.ROUNDS):
            S1 = c._rotr(e, c.S1[0]) ^ c._rotr(e, c.S1[1]) ^ c._rotr(e, c.S1[2])
            ch = (e & f) ^ (~e & mask & g)
            t1 = (h + S1 + ch + c._K[t] + w[t]) & mask
            S0 = c._rotr(a, c.S0[0]) ^ c._rotr(a, c.S0[1]) ^ c._rotr(a, c.S0[2])
            maj = (a & b) ^ (a & cc) ^ (b & cc)
            t2 = (S0 + maj) & mask
            h, g, f, e, d, cc, b, a = g, f, e, (d + t1) & mask, cc, b, a, (t1 + t2) & mask
        self._h = [(x + y) & mask for x, y in zip(self._h, (a, b, cc, d, e, f, g, h))]

    def update(self, data: bytes):
        self._len += len(data)
        self._buf += data
        while len(self._buf) >= self.BLOCK:
            self._compress(self._buf[:self.BLOCK])
            self._buf = self._buf[self.BLOCK:]
        return self

    def copy(self):
        o = type(self).__new__(type(self))
        o._h, o._buf, o._len = list(self._h), self._buf, self._len
        return o

    def digest(self) -> bytes:
        o = self.copy()
        pad_zeros = (-(o._len + 1 + self.LEN_BYTES)) % self.BLOCK
        tail = b"\x80" + b"\x00" * pad_zeros + (o._len * 8).to_bytes(self.LEN_BYTES, "big")
        o._h, o._buf = list(o._h), o._buf
        buf = o._buf + tail
        for i in range(0, len(buf), self.BLOCK):
            o._compress(buf[i:i + self.BLOCK])
        return b"".join(x.to_bytes(self.WORD // 8, "big") for x in o._h)[:self.DIGEST_SIZE]

    def hexdigest(self) -> str:
        return self.digest().hex()


class SHA256(_SHA2):
    WORD, BLOCK, ROUNDS, LEN_BYTES, DIGEST_SIZE = 32, 64, 64, 8, 32
    S0, S1, s0, s1 = (2, 13, 22), (6, 11, 25), (7, 18, 3), (17, 19, 10)
    _K, _H0 = _consts(32, 64)
    block_size = 64


class SHA512(_SHA2):
    WORD, BLOCK, ROUNDS, LEN_BYTES, DIGEST_SIZE = 64, 128, 80, 16, 64
    S0, S1, s0, s1 = (28, 34, 39), (14, 18, 41), (1, 8, 7), (19, 61, 6)
    _K, _H0 = _consts(64, 80)
    block_size = 128


def sha256(data: bytes = b"") -> SHA256:
    return SHA256(data)


def sha512(data: bytes = b"") -> SHA512:
    return SHA512(data)


def hmac(key: bytes, msg: bytes, hash_cls=SHA256) -> bytes:
    bs = hash_cls.block_size
    if len(key) > bs:
        key = hash_cls(key).digest()
    key = key.ljust(bs, b"\x00")
    inner = hash_cls(bytes(k ^ 0x36 for k in key) + msg).digest()
    return hash_cls(bytes(k ^ 0x5C for k in key) + inner).digest()


def pbkdf2_hmac(password: bytes, salt: bytes, iterations: int, dklen: int, hash_cls=SHA256) -> bytes:
    """PBKDF2 - pure Python and therefore SLOW; use hashlib.pbkdf2_hmac for real workloads."""
    out, block = b"", 1
    while len(out) < dklen:
        u = hmac(password, salt + block.to_bytes(4, "big"), hash_cls)
        t = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac(password, u, hash_cls)
            t ^= int.from_bytes(u, "big")
        out += t.to_bytes(hash_cls.DIGEST_SIZE, "big")
        block += 1
    return out[:dklen]
