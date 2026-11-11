"""RSA: Miller-Rabin prime generation, key generation (CRT), OAEP encryption (RFC 8017),
PKCS#1 v1.5 signatures with SHA-256, and PKCS#1 PEM import/export (OpenSSL compatible)."""
import base64
import math
import secrets
from dataclasses import dataclass

from .sha2 import sha256
from .utils import ct_equal, xor_bytes

_SMALL_PRIMES = [p for p in range(2, 2000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
HLEN = 32


# ------------------------------------------------------------------ primes
def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1  # top 2 bits -> n has full length
        if is_probable_prime(c):
            return c


# ------------------------------------------------------------------ keys
@dataclass
class PublicKey:
    n: int
    e: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def _raw(self, c: int) -> int:           # CRT: ~4x faster than pow(c, d, n)
        m1, m2 = pow(c, self.dp, self.p), pow(c, self.dq, self.q)
        return m2 + self.q * ((self.qinv * (m1 - m2)) % self.p)


def generate_keypair(bits: int = 2048, e: int = 65537) -> PrivateKey:
    if bits < 512 or bits % 2:
        raise ValueError("bits must be an even number >= 512")
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        n, d = p * q, pow(e, -1, lam)
        if abs(p - q) < (1 << (bits // 2 - 100)):   # primes too close -> Fermat factoring
            continue
        return PrivateKey(n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))


# ------------------------------------------------------------------ OAEP (SHA-256, MGF1-SHA-256)
def _mgf1(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def oaep_encrypt(pub: PublicKey, message: bytes, label: bytes = b"", _seed: bytes = None) -> bytes:
    k = pub.size
    if len(message) > k - 2 * HLEN - 2:
        raise ValueError(f"message too long (max {k - 2 * HLEN - 2} bytes for this key)")
    db = sha256(label).digest() + b"\x00" * (k - len(message) - 2 * HLEN - 2) + b"\x01" + message
    seed = _seed or secrets.token_bytes(HLEN)
    masked_db = xor_bytes(db, _mgf1(seed, k - HLEN - 1))
    masked_seed = xor_bytes(seed, _mgf1(masked_db, HLEN))
    em = b"\x00" + masked_seed + masked_db
    return pow(int.from_bytes(em, "big"), pub.e, pub.n).to_bytes(k, "big")


def oaep_decrypt(priv: PrivateKey, ciphertext: bytes, label: bytes = b"") -> bytes:
    k = priv.size
    err = ValueError("decryption error")        # one generic error: avoids padding-oracle leaks
    if len(ciphertext) != k or k < 2 * HLEN + 2:
        raise err
    c = int.from_bytes(ciphertext, "big")
    if c >= priv.n:
        raise err
    em = priv._raw(c).to_bytes(k, "big")
    y, masked_seed, masked_db = em[0], em[1:1 + HLEN], em[1 + HLEN:]
    seed = xor_bytes(masked_seed, _mgf1(masked_db, HLEN))
    db = xor_bytes(masked_db, _mgf1(seed, k - HLEN - 1))
    lhash, rest = db[:HLEN], db[HLEN:]
    idx = rest.find(b"\x01")
    ok = (y == 0) & ct_equal(lhash, sha256(label).digest()) & (idx >= 0) & (rest[:idx].strip(b"\x00") == b"" if idx >= 0 else False)
    if not ok:
        raise err
    return rest[idx + 1:]


# ------------------------------------------------------------------ PKCS#1 v1.5 signatures
def _emsa(message: bytes, k: int) -> bytes:
    t = _SHA256_DIGESTINFO + sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("key too small for SHA-256 signature")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign(priv: PrivateKey, message: bytes) -> bytes:
    return priv._raw(int.from_bytes(_emsa(message, priv.size), "big")).to_bytes(priv.size, "big")


def verify(pub: PublicKey, message: bytes, signature: bytes) -> bool:
    if len(signature) != pub.size:
        return False
    s = int.from_bytes(signature, "big")
    if s >= pub.n:
        return False
    return ct_equal(pow(s, pub.e, pub.n).to_bytes(pub.size, "big"), _emsa(message, pub.size))


# ------------------------------------------------------------------ DER / PEM (PKCS#1)
def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(i):
    return b"\x02" + _der_len((i.bit_length() + 8) // 8) + i.to_bytes((i.bit_length() + 8) // 8, "big")


def _der_seq(*ints):
    body = b"".join(_der_int(i) for i in ints)
    return b"\x30" + _der_len(len(body)) + body


def _der_read_ints(data: bytes):
    if data[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    pos = 2
    if data[1] & 0x80:
        pos = 2 + (data[1] & 0x7F)
    ints = []
    while pos < len(data):
        if data[pos] != 0x02:
            raise ValueError("expected INTEGER")
        ln, pos = data[pos + 1], pos + 2
        if ln & 0x80:
            nb = ln & 0x7F
            ln, pos = int.from_bytes(data[pos:pos + nb], "big"), pos + nb
        ints.append(int.from_bytes(data[pos:pos + ln], "big"))
        pos += ln
    return ints


def _pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def _unpem(text: str) -> bytes:
    return base64.b64decode("".join(l for l in text.strip().splitlines() if not l.startswith("-----")))


def export_private_pem(k: PrivateKey) -> str:
    return _pem("RSA PRIVATE KEY", _der_seq(0, k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.qinv))


def export_public_pem(k) -> str:
    return _pem("RSA PUBLIC KEY", _der_seq(k.n, k.e))


def import_private_pem(text: str) -> PrivateKey:
    v = _der_read_ints(_unpem(text))
    return PrivateKey(*v[1:9])


def import_public_pem(text: str) -> PublicKey:
    n, e = _der_read_ints(_unpem(text))
    return PublicKey(n, e)
