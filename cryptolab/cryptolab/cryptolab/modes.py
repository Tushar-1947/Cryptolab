"""Block-cipher modes built on cryptolab.aes: ECB, CBC, CTR and GCM."""
import secrets

from .aes import AES
from .utils import ct_equal, pkcs7_pad, pkcs7_unpad, xor_bytes


class InvalidTag(Exception):
    """Authentication tag mismatch - ciphertext, AAD, key or IV was altered."""


# ---------------------------------------------------------------- ECB (insecure; demo only)
def ecb_encrypt(key: bytes, data: bytes, pad: bool = True) -> bytes:
    a = AES(key)
    data = pkcs7_pad(data) if pad else data
    if len(data) % 16:
        raise ValueError("data not block aligned")
    return b"".join(a.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def ecb_decrypt(key: bytes, data: bytes, unpad: bool = True) -> bytes:
    a = AES(key)
    out = b"".join(a.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))
    return pkcs7_unpad(out) if unpad else out


# ---------------------------------------------------------------- CBC
def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    a, prev, out = AES(key), iv, []
    data = pkcs7_pad(data)
    for i in range(0, len(data), 16):
        prev = a.encrypt_block(xor_bytes(data[i:i + 16], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes, unpad: bool = True) -> bytes:
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("bad IV or ciphertext length")
    a, prev, out = AES(key), iv, []
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out.append(xor_bytes(a.decrypt_block(blk), prev))
        prev = blk
    plain = b"".join(out)
    return pkcs7_unpad(plain) if unpad else plain


# ---------------------------------------------------------------- CTR
def ctr_crypt(key: bytes, initial_counter_block: bytes, data: bytes) -> bytes:
    """CTR keystream XOR; the full 128-bit block is incremented big-endian (same as OpenSSL/NIST)."""
    if len(initial_counter_block) != 16:
        raise ValueError("counter block must be 16 bytes")
    a, ctr, out = AES(key), int.from_bytes(initial_counter_block, "big"), []
    for i in range(0, len(data), 16):
        ks = a.encrypt_block(ctr.to_bytes(16, "big"))
        out.append(xor_bytes(data[i:i + 16], ks[:len(data[i:i + 16])]))
        ctr = (ctr + 1) % (1 << 128)
    return b"".join(out)


# ---------------------------------------------------------------- GCM (NIST SP 800-38D, 96-bit IV)
def _gf128_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def _ghash(h: int, aad: bytes, ct: bytes) -> int:
    def blocks(b):
        b = b + b"\x00" * (-len(b) % 16)
        return [int.from_bytes(b[i:i + 16], "big") for i in range(0, len(b), 16)]
    y = 0
    for blk in blocks(aad) + blocks(ct) + [(len(aad) * 8 << 64) | (len(ct) * 8)]:
        y = _gf128_mul(y ^ blk, h)
    return y


def _gcm_ctr(a: AES, j0: bytes, data: bytes) -> bytes:
    prefix, ctr, out = j0[:12], int.from_bytes(j0[12:], "big"), []
    for i in range(0, len(data), 16):
        ctr = (ctr + 1) & 0xFFFFFFFF            # inc32
        ks = a.encrypt_block(prefix + ctr.to_bytes(4, "big"))
        chunk = data[i:i + 16]
        out.append(xor_bytes(chunk, ks[:len(chunk)]))
    return b"".join(out)


def gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b""):
    """Return (ciphertext, 16-byte tag). IV must be 12 bytes and NEVER reused with the same key."""
    if len(iv) != 12:
        raise ValueError("this implementation supports 96-bit IVs only")
    a = AES(key)
    h = int.from_bytes(a.encrypt_block(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ct = _gcm_ctr(a, j0, plaintext)
    s = _ghash(h, aad, ct)
    tag = xor_bytes(a.encrypt_block(j0), s.to_bytes(16, "big"))
    return ct, tag


def gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if len(iv) != 12:
        raise ValueError("this implementation supports 96-bit IVs only")
    a = AES(key)
    h = int.from_bytes(a.encrypt_block(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    expected = xor_bytes(a.encrypt_block(j0), _ghash(h, aad, ciphertext).to_bytes(16, "big"))
    if not ct_equal(expected, tag):              # verify BEFORE decrypting
        raise InvalidTag("authentication failed")
    return _gcm_ctr(a, j0, ciphertext)


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)
