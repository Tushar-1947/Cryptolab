"""Small helpers shared by the algorithms."""
import hmac as _stdlib_hmac


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes needs equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise ValueError("invalid padded data length")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison (delegates to the standard library)."""
    return _stdlib_hmac.compare_digest(a, b)
