"""Attack demonstrations - why 'correct' crypto still fails when used badly.
Each demo returns a dict (used by the tests) and prints a short explanation."""
import os

from . import modes, rsa
from .utils import xor_bytes


def ecb_pattern_leak(verbose=True):
    key = os.urandom(16)
    pt = b"ATTACK AT DAWN!!" * 3 + b"SOMETHING ELSE.."
    ecb = modes.ecb_encrypt(key, pt, pad=False)
    cbc = modes.cbc_encrypt(key, os.urandom(16), pt)
    blocks = lambda c: [c[i:i + 16] for i in range(0, len(c), 16)]
    ecb_dupes = len(blocks(ecb)) - len(set(blocks(ecb)))
    cbc_dupes = len(blocks(cbc)) - len(set(blocks(cbc)))
    if verbose:
        print("[ECB pattern leak] identical plaintext blocks -> identical ciphertext blocks")
        print(f"  ECB duplicate blocks: {ecb_dupes}   CBC duplicate blocks: {cbc_dupes}")
    return {"ecb_duplicates": ecb_dupes, "cbc_duplicates": cbc_dupes}


def cbc_bitflip(verbose=True):
    key, iv = os.urandom(16), os.urandom(16)
    token = b"AAAAAAAAAAAAAAAA" + b";admin=false;xxx" + b"trailer"
    ct = bytearray(modes.cbc_encrypt(key, iv, token))
    # flipping bit-pattern in ciphertext block 0 flips the same bits in plaintext block 1
    delta = xor_bytes(b"false", b"true;")
    for i, d in enumerate(delta):
        ct[7 + i] ^= d  # ";admin=" is 7 bytes -> 'false' starts at offset 7 of block 1
    forged = modes.cbc_decrypt(key, iv, bytes(ct), unpad=True)
    ok = b";admin=true;" in forged
    if verbose:
        print("[CBC bit-flipping] attacker edits ciphertext, no key needed; CBC gives NO integrity")
        print(f"  block 0 garbled, block 1 now: {forged[16:32]!r}  -> admin escalation: {ok}")
    return {"escalated": ok}


def ctr_nonce_reuse(verbose=True):
    key, nonce = os.urandom(16), os.urandom(16)
    p1, p2 = b"Transfer $100 to Alice", b"Transfer $999 to Mallo"
    c1, c2 = modes.ctr_crypt(key, nonce, p1), modes.ctr_crypt(key, nonce, p2)
    leaked = xor_bytes(c1, c2)
    expected = xor_bytes(p1, p2)
    if verbose:
        print("[CTR/GCM nonce reuse] C1 xor C2 == P1 xor P2 -> keystream cancels, plaintexts leak")
        print(f"  C1^C2 == P1^P2 : {leaked == expected}")
    return {"leak": leaked == expected}


def gcm_detects_tampering(verbose=True):
    key, iv = os.urandom(32), os.urandom(12)
    ct, tag = modes.gcm_encrypt(key, iv, b"pay 100 to alice", b"hdr")
    bad = bytearray(ct)
    bad[4] ^= 1
    try:
        modes.gcm_decrypt(key, iv, bytes(bad), tag, b"hdr")
        detected = False
    except modes.InvalidTag:
        detected = True
    if verbose:
        print("[GCM integrity] same bit-flip as above is REJECTED by the authentication tag")
        print(f"  tampering detected: {detected}")
    return {"detected": detected}


def textbook_rsa_malleability(verbose=True):
    k = rsa.generate_keypair(1024)
    pub = k.public
    m1, m2 = 6, 7
    c1, c2 = pow(m1, pub.e, pub.n), pow(m2, pub.e, pub.n)
    forged = (c1 * c2) % pub.n          # attacker multiplies ciphertexts
    result = pow(forged, k.d, k.n)
    oaep_blocked = False
    c = rsa.oaep_encrypt(k.public, b"6")
    mauled = (int.from_bytes(c, "big") * pow(2, pub.e, pub.n)) % pub.n
    try:
        rsa.oaep_decrypt(k, mauled.to_bytes(k.size, "big"))
    except ValueError:
        oaep_blocked = True
    if verbose:
        print("[Textbook RSA malleability] E(6)*E(7) decrypts to 6*7 without the key")
        print(f"  decrypted product = {result}   | OAEP rejects the same trick: {oaep_blocked}")
    return {"product": result, "oaep_blocked": oaep_blocked}


ALL = [ecb_pattern_leak, cbc_bitflip, ctr_nonce_reuse, gcm_detects_tampering, textbook_rsa_malleability]


def run_all():
    return {f.__name__: f() for f in ALL}
