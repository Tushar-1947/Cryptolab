"""Every algorithm is validated against official vectors AND an independent reference implementation."""
import hashlib
import hmac as std_hmac
import os

import pytest
from cryptography.hazmat.primitives import hashes, padding as cpad, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa as crsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as cmodes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptolab import demos, modes, rsa
from cryptolab.aes import AES, SBOX, INV_SBOX
from cryptolab.cli import decrypt_file, encrypt_file, main, selftest
from cryptolab.sha2 import SHA512, hmac, pbkdf2_hmac, sha256, sha512
from cryptolab.utils import pkcs7_pad, pkcs7_unpad

LENGTHS = [0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 255, 1000]


# ------------------------------------------------------------- hashes
def test_sha_known_answers():
    assert sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256(b"").hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha512(b"abc").hexdigest().startswith("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a")


@pytest.mark.parametrize("n", LENGTHS)
def test_sha_matches_hashlib(n):
    d = os.urandom(n)
    assert sha256(d).digest() == hashlib.sha256(d).digest()
    assert sha512(d).digest() == hashlib.sha512(d).digest()


def test_sha_incremental_and_digest_idempotent():
    h = sha256(); h.update(b"hello "); h.update(b"world")
    assert h.digest() == h.digest() == hashlib.sha256(b"hello world").digest()


def test_hmac_rfc4231_and_reference():
    assert hmac(b"\x0b" * 20, b"Hi There").hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    for klen in (5, 64, 200):          # key shorter than, equal to and longer than the block size
        k, m = os.urandom(klen), os.urandom(50)
        assert hmac(k, m) == std_hmac.new(k, m, "sha256").digest()
        assert hmac(k, m, SHA512) == std_hmac.new(k, m, "sha512").digest()


def test_pbkdf2_matches_hashlib():
    assert pbkdf2_hmac(b"password", b"salt", 50, 40) == hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 50, 40)


# ------------------------------------------------------------- AES
def test_sbox():
    assert (SBOX[0], SBOX[1], SBOX[0x53]) == (0x63, 0x7C, 0xED)
    assert all(INV_SBOX[SBOX[i]] == i for i in range(256))


@pytest.mark.parametrize("klen,expected", [
    (16, "69c4e0d86a7b0430d8cdb78070b4c55a"), (24, "dda97ca4864cdfe06eaf70a0ec0d7191"), (32, "8ea2b7ca516745bfeafc49904b496089")])
def test_aes_fips197(klen, expected):
    a, pt = AES(bytes(range(klen))), bytes.fromhex("00112233445566778899aabbccddeeff")
    assert a.encrypt_block(pt).hex() == expected and a.decrypt_block(bytes.fromhex(expected)) == pt


@pytest.mark.parametrize("klen", [16, 24, 32])
def test_aes_modes_match_reference(klen):
    key, iv = os.urandom(klen), os.urandom(16)
    data = os.urandom(75)
    enc = Cipher(algorithms.AES(key), cmodes.CBC(iv)).encryptor()
    padder = cpad.PKCS7(128).padder()
    ref_cbc = enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
    assert modes.cbc_encrypt(key, iv, data) == ref_cbc and modes.cbc_decrypt(key, iv, ref_cbc) == data
    ref_ctr = Cipher(algorithms.AES(key), cmodes.CTR(iv)).encryptor().update(data)
    assert modes.ctr_crypt(key, iv, data) == ref_ctr
    e = Cipher(algorithms.AES(key), cmodes.ECB()).encryptor()
    p = cpad.PKCS7(128).padder()
    assert modes.ecb_encrypt(key, data) == e.update(p.update(data) + p.finalize()) + e.finalize()


def test_gcm_nist_vectors_and_reference():
    ct, tag = modes.gcm_encrypt(bytes(16), bytes(12), b"")
    assert (ct, tag.hex()) == (b"", "58e2fccefa7e3061367f1d57a4e7455a")          # NIST test case 1
    ct, tag = modes.gcm_encrypt(bytes(16), bytes(12), bytes(16))
    assert ct.hex() == "0388dace60b6a392f328c2b971b2fe78" and tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"  # test case 2
    for n in (0, 1, 15, 16, 17, 100):
        key, iv, aad, m = os.urandom(32), os.urandom(12), os.urandom(13), os.urandom(n)
        ct, tag = modes.gcm_encrypt(key, iv, m, aad)
        assert ct + tag == AESGCM(key).encrypt(iv, m, aad)
        assert modes.gcm_decrypt(key, iv, ct, tag, aad) == m


def test_gcm_rejects_any_tampering():
    key, iv = os.urandom(16), os.urandom(12)
    ct, tag = modes.gcm_encrypt(key, iv, b"secret message", b"aad")
    with pytest.raises(modes.InvalidTag):
        modes.gcm_decrypt(key, iv, bytes([ct[0] ^ 1]) + ct[1:], tag, b"aad")
    with pytest.raises(modes.InvalidTag):
        modes.gcm_decrypt(key, iv, ct, tag, b"other-aad")
    with pytest.raises(modes.InvalidTag):
        modes.gcm_decrypt(key, iv, ct, bytes([tag[0] ^ 1]) + tag[1:], b"aad")


def test_padding_validation():
    assert pkcs7_unpad(pkcs7_pad(b"abc")) == b"abc"
    for bad in (b"", b"A" * 16, b"A" * 15 + b"\x02", b"A" * 15 + b"\x11"):
        with pytest.raises(ValueError):
            pkcs7_unpad(bad)
    with pytest.raises(ValueError):
        AES(b"short")


# ------------------------------------------------------------- RSA
@pytest.fixture(scope="module")
def key():
    return rsa.generate_keypair(1024)


def test_primality():
    assert all(rsa.is_probable_prime(p) for p in (2, 3, 97, 7919, 2 ** 127 - 1))
    assert not any(rsa.is_probable_prime(c) for c in (1, 91, 561, 1105, 2 ** 127 - 3 * 7))  # 561 = Carmichael


def test_keypair_consistency(key):
    assert key.n == key.p * key.q and key.n.bit_length() == 1024
    assert (key.e * key.d) % ((key.p - 1) * (key.q - 1) // __import__("math").gcd(key.p - 1, key.q - 1)) == 1


def test_oaep_roundtrip_and_randomised(key):
    c1, c2 = rsa.oaep_encrypt(key.public, b"hello"), rsa.oaep_encrypt(key.public, b"hello")
    assert c1 != c2 and rsa.oaep_decrypt(key, c1) == rsa.oaep_decrypt(key, c2) == b"hello"
    with pytest.raises(ValueError):
        rsa.oaep_encrypt(key.public, b"x" * 200)
    with pytest.raises(ValueError):
        rsa.oaep_decrypt(key, c1[:-1] + bytes([c1[-1] ^ 1]))


def test_interop_with_openssl_backend(key):
    nums = crsa.RSAPrivateNumbers(key.p, key.q, key.d, key.dp, key.dq, key.qinv,
                                  crsa.RSAPublicNumbers(key.e, key.n))
    ref = nums.private_key()
    oaep = apad.OAEP(mgf=apad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    # ours -> theirs
    assert ref.decrypt(rsa.oaep_encrypt(key.public, b"interop"), oaep) == b"interop"
    # theirs -> ours
    assert rsa.oaep_decrypt(key, ref.public_key().encrypt(b"interop2", oaep)) == b"interop2"
    # signatures both ways
    sig = rsa.sign(key, b"doc")
    ref.public_key().verify(sig, b"doc", apad.PKCS1v15(), hashes.SHA256())
    assert rsa.verify(key.public, b"doc", ref.sign(b"doc", apad.PKCS1v15(), hashes.SHA256()))


def test_signature_tamper(key):
    sig = rsa.sign(key, b"contract")
    assert rsa.verify(key.public, b"contract", sig)
    assert not rsa.verify(key.public, b"contract!", sig)
    assert not rsa.verify(key.public, b"contract", sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not rsa.verify(key.public, b"contract", sig[:-1])


def test_pem_roundtrip_and_openssl_can_parse(key):
    pem = rsa.export_private_pem(key)
    assert rsa.import_private_pem(pem) == key
    loaded = serialization.load_pem_private_key(pem.encode(), None)
    assert loaded.private_numbers().public_numbers.n == key.n
    pub = serialization.load_pem_public_key(rsa.export_public_pem(key.public).encode())
    assert pub.public_numbers().e == key.e
    assert rsa.import_public_pem(rsa.export_public_pem(key.public)) == key.public


# ------------------------------------------------------------- demos + CLI
def test_demos_show_expected_behaviour():
    r = demos.run_all()
    assert r["ecb_pattern_leak"]["ecb_duplicates"] >= 1 and r["ecb_pattern_leak"]["cbc_duplicates"] == 0
    assert r["cbc_bitflip"]["escalated"] and r["ctr_nonce_reuse"]["leak"] and r["gcm_detects_tampering"]["detected"]
    assert r["textbook_rsa_malleability"]["product"] == 42 and r["textbook_rsa_malleability"]["oaep_blocked"]


def test_file_encryption_roundtrip_and_wrong_password():
    blob = encrypt_file(b"top secret", b"pw")
    assert decrypt_file(blob, b"pw") == b"top secret"
    with pytest.raises(modes.InvalidTag):
        decrypt_file(blob, b"wrong")


def test_cli_selftest_and_hash(capsys):
    assert selftest() == 0
    assert main(["hash", "sha256", "-t", "abc"]) == 0
    assert "ba7816bf" in capsys.readouterr().out
