# 🔐 CryptoLab – Cryptography Algorithms From Scratch

Pure-Python, dependency-free implementations of **SHA-256/512, HMAC, PBKDF2, AES-128/192/256 (ECB, CBC, CTR, GCM)** and **RSA
(keygen, OAEP encryption, PKCS#1 v1.5 signatures, PEM import/export)** – each one **verified against official test vectors and
cross-checked with OpenSSL/`cryptography`/`hashlib`** – plus runnable demos of how misuse breaks "secure" crypto.

![python](https://img.shields.io/badge/python-3.9%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)

> ⚠️ **Educational only.** Not constant-time, not audited. Never use it to protect real data – use OpenSSL / `cryptography`.

## What's inside
| Module | Implements | Verified against |
|---|---|---|
| `sha2.py` | SHA-256, SHA-512, HMAC, PBKDF2 | NIST examples, RFC 4231, `hashlib`, `hmac` (random lengths incl. padding edge cases) |
| `aes.py` | AES block cipher, computed S-box, 3 key sizes | FIPS-197 Appendix C |
| `modes.py` | ECB, CBC (PKCS#7), CTR, **GCM** (GHASH in GF(2¹²⁸)) | NIST GCM test cases, `cryptography` |
| `rsa.py` | Miller–Rabin, keygen+CRT, **OAEP**, PKCS#1 v1.5 sign/verify, PEM | OpenSSL: encrypt/decrypt/sign both directions |
| `demos.py` | ECB pattern leak, CBC bit-flip, CTR nonce reuse, GCM tamper detection, textbook-RSA malleability | tests assert each outcome |
| `cli.py` | hashing, password file encryption, RSA tools | round-trip + `openssl dgst -verify` |

## Quick start
```bash
git clone https://github.com/<your-username>/cryptolab.git && cd cryptolab
pip install -r requirements.txt          # only needed for the tests
python -m cryptolab selftest             # known-answer tests
pytest -q                                # 40 tests
python -m cryptolab demo                 # attack demonstrations
```

### CLI examples
```bash
python -m cryptolab hash sha256 -t "abc"
python -m cryptolab encrypt secret.txt secret.enc            # PBKDF2 + AES-256-GCM, prompts for password
python -m cryptolab decrypt secret.enc secret.out
python -m cryptolab rsa-keygen --bits 2048 --out mykey        # mykey.pem / mykey.pub.pem
python -m cryptolab sign mykey.pem document.txt document.sig
python -m cryptolab verify mykey.pub.pem document.txt document.sig
openssl dgst -sha256 -verify mykey.pub.pem -signature document.sig document.txt   # independent check
```

### As a library
```python
from cryptolab import modes, rsa
ct, tag = modes.gcm_encrypt(key32, iv12, b"message", aad=b"header")
plain   = modes.gcm_decrypt(key32, iv12, ct, tag, aad=b"header")     # raises InvalidTag if altered

priv = rsa.generate_keypair(2048)
blob = rsa.oaep_encrypt(priv.public, b"hello")
assert rsa.oaep_decrypt(priv, blob) == b"hello"
```

## Demo output (`python -m cryptolab demo`)
```
[ECB pattern leak] identical plaintext blocks -> identical ciphertext blocks
  ECB duplicate blocks: 2   CBC duplicate blocks: 0
[CBC bit-flipping] attacker edits ciphertext, no key needed; CBC gives NO integrity
  ... -> admin escalation: True
[CTR/GCM nonce reuse] C1 xor C2 == P1 xor P2 -> keystream cancels, plaintexts leak
[GCM integrity] same bit-flip as above is REJECTED by the authentication tag
[Textbook RSA malleability] E(6)*E(7) decrypts to 6*7 without the key | OAEP rejects the same trick: True
```

## Design notes
* Constants (SHA round constants, AES S-box, Rcon) are **computed**, not pasted, so they're self-documenting and typo-proof.
* GCM verifies the tag **before** decrypting; RSA-OAEP returns a single generic error to avoid padding-oracle leaks.
* Details and limitations: [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md).

## Roadmap
RSA-PSS · ECDSA/Curve25519 · ChaCha20-Poly1305 · Diffie–Hellman · constant-time experiments · performance benchmark vs OpenSSL.

## License
MIT
