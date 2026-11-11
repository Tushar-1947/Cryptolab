# Algorithm notes

## SHA-256 / SHA-512 (`sha2.py`)
Merkle–Damgård construction. Message is padded (`0x80`, zeros, length in bits) to a block multiple and compressed
block-by-block with 64 (SHA-256) or 80 (SHA-512) rounds of `Ch`, `Maj`, `Σ0/Σ1` and a message schedule using `σ0/σ1`.
Initial hash values and round constants are **derived** at import time (fractional parts of √ and ∛ of the first primes),
so there is no table to mistype.

## HMAC & PBKDF2
HMAC = `H((K⊕opad) ‖ H((K⊕ipad) ‖ m))` (RFC 2104). PBKDF2 iterates HMAC to make password guessing expensive (RFC 8018).
Our PBKDF2 is pure Python and slow; the CLI uses `hashlib.pbkdf2_hmac` for the KDF step.

## AES (`aes.py`)
State is a 4×4 byte matrix. Each round: SubBytes (S-box = GF(2⁸) inverse + affine map), ShiftRows, MixColumns
(matrix multiply in GF(2⁸)), AddRoundKey. Rounds: 10/12/14 for 128/192/256-bit keys. Key schedule per FIPS-197 §5.2.

## Modes (`modes.py`)
| Mode | Confidentiality | Integrity | Notes |
|---|---|---|---|
| ECB | ✗ leaks patterns | ✗ | demo only |
| CBC | ✓ | ✗ malleable (bit-flip demo) | needs unpredictable IV; padding-oracle risk |
| CTR | ✓ | ✗ | nonce reuse is catastrophic |
| GCM | ✓ | ✓ (128-bit tag) | 96-bit IV, never reuse (key, IV) |

GCM: `H = E_K(0¹²⁸)`, `J0 = IV‖0³¹1`, ciphertext via CTR from `inc32(J0)`, tag = `E_K(J0) ⊕ GHASH_H(A, C)`.
GHASH multiplies in GF(2¹²⁸) with the reflected polynomial `x¹²⁸+x⁷+x²+x+1`.

## RSA (`rsa.py`)
Key generation: two random primes (Miller–Rabin, 40 rounds, top-two bits set), `e = 65537`, `d = e⁻¹ mod λ(n)`, CRT parameters.
Encryption: **OAEP** (SHA-256 / MGF1) – randomised and non-malleable. Signatures: **PKCS#1 v1.5** with SHA-256 (verification
re-encodes the expected block and compares in constant time, avoiding parser bugs such as Bleichenbacher's e=3 forgery).
Keys import/export as standard PKCS#1 PEM and are accepted by OpenSSL.

## Known limitations (intentional – this is a learning project)
* Not constant-time; Python big-int and table lookups leak timing/cache information.
* `random` source is `secrets` (OS CSPRNG) but keys are not protected in memory or encrypted at rest.
* GCM supports 96-bit IVs only; RSA-PSS and ECC are not implemented (good extensions).
