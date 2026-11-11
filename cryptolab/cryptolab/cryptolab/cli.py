"""CLI:  python -m cryptolab <hash|hmac|encrypt|decrypt|rsa-keygen|rsa-encrypt|rsa-decrypt|sign|verify|demo|selftest>"""
import argparse
import getpass
import hashlib
import sys

from . import demos, modes, rsa
from .sha2 import hmac as _hmac, sha256, sha512

MAGIC = b"CLAB1"
KDF_ITERATIONS = 300_000


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def _password(args):
    return (args.password or getpass.getpass("Password: ")).encode()


def encrypt_file(data: bytes, password: bytes) -> bytes:
    salt, iv = modes.random_bytes(16), modes.random_bytes(12)
    # hashlib's C implementation is used for the KDF: our pure-Python PBKDF2 is correct but far too slow
    key = hashlib.pbkdf2_hmac("sha256", password, salt, KDF_ITERATIONS, 32)
    ct, tag = modes.gcm_encrypt(key, iv, data, MAGIC)
    return MAGIC + salt + iv + ct + tag


def decrypt_file(blob: bytes, password: bytes) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 16 + 12 + 16:
        raise ValueError("not a CryptoLab file")
    salt, iv = blob[5:21], blob[21:33]
    ct, tag = blob[33:-16], blob[-16:]
    key = hashlib.pbkdf2_hmac("sha256", password, salt, KDF_ITERATIONS, 32)
    return modes.gcm_decrypt(key, iv, ct, tag, MAGIC)


def selftest() -> int:
    """Known-answer tests from NIST/RFC documents."""
    from .aes import AES
    checks = [
        ("SHA-256('abc')", sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("SHA-512('abc')", sha512(b"abc").hexdigest().startswith("ddaf35a193617aba")),
        ("HMAC-SHA256 RFC4231 #1", _hmac(b"\x0b" * 20, b"Hi There").hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ("AES-128 FIPS-197 C.1", AES(bytes(range(16))).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("AES-256 FIPS-197 C.3", AES(bytes(range(32))).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "8ea2b7ca516745bfeafc49904b496089"),
    ]
    ct, tag = modes.gcm_encrypt(bytes(16), bytes(12), b"")
    checks.append(("AES-128-GCM NIST test case 1", tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"))
    for name, ok in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in checks) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cryptolab", description="Educational crypto implementations (NOT for production)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hash"); h.add_argument("algo", choices=["sha256", "sha512"])
    g = h.add_mutually_exclusive_group(required=True); g.add_argument("-t", "--text"); g.add_argument("-f", "--file")
    m = sub.add_parser("hmac"); m.add_argument("key"); m.add_argument("text")
    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name} a file with a password (PBKDF2 + AES-256-GCM)")
        p.add_argument("infile"); p.add_argument("outfile"); p.add_argument("-p", "--password")
    k = sub.add_parser("rsa-keygen"); k.add_argument("--bits", type=int, default=2048); k.add_argument("--out", default="key")
    for name in ("rsa-encrypt", "rsa-decrypt", "sign", "verify"):
        p = sub.add_parser(name)
        p.add_argument("keyfile"); p.add_argument("infile")
        if name == "verify":
            p.add_argument("sigfile")
        else:
            p.add_argument("outfile")
    sub.add_parser("demo", help="run the attack demonstrations")
    sub.add_parser("selftest", help="run known-answer tests")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "hash":
            data = a.text.encode() if a.text is not None else _read(a.file)
            print((sha256 if a.algo == "sha256" else sha512)(data).hexdigest())
        elif a.cmd == "hmac":
            print(_hmac(a.key.encode(), a.text.encode()).hex())
        elif a.cmd == "encrypt":
            _write(a.outfile, encrypt_file(_read(a.infile), _password(a))); print(f"encrypted -> {a.outfile}")
        elif a.cmd == "decrypt":
            _write(a.outfile, decrypt_file(_read(a.infile), _password(a))); print(f"decrypted -> {a.outfile}")
        elif a.cmd == "rsa-keygen":
            key = rsa.generate_keypair(a.bits)
            open(a.out + ".pem", "w").write(rsa.export_private_pem(key))
            open(a.out + ".pub.pem", "w").write(rsa.export_public_pem(key.public))
            print(f"wrote {a.out}.pem and {a.out}.pub.pem ({a.bits}-bit)")
        elif a.cmd == "rsa-encrypt":
            _write(a.outfile, rsa.oaep_encrypt(rsa.import_public_pem(open(a.keyfile).read()), _read(a.infile)))
        elif a.cmd == "rsa-decrypt":
            _write(a.outfile, rsa.oaep_decrypt(rsa.import_private_pem(open(a.keyfile).read()), _read(a.infile)))
        elif a.cmd == "sign":
            _write(a.outfile, rsa.sign(rsa.import_private_pem(open(a.keyfile).read()), _read(a.infile)))
        elif a.cmd == "verify":
            ok = rsa.verify(rsa.import_public_pem(open(a.keyfile).read()), _read(a.infile), _read(a.sigfile))
            print("signature VALID" if ok else "signature INVALID"); return 0 if ok else 1
        elif a.cmd == "demo":
            demos.run_all()
        elif a.cmd == "selftest":
            return selftest()
    except (ValueError, modes.InvalidTag, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
