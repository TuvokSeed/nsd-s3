#!/usr/bin/env python3
"""Decrypt a nostr-signer-s3 vault blob off-device (disaster recovery).

Handles both vault formats (NVS namespace "nsd", key "vault"):
  v1 (legacy, pre-v0.0.6, 81 bytes) -- raw 32-byte key, no mnemonic ever
    existed for these:
      ver(1)=1 | pbkdf2-iters u32 LE | salt(16) | gcm-nonce(12) | ct(32) | tag(16)
  v2 (v0.0.6+, 177 bytes) -- the BIP-39 mnemonic itself (the key is BIP-32
    HD-derived from it at m/44'/1237'/0'/0/0, standard NIP-06, no passphrase):
      ver(1)=2 | pbkdf2-iters u32 LE | salt(16) | gcm-nonce(12)
      | ct(128, 1-byte length + up to 127 mnemonic chars, zero-padded) | tag(16)

Usage:
    python3 tools/vault-recover.py <vault-hex-or-file> <pin>

Needs: pip install cryptography
"""

import hashlib
import struct
import sys
from pathlib import Path


def decrypt_v1(raw, pin):
    iters = struct.unpack_from("<I", raw, 1)[0]
    salt, nonce, ct, tag = raw[5:21], raw[21:33], raw[33:65], raw[65:81]
    kek = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iters)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        seckey = AESGCM(kek).decrypt(nonce, ct + tag, None)
    except Exception:
        sys.exit("decryption failed: wrong PIN or corrupt blob")

    print(f"seckey hex: {seckey.hex()}")
    print("(legacy v1 vault -- raw key, no mnemonic ever existed for this key)")
    print("convert to nsec: nak encode nsec <hex>  (or any NIP-19 tool)")


def decrypt_v2(raw, pin):
    iters = struct.unpack_from("<I", raw, 1)[0]
    salt, nonce, ct, tag = raw[5:21], raw[21:33], raw[33:161], raw[161:177]
    kek = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iters)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        plain = AESGCM(kek).decrypt(nonce, ct + tag, None)
    except Exception:
        sys.exit("decryption failed: wrong PIN or corrupt blob")

    mlen = plain[0]
    mnemonic = plain[1 : 1 + mlen].decode()
    print(f"mnemonic: {mnemonic}")
    print("(standard NIP-06 -- derive with m/44'/1237'/0'/0/0, no passphrase,")
    print(" to get the same nsec any NIP-06-compatible signer would produce)")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, pin = sys.argv[1], sys.argv[2]

    p = Path(src)
    if p.is_file():
        raw = p.read_bytes()
        if len(raw) not in (81, 177):  # maybe a hex text file
            raw = bytes.fromhex(raw.decode().strip())
    else:
        raw = bytes.fromhex(src)

    if len(raw) == 81 and raw[0] == 1:
        decrypt_v1(raw, pin)
    elif len(raw) == 177 and raw[0] == 2:
        decrypt_v2(raw, pin)
    else:
        sys.exit(f"unrecognized vault blob (len={len(raw)}, ver={raw[0] if raw else '-'})")


if __name__ == "__main__":
    main()
