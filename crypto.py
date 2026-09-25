"""
Symmetric crypto layer.

Design: ENCRYPT-THEN-MAC
    1. AES-GCM encrypts payload -> ciphertext + iv + tag
       (GCM already authenticates the ciphertext; the tag catches tamper)
    2. HMAC-SHA256 over (seq_num || timestamp || iv || tag || ciphertext)
       adds an end-to-end integrity check keyed by a DIFFERENT key than AES.
"""
import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(aes_key: bytes, seq_num: int, timestamp: float, plaintext: bytes) -> dict:
    """
    Encrypt. We pass seq_num/timestamp as GCM 'associated data' so they are
    authenticated but not encrypted (they must stay readable for routing).
    """
    iv = os.urandom(12)                # 96-bit nonce, recommended for GCM
    aad = seq_num.to_bytes(4, "big") + timestamp.hex().encode()
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    # cryptography appends the 16-byte tag to the ciphertext
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return {"iv": iv, "ciphertext": ciphertext, "tag": tag, "aad": aad}


def decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext + tag, aad)


def compute_hmac(hmac_key: bytes, seq_num: int, timestamp: float,
                 iv: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """MAC over the full authenticated context (encrypt-then-MAC)."""
    msg = (seq_num.to_bytes(4, "big")
           + timestamp.hex().encode()
           + iv + tag + ciphertext)
    return hmac.new(hmac_key, msg, hashlib.sha256).digest()
def compute_hmac(hmac_key: bytes, seq_num: int, timestamp: float,
                 iv: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """MAC over the full authenticated context (encrypt-then-MAC)."""
    msg = (seq_num.to_bytes(4, "big")
           + timestamp.hex().encode()
           + iv + tag + ciphertext)
    return hmac.new(hmac_key, msg, hashlib.sha256).digest()


def verify_hmac(hmac_key: bytes, seq_num: int, timestamp: float,
                iv: bytes, tag: bytes, ciphertext: bytes,
                received_hmac: bytes) -> bool:
    expected = compute_hmac(hmac_key, seq_num, timestamp, iv, tag, ciphertext)
    return hmac.compare_digest(expected, received_hmac)

def verify_hmac(hmac_key: bytes, seq_num: int, timestamp: float,
                iv: bytes, tag: bytes, ciphertext: bytes, received_hmac: bytes) -> bool:
    expected = compute_hmac(hmac_key, seq_num, timestamp, iv, tag, ciphertext)
    # hmac.compare_digest is constant-time -> no timing side channel.
    return hmac.compare_digest(expected, received_hmac)