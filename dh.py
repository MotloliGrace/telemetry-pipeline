"""Deffie-Hellman Key exchange
    Math:
        Public:prime p,generator g
        Alice: secret a,sends A=g^a mod p
        Bob: secret b,sends B=g^b mod p
        Shared: K=B^a mod p=A^b mod p=g^(ab)mod p
        
    Security rests on the discrete logarithm problem:
        given g,p,A find a
"""
import secrets,hashlib
#RFC 3526 Group 14,2048-bit MODP.Safe prime,g=2. Using a standard group avoids small-subgroup attackes.

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
G=2

def generate_private_key()->int:
    """Random secret in[2,p-2]. secrets module =cryptographically secure."""
    return secrets.randbelow(P-3)+2

def compute_public_key(private_key: int) -> int:
    """A = g^a mod p. Python's pow() is constant-ish time for big ints."""
    return pow(G, private_key, P)

def compute_shared_secret(their_public: int, my_private: int) -> bytes:
    """K = B^a mod p, then serialize to bytes."""
    # Reject degenerate public keys (small-subgroup / invalid).
    if not (2 <= their_public <= P - 2):
        raise ValueError("Public key out of valid range")
    shared_int = pow(their_public, my_private, P)
    # Fixed-width big-endian byte encoding, so both sides produce the same bytes.
    return shared_int.to_bytes((P.bit_length() + 7) // 8, byteorder="big")

def derive_keys(shared_secret: bytes, info: bytes = b"telemetry-v1") -> tuple[bytes, bytes]:
    """
    HKDF-lite: from one shared secret, derive two independent keys.
    (Encrypt-then-MAC needs two keys -- one for AES, one for HMAC.)

    Real HKDF is RFC 5869; this is a simplified extract+expand that's fine
    for a demo but for production use `cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
    """
    prk = hashlib.sha256(shared_secret).digest()          # extract
    okm = hashlib.sha256(prk + info + b"\x01").digest()   # expand block 1
    okm2 = hashlib.sha256(prk + okm + info + b"\x02").digest()
    return okm[:32], okm2[:32]   # aes_key (32B for AES-256), hmac_key