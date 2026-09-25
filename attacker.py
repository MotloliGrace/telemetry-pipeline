"""
Attacker demos:
  (1) Passive eavesdrop  -> sees only opaque bytes.
  (2) Active tamper      -> HMAC verification rejects.
  (3) MITM on unauth DH  -> attacker derives BOTH shared secrets.
"""
import base64, copy
from dh import (generate_private_key, compute_public_key,
                compute_shared_secret, derive_keys)
from crypto import verify_hmac
from packet import Packet, serialize, deserialize


# --- (1) Eavesdrop: tap the queue, print what you see -----------------------
def eavesdrop(bytes_on_wire: bytes):
    pkt = deserialize(bytes_on_wire)
    print("[attacker] observed seq:", pkt.seq_num)
    print("[attacker] observed ciphertext (b64):", pkt.payload["ciphertext"][:60], "...")
    print("[attacker] without the DH secret this is opaque.")


# --- (2) Tamper: flip one byte of ciphertext --------------------------------
def tamper(bytes_on_wire: bytes) -> bytes:
    pkt = deserialize(bytes_on_wire)
    ct = bytearray(base64.b64decode(pkt.payload["ciphertext"]))
    ct[0] ^= 0x01                              # flip a bit
    pkt.payload["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    return serialize(pkt)                      # HMAC will now fail at receiver


# --- (3) MITM on unauthenticated DH ----------------------------------------
def mitm_handshake(alice_A: int, bob_B_callback):
    """
    Classic unauthenticated-DH MITM.
    Attacker sits between Alice and Bob:
       - to Alice, attacker pretends to be Bob with public M1
       - to Bob,   attacker pretends to be Alice with public M2
    Attacker then learns BOTH shared secrets.
    """
    m1 = generate_private_key(); M1 = compute_public_key(m1)
    m2 = generate_private_key(); M2 = compute_public_key(m2)

    # shared with Alice = A^m1 mod p
    shared_with_alice = compute_shared_secret(alice_A, m1)
    # shared with Bob   = B^m2 mod p  (attacker sends M2 to Bob and later receives B)
    B = bob_B_callback(M2)
    shared_with_bob = compute_shared_secret(B, m2)

    ka, hmaca = derive_keys(shared_with_alice)
    kb, hmacb = derive_keys(shared_with_bob)
    print("[attacker] MITM keys recovered:", ka.hex()[:16], "...", kb.hex()[:16], "...")
    print("[attacker] All traffic can now be decrypted and re-encrypted transparently.")