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
    

if __name__ == "__main__":
    from dh import (generate_private_key, compute_public_key,
                    compute_shared_secret, derive_keys)

    print("=" * 60)
    print("Attacker demonstrations")
    print("=" * 60)

    # --- 1. Passive eavesdrop --------------------------------------
    print("\n[1] Passive eavesdrop")
    print("-" * 60)

    a = generate_private_key()
    A = compute_public_key(a)
    b = generate_private_key()
    B = compute_public_key(b)

    print(f"Alice's public key A (wire-visible):  {str(A)[:48]}...")
    print(f"Bob's   public key B (wire-visible):  {str(B)[:48]}...")
    print()
    print("The eavesdropper sees A and B but cannot compute the")
    print("shared secret g^(ab) mod p without solving the Discrete")
    print("Logarithm Problem — believed infeasible for 2048-bit")
    print("safe primes.")

    # --- 2. MITM on unauthenticated DH -----------------------------
    print("\n[2] MITM on unauthenticated DH")
    print("-" * 60)

    m = generate_private_key()
    M = compute_public_key(m)

    # Attacker derives a secret with Alice and a separate one with Bob
    shared_with_alice = compute_shared_secret(A, m)
    shared_with_bob   = compute_shared_secret(B, m)

    alice_real, alice_mac = derive_keys(compute_shared_secret(B, a))
    bob_real,   bob_mac   = derive_keys(compute_shared_secret(A, b))

    attacker_alice, _ = derive_keys(shared_with_alice)
    attacker_bob,   _ = derive_keys(shared_with_bob)

    print(f"Alice <-> Bob real shared key:     {alice_real.hex()[:32]}...")
    print(f"Attacker <-> Alice derived key:    {attacker_alice.hex()[:32]}...")
    print(f"Attacker <-> Bob   derived key:    {attacker_bob.hex()[:32]}...")
    print()
    print("Attacker sits in the middle: decrypts/re-encrypts every")
    print("packet transparently. Neither side can tell.")
    print()
    print(">>> This is why unauthenticated DH is not enough. Real")
    print("    deployments authenticate the DH public keys with")
    print("    signatures or a pre-shared fingerprint (TLS, Noise,")
    print("    Signal, SSH all do this).")

    # --- 3. Tamper detection ---------------------------------------
    print("\n[3] Tamper detection")
    print("-" * 60)

    import os
    from crypto import (encrypt, decrypt, compute_hmac, verify_hmac)
    from packet import Packet, serialize, deserialize

    aes_key  = os.urandom(32)
    hmac_key = os.urandom(32)
    plaintext = b"transfer: 1000 KES to 2547XXXXXXXX"

    enc = encrypt(aes_key, seq_num=7, timestamp=1234567890.0,
                  plaintext=plaintext)
    mac = compute_hmac(hmac_key, 7, 1234567890.0,
                       enc["iv"], enc["tag"], enc["ciphertext"])

    print("Original packet MAC verifies:",
          verify_hmac(hmac_key, 7, 1234567890.0,
                      enc["iv"], enc["tag"], enc["ciphertext"], mac))

    tampered = bytearray(enc["ciphertext"])
    tampered[0] ^= 0x01

    print("Tampered packet MAC verifies:",
          verify_hmac(hmac_key, 7, 1234567890.0,
                      enc["iv"], enc["tag"], bytes(tampered), mac))
    print()
    print("One flipped bit is enough for the receiver to reject the")
    print("packet. This is what sends rows into rejected_packets.")

    print("\n" + "=" * 60)
    print("Done.")