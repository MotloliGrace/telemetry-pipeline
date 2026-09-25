"""
Receiver: performs DH, decrypts, verifies MAC, writes to DB.
"""
import ast, base64
from queue import Queue

from packet import Packet, deserialize
from dh import (generate_private_key, compute_public_key,
                compute_shared_secret, derive_keys)
from crypto import decrypt, verify_hmac
from db import insert_verified, insert_rejected

def b64d(s: str) -> bytes:
    return base64.b64decode(s)


class Receiver:
    def __init__(self, in_queue: Queue, out_queue: Queue):
        self.inbox = in_queue
        self.out = out_queue
        self.aes_key = None
        self.hmac_key = None
        self.last_seq = -1

    def handshake(self):
        msg = self.inbox.get()          # wait for sender's A
        A = msg["value"]
        b = generate_private_key()
        B = compute_public_key(b)
        self.out.put({"type": "dh_pub", "value": B})
        shared = compute_shared_secret(A, b)
        self.aes_key, self.hmac_key = derive_keys(shared)
        print("[receiver] handshake complete")

    def handle(self, raw: bytes):
        try:
            pkt = deserialize(raw)
        except Exception as e:
            insert_rejected(None, f"deserialize: {e}")
            return

        # 1. Replay / ordering check BEFORE crypto (cheap).
        if pkt.seq_num <= self.last_seq:
            insert_rejected(pkt.seq_num, "replay or out-of-order")
            return

        try:
            ct = b64d(pkt.payload["ciphertext"])
        except Exception as e:
            insert_rejected(pkt.seq_num, f"payload decode: {e}")
            return

        # 2. Verify HMAC (encrypt-then-MAC -> verify MAC FIRST).
        if not verify_hmac(self.hmac_key, pkt.seq_num, pkt.timestamp,
                           pkt.iv, pkt.tag, ct, pkt.hmac):
            insert_rejected(pkt.seq_num, "HMAC mismatch")
            return

        # 3. Decrypt.
        try:
            aad = pkt.seq_num.to_bytes(4, "big") + pkt.timestamp.hex().encode()
            plaintext = decrypt(self.aes_key, pkt.iv, ct, pkt.tag, aad)
        except Exception as e:
            insert_rejected(pkt.seq_num, f"AES-GCM auth failed: {e}")
            return

        tx = ast.literal_eval(plaintext.decode())
        insert_verified(pkt.seq_num, tx)
        self.last_seq = pkt.seq_num