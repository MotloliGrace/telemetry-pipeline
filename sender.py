"""
Sender: performs DH with receiver, encrypts each transaction, sends over queue.
"""
import time
import base64
from queue import Queue

from packet import Packet, serialize
from dh import (generate_private_key, compute_public_key,
                compute_shared_secret, derive_keys)
from crypto import encrypt, compute_hmac


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Sender:
    def __init__(self, out_queue: Queue, in_queue: Queue):
        self.out = out_queue
        self.inbox = in_queue
        self.aes_key = None
        self.hmac_key = None
        self.seq = 0

    def handshake(self):
        """Unauthenticated DH handshake. (Vulnerable to MITM -- demoed in attacker.py.)"""
        a = generate_private_key()
        A = compute_public_key(a)
        self.out.put({"type": "dh_pub", "value": A})

        msg = self.inbox.get()   # blocking wait for receiver's public key
        B = msg["value"]
        shared = compute_shared_secret(B, a)
        self.aes_key, self.hmac_key = derive_keys(shared)
        print("[sender] handshake complete")

    def send_transaction(self, tx: dict):
        pkt = Packet(seq_num=self.seq, payload={}, timestamp=time.time())
        # 1. serialize the plaintext transaction
        plaintext = str(tx).encode()    # or json.dumps(tx).encode() -- your choice
        # 2. encrypt
        enc = encrypt(self.aes_key, pkt.seq_num, pkt.timestamp, plaintext)
        # 3. MAC the ciphertext + header
        mac = compute_hmac(self.hmac_key, pkt.seq_num, pkt.timestamp,
                           enc["iv"], enc["tag"], enc["ciphertext"])
        # 4. fill the packet
        pkt.iv = enc["iv"]
        pkt.tag = enc["tag"]
        pkt.hmac = mac
        pkt.payload = {
            "ciphertext": b64e(enc["ciphertext"]),
            "tx_id": tx.get("transaction_id", "?"),  # plaintext hint, OK for routing
        }
        self.out.put({"type": "packet", "bytes": serialize(pkt)})
        self.seq += 1