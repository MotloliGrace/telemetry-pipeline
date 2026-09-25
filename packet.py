from dataclasses import dataclass, field
import time
import json
import struct


@dataclass
class Packet:
    seq_num: int
    payload: dict
    timestamp: float = field(default_factory=time.time)
    iv: bytes = b""
    tag: bytes = b""
    hmac: bytes = b""


def serialize(packet: Packet) -> bytes:
    payload_bytes = json.dumps(packet.payload).encode("utf-8")
    return (packet.seq_num.to_bytes(4, byteorder="big")
            + struct.pack("!d", packet.timestamp)
            + len(packet.iv).to_bytes(2, "big") + packet.iv
            + len(packet.tag).to_bytes(2, "big") + packet.tag
            + len(packet.hmac).to_bytes(2, "big") + packet.hmac
            + len(payload_bytes).to_bytes(4, "big") + payload_bytes)


def deserialize(data: bytes) -> Packet:
    pos = 0
    seq_num = int.from_bytes(data[pos:pos+4], byteorder="big")
    pos += 4
    timestamp = struct.unpack("!d", data[pos:pos+8])[0]
    pos += 8

    def read_field(n_length_bytes: int) -> bytes:
        nonlocal pos
        length = int.from_bytes(data[pos:pos+n_length_bytes], byteorder="big")
        pos += n_length_bytes
        field_bytes = data[pos:pos+length]
        pos += length
        return field_bytes

    iv = read_field(2)
    tag = read_field(2)
    hmac = read_field(2)
    payload = json.loads(read_field(4).decode("utf-8"))
    return Packet(seq_num=seq_num, payload=payload, timestamp=timestamp,
                  iv=iv, tag=tag, hmac=hmac)