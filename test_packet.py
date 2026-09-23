import random,string
from packet import Packet,serialize,deserialize

def random_payload():
    return {"tx_id":"".join(random.choices(string.ascii_letters,k=12)),
            "amount":random.randint(1,1000),
            "sender":"Alice",
            "note":"hello, world",}
for i in range(100):
    p=Packet(seq_num=i, payload=random_payload())
    assert deserialize(serialize(p))==p,f"round-trip failed at seq{i}"

#edge cases
p=Packet(0,{})
assert deserialize(serialize(p))==p,"empty payload failed!"
big=Packet(2**31,{"big":"x"*5000})
assert deserialize(serialize(big))==big,"large packet failed"
print("all round trips passed!")