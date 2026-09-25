import time
from queue import Queue
from sender import Sender
from receiver import Receiver
from db import db_init, insert_verified, insert_rejected

def load_transactions(n=20):
    import pandas as pd
    df = pd.read_csv("data/mpesa_synthetic.csv").head(n)
    # rename schema
    df = df.rename(columns={
        "transaction_id":"transaction_id",
        "amount":"amount",
    })
    return df.to_dict(orient="records")

def main():
    db_init()
    a2r, r2a = Queue(), Queue()
    sender   = Sender(out_queue=a2r, in_queue=r2a)
    receiver = Receiver(in_queue=a2r, out_queue=r2a)

    # 1. handshake
    receiver.handshake.__wrapped__ if False else None  # no-op for clarity
    # do them in threads or interleave manually:
    import threading
    t = threading.Thread(target=receiver.handshake); t.start()
    sender.handshake()
    t.join()

    # 2. stream transactions
    for tx in load_transactions(20):
        sender.send_transaction(tx)
        time.sleep(0.01)

    # 3. drain queue at receiver
    while not a2r.empty():
        msg = a2r.get()
        if msg["type"] == "packet":
            receiver.handle(msg["bytes"])

    print("done")

if __name__ == "__main__":
    main()