import sqlite3, os
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "telemetry.db"
SCHEMA  = Path(__file__).parent / "schema.sql"

def db_init():
    DB_PATH.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA.read_text())
    con.commit()
    return con

_conn = None
def get_conn():
    global _conn
    if _conn is None:
        _conn = db_init()
    return _conn

def insert_verified(seq_num, tx: dict):
    c = get_conn().cursor()
    c.execute("""INSERT OR REPLACE INTO verified_packets
                 (seq_num, tx_id, amount, receiver_before, receiver_after,
                  sender_before, sender_after, hour, month, day_of_week)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
              (seq_num,
               tx.get("transaction_id"), tx.get("amount"),
               tx.get("receiver_balance_before"), tx.get("receiver_balance_after"),
               tx.get("sender_balance_before"),   tx.get("sender_balance_after"),
               tx.get("hour"), tx.get("month"), tx.get("day_of_week")))
    get_conn().commit()

def insert_rejected(seq_num, reason: str):
    c = get_conn().cursor()
    c.execute("INSERT INTO rejected_packets (seq_num, reason) VALUES (?, ?)",
              (seq_num, reason))
    get_conn().commit()
__all__ = ["insert_verified", "insert_rejected"]