CREATE TABLE IF NOT EXISTS verified_packets (
    seq_num     INTEGER PRIMARY KEY,
    tx_id       TEXT,
    amount      REAL,
    receiver_before REAL,
    receiver_after  REAL,
    sender_before   REAL,
    sender_after    REAL,
    hour        INTEGER,
    month       INTEGER,
    day_of_week INTEGER,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rejected_packets (
    id          INTEGER PRIMARY KEY ,AUTO INCREMENT,
    seq_num     INTEGER,
    reason      TEXT NOT NULL,
    rejected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);