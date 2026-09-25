import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "telemetry.db"

print("DB file exists:", DB_PATH.exists())
print("DB file path:  ", DB_PATH.resolve())

if not DB_PATH.exists():
    print("No database file at that path.")
else:
    c = sqlite3.connect(DB_PATH)
    tables = [r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    print("Tables:", tables)

    for t in tables:
        count = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {count} rows")

    if "rejected_packets" in tables:
        rows = c.execute(
            "SELECT seq_num, reason FROM rejected_packets LIMIT 10"
        ).fetchall()
        print("Sample rejections:", rows)