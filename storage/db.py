"""SQLite storage for structured security events (stand-in for Elasticsearch)."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    severity TEXT,
    event_type TEXT,
    source_ip TEXT,
    target_user TEXT,
    is_attack INTEGER,
    confidence REAL,
    summary TEXT,
    recommended_action TEXT,
    detected_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(SCHEMA)
        conn.commit()


def insert_event(source: str, event: dict, detected_by: str):
    """detected_by is 'rule' or 'llm' — lets us track which layer caught what."""
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO events
               (source, severity, event_type, source_ip, target_user,
                is_attack, confidence, summary, recommended_action, detected_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                source,
                event.get("severity"),
                event.get("event_type"),
                event.get("source_ip"),
                event.get("target_user"),
                int(event.get("is_attack", False)),
                event.get("confidence", 0.0),
                event.get("summary"),
                event.get("recommended_action"),
                detected_by,
            ),
        )
        conn.commit()


def get_all_events(min_severity: str | None = None) -> list[dict]:
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
