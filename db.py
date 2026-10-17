"""
Shared SQLite logging layer for all honeypot protocol services.
Thread-safe via a per-call connection (SQLite handles this fine at this scale).
"""
import sqlite3
import threading
import time
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "honeypot.db")
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    event_type TEXT NOT NULL,   -- connect, auth_attempt, command, disconnect, error
    detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    username TEXT,
    password TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts);
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()


def log_event(protocol, src_ip, src_port, event_type, detail=""):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO events (ts, protocol, src_ip, src_port, event_type, detail) VALUES (?,?,?,?,?,?)",
            (time.time(), protocol, src_ip, src_port, event_type, detail),
        )
        conn.commit()
        conn.close()


def log_auth(protocol, src_ip, username, password):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO auth_attempts (ts, protocol, src_ip, username, password) VALUES (?,?,?,?,?)",
            (time.time(), protocol, src_ip, username, password),
        )
        conn.commit()
        conn.close()


def get_recent_events(limit=200, protocol=None):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        if protocol and protocol != "all":
            cur = conn.execute(
                "SELECT * FROM events WHERE protocol=? ORDER BY id DESC LIMIT ?", (protocol, limit)
            )
        else:
            cur = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


def get_recent_auth(limit=200):
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM auth_attempts ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


def get_stats():
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT protocol, COUNT(*) as c FROM events WHERE event_type='connect' GROUP BY protocol"
        )
        by_proto = {r["protocol"]: r["c"] for r in cur.fetchall()}
        total = conn.execute("SELECT COUNT(*) c FROM events WHERE event_type='connect'").fetchone()["c"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM events").fetchone()["c"]
        auth_total = conn.execute("SELECT COUNT(*) c FROM auth_attempts").fetchone()["c"]
        conn.close()
        return {
            "by_protocol": by_proto,
            "total_connections": total,
            "unique_ips": unique_ips,
            "auth_attempts": auth_total,
        }


def export_logs_json():
    return {"events": get_recent_events(limit=100000), "auth_attempts": get_recent_auth(limit=100000)}
