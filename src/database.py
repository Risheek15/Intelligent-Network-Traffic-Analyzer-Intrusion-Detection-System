"""
database.py

Thin SQLite wrapper for storing every processed traffic window and,
separately, the subset that got flagged as an incident.
"""

import sqlite3
import json
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "traffic.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    packet_count INTEGER,
    byte_count INTEGER,
    tcp_ratio REAL,
    udp_ratio REAL,
    icmp_ratio REAL,
    features_json TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source_model TEXT NOT NULL,       -- 'random_forest' or 'isolation_forest'
    label TEXT,                       -- e.g. 'port_scan', 'dos', 'anomaly'
    confidence REAL,
    features_json TEXT,
    reviewed INTEGER DEFAULT 0,       -- admin can mark true/false positive
    verdict TEXT DEFAULT NULL         -- 'true_positive' / 'false_positive'
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'technician'
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    # Ensure default admin account exists
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')"
    )
    conn.commit()
    conn.close()


def add_user(username, password, role="technician"):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)",
            (username.strip(), password.strip(), role),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def authenticate_user(username, password):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username.strip(), password.strip()),
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def log_window(features):
    conn = get_connection()
    conn.execute(
        """INSERT INTO windows
           (timestamp, packet_count, byte_count, tcp_ratio, udp_ratio, icmp_ratio, features_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            time.time(),
            features.get("packet_count", 0),
            features.get("byte_count", 0),
            features.get("tcp_ratio", 0),
            features.get("udp_ratio", 0),
            features.get("icmp_ratio", 0),
            json.dumps(features),
        ),
    )
    conn.commit()
    conn.close()


def log_incident(source_model, label, confidence, features):
    conn = get_connection()
    conn.execute(
        """INSERT INTO incidents
           (timestamp, source_model, label, confidence, features_json)
           VALUES (?, ?, ?, ?, ?)""",
        (time.time(), source_model, label, confidence, json.dumps(features)),
    )
    conn.commit()
    conn.close()


def get_recent_windows(limit=100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM windows ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("features_json"):
            try:
                d["features"] = json.loads(d["features_json"])
            except Exception:
                d["features"] = {}
        else:
            d["features"] = {}
        result.append(d)
    return result


def _enrich_incident(row_dict):
    feats = {}
    if row_dict.get("features_json"):
        try:
            feats = json.loads(row_dict["features_json"])
        except Exception:
            pass

    src_ip = feats.get("src_ip", "-")
    dst_ip = feats.get("dst_ip", "-")
    dst_port = feats.get("dst_port", "-")
    protocol = feats.get("protocol", "TCP")
    label = (row_dict.get("label") or "").lower()

    if label in ("dos", "brute_force"):
        severity = "HIGH"
    elif label == "port_scan":
        severity = "MEDIUM"
    else:
        score = row_dict.get("confidence") or 0.0
        severity = "MEDIUM" if score < -0.12 else "LOW"

    suggested_action = None
    firewall_cmd = None

    if label == "port_scan":
        suggested_action = (
            f"Active port reconnaissance detected from host {src_ip}. The host is probing multiple "
            f"open ports to identify vulnerable services. Recommended action: Immediately block all inbound "
            f"traffic from {src_ip} at the Windows Firewall to terminate reconnaissance."
        )
        if src_ip and src_ip != "-":
            firewall_cmd = f'New-NetFirewallRule -DisplayName "IDS_Block_{src_ip}" -Direction Inbound -Action Block -RemoteAddress "{src_ip}"'
    elif label == "dos":
        suggested_action = (
            f"Volumetric Denial of Service (DoS) traffic detected from {src_ip}. High packet volume is "
            f"exhausting network buffers. Recommended action: Apply an immediate inbound block rule "
            f"to drop all frames originating from {src_ip}."
        )
        if src_ip and src_ip != "-":
            firewall_cmd = f'New-NetFirewallRule -DisplayName "IDS_Block_{src_ip}" -Direction Inbound -Action Block -RemoteAddress "{src_ip}"'
    elif label == "brute_force":
        suggested_action = (
            f"Rapid repetitive authentication attempts originating from {src_ip} against port {dst_port}. "
            f"Potential credential stuffing or dictionary attack. Recommended action: Block {src_ip} and audit "
            f"authentication logs on the target service."
        )
        if src_ip and src_ip != "-":
            firewall_cmd = f'New-NetFirewallRule -DisplayName "IDS_Block_{src_ip}" -Direction Inbound -Action Block -RemoteAddress "{src_ip}"'

    row_dict["src_ip"] = src_ip
    row_dict["dst_ip"] = dst_ip
    row_dict["dst_port"] = dst_port
    row_dict["protocol"] = protocol
    row_dict["severity"] = severity
    row_dict["suggested_action"] = suggested_action
    row_dict["firewall_cmd"] = firewall_cmd
    return row_dict


def get_recent_incidents(limit=500):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [_enrich_incident(dict(r)) for r in rows]


def get_incident_by_id(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    conn.close()
    return _enrich_incident(dict(row)) if row else None


def get_iso_threshold():
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = 'iso_threshold'").fetchone()
    conn.close()
    return float(row["value"]) if row else -0.08


def adapt_iso_threshold(verdict, score, prev_verdict=None):
    if prev_verdict == verdict:
        return get_iso_threshold()  # No change if clicking the same verdict twice

    current = get_iso_threshold()
    step = 0.25 * max(0.01, abs(score - current))

    if prev_verdict == "false_positive" and verdict == "true_positive":
        # Reversing False Positive -> True Positive: restore previous drop + add true reward
        new_val = min(-0.05, current + step + 0.01)
    elif prev_verdict == "true_positive" and verdict == "false_positive":
        # Reversing True Positive -> False Positive: remove true reward - apply false drop
        new_val = max(-0.20, current - 0.01 - step)
    elif verdict == "false_positive":
        # Fresh False Positive
        new_val = max(-0.20, current - step)
    elif verdict == "true_positive":
        # Fresh True Positive
        new_val = min(-0.05, current + 0.01)
    else:
        return current

    new_val = round(new_val, 4)
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('iso_threshold', ?)",
        (str(new_val),),
    )
    conn.commit()
    conn.close()
    return new_val


def set_incident_verdict(incident_id, verdict):
    conn = get_connection()
    conn.execute(
        "UPDATE incidents SET reviewed = 1, verdict = ? WHERE id = ?",
        (verdict, incident_id),
    )
    conn.commit()
    conn.close()


def clear_incidents():
    conn = get_connection()
    conn.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()


def clear_windows():
    conn = get_connection()
    conn.execute("DELETE FROM windows")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"[database] initialized at {DB_PATH}")
