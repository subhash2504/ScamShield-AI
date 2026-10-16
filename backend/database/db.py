import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from backend.config import get_config

def get_db_connection(db_path=None):
    """Establish and return a SQLite database connection with row factory."""
    if db_path is None:
        db_path = get_config().DATABASE_PATH
    
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=None):
    """Initialize the SQLite database schema."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            scan_type TEXT NOT NULL,
            target_snippet TEXT,
            timestamp DATETIME NOT NULL,
            risk_category TEXT NOT NULL,
            risk_score REAL NOT NULL,
            indicators_summary TEXT,
            recommendations TEXT
        )
    """)
    conn.commit()
    conn.close()

def record_scan(scan_type: str, risk_category: str, risk_score: float, 
                indicators: list, recommendations: list = None, 
                target_snippet: str = None, db_path=None) -> str:
    """
    Safely record a scan event with minimal telemetry.
    Full private messages are NOT retained.
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    # Truncate and sanitize snippet (max 80 chars)
    sanitized_snippet = ""
    if target_snippet:
        sanitized_snippet = target_snippet.strip().replace("\n", " ")[:80]
    
    # Extract indicator titles only
    ind_titles = []
    if indicators:
        for ind in indicators:
            if isinstance(ind, dict):
                ind_titles.append(ind.get("title") or ind.get("name") or "Indicator")
            elif isinstance(ind, str):
                ind_titles.append(ind)
                
    indicators_json = json.dumps(ind_titles)
    recs_json = json.dumps(recommendations or [])

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (scan_id, scan_type, target_snippet, timestamp, risk_category, risk_score, indicators_summary, recommendations)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, scan_type, sanitized_snippet, timestamp, risk_category, float(risk_score), indicators_json, recs_json))
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 50, db_path=None) -> list:
    """Retrieve the most recent scans ordered by timestamp descending."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, scan_type, target_snippet, timestamp, risk_category, risk_score, indicators_summary
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        ind_list = []
        if row["indicators_summary"]:
            try:
                ind_list = json.loads(row["indicators_summary"])
            except Exception:
                ind_list = []
        results.append({
            "scan_id": row["scan_id"],
            "scan_type": row["scan_type"],
            "target_snippet": row["target_snippet"],
            "timestamp": row["timestamp"],
            "risk_category": row["risk_category"],
            "risk_score": row["risk_score"],
            "indicators_summary": ind_list
        })
    return results

def get_scan_stats(db_path=None) -> dict:
    """Aggregate statistics for the analytics dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'High Risk'")
    high_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'Medium Risk'")
    medium_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'Low Risk'")
    low_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'Unable to Determine'")
    undetermined_count = cursor.fetchone()[0]

    # Channel distribution
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    channel_counts = dict(cursor.fetchall())

    # Daily trends (last 7 days)
    cursor.execute("""
        SELECT date(timestamp) as scan_date, COUNT(*)
        FROM scans
        GROUP BY date(timestamp)
        ORDER BY scan_date DESC
        LIMIT 7
    """)
    trend_rows = cursor.fetchall()
    trends = [{"date": r[0], "count": r[1]} for r in reversed(trend_rows)]

    conn.close()

    return {
        "total_scans": total_scans,
        "high_risk_count": high_risk_count,
        "medium_risk_count": medium_risk_count,
        "low_risk_count": low_risk_count,
        "risk_distribution": {
            "High Risk": high_risk_count,
            "Medium Risk": medium_risk_count,
            "Low Risk": low_risk_count,
            "Unable to Determine": undetermined_count
        },
        "channel_distribution": {
            "message": channel_counts.get("message", 0),
            "url": channel_counts.get("url", 0),
            "email": channel_counts.get("email", 0),
            "screenshot": channel_counts.get("screenshot", 0)
        },
        "trends": trends
    }

def clear_scans(db_path=None) -> int:
    """Purge all scan records from the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted
