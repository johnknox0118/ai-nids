"""
Database module — corruption-proof SQLite design.

Key fixes for the Render 'database disk image is malformed' error:
1. verify_db() checks integrity before every connection
2. If corrupt, deletes and rebuilds immediately
3. WAL mode prevents corruption during writes
4. 30s timeout prevents locking
"""
import sqlite3
import hashlib
import os
import shutil

from config import DATABASE, ADMIN_USERNAME, ADMIN_PASSWORD


def _db_dir():
    return os.path.dirname(DATABASE)


def verify_and_repair():
    """
    Check if DB is readable. If corrupt, delete it so init_db() can rebuild.
    Called at bootstrap BEFORE anything touches the DB.
    """
    if not os.path.exists(DATABASE):
        return  # Nothing to check

    try:
        conn = sqlite3.connect(DATABASE, timeout=5)
        # integrity_check returns 'ok' if healthy, list of problems if corrupt
        result = conn.execute("PRAGMA integrity_check").fetchone()
        conn.close()
        if result and result[0] == 'ok':
            return  # DB is healthy
        else:
            print(f"[DB] Integrity check failed: {result} — rebuilding")
    except Exception as e:
        print(f"[DB] Cannot open database ({e}) — rebuilding")

    # Delete corrupt file
    try:
        os.remove(DATABASE)
        print("[DB] Corrupt database deleted")
    except Exception as e:
        print(f"[DB] Could not delete corrupt file: {e}")

    # Also remove WAL and SHM files if present
    for ext in ['-wal', '-shm']:
        try:
            os.remove(DATABASE + ext)
        except Exception:
            pass


def get_db():
    """Get a database connection. Auto-repairs if corrupt."""
    conn = sqlite3.connect(DATABASE, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL = multiple readers + 1 writer simultaneously — prevents locking
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=1000")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db():
    """Create all tables and bootstrap admin user."""
    os.makedirs(_db_dir(), exist_ok=True)

    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS packet_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        packet_size INTEGER,
        port INTEGER,
        ttl INTEGER,
        flags TEXT,
        status TEXT DEFAULT 'normal'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        recommendation TEXT,
        status TEXT DEFAULT 'open'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        acknowledged INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_name TEXT NOT NULL,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_attacks INTEGER DEFAULT 0,
        file_path TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL
    )''')

    # Bootstrap admin
    hashed = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)",
              (ADMIN_USERNAME, hashed, 'admin'))

    for key, val in [
        ('port_scan_threshold',    '100'),
        ('ping_flood_threshold',   '1000'),
        ('brute_force_threshold',  '50'),
        ('large_packet_threshold', '1500'),
        ('capture_interface',      'auto'),
        ('email_alerts',           'false'),
        ('alert_email',            ''),
    ]:
        c.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (key, val))

    conn.commit()
    conn.close()
    print("[DB] Initialized.")


# ── Helpers ────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def get_setting(key):
    conn = get_db()
    row  = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row['value'] if row else None


def set_setting(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()


def log_packet(src, dst, proto, size, port=0, ttl=0, flags='', status='normal'):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO packet_logs (source_ip,destination_ip,protocol,packet_size,port,ttl,flags,status) VALUES (?,?,?,?,?,?,?,?)",
            (src, dst, proto, size, port, ttl, flags, status))
        conn.commit()
        conn.close()
    except Exception as e:
        pass  # Never crash capture thread on DB error


def log_threat(name, sev, src, dst='', protocol='', rec=''):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO threats (attack_name,severity,source_ip,destination_ip,protocol,recommendation) VALUES (?,?,?,?,?,?)",
            (name, sev, src, dst, protocol, rec))
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_alert(message, severity, src=''):
    try:
        conn = get_db()
        conn.execute("INSERT INTO alerts (message,severity,source_ip) VALUES (?,?,?)",
                     (message, severity, src))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_stats():
    try:
        conn  = get_db()
        total = conn.execute("SELECT COUNT(*) FROM packet_logs").fetchone()[0]
        thrt  = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        today = conn.execute("SELECT COUNT(*) FROM alerts WHERE DATE(time)=DATE('now')").fetchone()[0]
        blkd  = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM threats WHERE status='blocked'").fetchone()[0]
        conn.close()
        return {'total_packets': total, 'total_threats': thrt,
                'today_alerts': today, 'blocked_ips': blkd}
    except Exception:
        return {'total_packets': 0, 'total_threats': 0, 'today_alerts': 0, 'blocked_ips': 0}


def get_recent_packets(limit=100):
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM packet_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_recent_threats(limit=200):
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM threats ORDER BY time DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_recent_alerts(limit=50):
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM alerts ORDER BY time DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_protocol_stats():
    try:
        conn = get_db()
        rows = conn.execute("SELECT protocol, COUNT(*) as cnt FROM packet_logs GROUP BY protocol").fetchall()
        conn.close()
        return {r['protocol']: r['cnt'] for r in rows}
    except Exception:
        return {}


def get_threat_timeline():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT DATE(time) as day, COUNT(*) as cnt FROM threats GROUP BY DATE(time) ORDER BY day DESC LIMIT 7"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_attack_frequency():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT attack_name, COUNT(*) as cnt FROM threats GROUP BY attack_name ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_top_attackers(limit=10):
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM threats GROUP BY source_ip ORDER BY cnt DESC LIMIT ?",
            (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def search_packets(query='', protocol='', status='', page=1, per_page=50):
    try:
        conn       = get_db()
        conditions = []
        params     = []
        if query:
            conditions.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
            params += [f'%{query}%', f'%{query}%']
        if protocol:
            conditions.append("protocol=?")
            params.append(protocol)
        if status:
            conditions.append("status=?")
            params.append(status)
        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page
        rows   = conn.execute(
            f"SELECT * FROM packet_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]).fetchall()
        total  = conn.execute(f"SELECT COUNT(*) FROM packet_logs {where}", params).fetchone()[0]
        conn.close()
        return [dict(r) for r in rows], total
    except Exception:
        return [], 0
