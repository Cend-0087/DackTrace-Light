import sqlite3
import json
from datetime import datetime
from pathlib import Path

class Database:
    def __init__(self, db_path="database/darktrace.db"):
        self.db_path = Path(__file__).parent.parent / db_path
        self.db_path.parent.mkdir(exist_ok=True)
        self.init_tables()
    
    def init_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload TEXT
                );
                
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    attack_type TEXT,
                    anomaly_score REAL,
                    blocked INTEGER DEFAULT 1,
                    details TEXT
                );
                
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT,
                    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME
                );
                
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
            ''')
    
    def log_packet(self, packet):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet.get('src_ip'), packet.get('dst_ip'),
                packet.get('src_port'), packet.get('dst_port'),
                packet.get('protocol'), packet.get('length'),
                packet.get('payload', '')[:1000]
            ))
    
    def log_alert(self, src_ip, attack_type, score, details=None):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO alerts (src_ip, attack_type, anomaly_score, details)
                VALUES (?, ?, ?, ?)
            ''', (src_ip, attack_type, score, json.dumps(details) if details else None))
    
    def add_to_blacklist(self, ip, reason, duration_minutes=5):
        from datetime import datetime, timedelta
        expires = datetime.now() + timedelta(minutes=duration_minutes)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO blacklist (ip, reason, expires_at)
                VALUES (?, ?, ?)
            ''', (ip, reason, expires))
    
    def get_blacklist(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('SELECT ip FROM blacklist WHERE expires_at > datetime("now")')
            return [row[0] for row in cur.fetchall()]
    
    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM packets) as total_packets,
                    (SELECT COUNT(*) FROM alerts) as total_alerts,
                    (SELECT COUNT(*) FROM blacklist WHERE expires_at > datetime("now")) as active_blocks
            ''')
            return cur.fetchone()