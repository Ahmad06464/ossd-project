import sqlite3
from contextlib import contextmanager

class DB:
    def __init__(self, db_path="recon.db"):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self):
        with open("schema.sql", "r") as f:
            schema = f.read()

        with self.connect() as conn:
            conn.executescript(schema)

    # ---------------- TARGETS ----------------
    def add_target(self, domain):
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO targets(domain) VALUES(?)",
                (domain,)
            )
            return cur.lastrowid

    def get_target_id(self, domain):
        with self.connect() as conn:
            cur = conn.execute(
                "SELECT id FROM targets WHERE domain=?",
                (domain,)
            )
            row = cur.fetchone()
            return row["id"] if row else None

    # ---------------- SUBDOMAINS ----------------
    def add_subdomain(self, target_id, subdomain, source="", ip=None, status=None, title=None):
        with self.connect() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO subdomains
                (target_id, subdomain, source, ip, status, title)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (target_id, subdomain, source, ip, status, title))

    def get_subdomains(self, target_id):
        with self.connect() as conn:
            cur = conn.execute(
                "SELECT * FROM subdomains WHERE target_id=?",
                (target_id,)
            )
            return cur.fetchall()

    # ---------------- ENDPOINTS ----------------
    def add_endpoint(self, subdomain_id, url, method="GET", status=None, length=None, source=""):
        with self.connect() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO endpoints
                (subdomain_id, url, method, status, length, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (subdomain_id, url, method, status, length, source))

    def get_endpoints(self, subdomain_id):
        with self.connect() as conn:
            cur = conn.execute(
                "SELECT * FROM endpoints WHERE subdomain_id=?",
                (subdomain_id,)
            )
            return cur.fetchall()

    # ---------------- SCANS ----------------
    def start_scan(self, target_id, tool):
        with self.connect() as conn:
            cur = conn.execute("""
                INSERT INTO scans(target_id, tool, status)
                VALUES (?, ?, 'running')
            """, (target_id, tool))
            return cur.lastrowid

    def finish_scan(self, scan_id):
        with self.connect() as conn:
            conn.execute("""
                UPDATE scans
                SET status='done', finished_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (scan_id,))
            