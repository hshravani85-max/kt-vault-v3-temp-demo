import sqlite3
import os

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'kt_vault_v3.db')

DB_PATH = DEFAULT_DB_PATH

def get_db_path() -> str:
    """
    Returns the active database file path.
    Prioritizes environment variable KT_VAULT_DB_PATH,
    falling back to module-level DB_PATH (allowing tests to isolate databases),
    and finally DEFAULT_DB_PATH.
    """
    env_path = os.environ.get("KT_VAULT_DB_PATH")
    if env_path and env_path.strip():
        return env_path.strip()
    return DB_PATH

def is_wal_enabled_by_config() -> bool:
    """Returns True when SQLite WAL journal mode is explicitly enabled for multi-request deployments."""
    return os.environ.get("KT_VAULT_SQLITE_WAL", "").strip().lower() in ("1", "true", "yes", "on")


def enable_wal_mode(conn) -> str:
    """Enables SQLite WAL mode and NORMAL synchronous durability on the given connection."""
    row = conn.execute("PRAGMA journal_mode = WAL;").fetchone()
    conn.execute("PRAGMA synchronous = NORMAL;")
    return row[0] if row else "unknown"


def get_connection(enforce_foreign_keys: bool = True, enable_wal: bool = None):
    db_file = get_db_path()
    db_dir = os.path.dirname(db_file)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_file, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000;")
    if enforce_foreign_keys:
        conn.execute("PRAGMA foreign_keys = ON;")
    if enable_wal is True or (enable_wal is None and is_wal_enabled_by_config()):
        enable_wal_mode(conn)
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    c.executescript('''
        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            name TEXT,
            customer_type TEXT,
            status TEXT
        );
        CREATE TABLE IF NOT EXISTS travellers (
            id TEXT PRIMARY KEY,
            customer_id TEXT,
            name TEXT,
            type TEXT,
            role TEXT,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS trips (
            id TEXT PRIMARY KEY,
            customer_id TEXT,
            name TEXT,
            destination TEXT,
            start_date TEXT,
            end_date TEXT,
            trip_type TEXT,
            service TEXT,
            department TEXT,
            status TEXT,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS trip_travellers (
            trip_id TEXT,
            traveller_id TEXT,
            PRIMARY KEY(trip_id, traveller_id),
            FOREIGN KEY(trip_id) REFERENCES trips(id),
            FOREIGN KEY(traveller_id) REFERENCES travellers(id)
        );
        CREATE TABLE IF NOT EXISTS requirements (
            id TEXT PRIMARY KEY,
            trip_id TEXT,
            traveller_id TEXT,
            customer_id TEXT,
            name TEXT,
            type TEXT,
            UNIQUE(trip_id, traveller_id, name)
        );
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            requirement_id TEXT,
            status TEXT,
            extracted_data TEXT,
            file_path TEXT,
            uploaded_at TEXT,
            FOREIGN KEY(requirement_id) REFERENCES requirements(id)
        );
        CREATE TABLE IF NOT EXISTS user_profile (
            customer_id TEXT PRIMARY KEY,
            full_name TEXT,
            dob TEXT,
            nationality TEXT,
            passport_number TEXT,
            passport_expiry TEXT
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trip_id TEXT,
            customer_id TEXT,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Safely apply migrations for V3 onboarding requirements
    try:
        c.execute("ALTER TABLE customers ADD COLUMN mobile TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE customers ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE travellers ADD COLUMN dob TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE travellers ADD COLUMN relationship TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE activity ADD COLUMN customer_id TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE requirements ADD COLUMN customer_id TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_requirements_customer_doc ON requirements(customer_id, name) WHERE customer_id IS NOT NULL;")
    except sqlite3.OperationalError:
        pass

    # Safely apply migrations for Admin Archive, Delete, Replace & Recovery
    for col_sql in [
        "ALTER TABLE customers ADD COLUMN archived INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE customers ADD COLUMN archived_at TEXT",
        "ALTER TABLE customers ADD COLUMN archived_by TEXT",
        "ALTER TABLE customers ADD COLUMN archive_reason TEXT",
        "ALTER TABLE documents ADD COLUMN archived INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE documents ADD COLUMN archived_at TEXT",
        "ALTER TABLE documents ADD COLUMN archived_by TEXT",
        "ALTER TABLE documents ADD COLUMN archive_reason TEXT"
    ]:
        try:
            c.execute(col_sql)
        except sqlite3.OperationalError:
            pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS document_versions (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            version_number INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            sha256_checksum TEXT NOT NULL,
            original_filename TEXT,
            mime_type TEXT,
            size_bytes INTEGER,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            replacement_reason TEXT,
            replaced_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(document_id) REFERENCES documents(id)
        );
    """)
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_versions_unique ON document_versions(document_id, version_number);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_doc_versions_doc_id ON document_versions(document_id);")

    c.execute("""
        CREATE TABLE IF NOT EXISTS deletion_requests (
            id TEXT PRIMARY KEY,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_by_role TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            reviewed_by TEXT,
            reviewed_at TEXT,
            review_notes TEXT
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_deletion_requests_status ON deletion_requests(status);")

    try:
        c.execute("ALTER TABLE security_audit_logs ADD COLUMN previous_event_hash TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE security_audit_logs ADD COLUMN event_hash TEXT")
    except sqlite3.OperationalError:
        pass

    # Safely apply idempotent auth/MFA schemas without import-time DB side effects
    try:
        import auth_services
        auth_services.init_auth_schema(conn)
    except Exception:
        pass
    try:
        import mfa_service
        mfa_service.init_mfa_schema(conn)
    except Exception:
        pass
    
    c.execute("INSERT OR IGNORE INTO customers (id, name, customer_type, status) VALUES (?, ?, ?, ?)",
              ('KT-C-0001', 'Amit Mehta', 'Individual', 'Active'))
    
    c.execute("INSERT OR IGNORE INTO travellers (id, customer_id, name, type, role) VALUES (?, ?, ?, ?, ?)",
              ('KT-TR-0001', 'KT-C-0001', 'Amit Mehta', 'Adult', 'Lead Traveller'))
              
    c.execute("INSERT OR IGNORE INTO trips (id, customer_id, name, destination, start_date, end_date, trip_type, service, department, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              ('KT-T-0001', 'KT-C-0001', 'Dubai Holiday', 'Dubai, UAE', '2026-12-12', '2026-12-18', 'Holiday', 'International Package', 'Operations', 'Documents In Progress'))
              
    c.execute("INSERT OR IGNORE INTO trip_travellers (trip_id, traveller_id) VALUES (?, ?)",
              ('KT-T-0001', 'KT-TR-0001'))
              
    reqs = [
        ('REQ-TR-01', 'KT-T-0001', 'KT-TR-0001', 'Passport', 'TRAVELLER'),
        ('REQ-TR-02', 'KT-T-0001', 'KT-TR-0001', 'Visa / Entry Document', 'TRAVELLER'),
        ('REQ-T-01', 'KT-T-0001', None, 'Flight Ticket', 'TRIP'),
        ('REQ-T-02', 'KT-T-0001', None, 'Hotel Voucher', 'TRIP'),
        ('REQ-T-03', 'KT-T-0001', None, 'Travel Insurance', 'TRIP'),
        ('REQ-T-04', 'KT-T-0001', None, 'Transfer Voucher', 'TRIP'),
        ('REQ-T-05', 'KT-T-0001', None, 'Sightseeing Voucher', 'TRIP'),
        ('REQ-T-06', 'KT-T-0001', None, 'Arrival / Entry Document', 'TRIP'),
        ('REQ-T-07', 'KT-T-0001', None, 'Itinerary', 'TRIP')
    ]
    for r in reqs:
        c.execute("INSERT OR IGNORE INTO requirements (id, trip_id, traveller_id, name, type) VALUES (?, ?, ?, ?, ?)", r)
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
