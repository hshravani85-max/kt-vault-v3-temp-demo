"""
KT Vault V3 - Isolated Temporary Demo Environment Bootstrap (demo_bootstrap.py)

Initializes a completely isolated synthetic demo SQLite database, encrypted KTV2 demo PDFs,
and environment-configured demo staff accounts (MFA enrollment ready, zero real customer data,
zero hardcoded credentials or encryption keys).
"""

import hashlib
import io
import json
import os
import sqlite3
import uuid
from datetime import datetime


DEMO_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    name TEXT,
    customer_type TEXT,
    status TEXT,
    mobile TEXT,
    email TEXT,
    archived INTEGER NOT NULL DEFAULT 0,
    archived_at TEXT,
    archived_by TEXT,
    archive_reason TEXT
);
CREATE TABLE IF NOT EXISTS travellers (
    id TEXT PRIMARY KEY,
    customer_id TEXT,
    name TEXT,
    type TEXT,
    role TEXT,
    dob TEXT,
    relationship TEXT,
    passport_number TEXT,
    nationality TEXT,
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
    name TEXT,
    type TEXT,
    customer_id TEXT,
    UNIQUE(trip_id, traveller_id, name)
);
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    requirement_id TEXT,
    status TEXT,
    extracted_data TEXT,
    file_path TEXT,
    uploaded_at TEXT,
    archived INTEGER NOT NULL DEFAULT 0,
    archived_at TEXT,
    archived_by TEXT,
    archive_reason TEXT,
    FOREIGN KEY(requirement_id) REFERENCES requirements(id)
);
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
CREATE TABLE IF NOT EXISTS document_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT,
    event_type TEXT,
    previous_status TEXT,
    new_status TEXT,
    actor TEXT,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(document_id) REFERENCES documents(id)
);
CREATE TABLE IF NOT EXISTS document_recovery_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    pdf_sha256 TEXT NOT NULL,
    previous_extracted_data TEXT NOT NULL,
    new_extracted_data TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    outcome TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id)
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
    description TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    customer_id TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash BLOB,
    salt BLOB,
    full_name TEXT,
    role TEXT,
    is_active INTEGER DEFAULT 1,
    department TEXT DEFAULT 'General',
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    mfa_enabled INTEGER DEFAULT 0,
    auth_provider TEXT DEFAULT 'local',
    mfa_secret TEXT DEFAULT NULL,
    mfa_enrolled_at TEXT DEFAULT NULL,
    mfa_last_used_step INTEGER DEFAULT 0,
    mfa_failed_attempts INTEGER DEFAULT 0,
    mfa_locked_until TEXT DEFAULT NULL,
    mfa_recovery_hashes TEXT DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS pending_mfa_sessions (
    temp_token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_type TEXT NOT NULL,
    pending_secret TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address TEXT,
    attempts INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    username TEXT,
    user_id TEXT,
    role TEXT,
    ip_address TEXT,
    details TEXT,
    previous_event_hash TEXT,
    event_hash TEXT
);
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
CREATE INDEX IF NOT EXISTS idx_deletion_requests_status ON deletion_requests(status);
CREATE INDEX IF NOT EXISTS idx_doc_versions_doc_id ON document_versions(document_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_versions_unique ON document_versions(document_id, version_number);
CREATE INDEX IF NOT EXISTS idx_pending_mfa_user ON pending_mfa_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_audit_doc_id ON document_recovery_audit(document_id);
CREATE INDEX IF NOT EXISTS idx_recovery_audit_tx_id ON document_recovery_audit(transaction_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_requirements_customer_doc ON requirements(customer_id, name) WHERE customer_id IS NOT NULL;
"""


def _build_synthetic_pdf(title: str, lines: list[str]) -> bytes:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "SYNTHETIC DEMO DOCUMENT - FICTIONAL TEST DATA ONLY", ln=True)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, title, ln=True)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 11)
    for line in lines:
        pdf.cell(0, 7, line, ln=True)
    raw = pdf.output(dest="S")
    if isinstance(raw, (bytearray, bytes)):
        return bytes(raw)
    return raw.encode("latin-1")


def _seed_demo_accounts(auth_services) -> int:
    specs = [
        ("demo_admin", "KT_DEMO_ADMIN_PASS", "Demo Administrator", "Administrator", "Executive"),
        ("demo_ops", "KT_DEMO_OPS_PASS", "Demo Operations Lead", "Operations", "Operations"),
        ("demo_sales", "KT_DEMO_SALES_PASS", "Demo Sales Executive", "Sales", "Sales"),
        ("demo_auditor", "KT_DEMO_AUDITOR_PASS", "Demo Compliance Auditor", "Read-only Auditor", "Compliance"),
    ]
    created = 0
    for uname, env_key, full_name, role, dept in specs:
        pwd = os.environ.get(env_key, "").strip()
        if pwd:
            auth_services.create_user_account(uname, pwd, full_name, role, dept)
            created += 1
    return created


def _seed_demo_business_data(conn, storage_service, storage_root: str) -> None:
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    customers = [
        ("DEMO-C-001", "Priya Nair Demo", "Family", "Active", "+91-90000-00101", "priya.demo@example.invalid"),
        ("DEMO-C-002", "Vikram Kapoor Demo", "Corporate", "Active", "+91-90000-00102", "vikram.demo@example.invalid"),
    ]
    for c in customers:
        conn.execute(
            "INSERT OR IGNORE INTO customers (id, name, customer_type, status, mobile, email) VALUES (?, ?, ?, ?, ?, ?)",
            c,
        )

    travellers = [
        ("DEMO-TR-001", "DEMO-C-001", "Priya Nair Demo", "Adult", "Lead Traveller", "1991-04-12", "Self", "DEMO900101", "Indian"),
        ("DEMO-TR-002", "DEMO-C-001", "Riya Nair Demo", "Child", "Co-Traveller", "2016-09-03", "Daughter", "DEMO900102", "Indian"),
        ("DEMO-TR-003", "DEMO-C-002", "Vikram Kapoor Demo", "Adult", "Lead Traveller", "1986-11-20", "Self", "DEMO900201", "Indian"),
    ]
    for t in travellers:
        conn.execute(
            "INSERT OR IGNORE INTO travellers (id, customer_id, name, type, role, dob, relationship, passport_number, nationality) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            t,
        )

    trips = [
        ("DEMO-T-001", "DEMO-C-001", "Singapore Family Holiday (Demo)", "Singapore", "2026-12-20", "2026-12-27", "Holiday", "International Package", "Operations", "Documents In Progress"),
        ("DEMO-T-002", "DEMO-C-002", "Zurich Executive Summit (Demo)", "Zurich, Switzerland", "2027-01-15", "2027-01-21", "Business", "Corporate Package", "Visa", "Documents In Progress"),
    ]
    for tr in trips:
        conn.execute(
            "INSERT OR IGNORE INTO trips (id, customer_id, name, destination, start_date, end_date, trip_type, service, department, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            tr,
        )

    for link in [("DEMO-T-001", "DEMO-TR-001"), ("DEMO-T-001", "DEMO-TR-002"), ("DEMO-T-002", "DEMO-TR-003")]:
        conn.execute("INSERT OR IGNORE INTO trip_travellers (trip_id, traveller_id) VALUES (?, ?)", link)

    reqs = [
        ("DEMO-REQ-C1-AAD", None, "DEMO-TR-001", "Aadhaar Card", "CUSTOMER_MANDATORY", "DEMO-C-001"),
        ("DEMO-REQ-C1-PAN", None, "DEMO-TR-001", "PAN Card", "CUSTOMER_MANDATORY", "DEMO-C-001"),
        ("DEMO-REQ-C2-AAD", None, "DEMO-TR-003", "Aadhaar Card", "CUSTOMER_MANDATORY", "DEMO-C-002"),
        ("DEMO-REQ-C2-PAN", None, "DEMO-TR-003", "PAN Card", "CUSTOMER_MANDATORY", "DEMO-C-002"),
        ("DEMO-REQ-T1-P1", "DEMO-T-001", "DEMO-TR-001", "Passport", "TRAVELLER", None),
        ("DEMO-REQ-T1-P2", "DEMO-T-001", "DEMO-TR-002", "Passport", "TRAVELLER", None),
        ("DEMO-REQ-T1-FLT", "DEMO-T-001", None, "Flight Ticket", "TRIP", None),
        ("DEMO-REQ-T1-HTL", "DEMO-T-001", None, "Hotel Voucher", "TRIP", None),
        ("DEMO-REQ-T1-INS", "DEMO-T-001", None, "Travel Insurance", "TRIP", None),
        ("DEMO-REQ-T2-P1", "DEMO-T-002", "DEMO-TR-003", "Passport", "TRAVELLER", None),
        ("DEMO-REQ-T2-VIS", "DEMO-T-002", "DEMO-TR-003", "Visa / Entry Document", "TRAVELLER", None),
        ("DEMO-REQ-T2-FLT", "DEMO-T-002", None, "Flight Ticket", "TRIP", None),
    ]
    for r in reqs:
        conn.execute(
            "INSERT OR IGNORE INTO requirements (id, trip_id, traveller_id, name, type, customer_id) VALUES (?, ?, ?, ?, ?, ?)",
            r,
        )

    demo_docs = [
        (
            "DEMO-DOC-001",
            "DEMO-REQ-T1-P1",
            "Verified",
            {"Full Name": "Priya Nair Demo", "Passport Number": "DEMO900101", "Nationality": "Indian", "Date of Birth": "12 Apr 1991", "Expiry Date": "11 Apr 2033"},
            "demo_priya_passport.pdf",
            ("SYNTHETIC PASSPORT SAMPLE", ["Full Name: Priya Nair Demo", "Passport Number: DEMO900101", "Nationality: Indian", "Expiry: 2033-04-11"]),
        ),
        (
            "DEMO-DOC-002",
            "DEMO-REQ-C1-PAN",
            "Verified",
            {"Full Name": "Priya Nair Demo", "PAN Number": "ABCDE1234F", "Date of Birth": "12/04/1991"},
            "demo_priya_pan.pdf",
            ("SYNTHETIC PAN CARD SAMPLE", ["Full Name: Priya Nair Demo", "PAN: ABCDE1234F", "DOB: 12/04/1991"]),
        ),
        (
            "DEMO-DOC-003",
            "DEMO-REQ-T1-FLT",
            "Needs Review",
            {"Passenger Name": "Priya Nair Demo", "Route": "BOM -> SIN", "Travel Date": "2026-12-20"},
            "demo_singapore_flight.pdf",
            ("SYNTHETIC FLIGHT ITINERARY", ["Passenger: Priya Nair Demo", "Flight: DEMO-AIR 302", "Route: Mumbai (BOM) -> Singapore (SIN)", "Date: 20 Dec 2026"]),
        ),
    ]

    for doc_id, req_id, status, extracted, fname, (pdf_title, pdf_lines) in demo_docs:
        raw_pdf = _build_synthetic_pdf(pdf_title, pdf_lines)
        pdf_sha = hashlib.sha256(raw_pdf).hexdigest()
        meta = storage_service.write_document_file(
            fname,
            raw_pdf,
            system_context=True,
            key_id="ktv_2026_v1",
            envelope_version=2,
            base_dir=storage_root,
            file_storage_id=fname,
        )
        rel_path = f"documents/{fname}"
        conn.execute(
            "INSERT OR IGNORE INTO documents (id, requirement_id, status, extracted_data, file_path, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (doc_id, req_id, status, json.dumps(extracted), rel_path, now_iso),
        )
        ver_id = f"DEMO-VER-{uuid.uuid4().hex[:8]}"
        conn.execute(
            """
            INSERT OR IGNORE INTO document_versions
            (id, document_id, version_number, file_path, sha256_checksum, original_filename, mime_type, size_bytes, status, created_at, created_by, is_active)
            VALUES (?, ?, 1, ?, ?, ?, 'application/pdf', ?, ?, ?, 'demo_bootstrap', 1)
            """,
            (ver_id, doc_id, rel_path, pdf_sha, fname, len(raw_pdf), status, now_iso),
        )

    conn.execute(
        "INSERT INTO activity (trip_id, customer_id, description) VALUES (?, ?, ?)",
        ("DEMO-T-001", "DEMO-C-001", "Synthetic demo trip and KTV2 sample documents initialized."),
    )


def ensure_demo_vault() -> dict:
    """Idempotently initializes the isolated synthetic demo vault cleanly."""
    if os.environ.get("KT_DEMO_BOOTSTRAP", "").strip().lower() not in ("1", "true", "yes", "on"):
        return {"bootstrapped": False, "reason": "KT_DEMO_BOOTSTRAP not enabled"}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.environ.get("KT_VAULT_DB_PATH") or os.path.join(app_dir, "demo_runtime", "data", "kt_vault_demo.db")
    storage_root = os.environ.get("KT_VAULT_STORAGE_ROOT") or os.path.join(app_dir, "demo_runtime", "documents")
    log_dir = os.environ.get("KT_VAULT_LOG_DIR") or os.path.join(app_dir, "demo_runtime", "logs")

    os.environ["KT_VAULT_DB_PATH"] = os.path.realpath(db_path)
    os.environ["KT_VAULT_STORAGE_ROOT"] = os.path.realpath(storage_root)
    os.environ["KT_VAULT_LOG_DIR"] = os.path.realpath(log_dir)
    os.environ.setdefault("KT_VAULT_ENCRYPTION_MODE", "encrypted_only")
    os.environ.setdefault("AZAPI_ENABLED", "false")

    os.makedirs(os.path.dirname(os.environ["KT_VAULT_DB_PATH"]), exist_ok=True)
    os.makedirs(os.environ["KT_VAULT_STORAGE_ROOT"], exist_ok=True)
    os.makedirs(os.environ["KT_VAULT_LOG_DIR"], exist_ok=True)

    import database
    import storage_service
    import auth_services
    import mfa_service

    # Verify demo encryption key exists before creating vault state
    provider = storage_service.init_default_key_provider(force=True)
    if not provider.has_key("ktv_2026_v1"):
        raise RuntimeError("Demo vault requires KT_VAULT_STORAGE_KEY in environment or Streamlit Secrets.")
    storage_service.set_encryption_mode(storage_service.ENCRYPTION_MODE_ENFORCED)

    conn = sqlite3.connect(os.environ["KT_VAULT_DB_PATH"], timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        has_users = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone() is not None
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] if has_users else 0
        if has_users and user_count > 0:
            return {"bootstrapped": False, "reason": "Demo DB already initialized", "users": user_count}

        conn.executescript(DEMO_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()

    # Run standard application schema helpers safely
    auth_services.init_auth_schema()
    mfa_service.init_mfa_schema()

    created_users = _seed_demo_accounts(auth_services)

    conn2 = database.get_connection()
    try:
        _seed_demo_business_data(conn2, storage_service, os.environ["KT_VAULT_STORAGE_ROOT"])
        conn2.commit()
    finally:
        conn2.close()

    auth_services.log_security_event(
        "DEMO_VAULT_INITIALIZED",
        username="system",
        role="System",
        details=f"Synthetic demo environment initialized with {created_users} MFA-ready accounts and KTV2 documents.",
    )
    return {"bootstrapped": True, "users": created_users}
