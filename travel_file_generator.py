import os
import re
import secrets
from datetime import datetime
import json
import sqlite3
import database
import auth_services

def generate_consolidated_travel_file(trip_id, out_path=None, session_token=None):
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required to generate travel files.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    if not trip_id or not isinstance(trip_id, str) or not re.match(r'^[A-Za-z0-9_-]+$', trip_id):
        raise ValueError("Invalid trip_id format.")

    if out_path is not None:
        if '..' in out_path.replace('\\', '/').split('/') or '..' in out_path:
            raise PermissionError(f"Security violation: Path traversal detected in output path '{out_path}'.")
    else:
        out_path = f"documents/TravelFile_{trip_id}.pdf"

    conn = database.get_connection()
    try:
        trip = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
        if not trip:
            raise ValueError(f"Trip not found: '{trip_id}'.")
            
        if trip['status'] != 'TRAVEL FILE READY':
            raise ValueError(f"Cannot generate travel file: Trip '{trip_id}' is not approved (status is '{trip['status']}').")
            
        cust = conn.execute("SELECT name FROM customers WHERE id = ?", (trip['customer_id'],)).fetchone()
        
        trip_travellers = conn.execute('''
            SELECT t.* FROM travellers t
            JOIN trip_travellers tt ON t.id = tt.traveller_id
            WHERE tt.trip_id = ?
        ''', (trip_id,)).fetchall()
        
        docs = conn.execute('''
            SELECT r.name as req_name, r.type as req_type, d.status, d.extracted_data, t.name as traveller_name
            FROM requirements r
            LEFT JOIN documents d ON r.id = d.requirement_id
            LEFT JOIN travellers t ON r.traveller_id = t.id
            WHERE r.trip_id = ?
        ''', (trip_id,)).fetchall()

        lines = [
            f"Customer: {cust['name'] if cust else 'Unknown'}",
            f"Trip: {trip['name']} ({trip['destination']})",
            f"Dates: {trip['start_date']} to {trip['end_date']}",
            f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Travellers:"
        ]
        
        for t in trip_travellers:
            trav_passport = str(t['passport_number']).strip() if (t['passport_number'] and str(t['passport_number']).strip()) else None

            # Retrieve Verified Passport document for this exact traveller on this specific trip
            doc_row = conn.execute('''
                SELECT d.extracted_data
                FROM documents d
                JOIN requirements r ON d.requirement_id = r.id
                WHERE r.trip_id = ?
                  AND r.traveller_id = ?
                  AND r.name = 'Passport'
                  AND d.status = 'Verified'
                ORDER BY d.uploaded_at DESC, d.id DESC LIMIT 1
            ''', (trip_id, t['id'])).fetchone()

            doc_passport = None
            if doc_row and doc_row['extracted_data']:
                try:
                    ext_dict = json.loads(doc_row['extracted_data'])
                    if isinstance(ext_dict, dict):
                        raw_val = ext_dict.get('Passport Number')
                        if raw_val and str(raw_val).strip():
                            doc_passport = str(raw_val).strip()
                except Exception:
                    doc_passport = None

            if trav_passport and doc_passport:
                if trav_passport.upper() != doc_passport.upper():
                    raise ValueError(
                        f"Passport conflict for traveller '{t['name']}': profile passport '{trav_passport}' "
                        f"does not match verified document passport '{doc_passport}'. "
                        f"Please reconcile before generating travel file."
                    )
                resolved_passport = trav_passport
            elif trav_passport:
                resolved_passport = trav_passport
            elif doc_passport:
                resolved_passport = doc_passport
            else:
                resolved_passport = "N/A"

            lines.append(f" - {t['name']} (Passport: {resolved_passport})")

        lines.extend(["", "Document Status Checklist:"])
        
        for d in docs:
            # Exclude optional personal identity cards (PAN / Aadhaar) from the travel package
            if d['req_name'] in ['Aadhaar Card', 'PAN Card']:
                continue
            status = d['status'] or "Missing"
            if d['req_type'] == 'TRAVELLER':
                label = f"{d['traveller_name']} - {d['req_name']}"
            else:
                label = f"Trip - {d['req_name']}"
            lines.append(f" - {label}: [{status}]")
    finally:
        conn.close()

    return create_raw_pdf(out_path, "KHANNA TRAVELS - TRAVEL FILE", lines, session_token=session_token)

def create_raw_pdf(path, title, lines, session_token=None):
    if '..' in path.replace('\\', '/').split('/') or '..' in path:
        raise PermissionError(f"Security violation: Path traversal detected in output path '{path}'.")

    stream_lines = ["BT", "/F1 18 Tf", f"50 720 Td", f"({title}) Tj", "/F1 12 Tf", "0 -30 Td"]
    for line in lines:
        clean_line = line.replace("(", "\\(").replace(")", "\\)")
        stream_lines.append(f"({clean_line}) Tj")
        stream_lines.append("0 -20 Td")
    stream_lines.append("ET")
    
    stream_content = "\n".join(stream_lines) + "\n"
    stream_bytes = stream_content.encode('latin1')
    stream_len = len(stream_bytes)
    
    objects = []
    objects.append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n")
    objects.append("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objects.append(f"5 0 obj\n<< /Length {stream_len} >>\nstream\n{stream_content}endstream\nendobj\n")
    
    pdf_bytes = bytearray(b"%PDF-1.4\n")
    
    offsets = [0]
    for obj_str in objects:
        offsets.append(len(pdf_bytes))
        pdf_bytes.extend(obj_str.encode('latin1'))
        
    startxref = len(pdf_bytes)
    
    xref = f"xref\n0 {len(offsets)}\n"
    xref += "0000000000 65535 f \n"
    for i in range(1, len(offsets)):
        xref += f"{offsets[i]:010d} 00000 n \n"
        
    pdf_bytes.extend(xref.encode('latin1'))
    
    trailer = f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n"
    pdf_bytes.extend(trailer.encode('latin1'))
    
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    import storage_service
    is_external = False
    try:
        storage_service.validate_storage_path(path)
    except Exception:
        is_external = True

    res = storage_service.write_document_file(
        path,
        bytes(pdf_bytes),
        session_token=session_token,
        system_context=(session_token is None),
        allow_external=is_external
    )
    return res.get('file_path', path)
