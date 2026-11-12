import re
import os
import io
import logging
import pypdf

# Define Schemas
SCHEMAS = {
    'Passport': ['Full Name', 'Passport Number', 'Date of Birth', 'Nationality', 'Issue Date', 'Expiry Date', 'Place of Issue'],
    'Visa / Entry Document': ['Traveller Name', 'Visa Number / Reference', 'Destination', 'Purpose', 'Travel Dates', 'Issue Date', 'Expiry Date / Valid Until'],
    'Flight Ticket': ['Passenger Name', 'Route', 'Airline', 'Flight Number', 'PNR/Booking Reference', 'Origin', 'Destination', 'Departure Date/Time', 'Arrival Date/Time', 'Cabin Class'],
    'Hotel Voucher': ['Hotel Name', 'Guest Name', 'Check-in Date', 'Check-out Date', 'Booking Confirmation Number', 'Room Type', 'Hotel Address'],
    'Travel Insurance': ['Insured Name', 'Policy Number', 'Insurance Provider', 'Valid From', 'Valid Until', 'Destination / Coverage Area'],
    'Transfer Voucher': ['Passenger Name', 'Booking Reference', 'Pickup Location', 'Dropoff Location', 'Transfer Date', 'Transfer Time'],
    'Sightseeing Voucher': ['Guest Name', 'Booking Reference', 'Tour / Activity Name', 'Activity Date', 'Number of Guests'],
    'Land Voucher': ['Guest / Passenger Name', 'Booking Reference', 'Service / Activity Name', 'Service Date', 'Pickup / Location', 'Dropoff / Destination', 'Service Time', 'Number of Guests'],
    'Aadhaar Card': ['Full Name', 'Aadhaar Number', 'Date of Birth', 'Gender', 'Address'],
    'PAN Card': ['Full Name', 'PAN Number', 'Date of Birth', "Father's Name"],
    'Arrival / Entry Document': ['Traveller Name', 'Trip Name', 'Destination', 'Arrival Date', 'Departure Date', 'Reference Number'],
    'Itinerary': ['Trip Destination', 'Start Date', 'End Date', 'Schedule Summary'],
    'Needs Review': ['Document Details']
}

GLOBAL_STOP_LABELS = {
    'field', 'details', 'status', 'reference', 'reference number', 'reference no', 'ref no', 'document number', 'card number',
    'traveller', 'traveller name', 'travellers', 'traveler', 'traveler name', 'travelers',
    'passenger', 'passenger name', 'passengers', 'guest', 'guest name', 'guests', 'lead guest', 'primary guest',
    'customer', 'customer id', 'customer name', 'insured', 'insured name', 'insured traveller', 'name', 'surname', 'given name', 'given names',
    'trip id', 'trip', 'trip name',
    'route', 'origin', 'from', 'destination', 'to', 'port of entry', 'city', 'country', 'hotel address', 'address', 'location',
    'airline', 'carrier', 'operated by', 'flight', 'flight no', 'flight number', 'flt no', 'pnr', 'booking reference', 'booking ref', 'reservation reference',
    'booking confirmation number', 'booking confirmation', 'confirmation', 'confirmation number', 'voucher reference', 'voucher ref', 'voucher number', 'voucher no',
    'policy number', 'policy ref', 'certificate', 'certificate number',
    'outbound', 'departure', 'departure date', 'departure time', 'departure date/time', 'departing', 'exit date',
    'arrival', 'arrival date', 'arrival time', 'arrival date/time', 'arriving', 'return',
    'cabin', 'class', 'cabin class', 'room', 'room type', 'hotel', 'hotel name', 'property', 'check-in', 'check in', 'check-out', 'check out', 'nights',
    'insurance provider', 'insurance company', 'provider', 'insurer', 'underwriter', 'coverage', 'valid from', 'valid until',
    'pickup location', 'pickup', 'pick-up', 'dropoff location', 'dropoff', 'drop-off', 'transfer date', 'transfer time', 'service date',
    'tour', 'tour name', 'activity', 'activity name', 'tour / activity name', 'activity date', 'tour date', 'number of guests', 'no of guests', 'pax', 'participants',
    'passport no', 'passport number', 'dob', 'date of birth', 'nationality', 'issue date', 'expiry date', 'place of issue',
    'type', 'type: p', 'visa type', 'visa category', 'category', 'purpose', 'purpose of visit', 'entry type', 'visa reference', 'travel dates', 'validity', 'duration',
    'start date', 'end date', 'revision', 'prepared for', 'demo purpose', 'synthetic test value', 'sample value'
}

DISCLAIMER_PATTERNS = [
    r'demo\s*/\s*sample',
    r'not\s+a\s+real\s+(?:travel\s+)?document',
    r'internal\s+software\s+demonstration',
    r'not\s+valid\s+for\s+(?:travel|identification|payment|immigration|any|real-world)',
    r'official\s+purpose',
    r'prototype\s+notice',
    r'this\s+document\s+is\s+fictional',
    r'plain-text\s+passport\s+test\s+record',
    r'illustrative\s+itinerary\s+only',
    r'test-only\s+notice',
    r'no\s+(?:tour|admission|transport)\s+is\s+booked',
    r'this\s+is\s+not\s+an\s+insurance\s+policy',
    r'sample\s+only',
    r'demo\s+purpose',
    r'keep\s+this\s+unuploaded',
    r'use\s+as\s+a\s+completed',
    r'use\s+to\s+demonstrate',
    r'upload\s+first\s+to\s+test',
    r'^field$',
    r'^sample\s+value$',
    r'^details$',
    r'^synthetic\s+test\s+value$',
    r'^synthetic\s+(?:customer|traveller|accommodation|flight|arrival|identity|data|record)'
]

def is_disclaimer_line(line):
    l_lower = line.strip().lower()
    for pat in DISCLAIMER_PATTERNS:
        if re.search(pat, l_lower):
            return True
    return False

def is_any_label_or_header(s):
    if not s:
        return False
    s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
    s_clean = re.sub(r'\s+', ' ', s_clean)
    if s_clean in GLOBAL_STOP_LABELS:
        return True
    if ':' in s:
        pfx = re.sub(r'[^a-z0-9 ]', ' ', s.split(':')[0].lower()).strip()
        pfx = re.sub(r'\s+', ' ', pfx)
        if pfx in GLOBAL_STOP_LABELS:
            return True
    # Only check prefix for very short labels (<= 3 words), never full activity sentences
    words = s_clean.split()
    if len(words) <= 3:
        for lbl in GLOBAL_STOP_LABELS:
            if s_clean == lbl or s_clean == (lbl + ' demo'):
                return True
    return False

def clean_purpose_value(val):
    if not val:
        return ""
    v = re.sub(r'\s*-\s*DEMO\s*$', '', val, flags=re.IGNORECASE).strip()
    v = re.sub(r'\s*-\s*synthetic\s+test\s+value\b', '', v, flags=re.IGNORECASE).strip()
    # Strip common label prefixes
    v = re.sub(r'^(?:purpose(?:\s+of\s+visit)?|category|type|class(?:\s+of\s+entry)?)\s*:\s*', '', v, flags=re.IGNORECASE).strip()
    if '/' in v:
        parts = [p.strip() for p in v.split('/') if p.strip()]
        if parts:
            v = parts[0]
    # Check if the remaining value is itself a label or metadata term
    norm_v = re.sub(r'[^a-z0-9 ]', ' ', v.lower()).strip()
    norm_v = re.sub(r'\s+', ' ', norm_v)
    PURPOSE_LABELS = {
        'visa type', 'type', 'purpose', 'purpose of visit', 'category', 'class', 'class of entry',
        'entry type', 'visa category', 'validity', 'duration', 'remarks', 'status'
    }
    if not norm_v or norm_v in PURPOSE_LABELS or is_any_label_or_header(v):
        return ""
    return v

def normalize_person_name(name):
    if not name:
        return ""
    n = name.lower().strip()
    n = re.sub(r'\b(?:mr|mrs|ms|miss|dr|master)\b\.?', '', n)
    n = re.sub(r'\b(?:demo|sample|synthetic|test|fictional)\b', '', n)
    n = re.sub(r'[^a-z\s,]', ' ', n)
    return re.sub(r'\s+', ' ', n).strip()

def validate_traveller_identity(doc_type, extracted_fields, expected_traveller_name, trip_travellers=None, customer_name=None):
    if doc_type == 'Itinerary':
        return {'valid': True, 'status': 'no_identity_required', 'severity': 'info', 'message': 'Itineraries are general trip documents without individual identity requirements.'}

    name_field_map = {
        'Passport': 'Full Name',
        'Visa / Entry Document': 'Traveller Name',
        'Flight Ticket': 'Passenger Name',
        'Hotel Voucher': 'Guest Name',
        'Travel Insurance': 'Insured Name',
        'Transfer Voucher': 'Passenger Name',
        'Sightseeing Voucher': 'Guest Name',
        'Land Voucher': 'Guest / Passenger Name',
        'Aadhaar Card': 'Full Name',
        'PAN Card': 'Full Name',
        'Arrival / Entry Document': 'Traveller Name'
    }
    field_key = name_field_map.get(doc_type)
    if not field_key:
        return {'valid': True, 'status': 'no_identity_field', 'severity': 'info', 'message': 'Document type has no individual identity field.'}

    extracted_raw = extracted_fields.get(field_key, '')
    if not extracted_raw or not extracted_raw.strip():
        return {'valid': True, 'status': 'unknown_identity', 'severity': 'warning', 'message': f"No identifiable traveller detected in {field_key}. Requires manual verification."}

    norm_extracted = normalize_person_name(extracted_raw)
    norm_expected = normalize_person_name(expected_traveller_name) if expected_traveller_name else ""
    norm_customer = normalize_person_name(customer_name) if customer_name else ""
    
    all_allowed_names = set()
    if norm_expected:
        all_allowed_names.add(norm_expected)
    if norm_customer:
        all_allowed_names.add(norm_customer)
    if trip_travellers:
        for t in trip_travellers:
            nt = normalize_person_name(t)
            if nt:
                all_allowed_names.add(nt)

    is_strict_doc = doc_type in ['Passport', 'Visa / Entry Document', 'Arrival / Entry Document']

    # 1. Family / Group Voucher descriptor (e.g. "Sharma Family - 4 travellers")
    if re.search(r'\b(?:family|group|travellers?|guests?|passengers?)\b', extracted_raw, re.IGNORECASE):
        matched_surname = False
        for allowed in all_allowed_names:
            tokens = allowed.split()
            surname = tokens[-1] if len(tokens) >= 1 else ""
            if surname and re.search(rf'\b{re.escape(surname)}\b', norm_extracted):
                matched_surname = True
                break
        
        if matched_surname:
            return {'valid': True, 'status': 'family_group_match', 'severity': 'warning', 'message': f"Group/family voucher successfully associated with traveller family ({extracted_raw})."}
        else:
            return {'valid': False, 'status': 'mismatch', 'severity': 'error' if is_strict_doc else 'warning', 'message': f"Identity mismatch: Group/family descriptor '{extracted_raw}' does not match expected traveller '{expected_traveller_name or customer_name}'."}

    # 2. Multiple Passengers listing
    passenger_tokens = re.split(r'[,&]|\band\b', norm_extracted)
    raw_passengers = [p.strip() for p in passenger_tokens if p.strip()]
    if len(raw_passengers) > 1:
        last_words = raw_passengers[-1].split()
        shared_surname = last_words[-1] if len(last_words) >= 2 else ""
        passenger_list = []
        for p in raw_passengers:
            p_words = p.split()
            if len(p_words) == 1 and shared_surname:
                passenger_list.append(f"{p} {shared_surname}")
            else:
                passenger_list.append(p)

        matched_any = False
        for p in passenger_list:
            p_words = set(p.split())
            for allowed in all_allowed_names:
                a_words = set(allowed.split())
                if a_words.issubset(p_words) or (len(a_words & p_words) >= min(2, len(a_words))):
                    matched_any = True
                    break
            if matched_any:
                break
        if matched_any:
            return {'valid': True, 'status': 'multi_passenger_match', 'severity': 'info', 'message': f"Multiple passengers listed; matched trip traveller in manifest ({extracted_raw})."}
        else:
            return {'valid': False, 'status': 'mismatch', 'severity': 'error' if is_strict_doc else 'warning', 'message': f"Identity mismatch: None of the listed passengers ({extracted_raw}) match trip travellers ({expected_traveller_name or customer_name})."}

    # 3. Individual Comparison
    extracted_words = norm_extracted.split()
    if not extracted_words:
        return {'valid': True, 'status': 'unknown_identity', 'severity': 'warning', 'message': 'Traveller name could not be parsed.'}

    if norm_expected:
        exp_words = norm_expected.split()
        if norm_extracted == norm_expected:
            return {'valid': True, 'status': 'exact_match', 'severity': 'info', 'message': 'Traveller identity exactly matches requirement.'}
        
        if set(exp_words) == set(extracted_words):
            return {'valid': True, 'status': 'exact_match_reordered', 'severity': 'info', 'message': 'Traveller identity matches requirement (reordered).'}
        
        # Surnames match but first names differ
        if len(exp_words) >= 2 and len(extracted_words) >= 2:
            if exp_words[-1] == extracted_words[-1] and exp_words[0] != extracted_words[0]:
                if is_strict_doc or (norm_extracted not in all_allowed_names):
                    return {'valid': False, 'status': 'different_individual_same_surname', 'severity': 'error', 'message': f"Identity mismatch: Document is for '{extracted_raw}', which is a different individual than assigned traveller '{expected_traveller_name}'."}

    for allowed in all_allowed_names:
        a_words = allowed.split()
        if set(a_words) == set(extracted_words) or norm_extracted == allowed:
            if is_strict_doc and norm_expected and norm_extracted != norm_expected:
                return {'valid': False, 'status': 'traveller_cross_assignment', 'severity': 'error', 'message': f"Strict document mismatch: Document belongs to '{extracted_raw}', but this requirement is explicitly assigned to '{expected_traveller_name}'."}
            return {'valid': True, 'status': 'trip_traveller_match', 'severity': 'warning', 'message': f"Document matches trip traveller '{allowed}'."}

    return {'valid': False, 'status': 'mismatch', 'severity': 'error', 'message': f"Traveller identity mismatch: Document name '{extracted_raw}' does not match assigned traveller '{expected_traveller_name or customer_name}'."}

def extract_reference_code(val):
    if not val:
        return ""
    val_clean = re.sub(r'\s*-\s*DEMO\s*$', '', val, flags=re.IGNORECASE).strip()
    m = re.search(r'\b([A-Z0-9]{2,}(?:[-/][A-Z0-9]+)+|[A-Z][0-9]{6,8}|[A-Z0-9]{6,20})\b', val_clean)
    if m:
        return m.group(1).strip()
    return val_clean

def simple_pdf_extract(pdf_data):
    try:
        logging.getLogger("pypdf").setLevel(logging.ERROR)
        reader = pypdf.PdfReader(io.BytesIO(pdf_data))
        extracted = []
        for page in reader.pages:
            t = page.extract_text()
            if t:
                extracted.append(t)
        full_text = '\n'.join(extracted).strip()
        if full_text and len(full_text) > 30:
            return full_text
    except Exception:
        pass

    import zlib, base64
    text = ''
    try:
        streams = re.findall(b'<<(.*?)>>[\r\n\\s]*stream[\r\n]*(.*?)[\r\n]*endstream', pdf_data, re.DOTALL)
        for dict_part, stream_data in streams:
            if b'/ASCII85Decode' in dict_part:
                if stream_data.endswith(b'~>\n'): stream_data = stream_data[:-3]
                elif stream_data.endswith(b'~>\r\n'): stream_data = stream_data[:-4]
                elif stream_data.endswith(b'~>'): stream_data = stream_data[:-2]
                try: stream_data = base64.a85decode(stream_data)
                except: pass
            if b'/FlateDecode' in dict_part:
                try: stream_data = zlib.decompress(stream_data)
                except: pass
            blocks = re.findall(rb'(?:^|\s)BT\s+(.*?)\s+ET(?:\s|$)', stream_data, re.DOTALL)
            for block in blocks:
                strings = re.findall(b'\\((.*?)(?<!\\\\)\\)', block)
                for s in strings: text += s.decode('ascii', 'ignore').replace('\\(', '(').replace('\\)', ')') + '\n'
        if not text.strip():
            blocks = re.findall(rb'(?:^|\s)BT\s+(.*?)\s+ET(?:\s|$)', pdf_data, re.DOTALL)
            for block in blocks:
                strings = re.findall(b'\\((.*?)(?<!\\\\)\\)', block)
                for s in strings: text += s.decode('ascii', 'ignore').replace('\\(', '(').replace('\\)', ')') + '\n'
    except Exception:
        pass
    return text.strip()

def parse_passport_text(text, expected_requirement=None, warnings_list=None):
    if warnings_list is None:
        warnings_list = []
    data = {}
    confidence = {}
    
    # Clean raw lines
    raw_lines = [line.strip() for line in text.replace('\r', '\n').split('\n') if line.strip()]
    lines = []
    in_disclaimer = False
    for l in raw_lines:
        l_lower = l.lower()
        if 'prototype notice' in l_lower or 'this document is fictional' in l_lower:
            in_disclaimer = True
            continue
        if in_disclaimer:
            continue
        if is_disclaimer_line(l):
            continue
        lines.append(l)

    text_clean = ' '.join(lines)

    # Detect Document Type
    def detect_type(clean_lines, expected_req=None):
        t = ' '.join(clean_lines).lower()
        
        scores = {
            'Passport': 0, 'Visa / Entry Document': 0, 'Flight Ticket': 0,
            'Hotel Voucher': 0, 'Travel Insurance': 0, 'Transfer Voucher': 0,
            'Sightseeing Voucher': 0, 'Land Voucher': 0, 'Aadhaar Card': 0, 'PAN Card': 0, 'Arrival / Entry Document': 0, 'Itinerary': 0
        }
        
        # Requirement Prior (Bonus +5)
        if expected_req:
            req_lower = str(expected_req).lower().strip()
            matched = False
            for stype in scores.keys():
                if stype.lower() in req_lower:
                    scores[stype] += 5
                    matched = True
                    break
            if not matched:
                KEYWORD_MAP = {
                    'hotel': 'Hotel Voucher', 'flight': 'Flight Ticket', 'ticket': 'Flight Ticket',
                    'passport': 'Passport', 'visa': 'Visa / Entry Document', 'insurance': 'Travel Insurance',
                    'transfer': 'Transfer Voucher', 'cab': 'Transfer Voucher', 'taxi': 'Transfer Voucher',
                    'sightseeing': 'Sightseeing Voucher', 'tour': 'Sightseeing Voucher', 'activity': 'Sightseeing Voucher',
                    'land': 'Land Voucher', 'ground': 'Land Voucher',
                    'aadhaar': 'Aadhaar Card', 'adhaar': 'Aadhaar Card', 'uidai': 'Aadhaar Card',
                    'pan': 'PAN Card', 'pancard': 'PAN Card',
                    'arrival': 'Arrival / Entry Document', 'entry': 'Arrival / Entry Document', 'itinerary': 'Itinerary'
                }
                for kw, target_type in KEYWORD_MAP.items():
                    if kw in req_lower and target_type in scores:
                        scores[target_type] += 5
                        break

        # Header Title Detection
        header_text = ' '.join(clean_lines[:3]).lower()
        if re.search(r'\b(flight\s*ticket|flight\s*itinerary|flight\s*booking|e-ticket|boarding\s*pass)\b', header_text): scores['Flight Ticket'] += 6
        elif re.search(r'\b(arrival\s*transfer\s*voucher|departure\s*transfer\s*voucher|transfer\s*voucher)\b', header_text): scores['Transfer Voucher'] += 6
        elif re.search(r'\b(hotel\s*voucher|hotel\s*confirmation|hotel\s*booking)\b', header_text): scores['Hotel Voucher'] += 6
        elif re.search(r'\b(travel\s*insurance|insurance\s*policy|certificate\s*of\s*insurance)\b', header_text): scores['Travel Insurance'] += 6
        elif re.search(r'\b(sightseeing\s*voucher|tour\s*voucher)\b', header_text): scores['Sightseeing Voucher'] += 6
        elif re.search(r'\b(land\s*voucher|ground\s*voucher|ground\s*arrangements?)\b', header_text): scores['Land Voucher'] += 6
        elif re.search(r'\b(aadhaar|unique\s*identification\s*authority|uidai)\b', header_text): scores['Aadhaar Card'] += 6
        elif re.search(r'\b(income\s*tax\s*department|permanent\s*account\s*number|pan\s*card)\b', header_text): scores['PAN Card'] += 6
        elif re.search(r'\b(visa\s*/?\s*entry\s*(?:document)?|visa)\b', header_text): scores['Visa / Entry Document'] += 6
        elif re.search(r'\b(arrival\s*/?\s*entry\s*(?:document|information|card)?|arrival card|disembarkation)\b', header_text): scores['Arrival / Entry Document'] += 6
        elif re.search(r'\b(passport|republic\s*of)\b', header_text): scores['Passport'] += 6
        elif re.search(r'\b(travel\s*itinerary|tour\s*itinerary|trip\s*itinerary|itinerary)\b', header_text): scores['Itinerary'] += 6

        # Body text rules
        if re.search(r'\b(passport|republic of)\b', t): scores['Passport'] += 4
        if re.search(r'\b(visa|entry permit|entry clearance)\b', t): scores['Visa / Entry Document'] += 4
        if re.search(r'\b(flight ticket|boarding pass|e-ticket|flight itinerary|flight booking|airline)\b', t): scores['Flight Ticket'] += 4
        if re.search(r'\b(hotel voucher|hotel booking|hotel reservation|accommodation voucher)\b', t): scores['Hotel Voucher'] += 4
        if re.search(r'\b(travel insurance|insurance policy|certificate of insurance)\b', t): scores['Travel Insurance'] += 4
        if re.search(r'\b(transfer voucher|airport transfer|chauffeur service)\b', t): scores['Transfer Voucher'] += 4
        if re.search(r'\b(sightseeing voucher|tour voucher|attraction voucher)\b', t): scores['Sightseeing Voucher'] += 4
        if re.search(r'\b(land voucher|ground service|ground arrangements?|land package)\b', t): scores['Land Voucher'] += 4
        if re.search(r'\b(aadhaar|unique identification authority|uidai|\b\d{4}\s*\d{4}\s*\d{4}\b)\b', t): scores['Aadhaar Card'] += 4
        if re.search(r'\b(income tax department|permanent account number|\b[a-z]{5}[0-9]{4}[a-z]\b)\b', t): scores['PAN Card'] += 4
        if re.search(r'\b(arrival\s*/?\s*entry\s*document|arrival\s*entry\s*information|arrival document|disembarkation card|arrival card|electronic arrival)\b', t): scores['Arrival / Entry Document'] += 4
        if re.search(r'\b(travel\s*itinerary|tour\s*itinerary|itinerary|day 1|day 2|schedule)\b', t): scores['Itinerary'] += 3

        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        sorted_scores = sorted(scores.values(), reverse=True)
        if best_score < 2 or (sorted_scores[0] == sorted_scores[1] and sorted_scores[0] > 0):
            return 'Needs Review', 'low'
        return best_type, 'high' if best_score >= 3 else 'medium'

    doc_type, type_confidence = detect_type(lines, expected_req=expected_requirement)
    expected_fields = SCHEMAS.get(doc_type, SCHEMAS['Needs Review'])
    for f in expected_fields:
        data[f] = ""
        confidence[f] = "low"

    date_pattern = r'(\d{1,2}\s+[A-Za-z]{3,4}(?:\s+\d{4})?|\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4})'

    # ----------------------------------------------------
    # A. PASSPORT
    # ----------------------------------------------------
    if doc_type == 'Passport':
        def is_passport_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['passport', 'passport demo', 'passport data sheet demo', 'passport version 1', 'field', 'sample value', 'details']

        def is_parent_or_spouse(s):
            return bool(re.search(r'\b(?:father|mother|spouse|husband|wife|guardian|emergency)\b', s.lower()))

        def clean_passport_label(s):
            label_pattern = (
                r'(?:Full\s+Name|Name|Surname|Last\s+Name|Family\s+Name|'
                r'Given\s+Names?(?:\(s\))?|First\s+Names?(?:\(s\))?|Middle\s+Names?(?:\(s\))?|'
                r'Travellers?|Travelers?|Customer(?:\s+Name)?|'
                r'Passport\s*(?:No\.?|Number|#)?|Document\s*(?:No\.?|Number|#)?|'
                r'DOB|Date\s+of\s+Birth|Birth\s+Date|Nationality|Issue\s+Date|Date\s+of\s+Issue|'
                r'Expiry\s+Date|Date\s+of\s+Expiry|Valid\s+Until|Place\s+of\s+Issue|Issuing\s+Authority|Sex|Gender)'
            )
            p = rf'^(?:[ऀ-ॿ\s\.\/\-\:]*)?{label_pattern}(?:[ऀ-ॿ\s\.\/\(\)\-\:]*)\s*[:\-]?\s*'
            cleaned = re.sub(p, '', s, flags=re.IGNORECASE).strip()
            cleaned = re.sub(r'^[/:()\s\-]+', '', cleaned).strip()
            cleaned = re.sub(r'^[ऀ-ॿ\s\.\/]+\s*', '', cleaned).strip()
            return cleaned

        surname_val = ""
        given_names_val = ""
        full_name_val = ""
        current_label = None
        extracted = {}

        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_passport_header(line_str) or is_parent_or_spouse(line_lower):
                current_label = None
                continue

            found = None
            if re.search(r'\b(?:surname|last\s+name|family\s+name)\b', line_lower) and not surname_val:
                found = 'Surname'
            elif re.search(r'\b(?:given\s+names?|first\s+names?|middle\s+names?)\b', line_lower) and not given_names_val:
                found = 'Given Names'
            elif re.search(r'\b(?:full\s+name|travellers?(?:\s+name)?|travelers?(?:\s+name)?|customer(?:\s+name)?)\b', line_lower) and not full_name_val:
                found = 'Full Name'
            elif re.search(r'\bname\b', line_lower) and not full_name_val and not surname_val and not given_names_val:
                found = 'Full Name'
            elif re.search(r'\b(?:passport\s*(?:no\.?|number|#)|document\s*(?:no\.?|number|#))\b', line_lower) and not extracted.get('Passport Number'):
                found = 'Passport Number'
            elif re.search(r'\b(?:dob|date\s+of\s+birth|birth\s+date)\b', line_lower) and not extracted.get('Date of Birth'):
                found = 'Date of Birth'
            elif re.search(r'\b(?:nationality)\b', line_lower) and not extracted.get('Nationality'):
                found = 'Nationality'
            elif re.search(r'\b(?:issue\s+date|date\s+of\s+issue)\b', line_lower) and not extracted.get('Issue Date'):
                found = 'Issue Date'
            elif re.search(r'\b(?:expiry\s+date|date\s+of\s+expiry|valid\s+until)\b', line_lower) and not extracted.get('Expiry Date'):
                found = 'Expiry Date'
            elif re.search(r'\b(?:place\s+of(?:\s+issue)?|issuing\s+authority)\b', line_lower) and not extracted.get('Place of Issue'):
                found = 'Place of Issue'

            if found:
                v = clean_passport_label(line_str)
                if v and not is_any_label_or_header(v):
                    if found == 'Surname':
                        surname_val = v
                    elif found == 'Given Names':
                        given_names_val = v
                    elif found == 'Full Name':
                        full_name_val = v
                    else:
                        extracted[found] = v
                    current_label = None
                else:
                    current_label = found
            elif current_label:
                if not is_any_label_or_header(line_str):
                    if current_label == 'Surname':
                        surname_val = line_str
                    elif current_label == 'Given Names':
                        given_names_val = line_str
                    elif current_label == 'Full Name':
                        full_name_val = line_str
                    else:
                        extracted[current_label] = line_str
                    current_label = None
                else:
                    current_label = None

        if given_names_val and surname_val:
            data['Full Name'] = f"{given_names_val} {surname_val}".strip()
            confidence['Full Name'] = 'high'
        elif full_name_val:
            data['Full Name'] = full_name_val.strip()
            confidence['Full Name'] = 'high'
        elif surname_val:
            data['Full Name'] = surname_val.strip()
            confidence['Full Name'] = 'medium'
        elif given_names_val:
            data['Full Name'] = given_names_val.strip()
            confidence['Full Name'] = 'medium'

        if 'Passport Number' in extracted:
            cand_p = extract_reference_code(extracted['Passport Number'])
            # Must not be a label or noise
            if cand_p and not is_any_label_or_header(cand_p) and not any(w in cand_p.lower() for w in ('type', 'pass', 'num', 'doc', 'detail', 'record', 'gov')) and re.search(r'\d{5,}', cand_p):
                data['Passport Number'] = cand_p
                confidence['Passport Number'] = 'high'
            else:
                data['Passport Number'] = ''
                confidence['Passport Number'] = 'low'
        for f in ['Date of Birth', 'Issue Date', 'Expiry Date']:
            if f in extracted:
                m = re.search(date_pattern, extracted[f])
                if m:
                    data[f] = m.group(1).strip()
                    confidence[f] = 'high'
        if 'Nationality' in extracted:
            val = re.sub(r'\s*-\s*synthetic\s+test\s+value\b', '', extracted['Nationality'], flags=re.IGNORECASE).strip()
            if val and not is_any_label_or_header(val) and not re.search(r'\d', val):
                data['Nationality'] = val
                confidence['Nationality'] = 'high'
        if 'Place of Issue' in extracted:
            val_p = extracted['Place of Issue'].strip()
            if not is_any_label_or_header(val_p) and 'place of' not in val_p.lower() and val_p not in ('|', '/', ':', '-'):
                data['Place of Issue'] = val_p
                confidence['Place of Issue'] = 'high'
            else:
                data['Place of Issue'] = ''
                confidence['Place of Issue'] = 'low'

        # MRZ Reconciliation (ICAO Doc 9303 TD3)
        try:
            import mrz_parser
            mrz_res = mrz_parser.parse_td3_mrz(lines)
            if mrz_res and mrz_res.get('success'):
                mrz_fields = mrz_res.get('fields', {})
                is_validated = (mrz_res.get('status') == 'VALIDATED')

                # 1. Full Name
                mrz_full_name = mrz_fields.get('full_name', '')
                if not data['Full Name'] and mrz_full_name:
                    data['Full Name'] = mrz_full_name
                    confidence['Full Name'] = 'high' if is_validated else 'medium'
                elif data['Full Name'] and mrz_full_name:
                    viz_norm = normalize_person_name(data['Full Name'])
                    mrz_norm = normalize_person_name(mrz_full_name)
                    viz_tokens = set(viz_norm.split())
                    mrz_tokens = set(mrz_norm.split())
                    if viz_tokens and mrz_tokens and (viz_tokens.issubset(mrz_tokens) or mrz_tokens.issubset(viz_tokens)):
                        confidence['Full Name'] = 'high'
                    elif viz_norm != mrz_norm:
                        warnings_list.append(
                            f"Passport name conflict: VIZ has '{data['Full Name']}' but MRZ has '{mrz_full_name}'. Preserving VIZ value for manual review."
                        )

                # 2. Passport Number
                mrz_doc_num = mrz_fields.get('document_number', '')
                cd_doc = mrz_res.get('check_digits', {}).get('document_number', {})
                is_doc_valid = cd_doc.get('valid', False)

                viz_pnum = data.get('Passport Number', '').strip()
                is_viz_valid = bool(re.fullmatch(r'[A-Z0-9]{8,9}', viz_pnum) and not any(w in viz_pnum.lower() for w in ('pass', 'no', 'num', 'doc', 'qr')))

                if mrz_doc_num and (not is_viz_valid or is_doc_valid):
                    data['Passport Number'] = mrz_doc_num
                    confidence['Passport Number'] = 'high' if (is_doc_valid or is_validated) else 'medium'
                elif is_viz_valid and mrz_doc_num:
                    if viz_pnum.upper() == mrz_doc_num.upper():
                        confidence['Passport Number'] = 'high'
                    else:
                        warnings_list.append(
                            f"Passport number conflict: VIZ has '{viz_pnum}' but MRZ has '{mrz_doc_num}'. Preserving VIZ value for manual review."
                        )

                # 3. Date of Birth
                mrz_dob_fmt = mrz_fields.get('dob_formatted', '')
                cd_dob = mrz_res.get('check_digits', {}).get('date_of_birth', {})
                if mrz_dob_fmt:
                    if not data['Date of Birth'] or cd_dob.get('valid', False) or is_validated:
                        data['Date of Birth'] = mrz_dob_fmt
                        confidence['Date of Birth'] = 'high'
                    else:
                        confidence['Date of Birth'] = 'high'

                # 4. Expiry Date
                mrz_exp_fmt = mrz_fields.get('expiry_formatted', '')
                cd_exp = mrz_res.get('check_digits', {}).get('expiry_date', {})
                if mrz_exp_fmt:
                    if not data['Expiry Date'] or cd_exp.get('valid', False) or is_validated:
                        data['Expiry Date'] = mrz_exp_fmt
                        confidence['Expiry Date'] = 'high'
                    else:
                        confidence['Expiry Date'] = 'high'

                # 5. Nationality
                mrz_nat = mrz_fields.get('nationality', '')
                if mrz_nat:
                    resolved_nat = 'Indian' if mrz_nat in ('IND', 'Indian') else mrz_nat
                    if not data['Nationality'] or data['Nationality'].upper() in ('IND', 'INDIAN'):
                        data['Nationality'] = resolved_nat
                        confidence['Nationality'] = 'high' if (is_validated or is_doc_valid) else 'medium'

                if mrz_res.get('warnings'):
                    warnings_list.extend(mrz_res['warnings'])
        except Exception as e:
            warnings_list.append(f"MRZ processing note: {str(e)}")

        # Post-Processing 1: Place of Issue Indian passport office fallback
        if not data.get('Place of Issue'):
            INDIAN_PASSPORT_CITIES = [
                'NAVI MUMBAI', 'MUMBAI', 'NEW DELHI', 'DELHI', 'KOLKATA', 'CHENNAI',
                'HYDERABAD', 'BANGALORE', 'BENGALURU', 'AHMEDABAD', 'PUNE', 'THANE',
                'SURAT', 'JAIPUR', 'LUCKNOW', 'CHANDIGARH', 'GOA', 'KOCHI', 'TRIVANDRUM',
                'AMRITSAR', 'BHOPAL', 'BHUBANESWAR', 'COIMBATORE', 'DEHRADUN', 'GHAZIABAD',
                'GUWAHATI', 'JALANDHAR', 'JAMMU', 'KOZHIKODE', 'MADURAI', 'NAGPUR', 'PATNA',
                'RAIPUR', 'RANCHI', 'SHIMLA', 'SRINAGAR', 'TIRUCHIRAPPALLI', 'VISAKHAPATNAM'
            ]
            for i, l in enumerate(lines):
                if re.search(r'place\s+of', l, re.IGNORECASE) or 'place of' in l.lower():
                    for offset in (0, 1, 2, 3, 4):
                        if i + offset < len(lines):
                            cand_text = lines[i + offset].upper()
                            for c in INDIAN_PASSPORT_CITIES:
                                if c in cand_text:
                                    data['Place of Issue'] = c
                                    confidence['Place of Issue'] = 'high'
                                    break
                        if data.get('Place of Issue'):
                            break
                if data.get('Place of Issue'):
                    break

        # Post-Processing 2: VIZ Passport Number Lookalike Recovery (e.g. 'P _ 24635743')
        if not data.get('Passport Number'):
            for l in lines:
                m_pn = re.search(r'\b([A-Z])\s*[-_]?\s*(\d{7})\b', l.upper())
                if m_pn and m_pn.group(1) not in ('P', 'D', 'O', 'S'):
                    cand_num = f"{m_pn.group(1)}{m_pn.group(2)}"
                    if not is_any_label_or_header(cand_num):
                        data['Passport Number'] = cand_num
                        confidence['Passport Number'] = 'high'
                        break

        # Post-Processing 3: Issue Date and Expiry Date Synchronization (10-Year Indian Passport Validity)
        import datetime
        if not data.get('Issue Date') and data.get('Expiry Date'):
            try:
                exp_dt = None
                exp_str = data['Expiry Date']
                for fmt in ('%d %b %Y', '%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y'):
                    try:
                        exp_dt = datetime.datetime.strptime(exp_str, fmt).date()
                        break
                    except ValueError:
                        pass
                if exp_dt:
                    found_viz_date = None
                    target_year = exp_dt.year - 10
                    for l in lines:
                        m_d = re.search(date_pattern, l)
                        if m_d and str(target_year) in m_d.group(1):
                            found_viz_date = m_d.group(1).strip()
                            break
                    if found_viz_date:
                        data['Issue Date'] = found_viz_date
                        confidence['Issue Date'] = 'high'
                    else:
                        inferred_dt = datetime.date(exp_dt.year - 10, exp_dt.month, exp_dt.day) + datetime.timedelta(days=1)
                        data['Issue Date'] = inferred_dt.strftime('%d %b %Y')
                        confidence['Issue Date'] = 'high'
            except Exception:
                pass

        if not data.get('Expiry Date') and data.get('Issue Date'):
            try:
                iss_dt = None
                iss_str = data['Issue Date']
                for fmt in ('%d %b %Y', '%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y'):
                    try:
                        iss_dt = datetime.datetime.strptime(iss_str, fmt).date()
                        break
                    except ValueError:
                        pass
                if iss_dt:
                    inferred_exp = datetime.date(iss_dt.year + 10, iss_dt.month, iss_dt.day) - datetime.timedelta(days=1)
                    data['Expiry Date'] = inferred_exp.strftime('%d %b %Y')
                    confidence['Expiry Date'] = 'high'
            except Exception:
                pass

    # ----------------------------------------------------
    # B. VISA / ENTRY DOCUMENT
    # ----------------------------------------------------
    elif doc_type == 'Visa / Entry Document':
        def is_visa_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['visa entry document', 'visa', 'entry document', 'entry clearance', 'entry permit', 'visa entry document demo', 'field', 'sample value', 'details']

        def clean_visa_label(s):
            s_clean = re.sub(
                r'^(?:'
                r'Visa\s*(?:Number|No\.?|#)\s*/\s*Reference(?:\s*(?:Number|No\.?|#))?|'
                r'Reference(?:\s*(?:Number|No\.?|#))?\s*/\s*Visa\s*(?:Number|No\.?|#)|'
                r'Expiry\s+Date(?:\s+of\s+Expiry)?\s*/\s*Valid\s+Until|'
                r'Valid\s+Until\s*/\s*Expiry\s+Date(?:\s+of\s+Expiry)?|'
                r'Valid\s+From\s*/\s*Issue\s+Date|'
                r'Issue\s+Date\s*/\s*Valid\s+From|'
                r'Travellers?(?:\s+Name)?\s*/\s*Passengers?(?:\s+Name)?|'
                r'Destination\s*/\s*Country'
                r')\s*(?::|-)?\s*',
                '', s, flags=re.IGNORECASE
            ).strip()
            return re.sub(
                r'^(?:Travellers?(?:\s+Name)?|Travelers?(?:\s+Name)?|Customer(?:\s+Name)?|Passengers?(?:\s+Name)?|'
                r'Full\s+Name|Name|Visa\s+Reference|Visa\s*Ref(?:erence)?|Visa\s*(?:Number|No\.?|#)|'
                r'Reference(?:\s*(?:Number|No\.?|#))?|Destination|Country|Purpose(?:\s+of\s+Visit)?|'
                r'Visa\s+Type|Visa\s+Category|Entry\s+Type|Travel\s+Dates|Validity|Duration|'
                r'Valid\s+From|Valid\s+Until|Issue\s+Date|Date\s+of\s+Issue|Expiry\s+Date|Date\s+of\s+Expiry)\s*(?::|-)?\s*',
                '', s_clean, flags=re.IGNORECASE
            ).strip()

        current_label = None
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_visa_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id|demo\s+workflow|not\s+valid)\b', line_lower):
                current_label = None
                continue

            found_key = None
            if re.search(r'\b(?:visa\s+ref(?:erence)?|visa\s*(?:number|no\.?|#)|reference(?:\s*(?:number|no\.?|#))?)\b', line_lower) and not data['Visa Number / Reference']:
                found_key = 'Visa Number / Reference'
            elif re.search(r'\b(?:travellers?(?:\s+name)?|travelers?(?:\s+name)?|passengers?|customer(?:\s+name)?|full\s+name|name)\b', line_lower) and not data['Traveller Name']:
                found_key = 'Traveller Name'
            elif re.search(r'\b(?:issue\s+date|date\s+of\s+issue)\b', line_lower) and not data['Issue Date']:
                # Strictly issue date only - NEVER map Valid From to Issue Date
                found_key = 'Issue Date'
            elif re.search(r'\b(?:expiry\s+date|date\s+of\s+expiry|valid\s+until)\b', line_lower) and not data['Expiry Date / Valid Until']:
                found_key = 'Expiry Date / Valid Until'
            elif re.search(r'\btravel\s+dates\b', line_lower) and not data['Travel Dates']:
                # Strictly travel dates only - NEVER invent travel dates from validity
                found_key = 'Travel Dates'
            elif re.search(r'\b(?:destination|country)\b', line_lower) and not data['Destination']:
                found_key = 'Destination'
            elif re.search(r'\b(?:purpose(?:\s+of\s+visit)?|visa\s+type|visa\s+category)\b', line_lower) and not data['Purpose']:
                found_key = 'Purpose'

            if found_key:
                v = clean_visa_label(line_str)
                if v and not is_any_label_or_header(v):
                    if found_key == 'Purpose':
                        v = clean_purpose_value(v)
                    data[found_key] = extract_reference_code(v) if found_key == 'Visa Number / Reference' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if not is_any_label_or_header(line_str):
                    val = line_str
                    if current_label == 'Purpose':
                        val = clean_purpose_value(val)
                    data[current_label] = extract_reference_code(val) if current_label == 'Visa Number / Reference' else val
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

        if not data['Expiry Date / Valid Until'] and data['Travel Dates']:
            dates = re.findall(date_pattern, data['Travel Dates'])
            if dates:
                data['Expiry Date / Valid Until'] = dates[-1]
                confidence['Expiry Date / Valid Until'] = 'high'

    # ----------------------------------------------------
    # C. FLIGHT TICKET
    # ----------------------------------------------------
    elif doc_type == 'Flight Ticket':
        IATA_AIRLINES = {
            'EK': 'Emirates', 'SQ': 'Singapore Airlines', '6E': 'IndiGo', 'AI': 'Air India',
            'BA': 'British Airways', 'QR': 'Qatar Airways', 'LH': 'Lufthansa', 'EY': 'Etihad Airways',
            'QF': 'Qantas', 'AF': 'Air France', 'KL': 'KLM', 'TG': 'Thai Airways',
            'MH': 'Malaysia Airlines', 'CX': 'Cathay Pacific', 'UK': 'Vistara', 'SG': 'SpiceJet',
            'FZ': 'flydubai', 'GF': 'Gulf Air', 'WY': 'Oman Air', 'TK': 'Turkish Airlines'
        }

        def is_flight_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['flight ticket', 'flight ticket demo', 'flight ticket booking confirmation', 'flight itinerary demo', 'flight itinerary', 'field', 'sample value', 'details']

        def clean_flight_label(s):
            return re.sub(r'^(?:Passengers?(?:\s+Name)?|Travel[l]?ers?(?:\s+Name)?|Customer(?:\s+Name)?|Route|From|Origin|To|Destination|Outbound|Departure(?:\s+Date(?:/Time)?)?|Arrival(?:\s+Date(?:/Time)?)?|Return|Airline|Carrier|Operated\s+by|Flight(?:\s*(?:No\.?|Number|#))?|Flt(?:\s*(?:No\.?|#))?|PNR(?:/Booking\s+Reference)?|Booking\s+Ref(?:erence)?|Reservation\s+Ref(?:erence)?|Cabin(?:\s+Class)?|Class)\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        extracted_flight = {}
        passenger_was_customer = False

        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_flight_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id)\b', line_lower):
                current_label = None
                continue

            found_label = None
            if re.search(r'\b(?:passengers?(?:\s+name)?|travel[l]?ers?(?:\s+name)?)\b', line_lower):
                found_label = 'Passenger Name'
                passenger_was_customer = False
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and (not extracted_flight.get('Passenger Name') or passenger_was_customer):
                found_label = 'Passenger Name'
                passenger_was_customer = True
            elif re.search(r'\b(?:route)\b', line_lower) and not extracted_flight.get('Route'):
                found_label = 'Route'
            elif re.search(r'\b(?:outbound|departure(?:\s+date(?:/time)?)?)\b', line_lower) and not extracted_flight.get('Outbound'):
                found_label = 'Outbound'
            elif re.search(r'\b(?:return|arrival(?:\s+date(?:/time)?)?)\b', line_lower) and not extracted_flight.get('Return'):
                found_label = 'Return'
            elif re.search(r'\b(?:airline|carrier|operated\s+by)\b', line_lower) and not extracted_flight.get('Airline'):
                found_label = 'Airline'
            elif re.search(r'\b(?:pnr(?:/booking\s+reference)?|booking\s+ref(?:erence)?|reservation\s+ref(?:erence)?)\b', line_lower) and not extracted_flight.get('PNR/Booking Reference'):
                found_label = 'PNR/Booking Reference'
            elif re.search(r'\b(?:flight\s*(?:no\.?|number|#)|flt\s*(?:no\.?|#))\b', line_lower) and not extracted_flight.get('Flight Number'):
                found_label = 'Flight Number'
            elif re.search(r'\b(?:from|origin)\b', line_lower) and not extracted_flight.get('Origin'):
                found_label = 'Origin'
            elif re.search(r'\b(?:to|destination)\b', line_lower) and not extracted_flight.get('Destination'):
                found_label = 'Destination'
            elif re.search(r'\b(?:cabin(?:\s+class)?|class)\b', line_lower) and not extracted_flight.get('Cabin'):
                found_label = 'Cabin'

            if found_label:
                v = clean_flight_label(line_str)
                if v and not is_any_label_or_header(v):
                    extracted_flight[found_label] = extract_reference_code(v) if found_label == 'PNR/Booking Reference' else v
                    current_label = None
                else:
                    current_label = found_label
            elif current_label:
                if not is_any_label_or_header(line_str):
                    extracted_flight[current_label] = extract_reference_code(line_str) if current_label == 'PNR/Booking Reference' else line_str
                    current_label = None
                else:
                    current_label = None

        schema_map = {'Outbound': 'Departure Date/Time', 'Return': 'Arrival Date/Time', 'Cabin': 'Cabin Class'}
        for k_src, val in extracted_flight.items():
            k_dst = schema_map.get(k_src, k_src)
            data[k_dst] = val
            confidence[k_dst] = 'high'

        # Route splitting
        if data.get('Route'):
            r_parts = [p.strip() for p in re.split(r'\s*(?:[-–—>]|->|\bto\b)\s*', data['Route']) if p.strip()]
            if len(r_parts) >= 2:
                if not data.get('Origin'):
                    data['Origin'] = r_parts[0]; confidence['Origin'] = 'high'
                if not data.get('Destination'):
                    data['Destination'] = r_parts[1]; confidence['Destination'] = 'high'

        # Flight Number & Airline inference
        if not data.get('Flight Number'):
            m_flt = re.search(r'(?<![-A-Za-z0-9])(?:flight\s*(?:no\.?|number|#)|flt\s*(?:no\.?|#))\s*[:#.-]?\s*([A-Z0-9]{2}\s*[-]?\s*\d{2,4}\b|[A-Za-z0-9-]+)', text_clean, re.IGNORECASE)
            if m_flt:
                cand = m_flt.group(1).strip()
                if cand and len(cand) < 15 and not is_any_label_or_header(cand):
                    data['Flight Number'] = cand; confidence['Flight Number'] = 'high'
            else:
                m_iata = re.search(r'\b([A-Za-z]{2}|[A-Za-z][0-9]|[0-9][A-Za-z])\s*[-]?\s*(\d{2,4})\b', text_clean)
                if m_iata:
                    c_code = m_iata.group(1).upper()
                    c_num = m_iata.group(2)
                    if c_code not in ['IN', 'ON', 'TO', 'AT', 'IS', 'NO', 'DO', 'OR', 'BY', 'MY', 'HE', 'WE', 'SO', 'KT', 'DM']:
                        data['Flight Number'] = f"{c_code} {c_num}"; confidence['Flight Number'] = 'high'

        if not data.get('Airline') and data.get('Flight Number'):
            m_pfx = re.match(r'^([A-Z0-9]{2})', data['Flight Number'])
            if m_pfx and m_pfx.group(1).upper() in IATA_AIRLINES:
                data['Airline'] = IATA_AIRLINES[m_pfx.group(1).upper()]
                confidence['Airline'] = 'high'

    # ----------------------------------------------------
    # D. HOTEL VOUCHER
    # ----------------------------------------------------
    elif doc_type == 'Hotel Voucher':
        def is_hotel_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            s_clean = re.sub(r'\s+', ' ', s_clean)
            if re.match(r'^(?:hotel\s+voucher|hotel\s+confirmation|hotel\s+booking)\b', s_clean):
                return True
            return s_clean in ['field', 'sample value', 'details']

        def clean_hotel_label(s):
            return re.sub(r'^(?:Hotel\s+Name|Hotel\s+Address|Hotel|Property|Accommodation|Resort|Guests?(?:\s+Name)?|Primary\s+Guest|Lead\s+Guest|Travel[l]?ers?(?:\s+Name)?|Passengers?(?:\s+Name)?|Customer(?:\s+Name)?|Check-in(?:\s+Date)?|Check\s+In(?:\s+Date)?|Check-out(?:\s+Date)?|Check\s+Out(?:\s+Date)?|Booking\s+Confirmation(?:\s*(?:Number|No\.?|#))?|Confirmation(?:\s*(?:Number|No\.?|#))?|Booking\s*Ref(?:erence)?|Booking\s+ID|Voucher\s*Ref(?:erence)?|Voucher\s*(?:Number|No\.?|#)?|Room\s+Type|Room\s+Category|Room|Address|Location)\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        guest_was_customer = False

        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_hotel_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id)\b', line_lower):
                current_label = None
                continue

            found_key = None
            if re.search(r'\b(?:hotel\s+address|address|location)\b', line_lower) and not re.match(r'^(?:hotel\s+name|property|resort|guest|check|room|booking)\b', line_lower) and line_lower != 'hotel':
                found_key = 'Hotel Address'
            elif (re.match(r'^(?:hotel(?:\s+name)?|property|accommodation|resort)\b', line_lower) or re.search(r'\b(?:hotel(?:\s+name)?|property|accommodation|resort)\s*:', line_lower)) and not is_hotel_header(line_str):
                if not data['Hotel Name']: found_key = 'Hotel Name'
            elif re.match(r'^(?:booking\s+confirmation|confirmation|booking\s+ref(?:erence)?|reservation|voucher\s+ref)\b', line_lower) or re.search(r'\b(?:booking\s+confirmation|confirmation|booking\s+ref(?:erence)?)\s*:', line_lower):
                if not data['Booking Confirmation Number']: found_key = 'Booking Confirmation Number'
            elif re.search(r'\b(?:guests?(?:\s+name)?|primary\s+guest|lead\s+guest|travel[l]?ers?(?:\s+name)?|passengers?(?:\s+name)?)\b', line_lower):
                found_key = 'Guest Name'
                guest_was_customer = False
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and (not data['Guest Name'] or guest_was_customer):
                found_key = 'Guest Name'
                guest_was_customer = True
            elif re.search(r'\b(?:check-in(?:\s+date)?|check\s+in(?:\s+date)?|arrival\s+date)\b', line_lower):
                found_key = 'Check-in Date'
            elif re.search(r'\b(?:check-out(?:\s+date)?|check\s+out(?:\s+date)?|departure\s+date)\b', line_lower):
                found_key = 'Check-out Date'
            elif re.search(r'\b(?:room(?:\s+type|\s+category)?)\b', line_lower) or re.match(r'^room\b', line_lower):
                found_key = 'Room Type'

            if found_key:
                v = clean_hotel_label(line_str)
                if v and not is_any_label_or_header(v):
                    data[found_key] = extract_reference_code(v) if found_key == 'Booking Confirmation Number' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if not is_any_label_or_header(line_str):
                    data[current_label] = extract_reference_code(line_str) if current_label == 'Booking Confirmation Number' else line_str
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

    # ----------------------------------------------------
    # E. TRAVEL INSURANCE
    # ----------------------------------------------------
    elif doc_type == 'Travel Insurance':
        def is_ins_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['travel insurance', 'travel insurance demo', 'travel insurance demo policy', 'insurance policy', 'insurance certificate', 'certificate of travel insurance', 'certificate of insurance', 'field', 'sample value', 'details']

        def clean_ins_label(s):
            return re.sub(r'^(?:Insured(?:\s+Traveller|\s+Name|\s+Person)?|Travel[l]?ers?(?:\s+Name)?|Customer(?:\s+Name)?|Policy\s*Ref(?:erence)?|Policy\s*(?:Number|No\.?|#)|Certificate\s*(?:Number|No\.?|#|Ref(?:erence)?|:)|Insurance\s+Company|Insurance\s+Provider|Provider|Insurer|Underwriter|Company|Destination(?:\s*/\s*Coverage\s*Area)?|Coverage\s*Area|Coverage\s+Start(?:\s+Date)?|Coverage\s+End(?:\s+Date)?|Valid\s+From|Valid\s+Until|Coverage)\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_ins_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id|policy\s+status)\b', line_lower):
                current_label = None
                continue

            # Legacy single-line Coverage: Date1 - Date2
            if re.search(r'\bcoverage\s*:\s*', line_lower):
                cov_dates = re.findall(date_pattern, line_str)
                if len(cov_dates) >= 2:
                    if not data['Valid From']: data['Valid From'] = cov_dates[0]; confidence['Valid From'] = 'high'
                    if not data['Valid Until']: data['Valid Until'] = cov_dates[1]; confidence['Valid Until'] = 'high'
                continue

            found_key = None
            if re.search(r'\b(?:insurance\s+company|insurance\s+provider|provider|insurer|underwriter)\b', line_lower) and not data['Insurance Provider']:
                found_key = 'Insurance Provider'
            elif re.search(r'\b(?:insured(?:\s+traveller|\s+name|\s+person)?|travel[l]?ers?(?:\s+name)?)\b', line_lower) and not data['Insured Name']:
                found_key = 'Insured Name'
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and not data['Insured Name']:
                found_key = 'Insured Name'
            elif re.search(r'\b(?:policy\s*ref(?:erence)?|policy\s*(?:number|no\.?|#)|certificate\s*(?:number|no\.?|#|ref(?:erence)?))\b', line_lower) and not data['Policy Number']:
                if not re.search(r'\bcertificate\s+of\b', line_lower):
                    found_key = 'Policy Number'
            elif re.search(r'\bcertificate\s*:\s*\S+', line_lower) and not data['Policy Number']:
                if not re.search(r'\bcertificate\s+of\b', line_lower):
                    found_key = 'Policy Number'
            elif re.search(r'\b(?:destination|coverage\s+area)\b', line_lower) and not data['Destination / Coverage Area']:
                found_key = 'Destination / Coverage Area'
            elif re.search(r'\b(?:valid\s+from|coverage\s+start(?:\s+date)?)\b', line_lower) and not data['Valid From']:
                found_key = 'Valid From'
            elif re.search(r'\b(?:valid\s+until|coverage\s+end(?:\s+date)?)\b', line_lower) and not data['Valid Until']:
                found_key = 'Valid Until'

            if found_key:
                v = clean_ins_label(line_str)
                if v and not is_any_label_or_header(v):
                    data[found_key] = extract_reference_code(v) if found_key == 'Policy Number' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if not is_any_label_or_header(line_str):
                    data[current_label] = extract_reference_code(line_str) if current_label == 'Policy Number' else line_str
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

    # ----------------------------------------------------
    # F. TRANSFER VOUCHER
    # ----------------------------------------------------
    elif doc_type == 'Transfer Voucher':
        def is_trf_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['transfer voucher', 'transfer voucher demo', 'arrival transfer voucher', 'departure transfer voucher', 'airport transfer', 'field', 'sample value', 'details']

        def clean_trf_label(s):
            return re.sub(r'^(?:Passengers?(?:\s+Name)?|Travel[l]?ers?(?:\s+Name)?|Customer(?:\s+Name)?|Voucher\s*Ref(?:erence)?|Transfer\s*Ref(?:erence)?|Booking\s*Ref(?:erence)?|Reference(?:\s*(?:Number|No\.?|#))?|Pickup\s+Location|Pick-up\s+Location|Pickup|Pick-up|Dropoff\s+Location|Drop-off\s+Location|Dropoff|Drop-off|Transfer\s+Date|Service\s+Date|Arrival\s+Transfer\s+Date|Departure\s+Transfer\s+Date|Transfer\s+Time|Pickup\s+Time|Date(?:\s+of\s+Transfer)?|Date|Arrival|Departure|Route|Service)\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        passenger_was_customer = False

        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_trf_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id|vehicle\s+type)\b', line_lower):
                current_label = None
                continue

            # Route line with '->' (e.g. Arrival: Airport -> Hotel or Route: Airport -> Hotel)
            if '->' in line_str or ' to ' in line_str:
                rt_clean = re.sub(r'^(?:Arrival|Departure|Route|Service)\s*(?::|-)?\s*', '', line_str, flags=re.IGNORECASE).strip()
                parts = [p.strip() for p in re.split(r'\s*(?:->|\bto\b)\s*', rt_clean) if p.strip()]
                if not data['Pickup Location'] and len(parts) >= 1: data['Pickup Location'] = parts[0]; confidence['Pickup Location'] = 'high'
                if not data['Dropoff Location'] and len(parts) >= 2: data['Dropoff Location'] = parts[1]; confidence['Dropoff Location'] = 'high'
                current_label = None
                continue

            found_key = None
            if re.search(r'\b(?:passengers?(?:\s+name)?|travel[l]?ers?(?:\s+name)?)\b', line_lower):
                if not data['Passenger Name'] or passenger_was_customer:
                    found_key = 'Passenger Name'
                    passenger_was_customer = False
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and not data['Passenger Name']:
                found_key = 'Passenger Name'
                passenger_was_customer = True
            elif re.search(r'\b(?:voucher\s*ref(?:erence)?|transfer\s*ref(?:erence)?|booking\s*ref(?:erence)?|reference(?:\s*(?:number|no\.?|#))?)\b', line_lower) and not data['Booking Reference']:
                found_key = 'Booking Reference'
            elif re.match(r'^(?:pickup\s+location|pick-up\s+location|pickup|pick-up)\b', line_lower) and not data['Pickup Location']:
                found_key = 'Pickup Location'
            elif re.match(r'^(?:dropoff\s+location|drop-off\s+location|dropoff|drop-off)\b', line_lower) and not data['Dropoff Location']:
                found_key = 'Dropoff Location'
            elif re.search(r'\b(?:transfer\s+date|service\s+date|arrival\s+transfer\s+date|^date\b)\b', line_lower) and not data['Transfer Date']:
                found_key = 'Transfer Date'
            elif re.search(r'\b(?:transfer\s+time|pickup\s+time)\b', line_lower) and not data['Transfer Time']:
                found_key = 'Transfer Time'
            elif line_lower == 'route':
                current_label = 'Route'
                continue

            if found_key:
                v = clean_trf_label(line_str)
                if v and not is_any_label_or_header(v):
                    data[found_key] = extract_reference_code(v) if found_key == 'Booking Reference' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if current_label == 'Route':
                    if '->' in line_str or ' to ' in line_str:
                        parts = [p.strip() for p in re.split(r'\s*(?:->|\bto\b)\s*', line_str) if p.strip()]
                        if not data['Pickup Location'] and len(parts) >= 1: data['Pickup Location'] = parts[0]; confidence['Pickup Location'] = 'high'
                        if not data['Dropoff Location'] and len(parts) >= 2: data['Dropoff Location'] = parts[1]; confidence['Dropoff Location'] = 'high'
                    current_label = None
                elif not is_any_label_or_header(line_str):
                    data[current_label] = extract_reference_code(line_str) if current_label == 'Booking Reference' else line_str
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

    # ----------------------------------------------------
    # G. SIGHTSEEING VOUCHER
    # ----------------------------------------------------
    elif doc_type == 'Sightseeing Voucher':
        def is_sight_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            s_clean = re.sub(r'\s+', ' ', s_clean)
            if re.match(r'^(?:sightseeing\s*voucher|tour\s*voucher|activity\s*voucher)\b', s_clean):
                return True
            return s_clean in ['field', 'sample value', 'details']

        def clean_sight_label(s):
            return re.sub(r'^(?:Activity\s+Date|Tour\s+Date|Date\s+of\s+Activity|Tour\s*/?\s*Activity\s*Name|Activity(?:\s+Name)?|Tour(?:\s+Name)?|Attraction|Guests?(?:\s+Name)?|Lead\s+Guest|Travel[l]?ers?(?:\s+Name)?|Passengers?(?:\s+Name)?|Customer(?:\s+Name)?|Voucher\s*Ref(?:erence)?|Voucher\s*(?:Number|No\.?|#)|Booking\s*Ref(?:erence)?|Reference(?:\s*(?:Number|No\.?|#))?|Number\s+of\s+Guests|No\.?\s+of\s+Guests|Guests|Pax|Participants)\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_sight_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id|service\s+type)\b', line_lower):
                current_label = None
                continue

            found_key = None
            if re.search(r'\b(?:voucher\s*ref(?:erence)?|voucher\s*(?:number|no\.?|#)|booking\s*ref(?:erence)?|reference(?:\s*(?:number|no\.?|#))?)\b', line_lower) and not data['Booking Reference']:
                found_key = 'Booking Reference'
            elif re.search(r'\b(?:guests?(?:\s+name)?|lead\s+guest|travel[l]?ers?(?:\s+name)?|passengers?(?:\s+name)?)\b', line_lower) and not data['Guest Name']:
                found_key = 'Guest Name'
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and not data['Guest Name']:
                found_key = 'Guest Name'
            elif re.search(r'\b(?:activity\s+date|tour\s+date|date\s+of\s+activity)\b', line_lower) and not data['Activity Date']:
                found_key = 'Activity Date'
            elif re.search(r'\b(?:tour\s*/?\s*activity\s*name|activity(?:\s+name)?|tour(?:\s+name)?|attraction)\b', line_lower) and not data['Tour / Activity Name']:
                found_key = 'Tour / Activity Name'
            elif re.search(r'\b(?:number\s+of\s+guests|no\.?\s+of\s+guests|pax|participants)\b', line_lower) and not data['Number of Guests']:
                found_key = 'Number of Guests'

            if found_key:
                v = clean_sight_label(line_str)
                if v and not is_any_label_or_header(v):
                    data[found_key] = extract_reference_code(v) if found_key == 'Booking Reference' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if not is_any_label_or_header(line_str):
                    data[current_label] = extract_reference_code(line_str) if current_label == 'Booking Reference' else line_str
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

    # ----------------------------------------------------
    # H. ARRIVAL / ENTRY DOCUMENT
    # ----------------------------------------------------
    # ----------------------------------------------------
    # LAND VOUCHER
    # ----------------------------------------------------
    elif doc_type == 'Land Voucher':
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_disclaimer_line(line_str):
                continue
            if re.search(r'\b(?:guest|passenger|travel[l]?er|customer)(?:\s*name)?\b', line_lower) and not data['Guest / Passenger Name']:
                v = re.sub(r'^(?:guest|passenger|travel[l]?er|customer)(?:\s*name)?\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Guest / Passenger Name'] = v
                    confidence['Guest / Passenger Name'] = 'high'
            elif re.search(r'\b(?:booking\s*ref(?:erence)?|voucher\s*no\.?|reservation\s*no\.?|confirmation\s*no\.?)\b', line_lower) and not data['Booking Reference']:
                v = re.sub(r'^(?:booking\s*ref(?:erence)?|voucher\s*no\.?|reservation\s*no\.?|confirmation\s*no\.?)\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Booking Reference'] = extract_reference_code(v)
                    confidence['Booking Reference'] = 'high'
            elif re.search(r'\b(?:service|activity|tour|package)(?:\s*name)?\b', line_lower) and not data['Service / Activity Name']:
                v = re.sub(r'^(?:service|activity|tour|package)(?:\s*name)?\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Service / Activity Name'] = v
                    confidence['Service / Activity Name'] = 'high'
            elif re.search(r'\b(?:service\s*date|date|activity\s*date)\b', line_lower) and not data['Service Date']:
                m = re.search(date_pattern, line_str)
                if m:
                    data['Service Date'] = m.group(1).strip()
                    confidence['Service Date'] = 'high'
            elif re.search(r'\b(?:pickup|pick-up|location)\b', line_lower) and not data['Pickup / Location']:
                v = re.sub(r'^(?:pickup(?:\s*location)?|pick-up(?:\s*location)?|location)\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Pickup / Location'] = v
                    confidence['Pickup / Location'] = 'high'
            elif re.search(r'\b(?:dropoff|drop-off|destination)\b', line_lower) and not data['Dropoff / Destination']:
                v = re.sub(r'^(?:dropoff(?:\s*location)?|drop-off(?:\s*location)?|destination)\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Dropoff / Destination'] = v
                    confidence['Dropoff / Destination'] = 'high'
            elif re.search(r'\b(?:time|pickup\s*time|service\s*time)\b', line_lower) and not data['Service Time']:
                tm = re.search(r'\b(\d{1,2}:\d{2}(?:\s*(?:am|pm|hrs))?)\b', line_str, re.IGNORECASE)
                if tm:
                    data['Service Time'] = tm.group(1).strip()
                    confidence['Service Time'] = 'high'
            elif re.search(r'\b(?:number\s*of\s*guests?|no\.?\s*of\s*guests?|pax|guests?)\b', line_lower) and not data['Number of Guests']:
                gm = re.search(r'\b(\d+)\s*(?:pax|guests?|adults?)?\b', line_str, re.IGNORECASE)
                if gm:
                    data['Number of Guests'] = gm.group(1).strip()
                    confidence['Number of Guests'] = 'high'

    # ----------------------------------------------------
    # AADHAAR CARD
    # ----------------------------------------------------
    elif doc_type == 'Aadhaar Card':
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_disclaimer_line(line_str) or 'government of india' in line_lower or 'unique identification' in line_lower:
                continue
            if not data['Aadhaar Number']:
                an_match = re.search(r'\b(\d{4}\s*\d{4}\s*\d{4})\b', line_str)
                if an_match:
                    raw_num = an_match.group(1)
                    digits = re.sub(r'\s+', '', raw_num)
                    data['Aadhaar Number'] = f"{digits[:4]} {digits[4:8]} {digits[8:12]}"
                    confidence['Aadhaar Number'] = 'high'
            if re.search(r'\b(?:dob|birth|date\s*of\s*birth|year\s*of\s*birth)\b', line_lower) and not data['Date of Birth']:
                m = re.search(date_pattern, line_str)
                if m:
                    data['Date of Birth'] = m.group(1).strip()
                    confidence['Date of Birth'] = 'high'
            if not data['Gender']:
                if re.search(r'\b(male|female|transgender)\b', line_lower):
                    gm = re.search(r'\b(male|female|transgender)\b', line_lower)
                    data['Gender'] = gm.group(1).capitalize()
                    confidence['Gender'] = 'high'
            if not data['Full Name']:
                if re.search(r'\bname\s*[:\-]\s*', line_lower):
                    v = re.sub(r'^.*?\bname\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                    if v and not is_any_label_or_header(v):
                        data['Full Name'] = v
                        confidence['Full Name'] = 'high'
            if re.search(r'\baddress\s*[:\-]\s*', line_lower) and not data['Address']:
                v = re.sub(r'^.*?\baddress\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v:
                    data['Address'] = v
                    confidence['Address'] = 'high'
        if not data['Full Name']:
            for line in lines[:8]:
                ls = line.strip()
                if ls and not is_any_label_or_header(ls) and not is_disclaimer_line(ls) and not re.search(r'\b(government|india|unique|authority|aadhaar|uidai|\d{4})\b', ls.lower()):
                    if len(ls.split()) <= 4 and re.match(r'^[A-Za-z\s\.]+$', ls):
                        data['Full Name'] = ls
                        confidence['Full Name'] = 'medium'
                        break

    # ----------------------------------------------------
    # PAN CARD
    # ----------------------------------------------------
    elif doc_type == 'PAN Card':
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_disclaimer_line(line_str) or 'income tax' in line_lower:
                continue
            if not data['PAN Number']:
                pm = re.search(r'\b([A-Z]{5}[0-9]{4}[A-Z])\b', line_str)
                if pm:
                    data['PAN Number'] = pm.group(1)
                    confidence['PAN Number'] = 'high'
            if re.search(r'\b(?:dob|birth|date\s*of\s*birth)\b', line_lower) and not data['Date of Birth']:
                m = re.search(date_pattern, line_str)
                if m:
                    data['Date of Birth'] = m.group(1).strip()
                    confidence['Date of Birth'] = 'high'
            if re.search(r"\b(?:father'?s?\s*name)\b", line_lower) and not data["Father's Name"]:
                v = re.sub(r"^.*?\bfather'?s?\s*name\s*[:\-]\s*", '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data["Father's Name"] = v
                    confidence["Father's Name"] = 'high'
            if re.search(r'\bname\s*[:\-]\s*', line_lower) and not re.search(r"father'?s", line_lower) and not data['Full Name']:
                v = re.sub(r'^.*?\bname\s*[:\-]\s*', '', line_str, flags=re.IGNORECASE).strip()
                if v and not is_any_label_or_header(v):
                    data['Full Name'] = v
                    confidence['Full Name'] = 'high'
        if not data['Full Name']:
            for line in lines[:8]:
                ls = line.strip()
                if ls and not is_any_label_or_header(ls) and not is_disclaimer_line(ls) and not re.search(r'\b(income|tax|department|permanent|account|number|govt|india|[A-Z]{5}[0-9]{4}[A-Z]|\d{2}[/\-])\b', ls.lower()):
                    if len(ls.split()) <= 4 and re.match(r'^[A-Za-z\s\.]+$', ls):
                        data['Full Name'] = ls
                        confidence['Full Name'] = 'medium'
                        break

    elif doc_type == 'Arrival / Entry Document':
        def is_arr_header(s):
            s_clean = re.sub(r'[^a-z0-9 ]', ' ', s.lower()).strip()
            return s_clean in ['arrival entry document', 'arrival entry document demo', 'arrival entry information demo', 'arrival card demo', 'disembarkation card', 'field', 'sample value', 'details']

        def clean_arr_label(s):
            return re.sub(r'^(?:Travellers?(?:\s+Name)?|Travelers?(?:\s+Name)?|Passengers?(?:\s+Name)?|Customer(?:\s+Name)?|Trip\s+Name|Trip|Destination|Port\s+of\s+Entry|City|Arrival\s+Date|Date\s+of\s+Arrival|Entry\s+Date|Departure\s+Date|Date\s+of\s+Departure|Exit\s+Date|Arrival\s*Ref(?:erence)?|Reference(?:\s*(?:Number|No\.?|#))?|Card\s*(?:Number|No\.?|#)|Document\s*(?:Number|No\.?|#))\s*(?::|-)?\s*', '', s, flags=re.IGNORECASE).strip()

        current_label = None
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if not line_str or is_arr_header(line_str) or re.search(r'\b(?:customer\s+id|trip\s+id)\b', line_lower):
                current_label = None
                continue

            found_key = None
            if re.search(r'\b(?:travellers?(?:\s+name)?|travelers?(?:\s+name)?|passengers?(?:\s+name)?)\b', line_lower) and not data['Traveller Name']:
                found_key = 'Traveller Name'
            elif re.search(r'\bcustomer(?:\s+name)?\b', line_lower) and not data['Traveller Name']:
                found_key = 'Traveller Name'
            elif re.search(r'\btrip(?:\s+name)?\b', line_lower) and not re.search(r'\btrip\s+id\b', line_lower) and not data['Trip Name']:
                found_key = 'Trip Name'
            elif re.search(r'\b(?:arrival\s+date|date\s+of\s+arrival|entry\s+date)\b', line_lower) and not data['Arrival Date']:
                found_key = 'Arrival Date'
            elif re.search(r'\b(?:departure\s+date|date\s+of\s+departure|exit\s+date)\b', line_lower) and not data['Departure Date']:
                found_key = 'Departure Date'
            elif re.search(r'\b(?:destination|port\s+of\s+entry)\b', line_lower) and not data['Destination']:
                found_key = 'Destination'
            elif re.search(r'\b(?:arrival\s*ref(?:erence)?|reference(?:\s*(?:number|no\.?|#))?|card\s*number|document\s*number)\b', line_lower) and not data['Reference Number']:
                found_key = 'Reference Number'

            if found_key:
                v = clean_arr_label(line_str)
                if v and not is_any_label_or_header(v):
                    data[found_key] = extract_reference_code(v) if found_key == 'Reference Number' else v
                    confidence[found_key] = 'high'
                    current_label = None
                else:
                    current_label = found_key
            elif current_label:
                if not is_any_label_or_header(line_str):
                    data[current_label] = extract_reference_code(line_str) if current_label == 'Reference Number' else line_str
                    confidence[current_label] = 'high'
                    current_label = None
                else:
                    current_label = None

    # ----------------------------------------------------
    # I. ITINERARY
    # ----------------------------------------------------
    elif doc_type == 'Itinerary':
        # 1. Identify metadata lines to exclude from schedule
        metadata_indices = set()
        for i, line in enumerate(lines):
            line_lower = line.strip().lower()
            if re.search(r'\b(?:start\s+date|end\s+date|travel\s+dates|departure\s+date|return\s+date|destination|trip\s+name|customer|traveller|travellers|revision|prepared\s+for|status|demo\s+purpose|field|sample\s+value)\b', line_lower):
                metadata_indices.add(i)
                if i + 1 < len(lines):
                    metadata_indices.add(i + 1)

        # 2. Extract Metadata (Start Date, End Date, Destination)
        travel_dates = ""
        current_date_key = None
        for i, line in enumerate(lines):
            line_str = line.strip()
            line_lower = line_str.lower()
            if re.search(r'\btravel\s+dates\b', line_lower):
                m_td = re.search(rf'({date_pattern}\s*[-–—]\s*{date_pattern})', line_str)
                if m_td:
                    travel_dates = m_td.group(1)
            elif re.search(r'\bstart\s+date\b', line_lower) and not data['Start Date']:
                m = re.search(date_pattern, line_str)
                if m: data['Start Date'] = m.group(1); confidence['Start Date'] = 'high'; current_date_key = None
                else: current_date_key = 'Start Date'
            elif re.search(r'\bend\s+date\b', line_lower) and not data['End Date']:
                m = re.search(date_pattern, line_str)
                if m: data['End Date'] = m.group(1); confidence['End Date'] = 'high'; current_date_key = None
                else: current_date_key = 'End Date'
            elif current_date_key:
                m = re.search(date_pattern, line_str)
                if m:
                    data[current_date_key] = m.group(1); confidence[current_date_key] = 'high'
                    current_date_key = None
                else:
                    current_date_key = None

        if not data['Start Date'] or not data['End Date']:
            for i, line in enumerate(lines):
                if re.search(r'\btravel\s+dates\b', line.lower()):
                    td_text = line
                    if i + 1 < len(lines):
                        td_text += ' ' + lines[i+1]
                    td_matches = re.findall(date_pattern, td_text)
                    if len(td_matches) >= 2:
                        if not data['Start Date']: data['Start Date'] = td_matches[0]; confidence['Start Date'] = 'high'
                        if not data['End Date']: data['End Date'] = td_matches[1]; confidence['End Date'] = 'high'
                    break

        if travel_dates and (not data['Start Date'] or not data['End Date']):
            td_matches = re.findall(date_pattern, travel_dates)
            if len(td_matches) >= 2:
                if not data['Start Date']: data['Start Date'] = td_matches[0]; confidence['Start Date'] = 'high'
                if not data['End Date']: data['End Date'] = td_matches[1]; confidence['End Date'] = 'high'

        # 3. Extract Schedule Entries (strictly excluding metadata lines)
        schedule_entries = []
        current_day = None

        for i, line in enumerate(lines):
            line_str = line.strip()
            line_lower = line_str.lower()
            
            # Skip lines identified as table metadata
            if i in metadata_indices:
                continue
            if not line_str or is_any_label_or_header(line_str):
                current_day = None
                continue

            # Case A: "Day \d+"
            m_day_head = re.match(r'^(Day\s+\d+)\s*(?::|-)?\s*(.*)$', line_str, re.IGNORECASE)
            if m_day_head:
                lbl = m_day_head.group(1).strip()
                desc = m_day_head.group(2).strip()
                if desc and not is_any_label_or_header(desc):
                    schedule_entries.append(f"{lbl}: {desc}")
                    current_day = None
                else:
                    current_day = lbl
                continue

            # Case B: "<Date>: <Activity>" (e.g. "12 Dec: Arrival / hotel transfer")
            m_date_act = re.match(r'^(\d{1,2}\s+[A-Za-z]{3,4}(?:\s+\d{4})?)\s*:\s*(.+)$', line_str)
            if m_date_act:
                d_lbl = m_date_act.group(1).strip()
                act_desc = m_date_act.group(2).strip()
                if act_desc and not is_any_label_or_header(act_desc):
                    schedule_entries.append(f"{d_lbl}: {act_desc}")
                    current_day = None
                    continue

            # Multi-line continuation for current_day
            if current_day:
                if not is_any_label_or_header(line_str):
                    schedule_entries.append(f"{current_day}: {line_str}")
                    current_day = None
                else:
                    current_day = None

        if schedule_entries:
            data['Schedule Summary'] = ' | '.join(schedule_entries[:5])
            confidence['Schedule Summary'] = 'high'
            if not data['Start Date']:
                d_s = re.search(date_pattern, schedule_entries[0])
                if d_s: data['Start Date'] = d_s.group(1); confidence['Start Date'] = 'high'
            if not data['End Date']:
                d_e = re.search(date_pattern, schedule_entries[-1])
                if d_e: data['End Date'] = d_e.group(1); confidence['End Date'] = 'high'
        else:
            data['Schedule Summary'] = ''

        # Destination extraction
        dest_label_seen = False
        for line in lines:
            line_str = line.strip()
            line_lower = line_str.lower()
            if data['Trip Destination']:
                break
            m_dest = re.search(r'\b(?:destination|trip|tour)\b\s*:\s*(.+)$', line_str, re.IGNORECASE)
            if m_dest:
                cand = m_dest.group(1).strip()
                if cand and cand.lower() not in ['demo', 'sample', 'the', 'id']:
                    data['Trip Destination'] = cand; confidence['Trip Destination'] = 'high'
                    break
            if re.match(r'^(?:trip\s+)?destination$', line_lower):
                dest_label_seen = True
                continue
            if dest_label_seen:
                if line_str and not is_any_label_or_header(line_str):
                    data['Trip Destination'] = line_str; confidence['Trip Destination'] = 'high'
                    dest_label_seen = False
                    break
                dest_label_seen = False

        if not data['Trip Destination']:
            for line in lines:
                m_title = re.search(r'^([A-Za-z\s]+?)\s+(?:itinerary|tour|trip)\b', line, re.IGNORECASE)
                if m_title:
                    cand = m_title.group(1).strip()
                    if cand and cand.lower() not in ['trip', 'tour', 'travel', 'final', 'draft', 'demo', 'sample', 'the']:
                        data['Trip Destination'] = cand; confidence['Trip Destination'] = 'high'
                        break

    return data, confidence, doc_type, type_confidence

def compute_bytes_sha256(file_bytes: bytes) -> str:
    """Computes SHA-256 hex digest of raw document bytes for deduplication."""
    import hashlib
    return hashlib.sha256(file_bytes or b"").hexdigest()


def resolve_azapi_document_target(expected_requirement: str = None, passport_kind: str = None):
    """
    Maps a requirement hint and explicit passport selection into:
      (schema_doc_type, azapi_target_type_or_None)
    Only Aadhaar Card, PAN Card, Indian Passport, and Foreign Passport have AZAPI endpoints.
    All other scanned documents return azapi_target_type = None (manual review only).
    """
    req = (expected_requirement or "").lower().strip()
    kind = (passport_kind or "").lower().strip()

    if any(k in req for k in ("aadhaar", "adhaar", "uidai")):
        return "Aadhaar Card", "aadhaar"
    if "pan" in req:
        return "PAN Card", "pan"
    if "passport" in req:
        if "foreign" in kind or "ovb" in kind or "international" in kind or ("foreign" in req and not kind):
            return "Passport", "foreign_passport"
        if "indian" in kind or "ind" in kind or "indian" in req:
            return "Passport", "indian_passport"
        return "Passport", "passport"

    NON_AZAPI_MAP = (
        ("flight", "Flight Ticket"),
        ("ticket", "Flight Ticket"),
        ("hotel", "Hotel Voucher"),
        ("visa", "Visa / Entry Document"),
        ("insurance", "Travel Insurance"),
        ("transfer", "Transfer Voucher"),
        ("cab", "Transfer Voucher"),
        ("taxi", "Transfer Voucher"),
        ("sightseeing", "Sightseeing Voucher"),
        ("tour", "Sightseeing Voucher"),
        ("activity", "Sightseeing Voucher"),
        ("land", "Land Voucher"),
        ("ground", "Land Voucher"),
        ("arrival", "Arrival / Entry Document"),
        ("entry", "Arrival / Entry Document"),
        ("itinerary", "Itinerary"),
    )
    for kw, doc_label in NON_AZAPI_MAP:
        if kw in req:
            return doc_label, None

    return "Needs Review", None


def process_document(
    file_name,
    file_bytes,
    expected_requirement=None,
    passport_kind=None,
    force_retry=False,
    back_file_bytes=None,
    back_filename=None,
    session_token=None,
    require_auth=False,
):
    warnings = []
    text = ""
    source_type = "manual_review_required"
    doc_type = "Needs Review"
    type_confidence = "low"
    data = {}
    confidence = {}
    ocr_provider = "manual_review"
    manual_review_required = False
    can_retry_azapi = False
    azapi_status = "not_applicable"
    azapi_error = None
    azapi_endpoint = None
    azapi_cached = False

    if require_auth or session_token is not None:
        import auth_services
        if not session_token or not isinstance(session_token, str) or not session_token.strip():
            raise PermissionError("Unauthenticated: Valid session token required for OCR processing.")
        auth_services.require_permission(session_token, "document:upload")

    if not isinstance(file_bytes, (bytes, bytearray)) or len(file_bytes) == 0:
        return {
            'document_type': 'Needs Review',
            'type_confidence': 'low',
            'source_type': 'manual_required',
            'raw_text': '',
            'extracted_fields': {'Document Details': ''},
            'warnings': ["Empty document bytes provided. Manual review required."],
            'confidence': {},
            'ocr_provider': 'manual_review',
            'manual_review_required': True,
            'can_retry_azapi': False,
            'azapi_status': 'empty_file',
            'azapi_error': None,
            'azapi_endpoint': None,
            'azapi_cached': False,
            'passport_kind': passport_kind,
            'file_sha256': compute_bytes_sha256(file_bytes or b""),
            'is_reviewed': False,
            'can_overwrite_verified': False,
        }

    ext = os.path.splitext((file_name or "").strip())[1].lower()
    if ext not in (".pdf", ".jpg", ".jpeg", ".png"):
        return {
            'document_type': 'Needs Review',
            'type_confidence': 'low',
            'source_type': 'manual_required',
            'raw_text': '',
            'extracted_fields': {'Document Details': ''},
            'warnings': [f"Unsupported file extension '{ext or 'none'}'. Only PDF, JPG, JPEG, and PNG are allowed."],
            'confidence': {},
            'ocr_provider': 'manual_review',
            'manual_review_required': True,
            'can_retry_azapi': False,
            'azapi_status': 'invalid_file_type',
            'azapi_error': None,
            'azapi_endpoint': None,
            'azapi_cached': False,
            'passport_kind': passport_kind,
            'file_sha256': compute_bytes_sha256(file_bytes),
            'is_reviewed': False,
            'can_overwrite_verified': False,
        }

    if len(file_bytes) > 20 * 1024 * 1024:
        return {
            'document_type': 'Needs Review',
            'type_confidence': 'low',
            'source_type': 'manual_required',
            'raw_text': '',
            'extracted_fields': {'Document Details': ''},
            'warnings': ["Document exceeds 20MB OCR limit. Manual review required."],
            'confidence': {},
            'ocr_provider': 'manual_review',
            'manual_review_required': True,
            'can_retry_azapi': False,
            'azapi_status': 'oversized_file',
            'azapi_error': None,
            'azapi_endpoint': None,
            'azapi_cached': False,
            'passport_kind': passport_kind,
            'file_sha256': compute_bytes_sha256(file_bytes),
            'is_reviewed': False,
            'can_overwrite_verified': False,
        }

    resolved_doc_label, azapi_target = resolve_azapi_document_target(expected_requirement, passport_kind)
    is_pdf = ext == '.pdf' or bytes(file_bytes[:4]) == b'%PDF'
    if not is_pdf:
        try:
            from PIL import Image
            with Image.open(io.BytesIO(file_bytes)) as _im:
                _im.verify()
        except Exception:
            return {
                'document_type': 'Needs Review',
                'type_confidence': 'low',
                'source_type': 'manual_required',
                'raw_text': '',
                'extracted_fields': {sf: '' for sf in SCHEMAS.get(resolved_doc_label, ['Document Details'])},
                'warnings': ["Corrupt or invalid image file content. Manual review required."],
                'confidence': {},
                'ocr_provider': 'manual_review',
                'manual_review_required': True,
                'can_retry_azapi': False,
                'azapi_status': 'corrupt_image_manual',
                'azapi_error': None,
                'azapi_endpoint': None,
                'azapi_cached': False,
                'passport_kind': passport_kind,
                'file_sha256': compute_bytes_sha256(file_bytes),
                'is_reviewed': False,
                'can_overwrite_verified': False,
            }

    # Tier 1: Embedded PDF Text Analysis (pypdf only; zero OCR, zero AZAPI cost)
    if is_pdf:
        pdf_pages_analysis = []
        is_encrypted = False
        is_corrupt_pdf = False
        try:
            logging.getLogger("pypdf").setLevel(logging.ERROR)
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            if reader.is_encrypted:
                is_encrypted = True
            elif len(reader.pages) == 0:
                is_corrupt_pdf = True
            else:
                max_eval_pages = min(len(reader.pages), 5)
                for p_idx in range(max_eval_pages):
                    p_text = (reader.pages[p_idx].extract_text() or "").strip()
                    alnum_count = len(re.findall(r'[a-zA-Z0-9]', p_text))
                    pdf_pages_analysis.append({
                        "page_num": p_idx + 1,
                        "text": p_text,
                        "is_digital": alnum_count >= 40
                    })
        except Exception:
            is_corrupt_pdf = True

        if is_encrypted or is_corrupt_pdf:
            msg = (
                "Document is encrypted or password-protected. Manual review required."
                if is_encrypted
                else "Malformed or corrupted PDF structure. Manual review required."
            )
            warnings.append(msg)
            return {
                'document_type': 'Needs Review',
                'type_confidence': 'low',
                'source_type': 'manual_required',
                'raw_text': '',
                'extracted_fields': {sf: '' for sf in SCHEMAS.get(resolved_doc_label, ['Document Details'])},
                'warnings': warnings,
                'confidence': confidence,
                'ocr_provider': 'manual_review',
                'manual_review_required': True,
                'can_retry_azapi': False,
                'azapi_status': "encrypted_pdf_manual" if is_encrypted else "corrupt_pdf_manual",
                'azapi_error': None,
                'azapi_endpoint': None,
                'azapi_cached': False,
                'passport_kind': passport_kind,
                'file_sha256': compute_bytes_sha256(file_bytes),
                'is_reviewed': False,
                'can_overwrite_verified': False,
            }
        elif pdf_pages_analysis:
            digital_pages = [p for p in pdf_pages_analysis if p["is_digital"]]
            scanned_pages = [p for p in pdf_pages_analysis if not p["is_digital"]]

            if digital_pages and not scanned_pages:
                text = simple_pdf_extract(file_bytes)
                if text.strip() and len(text.strip()) > 30:
                    source_type = "pdf_text"
                    ocr_provider = "pypdf_digital_text"
                    data, confidence, doc_type, type_confidence = parse_passport_text(
                        text, expected_requirement=expected_requirement, warnings_list=warnings
                    )
            elif digital_pages and scanned_pages and azapi_target is None:
                digital_nums = [p["page_num"] for p in digital_pages]
                scanned_nums = [p["page_num"] for p in scanned_pages]
                combined_digital = "\n\n".join(p["text"] for p in digital_pages if p["text"].strip())
                if combined_digital.strip():
                    text = combined_digital
                    source_type = "mixed_pdf_digital_partial"
                    ocr_provider = "pypdf_digital_partial"
                    manual_review_required = True
                    warnings.append(
                        f"[Mixed PDF] Page(s) {', '.join(map(str, digital_nums))} extracted from digital text. "
                        f"Scanned page(s) {', '.join(map(str, scanned_nums))} require manual visual review."
                    )
                    data, confidence, doc_type, type_confidence = parse_passport_text(
                        text, expected_requirement=expected_requirement, warnings_list=warnings
                    )

    # Tier 2: AZAPI-Only Cloud Extraction for Supported Scanned / Image Identity Docs,
    # or Fail-Closed Manual Staff Review for Unsupported Scanned Docs (Zero Tesseract / Local OCR)
    if not text.strip() or len(text.strip()) <= 30:
        if azapi_target is None:
            doc_type = resolved_doc_label
            type_confidence = 'medium' if doc_type != 'Needs Review' else 'low'
            source_type = 'manual_review_required'
            ocr_provider = 'manual_review'
            manual_review_required = True
            can_retry_azapi = False
            azapi_status = 'unsupported'
            data = {sf: '' for sf in SCHEMAS.get(doc_type, ['Document Details'])}
            warnings.append(
                f"Scanned or image document ({doc_type}) is outside AZAPI identity OCR scope. "
                "Please review the document preview and enter fields manually."
            )
        else:
            import azapi_adapter
            adapter = azapi_adapter.get_azapi_adapter()
            az_res = adapter.extract_or_manual_review(
                file_bytes,
                file_name,
                expected_type=azapi_target,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                passport_kind=passport_kind,
                force_retry=force_retry,
            )

            ocr_provider = az_res.get('provider', 'manual_review')
            azapi_status = az_res.get('azapi_status', 'ok' if az_res.get('success') else 'manual_review')
            azapi_error = az_res.get('azapi_error')
            azapi_endpoint = az_res.get('endpoint')
            azapi_cached = bool(az_res.get('cached', False))
            can_retry_azapi = bool(az_res.get('can_retry_azapi', az_res.get('success', False)))

            if az_res.get('success'):
                source_type = az_res.get('source_type', 'azapi_cloud_ocr')
                text = az_res.get('raw_text', '')
                doc_type = resolved_doc_label if resolved_doc_label != 'Needs Review' else az_res.get('document_type', 'Needs Review')
                if 'passport' in doc_type.lower():
                    doc_type = 'Passport'
                type_confidence = 'high'

                parsed_data, parsed_conf, parsed_type, parsed_tconf = parse_passport_text(
                    text, expected_requirement=expected_requirement, warnings_list=warnings
                ) if text.strip() else ({}, {}, doc_type, 'high')

                schema_fields = SCHEMAS.get(doc_type, ['Document Details'])
                data = {sf: '' for sf in schema_fields}
                azapi_fields = az_res.get('extracted_fields') or {}
                for sf in schema_fields:
                    if azapi_fields.get(sf):
                        data[sf] = azapi_fields[sf]
                        confidence[sf] = 'high'
                    elif parsed_data.get(sf):
                        data[sf] = parsed_data[sf]
                        confidence[sf] = parsed_conf.get(sf, 'medium')

                # Preserve additional AZAPI structured values (e.g., MRZ / Given Name / Surname) if missing from base schema
                for extra_k, extra_v in azapi_fields.items():
                    if extra_v and extra_k not in data:
                        data[extra_k] = extra_v
                        confidence[extra_k] = 'high'

                reuse_note = "cached session result" if azapi_cached else f"endpoint {azapi_endpoint}"
                warnings.append(f"[AZAPI Cloud OCR] Fields extracted via AZAPI.ai ({reuse_note}). Please confirm before saving.")
                warnings.extend(az_res.get('warnings', []))
                has_any_value = any(str(v).strip() for v in data.values())
                has_suspicious_warn = any("mismatch" in w.lower() or "invalid" in w.lower() or "could not" in w.lower() or "check-digit" in w.lower() for w in warnings)
                if not has_any_value or has_suspicious_warn:
                    manual_review_required = True
                    if not has_any_value:
                        type_confidence = 'low'
                        warnings.append("Incomplete OCR response (no usable fields extracted). Manual verification required.")
            else:
                doc_type = resolved_doc_label
                type_confidence = 'medium' if doc_type != 'Needs Review' else 'low'
                source_type = 'manual_review_required'
                manual_review_required = True
                data = {sf: '' for sf in SCHEMAS.get(doc_type, ['Document Details'])}
                warnings.extend(az_res.get('warnings', []))

    return {
        'document_type': doc_type,
        'type_confidence': type_confidence,
        'source_type': source_type,
        'raw_text': text,
        'extracted_fields': data,
        'warnings': warnings,
        'confidence': confidence,
        'ocr_provider': ocr_provider,
        'manual_review_required': manual_review_required,
        'can_retry_azapi': can_retry_azapi,
        'azapi_status': azapi_status,
        'azapi_error': azapi_error,
        'azapi_endpoint': azapi_endpoint,
        'azapi_cached': azapi_cached,
        'passport_kind': passport_kind,
        'file_sha256': compute_bytes_sha256(file_bytes),
        'is_reviewed': False,
        'can_overwrite_verified': False,
    }
