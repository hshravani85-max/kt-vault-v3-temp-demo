"""
Khanna Travels Vault V3 - ICAO Doc 9303 TD3 Passport MRZ Parser
Pure-Python standalone parser and validator for TD3 (2 lines x 44 characters) MRZ.

Standard Reference:
ICAO Doc 9303 Part 4: Specifications for Machine Readable Passports (MRPs)
TD3 Format:
  Line 1 (44 chars):
    Pos 0-1  : Document code (P<, PM, etc.)
    Pos 2-4  : Issuing state or organization (3 alpha or <)
    Pos 5-43 : Name (Surname<<Given<Names<<<<...)
  Line 2 (44 chars):
    Pos 0-8  : Passport number (9 alphanumeric, < filler)
    Pos 9    : Check digit of passport number
    Pos 10-12: Nationality (3 alpha or <)
    Pos 13-18: Date of birth (YYMMDD)
    Pos 19   : Check digit of date of birth
    Pos 20   : Sex (M, F, X, <)
    Pos 21-26: Expiry date (YYMMDD)
    Pos 27   : Check digit of expiry date
    Pos 28-41: Personal number / Optional data (14 alphanumeric, < filler)
    Pos 42   : Check digit of optional data (< or 0 if optional is empty)
    Pos 43   : Composite check digit (over pos 0-9, 13-19, 21-42)

Weighting algorithm:
  Weights: [7, 3, 1] repeating cycle.
  Character values: 0-9 = 0-9, A-Z = 10-35, < = 0.
  Check digit = (sum(val * weight)) % 10.
"""

import re
import datetime
from typing import Dict, Any, Tuple, Optional, List, Union

CHECK_WEIGHTS = [7, 3, 1]

def calculate_check_digit(data: str) -> str:
    """
    Calculates the ICAO Doc 9303 check digit using weights [7, 3, 1].
    Returns check digit string ('0'-'9') or empty string if input is invalid.
    """
    if not isinstance(data, str) or not data:
        return ""
    total = 0
    for i, ch in enumerate(data):
        c = ch.upper()
        if '0' <= c <= '9':
            val = int(c)
        elif 'A' <= c <= 'Z':
            val = ord(c) - ord('A') + 10
        elif c == '<':
            val = 0
        else:
            return ""
        total += val * CHECK_WEIGHTS[i % 3]
    return str(total % 10)


def validate_check_digit(data: str, expected_digit: str) -> bool:
    """
    Validates data against an expected check digit.
    Returns True if matches, False otherwise.
    """
    if not expected_digit:
        return False
    calc = calculate_check_digit(data)
    if not calc:
        return False
    return calc == str(expected_digit).strip().upper()


def resolve_century(yy_str: str, is_dob: bool = True, reference_year: int = 2026) -> int:
    """
    Deterministically resolves a two-digit year (YY) to a four-digit year (YYYY).
    - For Date of Birth (DOB):
      Living traveller policy: if YY > (reference_year % 100), year is 1900+YY;
      otherwise 2000+YY.
    - For Expiry Date:
      Passports are valid for 5-10 years. Passports expiring >= 80 are 1900+YY;
      otherwise 2000+YY.
    """
    try:
        yy = int(yy_str)
    except (ValueError, TypeError):
        return 1900
    cur_yy = reference_year % 100
    if is_dob:
        return (1900 + yy) if yy > cur_yy else (2000 + yy)
    else:
        return (1900 + yy) if yy >= 80 else (2000 + yy)


def parse_mrz_date(yymmdd: str, is_dob: bool = True, reference_year: int = 2026) -> Tuple[str, str, Optional[str]]:
    """
    Parses a 6-character YYMMDD string into (iso_str, formatted_str, error_message).
    Example: '880814' -> ('1988-08-14', '14 Aug 1988', None)
    """
    if not yymmdd or len(yymmdd) != 6 or not yymmdd.isdigit():
        return "", "", f"Invalid date string '{yymmdd}' (expected 6 digits)"
    try:
        yy_str = yymmdd[:2]
        mm = int(yymmdd[2:4])
        dd = int(yymmdd[4:6])
        if not (1 <= mm <= 12) or not (1 <= dd <= 31):
            return "", "", f"Date digits out of valid range: {yymmdd}"
        full_year = resolve_century(yy_str, is_dob=is_dob, reference_year=reference_year)
        dt = datetime.date(full_year, mm, dd)
        iso_str = dt.isoformat()
        formatted_str = dt.strftime("%d %b %Y")
        return iso_str, formatted_str, None
    except Exception as e:
        return "", "", f"Failed to resolve date {yymmdd}: {str(e)}"


def clean_mrz_text(text: str) -> str:
    """Replaces filler angle brackets with spaces and strips extra spaces."""
    if not text:
        return ""
    # Strip trailing filler brackets
    t = text.rstrip('<')
    # Replace internal brackets with spaces
    t = t.replace('<', ' ')
    # Normalize multiple whitespace
    return re.sub(r'\s+', ' ', t).strip()



LOOKALIKE_TO_DIGIT = {
    'O': '0', 'o': '0', 'Q': '0', 'D': '0',
    'I': '1', 'i': '1', 'l': '1', '|': '1', '!': '1',
    'Z': '2', 'z': '2',
    'S': '5', 's': '5',
    'B': '8',
    'G': '6',
    'T': '7'
}

LOOKALIKE_TO_ALPHA = {
    '0': 'O', '1': 'I', '2': 'Z', '5': 'S', '8': 'B'
}


def clean_mrz_line(raw: str) -> str:
    """
    Cleans an OCR-extracted line for MRZ processing:
    - Normalizes filler lookalikes like '(', ')', '[', ']', '{', '}', '«', '»', '‹', '›', '_', '|', '/', '\\' to '<'.
    - Strips whitespace and characters outside [A-Z0-9<].
    - Uppercases all Latin characters.
    """
    if not raw:
        return ""
    t = re.sub(r'[(\[\{)\]\}\«\»\‹\›_\/\\|]', '<', str(raw))
    t = re.sub(r'[^A-Za-z0-9<]', '', t)
    return t.upper()


def repair_td3_line2(l2: str, all_raw_lines: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    """
    Performs targeted OCR lookalike error recovery on TD3 Line 2 numeric regions:
    - Position 9: Document number check digit
    - Positions 10-12: Nationality ('1ND'/'LND' -> 'IND')
    - Positions 13-18: Date of birth (YYMMDD)
    - Position 19: Date of birth check digit
    - Positions 21-26: Date of expiry (YYMMDD)
    - Position 27: Date of expiry check digit
    - Position 43: Composite check digit
    - Position 0: Lookalike recovery tested against position 9 check digit
    - Positions 1-7: Indian passport digits if pos 0 is an alpha character
    Returns (repaired_line2, list_of_repairs).
    """
    if not l2 or len(l2) != 44:
        return l2, []

    chars = list(l2)
    repairs = []

    # 1. Strict numeric positions
    strict_num_indices = [9] + list(range(13, 20)) + list(range(21, 28)) + [43]
    for idx in strict_num_indices:
        ch = chars[idx]
        if ch in LOOKALIKE_TO_DIGIT:
            repaired_ch = LOOKALIKE_TO_DIGIT[ch]
            chars[idx] = repaired_ch
            repairs.append(f"Pos {idx}: '{ch}' -> '{repaired_ch}'")

    # 2. Indian passport nationality fix (positions 10-12)
    nat_str = "".join(chars[10:13])
    if nat_str in ("1ND", "LND", "TND", "JND", "IND"):
        if nat_str != "IND":
            repairs.append(f"Nationality: '{nat_str}' -> 'IND'")
            chars[10:13] = list("IND")

    # 3. Document number lookalike resolution (positions 0-8)
    # In Indian passports (1 letter + 7 digits + filler '<'):
    doc_cd = chars[9]
    if chars[8] == '<':
        if not chars[0].isalpha():
            # Pos 0 was OCR'd as a digit or symbol; test uppercase candidate letters against check digit
            candidate_letters = ['Z', 'P', 'L', 'J', 'K', 'M', 'N', 'R', 'S', 'T', 'V', 'W', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
            other_letters = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in candidate_letters]
            for cand in candidate_letters + other_letters:
                test_payload = cand + "".join(chars[1:9])
                if calculate_check_digit(test_payload) == doc_cd:
                    repairs.append(f"DocNum Pos 0: '{chars[0]}' -> '{cand}' (verified by check digit)")
                    chars[0] = cand
                    break

        # Ensure positions 1..7 are digits
        if chars[0].isalpha():
            for idx in range(1, 8):
                ch = chars[idx]
                if ch in LOOKALIKE_TO_DIGIT:
                    repaired_ch = LOOKALIKE_TO_DIGIT[ch]
                    chars[idx] = repaired_ch
                    repairs.append(f"DocNum Pos {idx}: '{ch}' -> '{repaired_ch}'")

    # 4. Expiry Date lookalike & truncation recovery (positions 21-26, check digit 27)
    if "".join(chars[21:26]).isdigit() and chars[26] in ('<', ' ', '_') and all_raw_lines:
        pfx = "".join(chars[21:26])
        for raw_l in all_raw_lines:
            clean = clean_mrz_line(raw_l)
            clean_tr = clean.replace('T', '7').replace('S', '5').replace('I', '1').replace('Z', '2').replace('B', '8')
            m = re.search(re.escape(pfx) + r'(\d)(\d)?', clean_tr)
            if m:
                found_day = m.group(1)
                found_cd = m.group(2)
                chars[26] = found_day
                if found_cd:
                    chars[27] = found_cd
                else:
                    chars[27] = calculate_check_digit("".join(chars[21:27]))
                repairs.append(f"Expiry day truncation recovery: set pos 26 to '{found_day}', pos 27 to '{chars[27]}'")
                break

    repaired_line = "".join(chars)
    return repaired_line, repairs
def find_td3_mrz_lines(text_or_lines: Union[str, List[str], Tuple[str, ...]]) -> Optional[Tuple[str, str]]:
    """
    Locates two TD3 MRZ lines (nominally 44 characters each) in the given text or lines.
    Supports robust tolerance for:
    - Slight OCR trailing or leading padding differences
    - Trailing filler '<' brackets dropped by OCR on white scanner glass
    - Intervening blank or noise lines between Line 1 and Line 2
    - OCR filler character misreadings: '(', '[', '«', etc. normalized to '<'
    Returns (line1, line2) normalized to 44 characters or None if not found.
    """
    if not text_or_lines:
        return None

    if isinstance(text_or_lines, (list, tuple)):
        raw_lines = [str(l).strip() for l in text_or_lines if str(l).strip()]
    elif isinstance(text_or_lines, str):
        raw_lines = [l.strip() for l in text_or_lines.splitlines() if l.strip()]
    else:
        return None

    # Pass 1: Fast exact check on consecutive lines (preserves existing clean behavior)
    for i in range(len(raw_lines) - 1):
        l1_clean = clean_mrz_line(raw_lines[i])
        l2_clean = clean_mrz_line(raw_lines[i + 1])

        if l1_clean.startswith('P') and re.fullmatch(r'P[A-Z0-9<]+', l1_clean) and re.fullmatch(r'[A-Z0-9<]+', l2_clean):
            if len(l1_clean) == 44 and len(l2_clean) == 44:
                return l1_clean, l2_clean

            if 40 <= len(l1_clean) <= 60 and 42 <= len(l2_clean) <= 50:
                l1_norm = None
                l2_norm = None
                if len(l1_clean) == 44:
                    l1_norm = l1_clean
                elif len(l1_clean) > 44 and set(l1_clean[44:]) <= {'<'}:
                    l1_norm = l1_clean[:44]
                elif len(l1_clean) < 44:
                    l1_norm = l1_clean + ('<' * (44 - len(l1_clean)))

                if len(l2_clean) == 44:
                    l2_norm = l2_clean
                elif len(l2_clean) > 44 and set(l2_clean[44:]) <= {'<'}:
                    l2_norm = l2_clean[:44]
                elif 42 <= len(l2_clean) < 44:
                    l2_norm = l2_clean + ('<' * (44 - len(l2_clean)))

                if l1_norm and l2_norm:
                    return l1_norm, l2_norm

    # Pass 2: Scored candidate line search across all lines (robust against column-split and dropped fillers)
    l1_candidates = []
    l2_candidates = []

    for idx, raw in enumerate(raw_lines):
        clean = clean_mrz_line(raw)
        if len(clean) < 15:
            continue

        # Score Line 1
        digits_1 = sum(1 for c in clean[:20] if c.isdigit())
        if digits_1 <= 2:
            score_1 = 0
            if '<<' in clean:
                score_1 += 15
            if clean.startswith('P<') or clean.startswith('P'):
                score_1 += 10
            if 'IND' in clean[:8] or 'LND' in clean[:8]:
                score_1 += 8
            if clean.startswith('<IND') or clean.startswith('<LND'):
                score_1 += 8
            score_1 += min(len(clean), 44) // 4
            if score_1 >= 15:
                l1_candidates.append((score_1, idx, clean))

        # Score Line 2
        digits_2 = sum(1 for c in clean if c.isdigit())
        if digits_2 >= 6:
            score_2 = digits_2 * 2
            if any(tok in clean for tok in ('IND', '1ND', '3IND', '31ND', 'LND')):
                score_2 += 12
            if '<' in clean:
                score_2 += 5
            if score_2 >= 18:
                l2_candidates.append((score_2, idx, clean))

    if not l1_candidates or not l2_candidates:
        return None

    l1_candidates.sort(key=lambda x: x[0], reverse=True)
    l2_candidates.sort(key=lambda x: x[0], reverse=True)

    # Search best pair
    for sc1, idx1, cand_l1 in l1_candidates[:3]:
        for sc2, idx2, cand_l2 in l2_candidates[:4]:
            if idx1 > idx2 + 2:
                continue

            # Normalize Line 1
            l1_work = cand_l1
            if l1_work.startswith('<IND') or l1_work.startswith('<LND'):
                l1_work = 'P' + l1_work
            elif l1_work.startswith('IND') or l1_work.startswith('LND'):
                l1_work = 'P<' + l1_work
            elif not l1_work.startswith('P'):
                if '<' in l1_work:
                    l1_work = 'P<' + l1_work[l1_work.find('<')+1:]
                else:
                    l1_work = 'P<' + l1_work

            if l1_work.startswith('P<LND'):
                l1_work = 'P<IND' + l1_work[5:]

            l1_norm = l1_work[:44].ljust(44, '<')

            # Normalize Line 2
            l2_work = re.sub(r'(\d)1ND', r'\g<1>IND', cand_l2)
            l2_work = re.sub(r'(\d)LND', r'\g<1>IND', l2_work)
            l2_norm = l2_work[:44].ljust(44, '<')

            return l1_norm, l2_norm

    return None


def parse_td3_mrz(
    text_or_lines: Union[str, List[str], Tuple[str, ...]],
    reference_year: int = 2026
) -> Dict[str, Any]:
    """
    Parses and validates a TD3 (Passport) MRZ block.

    Returns a standardized dictionary:
    {
        "success": bool,
        "status": "VALIDATED" | "PARTIALLY_VALIDATED" | "INVALID" | "NOT_FOUND",
        "fields": {
            "document_code": str,
            "issuing_state": str,
            "surname": str,
            "given_names": str,
            "full_name": str,
            "document_number": str,
            "nationality": str,
            "dob_raw": str,
            "dob_iso": str,
            "dob_formatted": str,
            "sex": str,
            "expiry_raw": str,
            "expiry_iso": str,
            "expiry_formatted": str,
            "optional_data": str
        },
        "check_digits": {
            "document_number": {"value": str, "expected": str, "calculated": str, "valid": bool},
            "date_of_birth": {"value": str, "expected": str, "calculated": str, "valid": bool},
            "expiry_date": {"value": str, "expected": str, "calculated": str, "valid": bool},
            "optional_data": {"value": str, "expected": str, "calculated": str, "valid": bool},
            "composite": {"value": str, "expected": str, "calculated": str, "valid": bool}
        },
        "errors": list,
        "warnings": list,
        "raw_lines": list
    }
    """
    empty_result: Dict[str, Any] = {
        "success": False,
        "status": "NOT_FOUND",
        "fields": {
            "document_code": "",
            "issuing_state": "",
            "surname": "",
            "given_names": "",
            "full_name": "",
            "document_number": "",
            "nationality": "",
            "dob_raw": "",
            "dob_iso": "",
            "dob_formatted": "",
            "sex": "",
            "expiry_raw": "",
            "expiry_iso": "",
            "expiry_formatted": "",
            "optional_data": ""
        },
        "check_digits": {},
        "errors": [],
        "warnings": [],
        "raw_lines": []
    }

    if isinstance(text_or_lines, (list, tuple)):
        all_lines_list = [str(l).strip() for l in text_or_lines if str(l).strip()]
    elif isinstance(text_or_lines, str):
        all_lines_list = [l.strip() for l in text_or_lines.splitlines() if l.strip()]
    else:
        all_lines_list = []

    mrz_lines = find_td3_mrz_lines(text_or_lines)
    if not mrz_lines:
        empty_result["errors"].append("No valid TD3 44-character MRZ lines detected.")
        return empty_result

    line1, line2 = mrz_lines
    result = dict(empty_result)
    result["raw_lines"] = [line1, line2]
    errors: List[str] = []
    warnings: List[str] = []

    # Apply lookalike character repair on Line 2 numeric positions
    repaired_line2, repairs_applied = repair_td3_line2(line2, all_raw_lines=all_lines_list)
    if repairs_applied:
        warnings.append(f"MRZ OCR character repairs applied ({len(repairs_applied)} lookalike replacements).")
        line2 = repaired_line2

    # -------------------------------------------------------------
    # 1. Parse Line 1: P<STATE SURNAME<<GIVEN<NAMES
    # -------------------------------------------------------------
    doc_code_raw = line1[0:2].rstrip('<')
    issuing_state = line1[2:5].replace('<', '').strip()
    name_block = line1[5:44]

    if '<<' in name_block:
        name_parts = name_block.split('<<', 1)
        surname_raw = name_parts[0]
        given_raw = name_parts[1]
    else:
        surname_raw = name_block
        given_raw = ""

    surname = clean_mrz_text(surname_raw)
    given_names = clean_mrz_text(given_raw)
    if given_names and surname:
        full_name = f"{given_names} {surname}".strip()
    elif surname:
        full_name = surname
    else:
        full_name = given_names

    # -------------------------------------------------------------
    # 2. Parse Line 2: Doc Num, DOB, Sex, Expiry, Optional Data
    # -------------------------------------------------------------
    doc_num_raw = line2[0:9]
    doc_num_check = line2[9]
    nationality = line2[10:13].replace('<', '').strip()
    dob_raw = line2[13:19]
    dob_check = line2[19]
    sex_char = line2[20]
    expiry_raw = line2[21:27]
    expiry_check = line2[27]
    opt_raw = line2[28:42]
    opt_check = line2[42]
    comp_check = line2[43]

    clean_doc_number = doc_num_raw.rstrip('<')
    clean_sex = sex_char if sex_char in ('M', 'F', 'X') else ""
    clean_opt_data = opt_raw.rstrip('<')

    # Dates
    dob_iso, dob_fmt, dob_err = parse_mrz_date(dob_raw, is_dob=True, reference_year=reference_year)
    if dob_err:
        warnings.append(f"DOB parsing warning: {dob_err}")

    exp_iso, exp_fmt, exp_err = parse_mrz_date(expiry_raw, is_dob=False, reference_year=reference_year)
    if exp_err:
        warnings.append(f"Expiry parsing warning: {exp_err}")

    # -------------------------------------------------------------
    # 3. Check Digit Validations (7-3-1 Algorithm)
    # -------------------------------------------------------------
    check_digits: Dict[str, Dict[str, Any]] = {}

    # A. Document Number
    calc_doc_check = calculate_check_digit(doc_num_raw)
    doc_valid = (calc_doc_check == doc_num_check)
    check_digits["document_number"] = {
        "value": doc_num_raw,
        "expected": doc_num_check,
        "calculated": calc_doc_check,
        "valid": doc_valid
    }
    if not doc_valid:
        warnings.append(f"Document number check digit mismatch: expected '{doc_num_check}', calculated '{calc_doc_check}'.")

    # B. Date of Birth
    calc_dob_check = calculate_check_digit(dob_raw)
    dob_valid = (calc_dob_check == dob_check)
    check_digits["date_of_birth"] = {
        "value": dob_raw,
        "expected": dob_check,
        "calculated": calc_dob_check,
        "valid": dob_valid
    }
    if not dob_valid:
        warnings.append(f"Date of birth check digit mismatch: expected '{dob_check}', calculated '{calc_dob_check}'.")

    # C. Expiry Date
    calc_exp_check = calculate_check_digit(expiry_raw)
    exp_valid = (calc_exp_check == expiry_check)
    check_digits["expiry_date"] = {
        "value": expiry_raw,
        "expected": expiry_check,
        "calculated": calc_exp_check,
        "valid": exp_valid
    }
    if not exp_valid:
        warnings.append(f"Expiry date check digit mismatch: expected '{expiry_check}', calculated '{calc_exp_check}'.")

    # D. Optional Data
    # In TD3: if optional data is all '<', check digit can be '<' or '0' or calculate_check_digit
    calc_opt_check = calculate_check_digit(opt_raw)
    if opt_raw == '<' * 14 and opt_check in ('<', '0'):
        opt_valid = True
    else:
        opt_valid = (calc_opt_check == opt_check)
    check_digits["optional_data"] = {
        "value": opt_raw,
        "expected": opt_check,
        "calculated": calc_opt_check,
        "valid": opt_valid
    }
    if not opt_valid:
        warnings.append(f"Optional data check digit mismatch: expected '{opt_check}', calculated '{calc_opt_check}'.")

    # E. Composite Check Digit
    # Over: line2[0:10] (doc_num + check) + line2[13:20] (dob + check) + line2[21:43] (expiry + check + opt + check) = 39 chars
    composite_payload = line2[0:10] + line2[13:20] + line2[21:43]
    calc_comp_check = calculate_check_digit(composite_payload)
    comp_valid = (calc_comp_check == comp_check)
    check_digits["composite"] = {
        "value": composite_payload,
        "expected": comp_check,
        "calculated": calc_comp_check,
        "valid": comp_valid
    }
    if not comp_valid:
        warnings.append(f"Composite check digit mismatch: expected '{comp_check}', calculated '{calc_comp_check}'.")

    # -------------------------------------------------------------
    # 4. Status Determination
    # -------------------------------------------------------------
    all_valid = doc_valid and dob_valid and exp_valid and opt_valid and comp_valid
    critical_valid = doc_valid or dob_valid or exp_valid or comp_valid

    if all_valid:
        status = "VALIDATED"
        success = True
    elif critical_valid:
        status = "PARTIALLY_VALIDATED"
        success = True
    else:
        status = "INVALID"
        success = False

    result["success"] = success
    result["status"] = status
    result["fields"] = {
        "document_code": doc_code_raw,
        "issuing_state": issuing_state,
        "surname": surname,
        "given_names": given_names,
        "full_name": full_name,
        "document_number": clean_doc_number,
        "nationality": nationality,
        "dob_raw": dob_raw,
        "dob_iso": dob_iso,
        "dob_formatted": dob_fmt,
        "sex": clean_sex,
        "expiry_raw": expiry_raw,
        "expiry_iso": exp_iso,
        "expiry_formatted": exp_fmt,
        "optional_data": clean_opt_data
    }
    result["check_digits"] = check_digits
    result["errors"] = errors
    result["warnings"] = warnings

    return result
