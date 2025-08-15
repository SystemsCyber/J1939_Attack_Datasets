# labeling/parser.py
import pandas as pd
from typing import Dict, Optional, Any


def parse_candump(
    file_path: str,
    pgn_labels: Optional[Dict[int, str]] = None,
) -> pd.DataFrame:
    """
    Parse a candump-format log into a DataFrame with J1939-derived fields and metadata.

    Parameters
    ----------
    file_path : str
        Path to candump log file.
    pgn_labels : dict[int,str], optional
        Map of PGN -> human-readable PGN label.

    Returns
    -------
    pd.DataFrame
        Parsed CAN/J1939 frames with optional PGN metadata.
    """
    # Normalize pgn_labels keys to int
    pgn_labels = {int(k): v for k, v in (pgn_labels or {}).items()}

    records = []

    with open(file_path, 'r') as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                parts = raw.split()

                # Parse timestamp like "(0.004231)"
                ts_str = parts[0].strip("()")
                timestamp = float(ts_str)

                iface = parts[1]

                # CAN ID in hex (e.g., "18FEF100" or "0C010503")
                can_id = int(parts[2], 16)

                # DLC like "[8]"
                dlc = int(parts[3].strip("[]"))

                # Next dlc tokens are data bytes (hex)
                data_tokens = parts[4:4 + dlc]
                data = ''.join(b.zfill(2) for b in data_tokens).upper()

                dec = extract_j1939_fields(can_id)

                # Lookup PGN label if provided
                pgn_label = pgn_labels.get(dec['pgn'])

                records.append({
                    'timestamp': timestamp,
                    'iface': iface,
                    'can_id': can_id,         # decimal int; convert to hex for display if needed
                    'dlc': dlc,
                    'data': data,
                    'priority': dec['priority'],
                    'pdu_format': dec['pf'],
                    'pdu_specific': dec['ps'],
                    'pdu_type': dec['pdu_type'],  # "PDU1" or "PDU2"
                    'pgn': dec['pgn'],
                    'pgn_label': pgn_label,
                    'destination': dec['da'],
                    'source': dec['sa'],
                    'label': 'normal',  # default; will be updated by rule engine
                })
            except Exception as e:
                print(f"⚠️ Failed to parse line: {raw} ({e})")
                continue

    return pd.DataFrame(records)


def extract_j1939_fields(can_id: int) -> Dict[str, Any]:
    """
    Extract J1939 fields from a 29-bit extended CAN identifier.

    Returns:
        priority, pf, ps, sa, da, pgn, pdu_type
    """
    priority = (can_id >> 26) & 0x7
    pf = (can_id >> 16) & 0xFF
    ps = (can_id >> 8) & 0xFF
    sa = can_id & 0xFF

    pgn_raw = (can_id >> 8) & 0xFFFF

    if pf >= 240:  # PDU2 (broadcast)
        pgn = pgn_raw
        da = None
        pdu_type = "PDU2"
    else:          # PDU1 (destination-specific)
        pgn = pgn_raw & 0xFF00
        da = ps
        pdu_type = "PDU1"

    return {
        'priority': priority,
        'pf': pf,
        'ps': ps,
        'sa': sa,
        'da': da,
        'pgn': pgn,
        'pdu_type': pdu_type,
    }



# # labeling/parser.py
# import pandas as pd

# def parse_candump(file_path):
#     records = []

#     with open(file_path, 'r') as f:
#         for line in f:
#             if not line.strip():
#                 continue
#             try:
#                 parts = line.strip().split()
#                 timestamp = float(parts[0].strip("()"))
#                 iface = parts[1]
#                 can_id = int(parts[2], 16)
#                 dlc = int(parts[3].strip("[]"))
#                 data_bytes = parts[4:4 + dlc]
#                 data = ''.join([b.zfill(2) for b in data_bytes])  # ensure two hex digits per byte

#                 pgn, prio, da, sa = extract_j1939_fields(can_id)

#                 records.append({
#                     'timestamp': timestamp,
#                     'iface': iface,
#                     'can_id': can_id,
#                     'data': data,
#                     'pgn': pgn,
#                     'priority': prio,
#                     'destination': da,
#                     'source': sa,
#                     'label': 'normal'
#                 })
#             except Exception as e:
#                 print(f"⚠️ Failed to parse line: {line.strip()} ({e})")

#     return pd.DataFrame(records)

# def extract_j1939_fields(can_id):
#     prio = (can_id >> 26) & 0x7
#     pgn_raw = (can_id >> 8) & 0xFFFF
#     sa = can_id & 0xFF

#     if (pgn_raw & 0xFF00) >= 0xF000:
#         # PDU2
#         pgn = pgn_raw
#         da = None
#     else:
#         # PDU1
#         da = (can_id >> 8) & 0xFF
#         pgn = pgn_raw & 0xFF00

#     return pgn, prio, da, sa
