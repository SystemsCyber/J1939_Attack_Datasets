# labeling/parser.py
import pandas as pd

def parse_candump(file_path):
    records = []

    with open(file_path, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                parts = line.strip().split()
                timestamp = float(parts[0].strip("()"))
                iface = parts[1]
                can_id = int(parts[2], 16)
                dlc = int(parts[3].strip("[]"))
                data_bytes = parts[4:4 + dlc]
                data = ''.join([b.zfill(2) for b in data_bytes])  # ensure two hex digits per byte

                pgn, prio, da, sa = extract_j1939_fields(can_id)

                records.append({
                    'timestamp': timestamp,
                    'iface': iface,
                    'can_id': can_id,
                    'data': data,
                    'pgn': pgn,
                    'priority': prio,
                    'destination': da,
                    'source': sa,
                    'label': 'normal'
                })
            except Exception as e:
                print(f"⚠️ Failed to parse line: {line.strip()} ({e})")

    return pd.DataFrame(records)

def extract_j1939_fields(can_id):
    prio = (can_id >> 26) & 0x7
    pgn_raw = (can_id >> 8) & 0xFFFF
    sa = can_id & 0xFF

    if (pgn_raw & 0xFF00) >= 0xF000:
        # PDU2
        pgn = pgn_raw
        da = None
    else:
        # PDU1
        da = (can_id >> 8) & 0xFF
        pgn = pgn_raw & 0xFF00

    return pgn, prio, da, sa
