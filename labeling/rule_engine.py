# labeling/rule_engine.py
import yaml
import pandas as pd

def apply_rules(df: pd.DataFrame, rules_path: str) -> pd.DataFrame:
    with open(rules_path, 'r') as f:
        rules = yaml.safe_load(f).get("rules", [])

    for rule in rules:
        rule_type = rule.get("type")
        name = rule.get("name", "<unnamed>")
        print(f"Applying rule: {name} ({rule_type})")

        if rule_type == "irule":
            apply_irule(df, rule)
        elif rule_type == "rule":
            apply_crule(df, rule)
        elif rule_type == "crule":
            pass  # TODO: implement context-sensitive rule
        else:
            print(f"Warning: Unknown rule type '{rule_type}' in rule '{name}'")

    return df

def apply_irule(df, rule):
    moi = rule.get("moi", {})
    interval_sec = rule.get("interval_ms", 1.0) / 1000
    threshold = rule.get("threshold", 5)
    label = rule.get("label", "irule_triggered")

    # Step 1: Optionally filter down to relevant messages
    filtered = df.copy()
    if "priority_max" in moi:
        filtered = filtered[filtered["priority"] <= moi["priority_max"]]

    if filtered.empty:
        return df

    indices_to_label = set()

    # Step 2: Group by CAN ID, apply sliding window per group
    for can_id, group in filtered.groupby("can_id"):
        group = group.sort_values(by="timestamp").copy()
        group["delta"] = group["timestamp"].diff()

        window = []

        for idx, row in group.iterrows():
            if not window:
                window = [idx]
                continue

            delta = row["delta"]
            if delta <= interval_sec:
                window.append(idx)
                if len(window) >= threshold:
                    indices_to_label.update(window)
            else:
                window = [idx]

    # Step 3: Label matching messages
    df.loc[list(indices_to_label), "label"] = label
    return df

def apply_crule(df, rule):
    moi_pgn = rule["moi"]["pgn"]
    context = rule["context"]

    ctx_pgn = context["pgn"]
    offset = context["offset"]
    length = context["length"]
    scale = context["scale"]
    comparator = context["comparator"]
    threshold = context["threshold"]
    label = rule["label"]

    # Step 1: Extract all PGN 65265 rows (vehicle speed)
    speed_rows = df[df["pgn"] == ctx_pgn].copy()
    speed_map = {}  # timestamp → decoded speed

    for idx, row in speed_rows.iterrows():
        try:
            data = row["data"]
            if len(data) < (offset + length) * 2:
                continue
            byte_seq = bytes.fromhex(data)
            raw = int.from_bytes(byte_seq[offset:offset+length], byteorder='little')
            speed_kmh = raw * scale
            speed_map[row["timestamp"]] = speed_kmh
        except Exception as e:
            continue

    # Step 2: Scan for MOI (PGN 60928), check prior speed context
    moi_rows = df[df["pgn"] == moi_pgn]

    for idx, row in moi_rows.iterrows():
        t = row["timestamp"]
        prior_speeds = [v for ts, v in speed_map.items() if ts <= t]
        if not prior_speeds:
            continue
        latest_speed = prior_speeds[-1]

        # Apply condition
        if comparator == ">" and latest_speed > threshold:
            df.at[idx, "label"] = label
        elif comparator == "<=" and latest_speed <= threshold:
            df.at[idx, "label"] = label
