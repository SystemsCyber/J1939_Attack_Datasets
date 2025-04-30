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

        if rule_type == "rule":
            apply_rule(df, rule)
        elif rule_type == "irule":
            apply_irule(df, rule)
        elif rule_type == "crule":
            apply_crule(df, rule)
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
    moi_pgn = rule['moi']['pgn']
    ctx = rule['context']
    ctx_pgn = ctx['pgn']
    ctx_sa = ctx['sa']
    offset = ctx['offset']
    length = ctx['length']
    scale = ctx['scale']
    comparator = ctx['comparator']
    threshold = ctx['threshold']
    label = rule['label']

    # Track latest context value by timestamp
    ctx_df = df[(df['pgn'] == ctx_pgn) & (df['source'] == ctx_sa)].copy()
    ctx_values = {}
    for idx, row in ctx_df.iterrows():
        try:
            data_hex = row['data']
            data_bytes = bytes.fromhex(data_hex)
            raw_val = int.from_bytes(data_bytes[offset:offset+length][::-1], byteorder='big')
            value = raw_val * scale
            ctx_values[row['timestamp']] = value
        except Exception as e:
            continue  # Skip malformed rows

    if not ctx_values:
        print(f"No context values found for PGN {ctx_pgn}")
        return df

    # Get sorted list of timestamps for context
    ctx_timestamps = sorted(ctx_values.keys())

    # Evaluate messages of interest
    moi_df = df[df['pgn'] == moi_pgn].copy()

    for idx, row in moi_df.iterrows():
        ts = row['timestamp']

        # Find latest context timestamp before current message
        prev_ctx_ts = max((t for t in ctx_timestamps if t < ts), default=None)

        if prev_ctx_ts is not None:
            ctx_val = ctx_values[prev_ctx_ts]
            # Evaluate comparator
            if comparator == ">" and ctx_val > threshold:
                df.loc[idx, 'label'] = label
            elif comparator == "<" and ctx_val < threshold:
                df.loc[idx, 'label'] = label
            elif comparator == "==" and ctx_val == threshold:
                df.loc[idx, 'label'] = label
        else:
            continue  # No context found before this message

    return df

def apply_rule(df, rule):
    moi = rule['moi']
    pgn = moi['pgn']
    sa = moi.get('sa', None)
    label = rule['label']

    # Filter messages matching PGN (and SA if specified)
    filtered = df[df['pgn'] == pgn]
    if sa is not None:
        filtered = filtered[filtered['source'] == sa]

    for idx in filtered.index:
        df.loc[idx, 'label'] = label
