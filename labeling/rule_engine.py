# labeling/rule_engine.py
import yaml
import pandas as pd

# Order of severities for picking the primary label when multiple rules hit
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

def apply_rules(df: pd.DataFrame, rules_path: str) -> pd.DataFrame:
    """
    Apply YAML-defined rules to a parsed CAN/J1939 DataFrame.
    Populates label + provenance columns when rules fire.
    """
    with open(rules_path, "r") as f:
        ydoc = yaml.safe_load(f) or {}
    rules = ydoc.get("rules", []) or []

    # Ensure provenance columns exist (safe if already present)
    for col in [
        "rule_name", "rule_type", "semantics", "rule_severity", "rule_layer",
        "rule_description", "context_pgn", "context_value"
    ]:
        if col not in df.columns:
            df[col] = ""

    for rule in rules:
        rtype = rule.get("type")
        name = rule.get("name", "<unnamed>")
        print(f"Applying rule: {name} ({rtype})")

        if rtype == "rule":
            apply_rule(df, rule)
        elif rtype == "irule":
            apply_irule(df, rule)
        elif rtype == "crule":
            apply_crule(df, rule)
        else:
            print(f"Warning: Unknown rule type '{rtype}' in rule '{name}'")

    return df


# ---------- helpers ----------

def _annotate_row(df: pd.DataFrame, idx, rule: dict, *, context_value=None):
    """
    Set/merge annotation metadata for a row when a rule fires.
    - Accumulates rule_name (pipe-separated).
    - Chooses the highest-severity rule as the primary label.
    """
    label = rule.get("label", "anomalous")
    semantics = (rule.get("semantics") or "").strip()   # usage | temporal | state
    meta = rule.get("metadata") or {}
    severity = (meta.get("severity") or "").lower()
    layer = meta.get("layer", "")
    desc = meta.get("description", "")
    rtype = rule.get("type", "")
    rname = rule.get("name", "")

    # Accumulate rule names
    prev_names = df.at[idx, "rule_name"]
    df.at[idx, "rule_name"] = (prev_names + "|" + rname) if prev_names else rname

    # Promote label by severity priority
    current_sev = df.at[idx, "rule_severity"]
    curr_rank = SEVERITY_ORDER.get(current_sev, -1)
    new_rank = SEVERITY_ORDER.get(severity, -1)

    if new_rank >= curr_rank:
        df.at[idx, "label"] = label
        df.at[idx, "rule_type"] = rtype
        df.at[idx, "semantics"] = semantics
        df.at[idx, "rule_severity"] = severity
        df.at[idx, "rule_layer"] = layer
        df.at[idx, "rule_description"] = desc

    # Attach context info if present
    if context_value is not None:
        df.at[idx, "context_value"] = context_value
        ctx = rule.get("context") or {}
        if ctx:
            df.at[idx, "context_pgn"] = str(ctx.get("pgn", ""))


def _moi_filter(df: pd.DataFrame, moi: dict) -> pd.DataFrame:
    """
    Apply a simple Message-Of-Interest filter using keys present in moi.
    Supported keys: pgn, sa, da, priority_min, priority_max.
    """
    if not moi:
        return df

    f = df
    if "pgn" in moi:
        f = f[f["pgn"] == moi["pgn"]]
    if "sa" in moi:
        f = f[f["source"] == moi["sa"]]
    if "da" in moi and "destination" in df.columns:
        f = f[f["destination"] == moi["da"]]
    if "priority_min" in moi:
        f = f[f["priority"] >= moi["priority_min"]]
    if "priority_max" in moi:
        f = f[f["priority"] <= moi["priority_max"]]
    return f


# ---------- rule types ----------

def apply_irule(df: pd.DataFrame, rule: dict) -> pd.DataFrame:
    """
    Interval-based rule (temporal semantics): label bursts within a small inter-arrival window.
    YAML:
      interval_ms: float
      threshold: int
      moi: { ... }   # optional
    """
    moi = rule.get("moi", {}) or {}
    interval_sec = float(rule.get("interval_ms", 1.0)) / 1000.0
    threshold = int(rule.get("threshold", 5))

    filtered = _moi_filter(df, moi)
    if filtered.empty:
        return df

    indices_to_label = set()

    # Group by CAN identifier (or PGN if you prefer—keep CAN ID for finer granularity)
    for can_id, g in filtered.groupby("can_id"):
        g = g.sort_values(by="timestamp").copy()
        g["delta"] = g["timestamp"].diff()

        window = []
        for idx, row in g.iterrows():
            if not window:
                window = [idx]
                continue
            delta = row["delta"]
            if pd.notna(delta) and delta <= interval_sec:
                window.append(idx)
                if len(window) >= threshold:
                    indices_to_label.update(window)
            else:
                window = [idx]

    for idx in indices_to_label:
        _annotate_row(df, idx, rule, context_value=None)

    return df


def apply_crule(df: pd.DataFrame, rule: dict) -> pd.DataFrame:
    """
    Context-based rule (state semantics): compare message-of-interest against latest context value.
    YAML 'context' fields:
      pgn, sa, offset, length, scale, comparator (>,<,==,>=,<=), threshold
    """
    moi = rule.get("moi") or {}
    ctx = rule.get("context") or {}

    if "pgn" not in moi or "pgn" not in ctx:
        return df

    ctx_pgn = ctx["pgn"]
    ctx_sa = ctx.get("sa")
    offset = int(ctx.get("offset", 0))
    length = int(ctx.get("length", 1))
    scale = float(ctx.get("scale", 1.0))
    comparator = str(ctx.get("comparator", ">")).strip()
    threshold = float(ctx.get("threshold", 0))

    # Build context time->value map
    ctx_df = df[df["pgn"] == ctx_pgn].copy()
    if ctx_sa is not None:
        ctx_df = ctx_df[ctx_df["source"] == ctx_sa]

    ctx_values = {}
    for _, row in ctx_df.iterrows():
        try:
            b = bytes.fromhex(row["data"])
            # J1939 often uses little-endian within the data field; reverse slice as in your code
            raw = int.from_bytes(b[offset:offset + length][::-1], byteorder="big")
            val = raw * scale
            ctx_values[row["timestamp"]] = val
        except Exception:
            continue

    if not ctx_values:
        print(f"No context values found for PGN {ctx_pgn}")
        return df

    ctx_times = sorted(ctx_values.keys())

    # Evaluate the messages-of-interest
    moi_df = _moi_filter(df, moi)

    for idx, row in moi_df.iterrows():
        ts = row["timestamp"]
        # pick latest context at or before ts
        prev_ctx_ts = max((t for t in ctx_times if t <= ts), default=None)
        if prev_ctx_ts is None:
            continue

        v = ctx_values[prev_ctx_ts]
        fired = (
            (comparator == ">"  and v >  threshold) or
            (comparator == "<"  and v <  threshold) or
            (comparator == "==" and v == threshold) or
            (comparator == ">=" and v >= threshold) or
            (comparator == "<=" and v <= threshold)
        )
        if fired:
            _annotate_row(df, idx, rule, context_value=v)

    return df


def apply_rule(df: pd.DataFrame, rule: dict) -> pd.DataFrame:
    """
    Content/scope rule (usage semantics): label messages that match MOI.
    """
    moi = rule.get("moi") or {}
    filt = _moi_filter(df, moi)
    if filt.empty:
        return df

    for idx in filt.index:
        _annotate_row(df, idx, rule, context_value=None)

    return df


# # labeling/rule_engine.py
# import yaml
# import pandas as pd

# def apply_rules(df: pd.DataFrame, rules_path: str) -> pd.DataFrame:
#     with open(rules_path, 'r') as f:
#         rules = yaml.safe_load(f).get("rules", [])

#     for rule in rules:
#         rule_type = rule.get("type")
#         name = rule.get("name", "<unnamed>")
#         print(f"Applying rule: {name} ({rule_type})")

#         if rule_type == "rule":
#             apply_rule(df, rule)
#         elif rule_type == "irule":
#             apply_irule(df, rule)
#         elif rule_type == "crule":
#             apply_crule(df, rule)
#         else:
#             print(f"Warning: Unknown rule type '{rule_type}' in rule '{name}'")

#     return df

# def apply_irule(df, rule):
#     moi = rule.get("moi", {})
#     interval_sec = rule.get("interval_ms", 1.0) / 1000
#     threshold = rule.get("threshold", 5)
#     label = rule.get("label", "irule_triggered")

#     # Step 1: Optionally filter down to relevant messages
#     filtered = df.copy()
#     if "priority_max" in moi:
#         filtered = filtered[filtered["priority"] <= moi["priority_max"]]

#     if filtered.empty:
#         return df

#     indices_to_label = set()

#     # Step 2: Group by CAN ID, apply sliding window per group
#     for can_id, group in filtered.groupby("can_id"):
#         group = group.sort_values(by="timestamp").copy()
#         group["delta"] = group["timestamp"].diff()

#         window = []

#         for idx, row in group.iterrows():
#             if not window:
#                 window = [idx]
#                 continue

#             delta = row["delta"]
#             if delta <= interval_sec:
#                 window.append(idx)
#                 if len(window) >= threshold:
#                     indices_to_label.update(window)
#             else:
#                 window = [idx]

#     # Step 3: Label matching messages
#     df.loc[list(indices_to_label), "label"] = label
#     return df

# def apply_crule(df, rule):
#     moi_pgn = rule['moi']['pgn']
#     ctx = rule['context']
#     ctx_pgn = ctx['pgn']
#     ctx_sa = ctx['sa']
#     offset = ctx['offset']
#     length = ctx['length']
#     scale = ctx['scale']
#     comparator = ctx['comparator']
#     threshold = ctx['threshold']
#     label = rule['label']

#     # Track latest context value by timestamp
#     ctx_df = df[(df['pgn'] == ctx_pgn) & (df['source'] == ctx_sa)].copy()
#     ctx_values = {}
#     for idx, row in ctx_df.iterrows():
#         try:
#             data_hex = row['data']
#             data_bytes = bytes.fromhex(data_hex)
#             raw_val = int.from_bytes(data_bytes[offset:offset+length][::-1], byteorder='big')
#             value = raw_val * scale
#             ctx_values[row['timestamp']] = value
#         except Exception as e:
#             continue  # Skip malformed rows

#     if not ctx_values:
#         print(f"No context values found for PGN {ctx_pgn}")
#         return df

#     # Get sorted list of timestamps for context
#     ctx_timestamps = sorted(ctx_values.keys())

#     # Evaluate messages of interest
#     moi_df = df[df['pgn'] == moi_pgn].copy()

#     for idx, row in moi_df.iterrows():
#         ts = row['timestamp']

#         # Find latest context timestamp before current message
#         prev_ctx_ts = max((t for t in ctx_timestamps if t < ts), default=None)

#         if prev_ctx_ts is not None:
#             ctx_val = ctx_values[prev_ctx_ts]
#             # Evaluate comparator
#             if comparator == ">" and ctx_val > threshold:
#                 df.loc[idx, 'label'] = label
#             elif comparator == "<" and ctx_val < threshold:
#                 df.loc[idx, 'label'] = label
#             elif comparator == "==" and ctx_val == threshold:
#                 df.loc[idx, 'label'] = label
#         else:
#             continue  # No context found before this message

#     return df

# def apply_rule(df, rule):
#     moi = rule['moi']
#     pgn = moi['pgn']
#     sa = moi.get('sa', None)
#     label = rule['label']

#     # Filter messages matching PGN (and SA if specified)
#     filtered = df[df['pgn'] == pgn]
#     if sa is not None:
#         filtered = filtered[filtered['source'] == sa]

#     for idx in filtered.index:
#         df.loc[idx, 'label'] = label
