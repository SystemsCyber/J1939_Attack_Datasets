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
            pass  # TODO: implement content-based SPN/value rule
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

# def apply_irule(df, rule):
#     moi_id = rule['moi']['can_id']
#     interval_sec = rule.get('interval_ms', 1.0) / 1000
#     threshold = rule.get('threshold', 5)
#     label = rule.get('label', 'irule_triggered')

#     # Filter only the messages of interest
#     filtered = df[df['can_id'] == moi_id].copy()
#     filtered['delta'] = filtered['timestamp'].diff()

#     indices_to_label = set()
#     window = []

#     for idx, row in filtered.iterrows():
#         if not window:
#             window = [idx]
#             continue

#         delta = row['delta']
#         if delta <= interval_sec:
#             window.append(idx)
#             if len(window) >= threshold:
#                 indices_to_label.update(window)
#         else:
#             window = [idx]

#     # Apply labels
#     df.loc[list(indices_to_label), 'label'] = label
