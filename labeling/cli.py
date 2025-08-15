# labeling/cli.py
import argparse
import os
import sys
import yaml
import pandas as pd

from labeling.parser import parse_candump
from labeling.rule_engine import apply_rules

sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Label CAN logs using rule-based engine.")
    parser.add_argument("--input", required=True, help="Path to candump log file")
    parser.add_argument("--rules", default=os.path.join(os.path.dirname(__file__), "rules.yaml"),
                        help="Path to rules.yaml")
    # Use either a YAML or CSV PGN map; both are optional.
    parser.add_argument("--pgn-map-yaml", default=os.path.join(os.path.dirname(__file__), "pgn_map.yaml"),
                        help="Path to pgn_map.yaml (optional)")
    parser.add_argument("--pgn-map-csv", default=None,
                        help="Path to pgn_labels_cleaned.csv (optional)")
    parser.add_argument("--output", required=True, help="Output CSV path")
    args = parser.parse_args()

    # Load PGN labels (prefer CSV if provided, else YAML if present)
    pgn_labels = {}
    if args.pgn_map_csv:
        try:
            df_map = pd.read_csv(args.pgn_map_csv)
            # Expect columns: "PGN", "PG Label"
            if not {"PGN", "PG Label"}.issubset(df_map.columns):
                raise ValueError("CSV must contain columns 'PGN' and 'PG Label'")
            # Force PGN to int, handles values like 256.0
            df_map["PGN"] = df_map["PGN"].apply(lambda x: int(float(x)))
            pgn_labels = {
                int(row["PGN"]): str(row["PG Label"]).strip()
                for _, row in df_map.iterrows()
            }
        except FileNotFoundError:
            print(f"Warning: PGN map CSV not found at {args.pgn_map_csv}; proceeding without PGN labels.")
        except Exception as e:
            print(f"Warning: failed to load PGN map CSV: {e}")
    else:
        # Try YAML map if it exists
        if os.path.exists(args.pgn_map_yaml):
            try:
                with open(args.pgn_map_yaml, "r") as f:
                    pdoc = yaml.safe_load(f) or {}
                pgn_labels = {int(k): v for k, v in (pdoc.get("pgn_labels", {}) or {}).items()}
            except Exception as e:
                print(f"Warning: failed to load PGN map YAML: {e}")

    # Parse -> Apply rules -> Save
    df = parse_candump(args.input, pgn_labels=pgn_labels)
    print(f"Parsed {len(df)} messages from log.")

    labeled_df = apply_rules(df, args.rules)
    labeled_df.to_csv(args.output, index=False)
    print(f"Labeled file written to {args.output}")

if __name__ == "__main__":
    main()



# # labeling/cli.py
# import argparse
# import os
# from labeling.parser import parse_candump
# from labeling.rule_engine import apply_rules
# import sys
# sys.stdout.flush()

# def main():
#     parser = argparse.ArgumentParser(description="Label CAN logs using rule-based engine.")
#     parser.add_argument("--input", required=True, help="Path to candump log file")
#     parser.add_argument("--rules", default=os.path.join(os.path.dirname(__file__), "rules.yaml"), help="Path to rules.yaml")
#     parser.add_argument("--output", required=True, help="Output CSV path")
#     args = parser.parse_args()

#     df = parse_candump(args.input)
#     print(f"Parsed {len(df)} messages from log.")
#     labeled_df = apply_rules(df, args.rules)
#     labeled_df.to_csv(args.output, index=False)
#     print(f"Labeled file written to {args.output}")

# if __name__ == "__main__":
#     main()
