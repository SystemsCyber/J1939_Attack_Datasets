# labeling/cli.py
import argparse
import os
from labeling.parser import parse_candump
from labeling.rule_engine import apply_rules
import sys
sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Label CAN logs using rule-based engine.")
    parser.add_argument("--input", required=True, help="Path to candump log file")
    parser.add_argument("--rules", default=os.path.join(os.path.dirname(__file__), "rules.yaml"), help="Path to rules.yaml")
    parser.add_argument("--output", required=True, help="Output CSV path")
    args = parser.parse_args()

    df = parse_candump(args.input)
    print(f"Parsed {len(df)} messages from log.")
    labeled_df = apply_rules(df, args.rules)
    labeled_df.to_csv(args.output, index=False)
    print(f"Labeled file written to {args.output}")

if __name__ == "__main__":
    main()
