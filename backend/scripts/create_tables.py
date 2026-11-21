"""Create (or clear) the DynamoDB table that keeps incident state (SJSU-131).

    python scripts/create_tables.py                  # create the table if it is missing
    python scripts/create_tables.py --clear          # delete every saved incident (all models)
    python scripts/create_tables.py --clear --model graphsage

Reads DYNAMODB_TABLE, AWS_REGION and DYNAMODB_ENDPOINT (set it for DynamoDB Local, leave it unset on AWS).
Table: partition key `model` (string), sort key `incident_id` (string), on-demand billing.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clear", action="store_true", help="delete saved incident state")
    parser.add_argument("--model", default=None, help="with --clear: only this live model (e.g. graphsage, hgt)")
    args = parser.parse_args()
    from eval_explanations import load_env
    load_env(HERE / ".env")
    from app.config import Settings
    from app.store import DynamoStore

    s = Settings.from_env()
    store = DynamoStore.connect(s.dynamodb_table, s.aws_region, s.dynamodb_endpoint, create=True)
    where = s.dynamodb_endpoint or f"AWS {s.aws_region}"
    print(f"Table {s.dynamodb_table} is ready ({where}).")
    if args.clear:
        print(f"Deleted {store.clear(args.model)} saved incident(s).")


if __name__ == "__main__":
    main()
