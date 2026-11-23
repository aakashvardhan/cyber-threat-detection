"""Create (or clear) the DynamoDB table that keeps incident state (SJSU-131).

Works from any folder (paths below are from the repository root; inside the backend container use
`docker compose run --rm backend python scripts/create_tables.py`):

    python backend/scripts/create_tables.py                        # create the table if it is missing
    python backend/scripts/create_tables.py --clear --yes          # delete every saved incident (all models)
    python backend/scripts/create_tables.py --clear --yes --model graphsage

Stop the backend before --clear (`docker compose stop backend`): it writes while the table is being scanned, so a
running backend could keep or recreate items. --clear refuses to run without --yes.

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
    parser.add_argument("--yes", action="store_true", help="with --clear: confirm that the backend is stopped")
    args = parser.parse_args()
    if args.clear and not args.yes:
        sys.exit("--clear deletes saved incident state. Stop the backend first (docker compose stop backend), "
                 "then run again with --yes.")
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
