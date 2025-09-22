#!/usr/bin/env python3
"""
Quick MongoDB connectivity test.

Usage examples:

  # Use .env (MONGODB_URI) and defaults
  python modules/test/test_mongo.py

  # Insert a test document
  python modules/test/test_mongo.py --insert

  # Clean up test documents created by this script
  python modules/test/test_mongo.py --cleanup

  # Provide URI explicitly (overrides .env)
  python modules/test/test_mongo.py --uri "mongodb+srv://user:ENC_PASS@cluster0.../admin?authSource=admin" --insert

  # Choose db/collection explicitly
  python modules/test/test_mongo.py --db defensedb --collection connectivity_tests --insert
"""
from __future__ import annotations

import os
import sys
import argparse
from datetime import datetime, timezone, timedelta
from typing import Optional

# Load .env if present (safe to ignore if missing)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# YAML is optional (only used to infer DB name if --db not provided)
try:
    import yaml
except Exception:
    yaml = None  # type: ignore

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, ConfigurationError, OperationFailure


def get_cfg_db_name(config_path: str) -> Optional[str]:
    """Best-effort to read default DB name from YAML config."""
    if not yaml:
        return None
    try:
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            m = cfg.get("mongodb") or {}
            return m.get("database")
    except Exception:
        return None
    return None


def main():
    p = argparse.ArgumentParser(description="MongoDB connectivity test")
    p.add_argument("--uri", help="MongoDB connection URI (overrides MONGODB_URI env)")
    p.add_argument("--db", help="Database name (defaults to config or 'defensedb')")
    p.add_argument(
        "--collection",
        default="connectivity_tests",
        help="Collection name (default: connectivity_tests)",
    )
    p.add_argument("--insert", action="store_true", help="Insert a test document")
    p.add_argument("--cleanup", action="store_true", help="Delete recent test documents created by this script")
    p.add_argument(
        "--config",
        default="config/base.yaml",
        help="Path to YAML config (used to infer DB name if --db not provided)",
    )
    p.add_argument("--timeout", type=int, default=5000, help="Server selection timeout in ms (default: 5000)")
    p.add_argument("--no-tls", action="store_true", help="Disable TLS (not recommended for Atlas)")
    args = p.parse_args()

    # Resolve URI
    uri = args.uri or os.getenv("MONGODB_URI")
    if not uri:
        print("ERROR: No URI found. Provide --uri or set MONGODB_URI in your environment/.env", file=sys.stderr)
        sys.exit(2)

    # Connect & ping
    tls = not args.no_tls
    try:
        client = MongoClient(uri, tls=tls, serverSelectionTimeoutMS=args.timeout)
        ping = client.admin.command("ping")
        print("✅ Ping OK:", ping)
    except ConfigurationError as e:
        print("❌ ConfigurationError:", e, file=sys.stderr)
        print("Hint: for mongodb+srv URIs, install with: pip install 'pymongo[srv]'", file=sys.stderr)
        sys.exit(3)
    except ServerSelectionTimeoutError as e:
        print("❌ Cannot reach cluster:", e, file=sys.stderr)
        print("Hints: allow-list your IP in Atlas; verify URI/credentials; ensure DNS for SRV works.", file=sys.stderr)
        sys.exit(4)
    except Exception as e:
        print("❌ Unexpected error during ping:", e, file=sys.stderr)
        sys.exit(5)

    # Choose DB/collection
    db_name = args.db or get_cfg_db_name(args.config) or os.getenv("MONGO_DB", "defensedb")
    db = client[db_name]
    col = db[args.collection]

    inserted_id = None

    # Optional insert
    if args.insert:
        try:
            doc = {
                "ts": datetime.now(timezone.utc),
                "ok": True,
                "source": "modules/test/test_mongo.py",
                "note": "Connectivity test document",
            }
            inserted_id = col.insert_one(doc).inserted_id
            print(f"✅ Inserted test doc into {db_name}.{args.collection}: _id={inserted_id}")
        except OperationFailure as e:
            print("❌ Insert failed (auth/roles?):", e, file=sys.stderr)
            sys.exit(6)
        except Exception as e:
            print("❌ Insert failed:", e, file=sys.stderr)
            sys.exit(7)

    # Optional cleanup
    if args.cleanup:
        try:
            if inserted_id is not None:
                res = col.delete_one({"_id": inserted_id})
                print(f"🧹 Cleanup by _id: deleted {res.deleted_count} document")
            else:
                cutoff = datetime.now(timezone.utc) - timedelta(days=1)
                res = col.delete_many({"source": "modules/test/test_mongo.py", "ts": {"$gte": cutoff}})
                print(f"🧹 Cleanup recent docs: deleted {res.deleted_count} document(s)")
        except Exception as e:
            print("⚠️ Cleanup failed:", e, file=sys.stderr)

    print(f"Done. Tested database '{db_name}', collection '{args.collection}'.")
    client.close()


if __name__ == "__main__":
    main()


# python -u modules/test/test_mongo.py \  --uri "mongodb+srv://doleminhtriet_db_user:vM8idQqgbbcrN5AH@cluster0.domkodf.mongodb.net/admin?retryWrites=true&w=majority&appName=Cluster0&authSource=admin" \--insert
