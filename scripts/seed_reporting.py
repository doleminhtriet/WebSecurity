#!/usr/bin/env python3
"""
Seed MongoDB with sample records so the Reporting dashboard has data to display.

It pulls a handful of rows from data/phishing/train.csv for phishing examples and
generates synthetic malware/pcap entries. All documents are tagged with
source="seed/reporting" so they can be cleaned up easily.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

# Optional: load .env so MONGODB_URI/PHISH_CFG are picked up when running locally
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# Ensure repo root on sys.path so `core` imports work even when run directly
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import load_config
from core.db.mongodb import get_db, reset_db


def load_phish_samples(path: Path, count: int, now: datetime) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            if idx >= count:
                break
            text = (row.get("text") or "").strip()
            label = int(row.get("label") or 0)
            ts = now - timedelta(hours=idx + 1)
            rows.append(
                {
                    "ts": ts,
                    "label": label,
                    "probability": 0.93 if label else 0.12,
                    "threshold": 0.9,
                    "subject": text[:60],
                    "snippet": text[:160],
                    "text_sha256": hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest(),
                    "source": "seed/reporting",
                }
            )
    return rows


def malware_samples(count: int, now: datetime) -> List[Dict[str, Any]]:
    base = [
        {
            "filename": "payload.exe",
            "sha256": hashlib.sha256(b"payload.exe").hexdigest(),
            "probability": 0.86,
            "label": 1,
            "indicators": ["high_entropy", "suspicious_strings"],
        },
        {
            "filename": "installer.msi",
            "sha256": hashlib.sha256(b"installer.msi").hexdigest(),
            "probability": 0.18,
            "label": 0,
            "indicators": ["low_entropy"],
        },
        {
            "filename": "script.ps1",
            "sha256": hashlib.sha256(b"script.ps1").hexdigest(),
            "probability": 0.72,
            "label": 1,
            "indicators": ["powershell", "network_calls"],
        },
    ]
    docs: List[Dict[str, Any]] = []
    for idx, template in enumerate(base[:count]):
        ts = now - timedelta(hours=idx + 2)
        docs.append(
            {
                "ts": ts,
                "threshold": 0.6,
                "size": 52_428,
                "content_type": "application/octet-stream",
                "source": "seed/reporting",
                **template,
            }
        )
    return docs


def pcap_samples(count: int, now: datetime) -> List[Dict[str, Any]]:
    base = [
        {
            "filename": "office-lan.pcap",
            "basic_stats": {"total_packets": 14200, "total_bytes": 1_860_000},
        },
        {
            "filename": "dmz-scan.pcap",
            "basic_stats": {"total_packets": 9800, "total_bytes": 1_120_500},
        },
    ]
    docs: List[Dict[str, Any]] = []
    for idx, template in enumerate(base[:count]):
        ts = now - timedelta(hours=idx + 3)
        docs.append({"timestamp": ts, "source": "seed/reporting", **template})
    return docs


def threat_samples(count: int, now: datetime) -> List[Dict[str, Any]]:
    base = [
        {
            "filename": "dmz-scan.pcap",
            "threat_summary": {"overall_threat_level": "medium", "syn_flood_alerts": 18},
        },
        {
            "filename": "edge-anomaly.pcap",
            "threat_summary": {"overall_threat_level": "low", "syn_flood_alerts": 2},
        },
    ]
    docs: List[Dict[str, Any]] = []
    for idx, template in enumerate(base[:count]):
        ts = now - timedelta(hours=idx + 4)
        docs.append({"timestamp": ts, "source": "seed/reporting", **template})
    return docs


def cleanup(db, collections: List[str]) -> None:
    for name in collections:
        if name:
            deleted = db[name].delete_many({"source": "seed/reporting"}).deleted_count
            print(f"🧹 {name}: removed {deleted} seeded documents")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Mongo for reporting dashboard demos")
    parser.add_argument("--config", default=os.getenv("PHISH_CFG", "config/base.yaml"), help="Path to YAML config")
    parser.add_argument("--phish", type=int, default=6, help="Number of phishing examples to insert")
    parser.add_argument("--malware", type=int, default=3, help="Number of malware examples to insert")
    parser.add_argument("--pcap", type=int, default=2, help="Number of pcap analysis examples to insert")
    parser.add_argument("--threats", type=int, default=2, help="Number of pcap threat examples to insert")
    parser.add_argument("--cleanup", action="store_true", help="Delete previously seeded documents and exit")
    args = parser.parse_args()

    reset_db()
    cfg = load_config(args.config)
    db = get_db(cfg)
    if db is None:
        raise SystemExit("MongoDB not configured. Set MONGODB_URI or disable mongodb.enabled in config.")

    collections = {
        "phishing": (cfg.get("phishing", {}).get("logging", {}) or {}).get("collection_predictions", "predictions"),
        "malware": (cfg.get("malware", {}).get("logging", {}) or {}).get("collection_scans", "malware"),
        "pcap_analyses": "analyses",
        "pcap_threats": "threats",
    }

    if args.cleanup:
        cleanup(db, list(collections.values()))
        return

    now = datetime.now(timezone.utc)
    docs_phish = load_phish_samples(Path("data/phishing/train.csv"), args.phish, now)
    docs_mal = malware_samples(args.malware, now)
    docs_pcap = pcap_samples(args.pcap, now)
    docs_threat = threat_samples(args.threats, now)

    cleanup(db, list(collections.values()))

    inserted = {}
    if docs_phish:
        inserted["phishing"] = len(db[collections["phishing"]].insert_many(docs_phish).inserted_ids)
    if docs_mal:
        inserted["malware"] = len(db[collections["malware"]].insert_many(docs_mal).inserted_ids)
    if docs_pcap:
        inserted["pcap_analyses"] = len(db[collections["pcap_analyses"]].insert_many(docs_pcap).inserted_ids)
    if docs_threat:
        inserted["pcap_threats"] = len(db[collections["pcap_threats"]].insert_many(docs_threat).inserted_ids)

    for name, count in inserted.items():
        print(f"✅ Seeded {count} docs into {collections[name]}")
    if not inserted:
        print("No documents inserted (missing sample files or counts set to zero).")


if __name__ == "__main__":
    main()
