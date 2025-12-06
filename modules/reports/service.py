"""
Reporting module to surface recent activity across phishing, malware, and PCAP logs.
Uses the same MongoDB connection/config as other modules.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from pymongo.collection import Collection
from pymongo.database import Database

from core.config import load_config
from core.db.mongodb import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reporting", tags=["reporting"])

_cfg: Dict[str, Any] = {}
_db: Database | None = None


def _load_db() -> None:
    """Load config and connect to Mongo using shared helper."""
    global _cfg, _db
    _cfg = load_config()
    try:
        _db = get_db(_cfg)
    except Exception as exc:
        logger.warning("Reporting Mongo unavailable: %s", exc)
        _db = None


def _col(name: str) -> Collection | None:
    if _db is None:
        return None
    try:
        return _db[name]
    except Exception:
        return None


def _count(col: Collection | None) -> int:
    if col is None:
        return 0
    try:
        return col.count_documents({})
    except Exception:
        return 0


def _recent(col: Collection | None, limit: int = 5) -> List[Dict[str, Any]]:
    return _query(col, limit=limit)


def _query(
    col: Collection | None,
    limit: int = 5,
    from_dt: datetime | None = None,
    to_dt: datetime | None = None,
) -> List[Dict[str, Any]]:
    if col is None:
        return []
    try:
        query: Dict[str, Any] = {}
        if from_dt or to_dt:
            lt_dt = to_dt + timedelta(days=1) if to_dt else None
            clauses: List[Dict[str, Any]] = []
            for field in ("ts", "timestamp"):
                clause: Dict[str, Any] = {}
                if from_dt:
                    clause["$gte"] = from_dt
                if lt_dt:
                    clause["$lt"] = lt_dt  # inclusive of the selected "to" date
                clauses.append({field: clause})
            query = {"$or": clauses}

        cursor = col.find(query or None).sort([("ts", -1), ("timestamp", -1)]).limit(limit)
        docs = list(cursor)
    except Exception:
        return []

    for doc in docs:
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        for k, v in list(doc.items()):
            if isinstance(v, datetime):
                doc[k] = v.isoformat()
    return docs


@router.get("/health")
def health() -> Dict[str, Any]:
    """Basic readiness for reporting module."""
    ok = _db is not None
    return {
        "ok": ok,
        "mongodb_enabled": bool(_cfg.get("mongodb", {}).get("enabled", False)),
        "mongodb_connected": ok,
        "database": (_cfg.get("mongodb", {}) or {}).get("database"),
        "collections": {
            "phishing": (_cfg.get("phishing", {}).get("logging", {}) or {}).get("collection_predictions", "predictions"),
            "malware": (_cfg.get("malware", {}).get("logging", {}) or {}).get("collection_scans", "malware"),
            "pcap_analyses": "analyses",
            "pcap_threats": "threats",
        },
    }


@router.get("/summary")
def summary(
    limit: int = Query(5, ge=1, le=100),
    from_ts: datetime | None = Query(None),
    to_ts: datetime | None = Query(None),
) -> Dict[str, Any]:
    """Aggregate counts and recent entries across modules."""
    if _db is None:
        raise HTTPException(status_code=503, detail="MongoDB not connected for reporting")

    phish_col = _col((_cfg.get("phishing", {}).get("logging", {}) or {}).get("collection_predictions", "predictions"))
    malware_col = _col((_cfg.get("malware", {}).get("logging", {}) or {}).get("collection_scans", "malware"))
    pcap_analyses_col = _col("analyses")
    pcap_threats_col = _col("threats")

    return {
        "counts": {
            "phishing_predictions": _count(phish_col),
            "malware_scans": _count(malware_col),
            "pcap_analyses": _count(pcap_analyses_col),
            "pcap_threats": _count(pcap_threats_col),
        },
        "recent": {
            "phishing_predictions": _query(phish_col, limit=limit, from_dt=from_ts, to_dt=to_ts),
            "malware_scans": _query(malware_col, limit=limit, from_dt=from_ts, to_dt=to_ts),
            "pcap_analyses": _query(pcap_analyses_col, limit=limit, from_dt=from_ts, to_dt=to_ts),
            "pcap_threats": _query(pcap_threats_col, limit=limit, from_dt=from_ts, to_dt=to_ts),
        },
    }


@router.get("/export")
def export(
    kind: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    from_ts: datetime | None = Query(None),
    to_ts: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> Any:
    """Export records for a specific collection."""
    if _db is None:
        raise HTTPException(status_code=503, detail="MongoDB not connected for reporting")

    mapping = {
        "phishing": (_cfg.get("phishing", {}).get("logging", {}) or {}).get("collection_predictions", "predictions"),
        "malware": (_cfg.get("malware", {}).get("logging", {}) or {}).get("collection_scans", "malware"),
        "pcap_analyses": "analyses",
        "pcap_threats": "threats",
    }
    col_name = mapping.get(kind)
    if not col_name:
        raise HTTPException(status_code=400, detail="Unknown kind")

    col = _col(col_name)
    rows = _query(col, limit=limit, from_dt=from_ts, to_dt=to_ts)

    if format == "json":
        return {"kind": kind, "count": len(rows), "data": rows}

    # CSV export
    import csv
    import io

    # Handle empty result set
    if not rows:
        return {"kind": kind, "count": 0, "data": ""}

    # Determine all fieldnames across rows
    fieldnames = sorted({k for row in rows for k in row.keys()})
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    
    # Write rows
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


# Initialize on import
_load_db()
