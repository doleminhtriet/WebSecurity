#!/usr/bin/env python3
"""
Phishing detection service (FastAPI router).

Endpoints:
- POST /phishing/predict : classify from JSON {subject, body, raw}
- POST /phishing/upload  : upload a .eml file and classify
- GET  /phishing/health  : basic health info (model/db)
- POST /phishing/reload  : reload config + artifacts at runtime
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# Load environment variables early so PHISH_CFG / MONGODB_URI are visible
from dotenv import load_dotenv
load_dotenv()

from fastapi import APIRouter, UploadFile, File, HTTPException
from email import policy
import email

from .schemas import EmailIn, PredictOut
from .model import load_artifacts
from core.config import load_config
from core.db.mongodb import get_db, reset_db



logger = logging.getLogger(__name__)

router = APIRouter(prefix="/phishing", tags=["phishing"])

# -------------------------
# Module-level singletons
# -------------------------
_cfg: Dict[str, Any] = {}
_pcfg: Dict[str, Any] = {}
_pipe: Dict[str, Any] = {}
_db = None  # pymongo.database.Database | None


def _load_everything() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Optional[Any]]:
    """
    (Re)load config, artifacts, and DB handle.
    Will not crash if Mongo is enabled but URI is missing; logs a warning instead.
    """
    cfg = load_config()  # PHISH_CFG env or default config/base.yaml
    pcfg = cfg["phishing"]

    # Load artifacts (vectorizer + classifier)
    pipe = load_artifacts(pcfg["artifacts_dir"])
    logger.info("Loaded phishing artifacts from %s", pcfg["artifacts_dir"])

    # Optional DB (for logging)
    db = None
    try:
        db = get_db(cfg)  # may raise if mongodb.enabled=True but no URI
        if db is not None:
            logger.info("Mongo connected to database '%s'", cfg["mongodb"].get("database"))
        else:
            logger.info("Mongo logging disabled (mongodb.enabled is false).")
    except Exception as e:
        logger.warning("Mongo logging unavailable: %s", e)
        db = None

    return cfg, pcfg, pipe, db


# Initialize on import
_cfg, _pcfg, _pipe, _db = _load_everything()

# -------------------------
# Helpers
# -------------------------
# Normalize subject/body/raw into a single text string for scoring.
def _combine_text(subject: Optional[str], body: Optional[str], raw: Optional[str]) -> str:
    """Prefer raw if provided; otherwise stitch subject + body."""
    if raw:
        return raw
    subject = subject or ""
    body = body or ""
    return f"subject: {subject}\n\n{body}"


# Optionally log a prediction to Mongo, honoring logging config.
def _mongo_log_prediction(
    text: str,
    email_in: EmailIn,
    label: int,
    prob: float,
    source: str,
) -> None:
    """
    Insert a prediction record into Mongo if configured.
    Does nothing if _db is None or logging is disabled in config.
    """
    # Only log according to config
    if _db is not None:
        mcfg = _cfg.get("phishing", {}).get("logging", {})
        only_pos = bool(mcfg.get("log_only_positives", True))
        do_log = (label == 1) if only_pos else True

        # Skip logging if only positives and label=0
        if not do_log:
            logger.debug("Skipping log (log_only_positives=True and label=0).")
            return

        col_name = mcfg.get("collection_predictions", "phishing_predictions")

        # Build document
        try:
            snippet = (
                text if mcfg.get("store_text", False)
                else (text[: int(mcfg.get("store_snippet_chars", 160))] if text else "")
            )

            # Insert into Mongo
            doc = {
                "ts": datetime.now(timezone.utc),
                "label": label,
                "probability": prob,
                "threshold": float(_pcfg.get("threshold", 0.5)),
                "subject": email_in.subject if mcfg.get("store_text", False) else None,
                "body": email_in.body if mcfg.get("store_text", False) else None,
                "raw_present": bool(email_in.raw),
                "text_sha256": hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest(),
                "snippet": snippet,
                "source": source,
            }

            # Insert document
            _db[col_name].insert_one(doc)
            logger.info("Logged prediction to Mongo: %s.%s", _cfg["mongodb"]["database"], col_name)
        except Exception as e:
            logger.exception("Mongo logging failed: %s", e)
    else:
        logger.debug("Mongo disabled or URI missing (_db is None) — skipping log.")


# Extract subject/body from .eml upload payloads.
def _parse_eml_bytes(data: bytes) -> Tuple[str, str]:
    """
    Parse a .eml payload and return (subject, body) as strings.
    Prefers text/plain, falls back to text/html, otherwise empty.
    Raises HTTPException(400) for invalid EML.
    """
    # Parse email
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid EML: {e}")

    subject = msg.get("subject") or ""
    body_text, html_text = "", ""

    # Extract body parts
    if msg.is_multipart():

        # Walk parts to find text/plain and text/html
        for part in msg.walk():
            ctype = part.get_content_type()

            # Prefer text/plain
            if ctype == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    pass
            #   Fallback to text/html    
            elif ctype == "text/html" and not html_text:
                try:
                    html_text = part.get_content()
                except Exception:
                    pass

    # Non-multipart message            
    else:
        ctype = msg.get_content_type()
        try:
            # Prefer text/plain
            if ctype == "text/plain":
                body_text = msg.get_content()

            #  Fallback to text/html    
            elif ctype == "text/html":
                html_text = msg.get_content()
        except Exception:
            pass

    body = body_text or html_text or ""
    return subject, body


# -------------------------
# Endpoints
# -------------------------
# Health probe for model+Mongo state.
@router.get("/health")
def health() -> Dict[str, Any]:
    """Quick health summary."""
    return {
        "model_loaded": bool(_pipe and "clf" in _pipe and "featurizer" in _pipe),
        "artifacts_dir": _pcfg.get("artifacts_dir"),
        "mongodb_enabled": bool(_cfg.get("mongodb", {}).get("enabled", False)),
        "mongodb_connected": _db is not None,
        "collection": _cfg.get("phishing", {}).get("logging", {}).get("collection_predictions"),
        "threshold": float(_pcfg.get("threshold", 0.5)),
    }


# Reload config/artifacts/DB without restarting the process.
@router.post("/reload")
def reload_runtime() -> Dict[str, Any]:
    """
    Reload config, artifacts, and DB at runtime (no process restart).
    Closes the previous Mongo client so TLS/URI changes are picked up.
    """
    global _cfg, _pcfg, _pipe, _db

    # Close cached client so new settings (URI, TLS, CA) take effect
    try:
        reset_db()
    except Exception:
        pass

    # Rebuild everything
    _cfg, _pcfg, _pipe, _db = _load_everything()

    # Definitive Mongo check (ping)
    mongo_ok = False
    mongo_err = None
    if _db is not None:
        try:
            _db.command("ping")
            mongo_ok = True
        except Exception as e:
            mongo_err = f"{type(e).__name__}: {e}"

    return {
        "ok": True,
        "artifacts_dir": _pcfg.get("artifacts_dir"),
        "mongodb_enabled": bool(_cfg.get("mongodb", {}).get("enabled", False)),
        "mongodb_connected": mongo_ok,
        "database": _cfg.get("mongodb", {}).get("database"),
        "collection": _cfg.get("phishing", {}).get("logging", {}).get("collection_predictions"),
        "threshold": float(_pcfg.get("threshold", 0.5)),
        "error": mongo_err,  # None if ping succeeded
    }


# Predict from JSON payload (subject/body/raw).
@router.post("/predict", response_model=PredictOut)
def predict(email_in: EmailIn) -> PredictOut:
    """
    Predict phishing from JSON payload:
    {
      "subject": "...",    # optional
      "body": "...",       # optional
      "raw": "..."         # optional; if present, subject/body are ignored
    }
    """
    text = _combine_text(email_in.subject, email_in.body, email_in.raw)
    X = _pipe["featurizer"].transform([text])
    prob = float(_pipe["clf"].predict_proba(X)[0, 1])
    label = int(prob >= _pcfg.get("threshold", 0.5))

    _mongo_log_prediction(text=text, email_in=email_in, label=label, prob=prob, source="api/phishing")
    return PredictOut(label=label, probability=prob)


# Predict from uploaded .eml file.
@router.post("/upload", response_model=PredictOut)
async def predict_eml(file: UploadFile = File(...)) -> PredictOut:
    """
    Upload a .eml file and classify. Logs to Mongo using same policy.
    """
    data = await file.read()
    subject, body = _parse_eml_bytes(data)

    # For model features, we still build a normalized text from subject+body
    text = _combine_text(subject, body, None)
    X = _pipe["featurizer"].transform([text])
    prob = float(_pipe["clf"].predict_proba(X)[0, 1])
    label = int(prob >= _pcfg.get("threshold", 0.5))

    tmp = EmailIn(subject=subject, body=body, raw=None)  # for consistent logging
    _mongo_log_prediction(text=text, email_in=tmp, label=label, prob=prob, source="api/phishing/upload")

    return PredictOut(label=label, probability=prob)
