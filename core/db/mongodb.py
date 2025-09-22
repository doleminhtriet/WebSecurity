import os
from typing import Any, Dict, Optional

import certifi
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from pymongo.errors import PyMongoError

_client: Optional[MongoClient] = None


def reset_db() -> None:
    """Close and clear the cached client. Call this before reloading config."""
    global _client
    if _client is not None:
        try:
            _client.close()
        except Exception:
            pass
    _client = None


def get_db(cfg: Dict[str, Any]):
    global _client
    mcfg = cfg.get("mongodb", {})
    if not mcfg.get("enabled", False):
        return None

    uri = os.environ.get("MONGODB_URI") or mcfg.get("uri")
    if not uri:
        raise RuntimeError("MongoDB enabled but no URI provided. Set MONGODB_URI or mongodb.uri.")

    kwargs = {
        "server_api": ServerApi("1"),
        "serverSelectionTimeoutMS": 30000,
        "tls": bool(mcfg.get("tls", True)),
        "tlsCAFile": certifi.where(),  # <-- key line
    }
    if mcfg.get("allow_invalid_certs", False):
        kwargs["tlsAllowInvalidCertificates"] = True  # TEMP ONLY if behind TLS interception

    if _client is None:
        try:
            _client = MongoClient(uri, **kwargs)
            _client.admin.command("ping")  # force handshake now
        except PyMongoError as e:
            raise RuntimeError(
                f"Failed to connect to MongoDB: {e}\n"
                "Hints: ensure 'certifi' is installed, and use an SRV URI (mongodb+srv://)."
            ) from e

    dbname = mcfg.get("database", "defensedb")
    return _client[dbname]