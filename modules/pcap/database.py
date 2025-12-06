"""
Database module for PCAP Analyzer.
Handles MongoDB connections and operations for storing analysis results.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# Attempt to import Motor for async MongoDB operations
try:
    from motor.motor_asyncio import AsyncIOMotorClient

# pragma: no cover - optional dependency
except Exception as exc:  # pragma: no cover - optional dependency
    AsyncIOMotorClient = None  # type: ignore
    MOTOR_IMPORT_ERROR = exc
else: # pragma: no cover
    MOTOR_IMPORT_ERROR = None

# MongoDB handler class
class Database:
    """MongoDB handler for PCAP analysis results."""

    # Initialize the database connection
    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        # Prefer environment variables; fall back to provided defaults.
        self.mongo_uri = uri if uri is not None else os.getenv("MONGODB_URI", "")
        # Align default with rest of app (defensedb) unless explicitly overridden.
        self.db_name = db_name if db_name is not None else os.getenv("MONGODB_DB", "defensedb")

        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self.analyses_collection = None
        self.threats_collection = None
        self._indexes_ready = False

    # Connect to MongoDB
    async def connect(self) -> bool:
        """Establish connection to MongoDB."""
        # Check if Motor is available
        if AsyncIOMotorClient is None:
            print(f"[WARN] Motor not installed; skipping Mongo logging ({MOTOR_IMPORT_ERROR})")
            return False

        # Check if URI is set
        if not self.mongo_uri:
            print("[INFO] MongoDB URI not set; skipping Mongo logging")
            return False

        # Attempt to connect
        try:
            if self.client is None:
                self.client = AsyncIOMotorClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
                self.db = self.client[self.db_name]
                self.analyses_collection = self.db["analyses"]
                self.threats_collection = self.db["threats"]

            await self.client.admin.command("ping")
            return True
        # pylint: disable=broad-except
        except Exception as e:  # pragma: no cover - external dependency
            print(f"[ERROR] MongoDB connection failed: {e}")
            print("  Make sure MongoDB is running and MONGODB_URI is correct.")
            return False

    # Initialize indexes
    async def initialize_indexes(self) -> None:
        """Create indexes for better query performance."""
        if self.analyses_collection is None or self.threats_collection is None:
            return
        if self._indexes_ready:
            return
        try:
            await self.analyses_collection.create_index([("timestamp", -1)])
            await self.analyses_collection.create_index([("filename", 1)])
            await self.threats_collection.create_index([("threat_level", 1)])
            await self.threats_collection.create_index([("timestamp", -1)])
            self._indexes_ready = True
            print("[OK] Database indexes initialized")
        except Exception as e:  # pragma: no cover - external dependency
            print(f"Warning: Could not create indexes: {e}")

    # Save analysis results
    async def save_analysis(self, filename: str, analysis_data: Dict[str, Any]) -> str:
        """Save PCAP analysis results to database."""
        if self.analyses_collection is None:
            return ""

        document = {
            "filename": filename,
            "timestamp": datetime.utcnow(),
            "basic_stats": analysis_data.get("basic_stats", {}),
            "protocol_stats": analysis_data.get("protocol_stats", {}),
            "top_talkers": analysis_data.get("top_talkers", []),
            "packet_details": analysis_data.get("packet_details", []),
        }

        result = await self.analyses_collection.insert_one(document)
        print(f"[OK] Analysis saved with ID: {result.inserted_id}")
        return str(result.inserted_id)

    # Save threat analysis
    async def save_threats(self, filename: str, threat_data: Dict[str, Any]) -> str:
        """Save security threat analysis to database."""
        if self.threats_collection is None:
            return ""

        document = {
            "filename": filename,
            "timestamp": datetime.utcnow(),
            "threat_summary": threat_data.get("threat_summary", {}),
            "syn_flood_detection": threat_data.get("syn_flood_detection", {}),
            "port_scan_detection": threat_data.get("port_scan_detection", {}),
            "volume_anomaly_detection": threat_data.get("volume_anomaly_detection", {}),
            "abuseipdb_results": threat_data.get("abuseipdb_results", {}),
        }

        result = await self.threats_collection.insert_one(document)
        print(f"[OK] Threats saved with ID: {result.inserted_id}")
        return str(result.inserted_id)

    # Retrieve recent analyses
    async def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent analysis results."""
        if self.analyses_collection is None:
            return []
        cursor = self.analyses_collection.find().sort("timestamp", -1).limit(limit)
        analyses = await cursor.to_list(length=limit)
        for analysis in analyses:
            analysis["_id"] = str(analysis["_id"])
        return analyses

    # Retrieve recent threats
    async def get_recent_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent threat detections."""
        if self.threats_collection is None:
            return []
        cursor = self.threats_collection.find().sort("timestamp", -1).limit(limit)
        threats = await cursor.to_list(length=limit)
        for threat in threats:
            threat["_id"] = str(threat["_id"])
        return threats

    # Retrieve high-severity threats
    async def get_high_threats(self) -> List[Dict[str, Any]]:
        """Get all high-severity threats."""
        if self.threats_collection is None:
            return []
        cursor = self.threats_collection.find({"threat_summary.overall_threat_level": "High"}).sort("timestamp", -1)
        threats = await cursor.to_list(length=None)
        for threat in threats:
            threat["_id"] = str(threat["_id"])
        return threats

    # Retrieve analysis by filename
    async def get_analysis_by_filename(self, filename: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis by filename."""
        if self.analyses_collection is None:
            return None
        analysis = await self.analyses_collection.find_one({"filename": filename}, sort=[("timestamp", -1)])
        if analysis:
            analysis["_id"] = str(analysis["_id"])
        return analysis

    # Get database statistics
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        if self.analyses_collection is None or self.threats_collection is None:
            return {"total_analyses": 0, "total_threats": 0, "high_severity_threats": 0}

        total_analyses = await self.analyses_collection.count_documents({})
        total_threats = await self.threats_collection.count_documents({})
        high_threats = await self.threats_collection.count_documents({"threat_summary.overall_threat_level": "High"})
        return {
            "total_analyses": total_analyses,
            "total_threats": total_threats,
            "high_severity_threats": high_threats,
        }

    # Close the MongoDB connection
    async def close(self) -> None:
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            print("[OK] MongoDB connection closed")


_db_instance: Optional[Database] = None

# Singleton pattern for database instance
def get_database() -> Database:
    """Get the singleton database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
