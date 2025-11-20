"""
Database Utility Functions
Helper functions for database operations
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from bson.objectid import ObjectId

logger = logging.getLogger(__name__)


class DatabaseHelper:
    """Helper class for common database operations"""

    def __init__(self, db):
        """
        Initialize database helper

        Args:
            db: PyMongo database instance
        """
        self.db = db

    # ==================== PACKET OPERATIONS ====================

    def insert_packet(self, packet_data: Dict[str, Any]) -> Optional[str]:
        """Insert a packet document"""
        try:
            packet_data["timestamp"] = packet_data.get("timestamp", datetime.utcnow())
            result = self.db.packets.insert_one(packet_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting packet: {e}")
            return None

    def get_recent_packets(
        self, limit: int = 100, threat_only: bool = False
    ) -> List[Dict]:
        """Get recent packets"""
        try:
            query = {"is_threat": True} if threat_only else {}
            packets = self.db.packets.find(query).sort("timestamp", -1).limit(limit)
            return list(packets)
        except Exception as e:
            logger.error(f"Error getting recent packets: {e}")
            return []

    # ==================== THREAT OPERATIONS ====================

    def insert_threat(self, threat_data: Dict[str, Any]) -> Optional[str]:
        """Insert a threat document"""
        try:
            threat_data["timestamp"] = threat_data.get("timestamp", datetime.utcnow())
            result = self.db.threats.insert_one(threat_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting threat: {e}")
            return None

    def get_recent_threats(
        self, limit: int = 20, severity: Optional[str] = None
    ) -> List[Dict]:
        """Get recent threats"""
        try:
            query = {}
            if severity:
                query["severity"] = severity

            threats = self.db.threats.find(query).sort("timestamp", -1).limit(limit)
            return list(threats)
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return []

    def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat statistics for specified time period"""
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)

            pipeline = [
                {"$match": {"timestamp": {"$gte": start_time}}},
                {
                    "$group": {
                        "_id": None,
                        "total_threats": {"$sum": 1},
                        "by_signature": {"$push": "$signature"},
                        "by_type": {"$push": "$threat_type"},
                        "by_severity": {"$push": "$severity"},
                    }
                },
            ]

            result = list(self.db.threats.aggregate(pipeline))

            if result:
                stats = result[0]
                # Count occurrences
                from collections import Counter

                stats["by_signature"] = dict(Counter(stats.get("by_signature", [])))
                stats["by_type"] = dict(Counter(stats.get("by_type", [])))
                stats["by_severity"] = dict(Counter(stats.get("by_severity", [])))
                return stats
            else:
                return {
                    "total_threats": 0,
                    "by_signature": {},
                    "by_type": {},
                    "by_severity": {},
                }

        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {}

    # ==================== FLOW OPERATIONS ====================

    def insert_flow(self, flow_data: Dict[str, Any]) -> Optional[str]:
        """Insert a flow document"""
        try:
            flow_data["start_time"] = flow_data.get("start_time", datetime.utcnow())
            flow_data["last_seen"] = flow_data.get("last_seen", datetime.utcnow())
            result = self.db.flows.insert_one(flow_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting flow: {e}")
            return None

    def update_flow(self, flow_id: str, update_data: Dict[str, Any]) -> bool:
        """Update a flow document"""
        try:
            update_data["last_seen"] = datetime.utcnow()
            result = self.db.flows.update_one(
                {"flow_id": flow_id}, {"$set": update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating flow: {e}")
            return False

    def get_active_flows(self, timeout_seconds: int = 300) -> List[Dict]:
        """Get active flows (updated within timeout period)"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(seconds=timeout_seconds)
            flows = self.db.flows.find(
                {"status": "active", "last_seen": {"$gte": cutoff_time}}
            )
            return list(flows)
        except Exception as e:
            logger.error(f"Error getting active flows: {e}")
            return []

    # ==================== ALERT OPERATIONS ====================

    def insert_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Insert an alert document"""
        try:
            alert_data["timestamp"] = alert_data.get("timestamp", datetime.utcnow())
            alert_data["read"] = alert_data.get("read", False)
            alert_data["acknowledged"] = alert_data.get("acknowledged", False)
            result = self.db.alerts.insert_one(alert_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            return None

    def get_recent_alerts(
        self, limit: int = 50, unread_only: bool = False
    ) -> List[Dict]:
        """Get recent alerts"""
        try:
            query = {"read": False} if unread_only else {}
            alerts = self.db.alerts.find(query).sort("timestamp", -1).limit(limit)
            return list(alerts)
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
            return []

    def mark_alert_read(self, alert_id: str) -> bool:
        """Mark alert as read"""
        try:
            result = self.db.alerts.update_one(
                {"_id": ObjectId(alert_id)}, {"$set": {"read": True}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error marking alert as read: {e}")
            return False

    def acknowledge_alert(self, alert_id: str, username: str) -> bool:
        """Acknowledge an alert"""
        try:
            result = self.db.alerts.update_one(
                {"_id": ObjectId(alert_id)},
                {
                    "$set": {
                        "acknowledged": True,
                        "acknowledged_by": username,
                        "acknowledged_at": datetime.utcnow(),
                    }
                },
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            return False

    # ==================== DETECTION OPERATIONS ====================

    def insert_detection(self, detection_data: Dict[str, Any]) -> Optional[str]:
        """Insert a detection document"""
        try:
            detection_data["timestamp"] = detection_data.get(
                "timestamp", datetime.utcnow()
            )
            result = self.db.detections.insert_one(detection_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting detection: {e}")
            return None

    def get_detection_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get detection statistics"""
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)

            # AI detections
            ai_count = self.db.detections.count_documents(
                {"detector_type": "ai", "timestamp": {"$gte": start_time}}
            )

            # RL detections
            rl_count = self.db.detections.count_documents(
                {"detector_type": "rl", "timestamp": {"$gte": start_time}}
            )

            # Signature detections
            sig_count = self.db.detections.count_documents(
                {"detector_type": "signature", "timestamp": {"$gte": start_time}}
            )

            return {
                "ai_detections": ai_count,
                "rl_decisions": rl_count,
                "signature_matches": sig_count,
                "total_detections": ai_count + rl_count + sig_count,
            }

        except Exception as e:
            logger.error(f"Error getting detection statistics: {e}")
            return {}

    # ==================== STATISTICS OPERATIONS ====================

    def save_statistics(
        self, metric_type: str, period: str, stats_data: Dict[str, Any]
    ) -> Optional[str]:
        """Save statistics snapshot"""
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "metric_type": metric_type,
                "period": period,
                **stats_data,
            }
            result = self.db.statistics.insert_one(doc)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error saving statistics: {e}")
            return None

    def get_statistics(
        self, metric_type: str, period: str, hours: int = 24
    ) -> List[Dict]:
        """Get statistics for specified period"""
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            stats = self.db.statistics.find(
                {
                    "metric_type": metric_type,
                    "period": period,
                    "timestamp": {"$gte": start_time},
                }
            ).sort("timestamp", -1)
            return list(stats)
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return []

    # ==================== SYSTEM LOG OPERATIONS ====================

    def log_event(
        self, level: str, component: str, message: str, **kwargs
    ) -> Optional[str]:
        """Log a system event"""
        try:
            log_entry = {
                "timestamp": datetime.utcnow(),
                "level": level,
                "component": component,
                "message": message,
                **kwargs,
            }
            result = self.db.system_logs.insert_one(log_entry)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error logging event: {e}")
            return None

    def get_recent_logs(
        self,
        limit: int = 100,
        level: Optional[str] = None,
        component: Optional[str] = None,
    ) -> List[Dict]:
        """Get recent system logs"""
        try:
            query = {}
            if level:
                query["level"] = level
            if component:
                query["component"] = component

            logs = self.db.system_logs.find(query).sort("timestamp", -1).limit(limit)
            return list(logs)
        except Exception as e:
            logger.error(f"Error getting recent logs: {e}")
            return []

    # ==================== CLEANUP OPERATIONS ====================

    def cleanup_old_data(self, days: int = 7) -> Dict[str, int]:
        """
        Clean up old data beyond retention period
        Note: This is a manual cleanup, TTL indexes handle automatic cleanup

        Args:
            days: Number of days to retain

        Returns:
            Dictionary with deleted counts per collection
        """
        results = {}
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        try:
            # Clean old packets
            result = self.db.packets.delete_many({"timestamp": {"$lt": cutoff_date}})
            results["packets"] = result.deleted_count

            # Clean old detections
            result = self.db.detections.delete_many({"timestamp": {"$lt": cutoff_date}})
            results["detections"] = result.deleted_count

            # Clean old logs
            result = self.db.system_logs.delete_many(
                {"timestamp": {"$lt": cutoff_date}}
            )
            results["system_logs"] = result.deleted_count

            logger.info(f"Cleanup completed: {results}")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        return results
