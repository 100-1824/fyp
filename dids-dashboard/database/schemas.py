"""
MongoDB Schema Definitions for DIDS Dashboard
Complete schema definitions with validation rules and indexes
"""

import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ==================== PACKETS COLLECTION ====================
PACKETS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["timestamp", "source", "destination", "protocol"],
            "properties": {
                "timestamp": {
                    "bsonType": "date",
                    "description": "Packet capture timestamp",
                },
                "source": {
                    "bsonType": "string",
                    "description": "Source IP address",
                    "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
                },
                "destination": {
                    "bsonType": "string",
                    "description": "Destination IP address",
                    "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
                },
                "protocol": {
                    "enum": [
                        "TCP",
                        "UDP",
                        "ICMP",
                        "ARP",
                        "DNS",
                        "HTTP",
                        "HTTPS",
                        "SSH",
                        "FTP",
                        "OTHER",
                    ],
                    "description": "Network protocol",
                },
                "src_port": {
                    "bsonType": "int",
                    "minimum": 0,
                    "maximum": 65535,
                    "description": "Source port number",
                },
                "dst_port": {
                    "bsonType": "int",
                    "minimum": 0,
                    "maximum": 65535,
                    "description": "Destination port number",
                },
                "size": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Packet size in bytes",
                },
                "tcp_flags": {
                    "bsonType": "object",
                    "properties": {
                        "syn": {"bsonType": "int", "minimum": 0, "maximum": 1},
                        "ack": {"bsonType": "int", "minimum": 0, "maximum": 1},
                        "fin": {"bsonType": "int", "minimum": 0, "maximum": 1},
                        "rst": {"bsonType": "int", "minimum": 0, "maximum": 1},
                        "psh": {"bsonType": "int", "minimum": 0, "maximum": 1},
                        "urg": {"bsonType": "int", "minimum": 0, "maximum": 1},
                    },
                },
                "flow_id": {
                    "bsonType": "string",
                    "description": "Associated flow identifier",
                },
                "payload_size": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Payload size in bytes",
                },
                "is_threat": {
                    "bsonType": "bool",
                    "description": "Whether packet is identified as threat",
                },
                "preprocessed": {
                    "bsonType": "bool",
                    "description": "Whether packet has been preprocessed",
                },
                "features": {
                    "bsonType": "object",
                    "description": "Extracted features for ML/RL analysis",
                },
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {"key": [("source", 1), ("timestamp", -1)], "name": "source_timestamp"},
        {"key": [("destination", 1), ("timestamp", -1)], "name": "dest_timestamp"},
        {"key": [("protocol", 1), ("timestamp", -1)], "name": "protocol_timestamp"},
        {"key": [("flow_id", 1)], "name": "flow_id"},
        {"key": [("is_threat", 1), ("timestamp", -1)], "name": "threat_timestamp"},
        {
            "key": [("timestamp", -1)],
            "name": "timestamp_ttl",
            "expireAfterSeconds": 604800,
        },  # 7 days
    ],
}

# ==================== THREATS COLLECTION ====================
THREATS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "timestamp",
                "source",
                "destination",
                "threat_type",
                "severity",
            ],
            "properties": {
                "timestamp": {
                    "bsonType": "date",
                    "description": "Threat detection timestamp",
                },
                "source": {"bsonType": "string", "description": "Source IP address"},
                "destination": {
                    "bsonType": "string",
                    "description": "Destination IP address",
                },
                "protocol": {
                    "enum": [
                        "TCP",
                        "UDP",
                        "ICMP",
                        "ARP",
                        "DNS",
                        "HTTP",
                        "HTTPS",
                        "SSH",
                        "FTP",
                        "OTHER",
                    ],
                    "description": "Network protocol",
                },
                "threat_type": {
                    "bsonType": "string",
                    "description": "Type of threat detected (DDoS, PortScan, BruteForce, etc.)",
                },
                "severity": {
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Threat severity level",
                },
                "signature": {
                    "bsonType": "string",
                    "description": "Signature rule that detected the threat",
                },
                "confidence": {
                    "bsonType": "double",
                    "minimum": 0.0,
                    "maximum": 100.0,
                    "description": "Detection confidence percentage",
                },
                "action": {
                    "enum": ["allow", "alert", "block"],
                    "description": "Action taken on the threat",
                },
                "detector": {
                    "enum": ["signature", "ai", "rl", "hybrid"],
                    "description": "Detection method used",
                },
                "packet_id": {
                    "bsonType": "objectId",
                    "description": "Reference to packet collection",
                },
                "flow_id": {
                    "bsonType": "string",
                    "description": "Associated flow identifier",
                },
                "blocked": {
                    "bsonType": "bool",
                    "description": "Whether threat was blocked",
                },
                "details": {
                    "bsonType": "object",
                    "description": "Additional threat details",
                },
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {"key": [("severity", 1), ("timestamp", -1)], "name": "severity_timestamp"},
        {"key": [("threat_type", 1), ("timestamp", -1)], "name": "type_timestamp"},
        {"key": [("source", 1), ("timestamp", -1)], "name": "source_timestamp"},
        {"key": [("detector", 1), ("timestamp", -1)], "name": "detector_timestamp"},
        {"key": [("action", 1), ("timestamp", -1)], "name": "action_timestamp"},
        {"key": [("flow_id", 1)], "name": "flow_id"},
    ],
}

# ==================== DETECTIONS COLLECTION ====================
DETECTIONS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["timestamp", "detector_type", "result"],
            "properties": {
                "timestamp": {"bsonType": "date", "description": "Detection timestamp"},
                "detector_type": {
                    "enum": ["signature", "ai", "rl"],
                    "description": "Type of detector",
                },
                "packet_data": {
                    "bsonType": "object",
                    "description": "Packet data analyzed",
                },
                "result": {
                    "bsonType": "object",
                    "properties": {
                        "is_threat": {"bsonType": "bool"},
                        "attack_type": {"bsonType": "string"},
                        "confidence": {
                            "bsonType": "double",
                            "minimum": 0.0,
                            "maximum": 100.0,
                        },
                        "severity": {
                            "enum": ["critical", "high", "medium", "low", "benign"]
                        },
                    },
                },
                "ai_prediction": {
                    "bsonType": "object",
                    "properties": {
                        "predicted_class": {"bsonType": "string"},
                        "probabilities": {"bsonType": "object"},
                        "model_version": {"bsonType": "string"},
                    },
                },
                "rl_decision": {
                    "bsonType": "object",
                    "properties": {
                        "action": {"enum": ["allow", "alert", "block"]},
                        "q_values": {"bsonType": "array"},
                        "state": {"bsonType": "array"},
                        "agent_version": {"bsonType": "string"},
                    },
                },
                "signature_matches": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "object",
                        "properties": {
                            "signature": {"bsonType": "string"},
                            "severity": {"bsonType": "string"},
                        },
                    },
                },
                "processing_time_ms": {
                    "bsonType": "double",
                    "minimum": 0,
                    "description": "Detection processing time in milliseconds",
                },
                "flow_id": {"bsonType": "string"},
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {
            "key": [("detector_type", 1), ("timestamp", -1)],
            "name": "detector_timestamp",
        },
        {
            "key": [("result.is_threat", 1), ("timestamp", -1)],
            "name": "threat_timestamp",
        },
        {"key": [("flow_id", 1)], "name": "flow_id"},
        {
            "key": [("timestamp", -1)],
            "name": "timestamp_ttl",
            "expireAfterSeconds": 2592000,
        },  # 30 days
    ],
}

# ==================== FLOWS COLLECTION ====================
FLOWS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["flow_id", "source", "destination", "start_time"],
            "properties": {
                "flow_id": {
                    "bsonType": "string",
                    "description": "Unique flow identifier",
                },
                "source": {"bsonType": "string", "description": "Source IP address"},
                "destination": {
                    "bsonType": "string",
                    "description": "Destination IP address",
                },
                "src_port": {"bsonType": "int", "minimum": 0, "maximum": 65535},
                "dst_port": {"bsonType": "int", "minimum": 0, "maximum": 65535},
                "protocol": {"bsonType": "string", "description": "Protocol type"},
                "start_time": {
                    "bsonType": "date",
                    "description": "Flow start timestamp",
                },
                "last_seen": {
                    "bsonType": "date",
                    "description": "Last packet timestamp",
                },
                "duration": {
                    "bsonType": "double",
                    "minimum": 0,
                    "description": "Flow duration in seconds",
                },
                "packet_count": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Total packets in flow",
                },
                "total_bytes": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Total bytes transferred",
                },
                "forward_packets": {"bsonType": "int", "minimum": 0},
                "backward_packets": {"bsonType": "int", "minimum": 0},
                "forward_bytes": {"bsonType": "int", "minimum": 0},
                "backward_bytes": {"bsonType": "int", "minimum": 0},
                "features": {
                    "bsonType": "object",
                    "description": "Extracted flow features (77 features for ML/RL)",
                },
                "is_threat": {
                    "bsonType": "bool",
                    "description": "Whether flow contains threats",
                },
                "threat_types": {"bsonType": "array", "items": {"bsonType": "string"}},
                "status": {
                    "enum": ["active", "closed", "timeout"],
                    "description": "Flow status",
                },
            },
        }
    },
    "indexes": [
        {"key": [("flow_id", 1)], "name": "flow_id_unique", "unique": True},
        {"key": [("start_time", -1)], "name": "start_time_desc"},
        {
            "key": [("source", 1), ("destination", 1), ("start_time", -1)],
            "name": "src_dst_time",
        },
        {"key": [("status", 1), ("last_seen", -1)], "name": "status_lastseen"},
        {"key": [("is_threat", 1), ("start_time", -1)], "name": "threat_time"},
        {
            "key": [("last_seen", 1)],
            "name": "lastseen_ttl",
            "expireAfterSeconds": 604800,
        },  # 7 days
    ],
}

# ==================== ALERTS COLLECTION ====================
ALERTS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["timestamp", "severity", "type", "message"],
            "properties": {
                "timestamp": {
                    "bsonType": "date",
                    "description": "Alert generation timestamp",
                },
                "severity": {
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Alert severity level",
                },
                "type": {
                    "bsonType": "string",
                    "description": "Alert type (threat type, system alert, etc.)",
                },
                "source": {
                    "bsonType": "string",
                    "description": "Source IP or system component",
                },
                "destination": {
                    "bsonType": "string",
                    "description": "Destination IP if applicable",
                },
                "message": {"bsonType": "string", "description": "Alert message"},
                "action": {
                    "enum": ["allow", "alert", "block"],
                    "description": "Action taken",
                },
                "threat_id": {
                    "bsonType": "objectId",
                    "description": "Reference to threat document",
                },
                "read": {
                    "bsonType": "bool",
                    "description": "Whether alert has been read",
                },
                "acknowledged": {
                    "bsonType": "bool",
                    "description": "Whether alert has been acknowledged",
                },
                "acknowledged_by": {
                    "bsonType": "string",
                    "description": "User who acknowledged the alert",
                },
                "acknowledged_at": {
                    "bsonType": "date",
                    "description": "Acknowledgement timestamp",
                },
                "details": {
                    "bsonType": "object",
                    "description": "Additional alert details",
                },
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {"key": [("severity", 1), ("timestamp", -1)], "name": "severity_timestamp"},
        {"key": [("type", 1), ("timestamp", -1)], "name": "type_timestamp"},
        {"key": [("read", 1), ("timestamp", -1)], "name": "read_timestamp"},
        {"key": [("acknowledged", 1), ("timestamp", -1)], "name": "ack_timestamp"},
    ],
}

# ==================== USERS COLLECTION ====================
USERS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["username", "password_hash", "role"],
            "properties": {
                "username": {
                    "bsonType": "string",
                    "minLength": 3,
                    "maxLength": 50,
                    "description": "Unique username",
                },
                "password_hash": {
                    "bsonType": "string",
                    "description": "Hashed password (bcrypt)",
                },
                "full_name": {"bsonType": "string", "description": "User's full name"},
                "email": {
                    "bsonType": "string",
                    "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                    "description": "User email address",
                },
                "role": {
                    "enum": ["admin", "analyst", "viewer", "user"],
                    "description": "User role",
                },
                "active": {
                    "bsonType": "bool",
                    "description": "Whether account is active",
                },
                "created_at": {
                    "bsonType": "date",
                    "description": "Account creation timestamp",
                },
                "last_login": {
                    "bsonType": "date",
                    "description": "Last login timestamp",
                },
                "failed_login_attempts": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Failed login attempt count",
                },
                "locked_until": {
                    "bsonType": "date",
                    "description": "Account lock expiration",
                },
                "preferences": {
                    "bsonType": "object",
                    "description": "User preferences and settings",
                },
            },
        }
    },
    "indexes": [
        {"key": [("username", 1)], "name": "username_unique", "unique": True},
        {"key": [("email", 1)], "name": "email_unique", "unique": True, "sparse": True},
        {"key": [("role", 1)], "name": "role"},
        {"key": [("active", 1)], "name": "active"},
    ],
}

# ==================== STATISTICS COLLECTION ====================
STATISTICS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["timestamp", "metric_type"],
            "properties": {
                "timestamp": {
                    "bsonType": "date",
                    "description": "Statistics collection timestamp",
                },
                "metric_type": {
                    "enum": [
                        "traffic",
                        "threats",
                        "detections",
                        "system",
                        "performance",
                    ],
                    "description": "Type of statistics",
                },
                "period": {
                    "enum": ["minute", "hour", "day", "week", "month"],
                    "description": "Aggregation period",
                },
                "traffic_stats": {
                    "bsonType": "object",
                    "properties": {
                        "total_packets": {"bsonType": "int"},
                        "total_bytes": {"bsonType": "int"},
                        "protocol_distribution": {"bsonType": "object"},
                        "top_sources": {"bsonType": "array"},
                        "top_destinations": {"bsonType": "array"},
                        "avg_packet_size": {"bsonType": "double"},
                    },
                },
                "threat_stats": {
                    "bsonType": "object",
                    "properties": {
                        "total_threats": {"bsonType": "int"},
                        "threats_blocked": {"bsonType": "int"},
                        "by_type": {"bsonType": "object"},
                        "by_severity": {"bsonType": "object"},
                        "by_detector": {"bsonType": "object"},
                    },
                },
                "detection_stats": {
                    "bsonType": "object",
                    "properties": {
                        "ai_detections": {"bsonType": "int"},
                        "rl_decisions": {"bsonType": "int"},
                        "signature_matches": {"bsonType": "int"},
                        "false_positives": {"bsonType": "int"},
                        "avg_confidence": {"bsonType": "double"},
                    },
                },
                "system_stats": {
                    "bsonType": "object",
                    "properties": {
                        "uptime_seconds": {"bsonType": "int"},
                        "cpu_usage": {"bsonType": "double"},
                        "memory_usage": {"bsonType": "double"},
                        "disk_usage": {"bsonType": "double"},
                        "services_healthy": {"bsonType": "int"},
                        "services_total": {"bsonType": "int"},
                    },
                },
                "performance_stats": {
                    "bsonType": "object",
                    "properties": {
                        "avg_detection_time_ms": {"bsonType": "double"},
                        "packets_per_second": {"bsonType": "double"},
                        "throughput_mbps": {"bsonType": "double"},
                    },
                },
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {"key": [("metric_type", 1), ("timestamp", -1)], "name": "type_timestamp"},
        {"key": [("period", 1), ("timestamp", -1)], "name": "period_timestamp"},
        {
            "key": [("timestamp", 1)],
            "name": "timestamp_ttl",
            "expireAfterSeconds": 7776000,
        },  # 90 days
    ],
}

# ==================== SYSTEM_LOGS COLLECTION ====================
SYSTEM_LOGS_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["timestamp", "level", "component", "message"],
            "properties": {
                "timestamp": {"bsonType": "date", "description": "Log entry timestamp"},
                "level": {
                    "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    "description": "Log level",
                },
                "component": {
                    "bsonType": "string",
                    "description": "System component (service name, module, etc.)",
                },
                "message": {"bsonType": "string", "description": "Log message"},
                "user": {
                    "bsonType": "string",
                    "description": "User associated with log entry",
                },
                "action": {"bsonType": "string", "description": "Action performed"},
                "ip_address": {
                    "bsonType": "string",
                    "description": "IP address if applicable",
                },
                "error_details": {
                    "bsonType": "object",
                    "description": "Error stack trace and details",
                },
                "metadata": {
                    "bsonType": "object",
                    "description": "Additional metadata",
                },
            },
        }
    },
    "indexes": [
        {"key": [("timestamp", -1)], "name": "timestamp_desc"},
        {"key": [("level", 1), ("timestamp", -1)], "name": "level_timestamp"},
        {"key": [("component", 1), ("timestamp", -1)], "name": "component_timestamp"},
        {"key": [("user", 1), ("timestamp", -1)], "name": "user_timestamp"},
        {
            "key": [("timestamp", 1)],
            "name": "timestamp_ttl",
            "expireAfterSeconds": 2592000,
        },  # 30 days
    ],
}

# ==================== RULES COLLECTION (Suricata/Snort) ====================
RULES_SCHEMA = {
    "validator": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["sid", "action", "protocol", "msg"],
            "properties": {
                "sid": {"bsonType": "string", "description": "Unique Signature ID"},
                "action": {
                    "enum": ["alert", "log", "pass", "drop", "reject", "sdrop"],
                    "description": "Rule action",
                },
                "protocol": {
                    "enum": [
                        "tcp",
                        "udp",
                        "icmp",
                        "ip",
                        "http",
                        "ftp",
                        "tls",
                        "smb",
                        "dns",
                        "ssh",
                    ],
                    "description": "Protocol to match",
                },
                "src_ip": {
                    "bsonType": "string",
                    "description": "Source IP specification",
                },
                "src_port": {
                    "bsonType": "string",
                    "description": "Source port specification",
                },
                "direction": {
                    "enum": ["->", "<>", "<-"],
                    "description": "Traffic direction",
                },
                "dst_ip": {
                    "bsonType": "string",
                    "description": "Destination IP specification",
                },
                "dst_port": {
                    "bsonType": "string",
                    "description": "Destination port specification",
                },
                "msg": {
                    "bsonType": "string",
                    "description": "Rule message/description",
                },
                "raw_rule": {
                    "bsonType": "string",
                    "description": "Original raw rule text",
                },
                "severity": {
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Rule severity level",
                },
                "priority": {
                    "bsonType": "int",
                    "minimum": 1,
                    "maximum": 4,
                    "description": "Rule priority (1=highest, 4=lowest)",
                },
                "classtype": {
                    "bsonType": "string",
                    "description": "Classification type (e.g., trojan-activity, attempted-admin)",
                },
                "reference": {
                    "bsonType": "string",
                    "description": "External reference (CVE, URL, etc.)",
                },
                "rev": {"bsonType": "string", "description": "Rule revision number"},
                "enabled": {
                    "bsonType": "bool",
                    "description": "Whether rule is active",
                },
                "hit_count": {
                    "bsonType": "int",
                    "minimum": 0,
                    "description": "Number of times rule has matched",
                },
                "last_hit": {
                    "bsonType": "date",
                    "description": "Last time rule matched a packet",
                },
                "created_at": {
                    "bsonType": "date",
                    "description": "Rule creation timestamp",
                },
                "last_modified": {
                    "bsonType": "date",
                    "description": "Last modification timestamp",
                },
                "source_file": {
                    "bsonType": "string",
                    "description": "Source file path if loaded from file",
                },
                "line_number": {
                    "bsonType": "int",
                    "description": "Line number in source file",
                },
                "options": {
                    "bsonType": "object",
                    "description": "Parsed rule options (content, pcre, flags, etc.)",
                },
            },
        }
    },
    "indexes": [
        {"key": [("sid", 1)], "name": "sid_unique", "unique": True},
        {"key": [("enabled", 1)], "name": "enabled"},
        {"key": [("severity", 1)], "name": "severity"},
        {"key": [("protocol", 1)], "name": "protocol"},
        {"key": [("action", 1)], "name": "action"},
        {"key": [("hit_count", -1)], "name": "hit_count_desc"},
        {"key": [("last_hit", -1)], "name": "last_hit_desc"},
        {"key": [("classtype", 1)], "name": "classtype"},
    ],
}


# ==================== DATABASE INITIALIZATION ====================


def init_database(db, drop_existing: bool = False) -> Dict[str, bool]:
    """
    Initialize all database collections with schemas and indexes

    Args:
        db: PyMongo database instance
        drop_existing: Whether to drop existing collections (use with caution!)

    Returns:
        Dictionary with collection names and initialization status
    """
    results = {}

    schemas = {
        "packets": PACKETS_SCHEMA,
        "threats": THREATS_SCHEMA,
        "detections": DETECTIONS_SCHEMA,
        "flows": FLOWS_SCHEMA,
        "alerts": ALERTS_SCHEMA,
        "users": USERS_SCHEMA,
        "statistics": STATISTICS_SCHEMA,
        "system_logs": SYSTEM_LOGS_SCHEMA,
        "rules": RULES_SCHEMA,
    }

    for collection_name, schema in schemas.items():
        try:
            # Drop collection if requested
            if drop_existing and collection_name in db.list_collection_names():
                db[collection_name].drop()
                logger.info(f"Dropped collection: {collection_name}")

            # Create collection with validator if it doesn't exist
            if collection_name not in db.list_collection_names():
                db.create_collection(collection_name, **schema)
                logger.info(f"Created collection: {collection_name}")
            else:
                # Update validator for existing collection
                db.command(
                    {"collMod": collection_name, "validator": schema["validator"]}
                )
                logger.info(f"Updated validator for collection: {collection_name}")

            results[collection_name] = True

        except Exception as e:
            logger.error(f"Error initializing collection {collection_name}: {e}")
            results[collection_name] = False

    # Create indexes
    index_results = create_indexes(db)

    return results


def create_indexes(db) -> Dict[str, List[str]]:
    """
    Create indexes for all collections

    Args:
        db: PyMongo database instance

    Returns:
        Dictionary with collection names and created index names
    """
    results = {}

    schemas = {
        "packets": PACKETS_SCHEMA,
        "threats": THREATS_SCHEMA,
        "detections": DETECTIONS_SCHEMA,
        "flows": FLOWS_SCHEMA,
        "alerts": ALERTS_SCHEMA,
        "users": USERS_SCHEMA,
        "statistics": STATISTICS_SCHEMA,
        "system_logs": SYSTEM_LOGS_SCHEMA,
        "rules": RULES_SCHEMA,
    }

    for collection_name, schema in schemas.items():
        try:
            collection = db[collection_name]
            created_indexes = []

            for index_spec in schema.get("indexes", []):
                # Extract index parameters
                key = index_spec.pop("key")
                name = index_spec.pop("name")

                # Create index
                collection.create_index(key, name=name, **index_spec)
                created_indexes.append(name)
                logger.debug(f"Created index {name} on {collection_name}")

            results[collection_name] = created_indexes
            logger.info(f"Created {len(created_indexes)} indexes for {collection_name}")

        except Exception as e:
            logger.error(f"Error creating indexes for {collection_name}: {e}")
            results[collection_name] = []

    return results


def get_collection_stats(db) -> Dict[str, Any]:
    """
    Get statistics for all collections

    Args:
        db: PyMongo database instance

    Returns:
        Dictionary with collection statistics
    """
    stats = {}

    collections = [
        "packets",
        "threats",
        "detections",
        "flows",
        "alerts",
        "users",
        "statistics",
        "system_logs",
        "rules",
    ]

    for collection_name in collections:
        try:
            collection = db[collection_name]
            stats[collection_name] = {
                "count": collection.count_documents({}),
                "indexes": len(collection.index_information()),
                "size_bytes": db.command("collStats", collection_name).get("size", 0),
            }
        except Exception as e:
            logger.error(f"Error getting stats for {collection_name}: {e}")
            stats[collection_name] = {"error": str(e)}

    return stats
