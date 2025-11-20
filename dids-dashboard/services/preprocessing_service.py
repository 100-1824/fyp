"""
Preprocessing Service
High-level service for packet preprocessing and feature extraction
Integrates with database and provides clean API for detection modules
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .packet_preprocessor import (EnhancedFlowData, EnhancedFlowTracker,
                                  PacketPreprocessor)

logger = logging.getLogger(__name__)


class PreprocessingService:
    """
    High-level preprocessing service
    Coordinates packet preprocessing, flow tracking, and feature extraction
    """

    def __init__(self, db=None, flow_timeout: int = 120, max_flows: int = 10000):
        """
        Initialize preprocessing service

        Args:
            db: MongoDB database instance (optional)
            flow_timeout: Flow timeout in seconds
            max_flows: Maximum concurrent flows to track
        """
        self.preprocessor = PacketPreprocessor()
        self.flow_tracker = EnhancedFlowTracker(
            flow_timeout=flow_timeout, max_flows=max_flows
        )
        self.db = db

        # Statistics
        self.stats = {
            "packets_processed": 0,
            "flows_created": 0,
            "features_extracted": 0,
            "errors": 0,
        }

        logger.info("PreprocessingService initialized")

    def process_packet(
        self, packet, store_db: bool = True
    ) -> Tuple[Optional[Dict], Optional[np.ndarray]]:
        """
        Process a single packet through the complete pipeline

        Args:
            packet: Scapy packet object
            store_db: Whether to store packet in database

        Returns:
            Tuple of (packet_info dict, feature_vector or None)
        """
        try:
            # Preprocess packet
            packet_info, features = self.preprocessor.preprocess_packet(
                packet, self.flow_tracker
            )

            if packet_info:
                self.stats["packets_processed"] += 1

                if features is not None:
                    self.stats["features_extracted"] += 1

                # Store in database if requested
                if store_db and self.db is not None:
                    self._store_packet(packet_info)

            return packet_info, features

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self.stats["errors"] += 1
            return None, None

    def process_packet_dict(self, packet_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Process packet data that's already in dictionary format
        Used when receiving packet data from API/microservices

        Args:
            packet_data: Dictionary with packet information

        Returns:
            Feature vector (77 features) or None
        """
        try:
            # Update flow tracker
            flow = self.flow_tracker.update_flow(packet_data)

            if not flow:
                return None

            # Extract features
            features = self.preprocessor.extract_flow_features(flow)

            # Normalize
            normalized = self.preprocessor.normalize_features(features, method="minmax")

            self.stats["features_extracted"] += 1

            return normalized

        except Exception as e:
            logger.error(f"Error processing packet dict: {e}")
            self.stats["errors"] += 1
            return None

    def extract_features_from_flow(self, flow_id: str) -> Optional[np.ndarray]:
        """
        Extract features from an existing flow

        Args:
            flow_id: Flow identifier

        Returns:
            Feature vector or None
        """
        # Find flow in tracker
        for key, flow in self.flow_tracker.flows.items():
            if flow.flow_id == flow_id:
                features = self.preprocessor.extract_flow_features(flow)
                return self.preprocessor.normalize_features(features, method="minmax")

        return None

    def get_flow_info(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete flow information

        Args:
            flow_id: Flow identifier

        Returns:
            Dictionary with flow information
        """
        for key, flow in self.flow_tracker.flows.items():
            if flow.flow_id == flow_id:
                return {
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "start_time": datetime.fromtimestamp(flow.start_time).isoformat(),
                    "last_seen": datetime.fromtimestamp(flow.last_seen).isoformat(),
                    "duration": flow.last_seen - flow.start_time,
                    "fwd_packets": len(flow.fwd_packets),
                    "bwd_packets": len(flow.bwd_packets),
                    "total_packets": len(flow.fwd_packets) + len(flow.bwd_packets),
                    "features": flow.compute_all_features(),
                }

        return None

    def get_active_flows(self) -> List[Dict[str, Any]]:
        """
        Get all active flows with basic information

        Returns:
            List of flow information dictionaries
        """
        flows = []

        for flow in self.flow_tracker.get_all_flows():
            flows.append(
                {
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "duration": flow.last_seen - flow.start_time,
                    "packet_count": len(flow.fwd_packets) + len(flow.bwd_packets),
                }
            )

        return flows

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get preprocessing statistics

        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            "active_flows": self.flow_tracker.get_flow_count(),
            "max_flows": self.flow_tracker.max_flows,
            "flow_timeout": self.flow_tracker.flow_timeout,
        }

    def cleanup_old_flows(self):
        """Manually trigger flow cleanup"""
        self.flow_tracker.cleanup_flows()

    def reset_statistics(self):
        """Reset statistics counters"""
        self.stats = {
            "packets_processed": 0,
            "flows_created": 0,
            "features_extracted": 0,
            "errors": 0,
        }

    def _store_packet(self, packet_info: Dict[str, Any]):
        """
        Store packet in database

        Args:
            packet_info: Packet information dictionary
        """
        try:
            if self.db is None:
                return

            # Prepare document
            doc = {
                "timestamp": datetime.fromtimestamp(packet_info["timestamp"]),
                "source": packet_info["source"],
                "destination": packet_info["destination"],
                "protocol": packet_info.get("protocol_name", "UNKNOWN"),
                "src_port": packet_info.get("src_port", 0),
                "dst_port": packet_info.get("dst_port", 0),
                "size": packet_info["size"],
                "tcp_flags": packet_info.get("flags", {}),
                "flow_id": packet_info.get("flow_id", ""),
                "payload_size": packet_info.get("payload_size", 0),
                "is_threat": packet_info.get("is_threat", False),
                "preprocessed": True,
            }

            # Add features if available
            if "features" in packet_info:
                doc["features"] = packet_info["features"]

            # Insert into packets collection
            self.db.packets.insert_one(doc)

        except Exception as e:
            logger.error(f"Error storing packet in database: {e}")

    def _store_flow(self, flow: EnhancedFlowData):
        """
        Store flow in database

        Args:
            flow: EnhancedFlowData object
        """
        try:
            if self.db is None:
                return

            features = flow.compute_all_features()

            doc = {
                "flow_id": flow.flow_id,
                "source": flow.src_ip,
                "destination": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "start_time": datetime.fromtimestamp(flow.start_time),
                "last_seen": datetime.fromtimestamp(flow.last_seen),
                "duration": flow.last_seen - flow.start_time,
                "packet_count": len(flow.fwd_packets) + len(flow.bwd_packets),
                "total_bytes": int(
                    features.get("Total Length of Fwd Packets", 0)
                    + features.get("Total Length of Bwd Packets", 0)
                ),
                "forward_packets": len(flow.fwd_packets),
                "backward_packets": len(flow.bwd_packets),
                "forward_bytes": int(features.get("Total Length of Fwd Packets", 0)),
                "backward_bytes": int(features.get("Total Length of Bwd Packets", 0)),
                "features": features,
                "status": "active",
            }

            # Upsert flow (update if exists, insert if not)
            self.db.flows.update_one(
                {"flow_id": flow.flow_id}, {"$set": doc}, upsert=True
            )

        except Exception as e:
            logger.error(f"Error storing flow in database: {e}")

    def batch_store_flows(self):
        """Store all active flows in database"""
        if self.db is None:
            return

        stored_count = 0
        for flow in self.flow_tracker.get_all_flows():
            self._store_flow(flow)
            stored_count += 1

        logger.info(f"Stored {stored_count} flows in database")


def create_preprocessing_service(
    db=None, config: Dict[str, Any] = None
) -> PreprocessingService:
    """
    Factory function to create preprocessing service

    Args:
        db: MongoDB database instance
        config: Configuration dictionary

    Returns:
        PreprocessingService instance
    """
    if config is None:
        config = {}

    flow_timeout = config.get("flow_timeout", 120)
    max_flows = config.get("max_flows", 10000)

    return PreprocessingService(db=db, flow_timeout=flow_timeout, max_flows=max_flows)
