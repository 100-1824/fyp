"""
RL-based Adaptive Threat Detection Service
Integrates trained RL agent for intelligent threat response
"""

import json
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import tensorflow as tf
from tensorflow import keras

logger = logging.getLogger(__name__)


class RLDetectionService:
    """Service for RL-based adaptive threat detection and response"""

    def __init__(self, config, model_path: str = None):
        """
        Initialize RL Detection Service

        Args:
            config: Application configuration
            model_path: Path to trained RL model
        """
        self.config = config
        self.model_path = Path(model_path or "rl-module/trained_models")

        # RL Agent model
        self.rl_model = None
        self.scaler = None
        self.feature_names = None

        # Action mapping
        self.action_map = {0: "allow", 1: "alert", 2: "block"}

        # Detection tracking
        self.detections = []
        self.actions_taken = {"allow": 0, "alert": 0, "block": 0}

        # Performance metrics
        self.decisions_made = 0
        self.threats_blocked = 0
        self.alerts_raised = 0

        # Load RL model
        self.load_model()

    def load_model(self) -> bool:
        """
        Load trained RL model

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Loading RL model from {self.model_path}")

            # Try to load Double DQN model first
            model_file = self.model_path / "double_dqn_final.keras"
            if not model_file.exists():
                # Fallback to regular DQN
                model_file = self.model_path / "dqn_final.keras"

            if not model_file.exists():
                logger.warning(
                    f"RL model not found at {model_file}. RL detection will not be available."
                )
                return False

            # Load RL model
            self.rl_model = keras.models.load_model(str(model_file))
            logger.info(f"✓ Loaded RL model: {model_file.name}")

            # Load scaler (from same directory as model)
            scaler_file = self.model_path / "scaler.pkl"
            if scaler_file.exists():
                with open(scaler_file, "rb") as f:
                    self.scaler = pickle.load(f)
                logger.info("✓ Loaded feature scaler")

            # Load feature names (from same directory as model)
            features_file = self.model_path / "feature_names.json"
            if features_file.exists():
                with open(features_file, "r") as f:
                    self.feature_names = json.load(f)
                logger.info(f"✓ Loaded {len(self.feature_names)} feature names")

            logger.info("RL Detection Service initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to load RL model: {e}")
            return False

    def extract_features(self, packet_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract features from packet data for RL agent.
        Feature names MUST match exactly with feature_names.json for model prediction.

        Args:
            packet_data: Dictionary containing packet information

        Returns:
            Feature vector as numpy array
        """
        try:
            # Get packet characteristics
            packet_size = float(packet_data.get("size", 64))

            # Extract TCP flags from packet data
            syn_flag = float(packet_data.get("syn", 0))
            ack_flag = float(packet_data.get("ack", 0))
            psh_flag = float(packet_data.get("psh", 0))
            rst_flag = float(packet_data.get("rst", 0))
            fin_flag = float(packet_data.get("fin", 0))
            urg_flag = float(packet_data.get("urg", 0))
            ece_flag = float(packet_data.get("ece", 0))
            cwr_flag = float(packet_data.get("cwr", 0))

            # Feature names must match exactly what the model expects
            # These are the 42 features from feature_names.json
            features = {
                "Flow Duration": 1.0,
                "Fwd Packet Length Max": packet_size,
                "Fwd Packet Length Min": packet_size,
                "Fwd Packet Length Mean": packet_size,
                "Fwd Packet Length Std": 0.0,
                "Bwd Packet Length Max": 0.0,
                "Bwd Packet Length Min": 0.0,
                "Bwd Packet Length Mean": 0.0,
                "Bwd Packet Length Std": 0.0,
                "Flow Bytes/s": packet_size,
                "Flow Packets/s": 1.0,
                "Flow IAT Mean": 0.0,
                "Flow IAT Std": 0.0,
                "Flow IAT Max": 0.0,
                "Flow IAT Min": 0.0,
                "Fwd IAT Mean": 0.0,
                "Fwd IAT Std": 0.0,
                "Fwd IAT Max": 0.0,
                "Fwd IAT Min": 0.0,
                "Bwd IAT Mean": 0.0,
                "Bwd IAT Std": 0.0,
                "Bwd IAT Max": 0.0,
                "Bwd IAT Min": 0.0,
                "FIN Flag Count": fin_flag,
                "SYN Flag Count": syn_flag,
                "RST Flag Count": rst_flag,
                "PSH Flag Count": psh_flag,
                "ACK Flag Count": ack_flag,
                "URG Flag Count": urg_flag,
                "ECE Flag Count": ece_flag,
                "CWR Flag Count": cwr_flag,
                "Fwd PSH Flags": psh_flag,
                "Bwd PSH Flags": 0.0,
                "Fwd URG Flags": urg_flag,
                "Bwd URG Flags": 0.0,
                "Fwd Header Length": 20.0,
                "Bwd Header Length": 0.0,
                "Packet Length Mean": packet_size,
                "Packet Length Std": 0.0,
                "Packet Length Variance": 0.0,
                "Down/Up Ratio": 0.0,
                "Average Packet Size": packet_size,
            }

            # Create feature vector matching training format
            if self.feature_names:
                feature_vector = []
                for feature_name in self.feature_names:
                    feature_vector.append(features.get(feature_name, 0.0))
                X = np.array(feature_vector).reshape(1, -1)
            else:
                # Use the 42 features in order
                feature_vector = list(features.values())
                X = np.array(feature_vector).reshape(1, -1)

            # Scale features if scaler available
            if self.scaler:
                X = self.scaler.transform(X)

            return X

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None

    def _encode_protocol(self, protocol: str) -> float:
        """Encode protocol string to numeric value"""
        protocol_map = {
            "TCP": 6.0,
            "UDP": 17.0,
            "ICMP": 1.0,
            "HTTP": 6.0,
            "HTTPS": 6.0,
            "DNS": 17.0,
            "SSH": 6.0,
            "FTP": 6.0,
        }
        return protocol_map.get(protocol.upper(), 0.0)

    def decide_action(
        self, packet_data: Dict[str, Any], ai_detection: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Use RL agent to decide action for network traffic

        Args:
            packet_data: Packet information
            ai_detection: Optional AI detection result for context

        Returns:
            Dictionary with action decision and metadata
        """
        if self.rl_model is None:
            # Fallback to basic policy if RL not available
            return self._fallback_policy(packet_data, ai_detection)

        try:
            # Extract features
            features = self.extract_features(packet_data)
            if features is None:
                return self._fallback_policy(packet_data, ai_detection)

            # Get Q-values from RL agent
            q_values = self.rl_model.predict(features, verbose=0)[0]

            # Select action with highest Q-value
            action_id = np.argmax(q_values)
            action = self.action_map[action_id]

            # Calculate confidence (softmax of Q-values)
            exp_q = np.exp(q_values - np.max(q_values))
            confidence = exp_q[action_id] / np.sum(exp_q)

            # Update metrics
            self.decisions_made += 1
            self.actions_taken[action] += 1

            if action == "block":
                self.threats_blocked += 1
            elif action == "alert":
                self.alerts_raised += 1

            # Create decision record
            decision = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "confidence": float(confidence * 100),
                "q_values": {
                    "allow": float(q_values[0]),
                    "alert": float(q_values[1]),
                    "block": float(q_values[2]),
                },
                "source": packet_data.get("source"),
                "destination": packet_data.get("destination"),
                "protocol": packet_data.get("protocol"),
                "reason": self._get_action_reason(action, q_values, ai_detection),
                "rl_based": True,
            }

            # Store detection if action is alert or block
            if action in ["alert", "block"]:
                self.detections.append(decision)
                # Keep only recent detections
                if len(self.detections) > 100:
                    self.detections.pop(0)

            return decision

        except Exception as e:
            logger.error(f"Error in RL decision: {e}")
            return self._fallback_policy(packet_data, ai_detection)

    def _fallback_policy(
        self, packet_data: Dict[str, Any], ai_detection: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fallback policy when RL agent is not available

        Args:
            packet_data: Packet information
            ai_detection: AI detection result

        Returns:
            Action decision
        """
        # Simple rule-based fallback
        if ai_detection:
            confidence = ai_detection.get("confidence", 0)
            attack_type = ai_detection.get("attack_type", "")

            if confidence >= 90:
                action = "block"
            elif confidence >= 70:
                action = "alert"
            else:
                action = "allow"

            return {
                "action": action,
                "confidence": confidence,
                "reason": f"AI detected {attack_type}",
                "rl_based": False,
            }

        # Default: allow
        return {
            "action": "allow",
            "confidence": 100.0,
            "reason": "No threat detected",
            "rl_based": False,
        }

    def _get_action_reason(
        self,
        action: str,
        q_values: np.ndarray,
        ai_detection: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate human-readable reason for action"""
        if ai_detection:
            attack_type = ai_detection.get("attack_type", "Unknown")
            ai_confidence = ai_detection.get("confidence", 0)

        if action == "block":
            if ai_detection:
                return f"RL agent decided to block based on {attack_type} detection (AI confidence: {ai_confidence}%)"
            return f"RL agent detected high threat level (Q-value: {q_values[2]:.2f})"

        elif action == "alert":
            if ai_detection:
                return f"RL agent raised alert for suspicious {attack_type} activity"
            return f"RL agent detected suspicious activity (Q-value: {q_values[1]:.2f})"

        else:  # allow
            return f"RL agent assessed traffic as benign (Q-value: {q_values[0]:.2f})"

    def get_statistics(self) -> Dict[str, Any]:
        """Get RL detection statistics"""
        return {
            "total_decisions": self.decisions_made,
            "threats_blocked": self.threats_blocked,
            "alerts_raised": self.alerts_raised,
            "actions_distribution": self.actions_taken.copy(),
            "recent_detections": len(self.detections),
            "rl_model_loaded": self.rl_model is not None,
        }

    def get_recent_decisions(self, limit: int = 20) -> list:
        """Get recent RL decisions"""
        return self.detections[-limit:]

    def is_ready(self) -> bool:
        """Check if RL service is ready"""
        return self.rl_model is not None

    def clear_old_detections(self, max_age_hours: int = 24) -> int:
        """Clear old detections"""
        original_count = len(self.detections)
        # For now, just keep last 100
        if len(self.detections) > 100:
            self.detections = self.detections[-100:]
        return original_count - len(self.detections)
