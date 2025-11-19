import numpy as np
import pandas as pd
import pickle
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

# Try to import joblib as a more robust alternative to pickle
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    logger.debug("joblib not available, using pickle only")


class AIDetectionService:
    """Service for AI-powered network intrusion detection using trained model"""
    
    def __init__(self, config, model_path: str = None):
        """
        Initialize AI Detection Service.
        
        Args:
            config: Application configuration
            model_path: Path to model directory (default: ./models)
        """
        self.config = config
        self.model_path = Path(model_path or 'model')
        
        # Model components
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.model_config = None
        self.metrics = None
        
        # Detection tracking
        self.detections = []
        self.detection_cache = {}  # Cache to prevent duplicate detections
        self.cache_ttl = 60  # Cache TTL in seconds
        
        # False positive filtering
        self.confidence_threshold = 0.75  # Minimum confidence for detection
        self.consecutive_threshold = 3  # Consecutive detections needed
        self.detection_tracker = defaultdict(lambda: {'count': 0, 'last_seen': None})
        
        # Attack type mapping
        self.attack_severity = {
            'DDoS': 'critical',
            'PortScan': 'high',
            'Bot': 'high',
            'Web Attack': 'high',
            'Brute Force': 'medium',
            'Infiltration': 'critical',
            'Benign': 'info'
        }
        
        # Load model and components
        self.load_model()

    def _safe_pickle_load(self, file_path: Path, description: str) -> Optional[Any]:
        """
        Safely load a pickle file with fallback mechanisms.

        Args:
            file_path: Path to pickle file
            description: Description for logging

        Returns:
            Loaded object or None if failed
        """
        if not file_path.exists():
            logger.debug(f"{description} file not found: {file_path}")
            return None

        # Try joblib first (more robust)
        if JOBLIB_AVAILABLE:
            try:
                obj = joblib.load(file_path)
                logger.info(f"✓ Loaded {description} using joblib")
                return obj
            except Exception as e:
                logger.debug(f"joblib load failed for {description}: {e}")

        # Try standard pickle with different protocols
        for encoding in [None, 'latin1', 'bytes']:
            try:
                with open(file_path, 'rb') as f:
                    if encoding:
                        obj = pickle.load(f, encoding=encoding)
                    else:
                        obj = pickle.load(f)
                logger.info(f"✓ Loaded {description} using pickle" +
                           (f" (encoding: {encoding})" if encoding else ""))
                return obj
            except Exception as e:
                logger.debug(f"pickle load failed for {description} with encoding {encoding}: {e}")
                continue

        logger.warning(f"Failed to load {description} from {file_path}")
        return None

    def load_model(self) -> bool:
        """
        Load trained model and preprocessing components.

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Loading AI detection model from {self.model_path}")

            # Load Keras model
            model_file = self.model_path / 'dids_final.keras'
            if not model_file.exists():
                model_file = self.model_path / 'dids.keras'

            if model_file.exists():
                try:
                    # Import TensorFlow only when needed
                    import tensorflow as tf
                    self.model = tf.keras.models.load_model(str(model_file))
                    logger.info(f"✓ Loaded model: {model_file.name}")
                except Exception as e:
                    logger.error(f"Failed to load Keras model: {e}")
                    return False
            else:
                logger.error(f"Model file not found in {self.model_path}")
                return False

            # Load scaler with safe loading
            scaler_file = self.model_path / 'scaler.pkl'
            self.scaler = self._safe_pickle_load(scaler_file, "scaler")
            if not self.scaler:
                logger.warning("Scaler not available - will use simple normalization")

            # Load label encoder with safe loading
            encoder_file = self.model_path / 'label_encoder.pkl'
            self.label_encoder = self._safe_pickle_load(encoder_file, "label encoder")

            # Create fallback label encoder if not available
            if not self.label_encoder:
                logger.warning("Label encoder not available - creating fallback")
                self._create_fallback_label_encoder()
            else:
                logger.info(f"✓ Label encoder has {len(self.label_encoder.classes_)} classes")

            # Load feature names
            feature_file = self.model_path / 'feature_names.json'
            if feature_file.exists():
                try:
                    with open(feature_file, 'r') as f:
                        self.feature_names = json.load(f)
                    logger.info(f"✓ Loaded {len(self.feature_names)} feature names")
                except Exception as e:
                    logger.warning(f"Failed to load feature names: {e}")
                    self._create_fallback_features()
            else:
                logger.warning("Feature names not found - creating fallback")
                self._create_fallback_features()

            # Load model configuration
            config_file = self.model_path / 'dids_config.json'
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        self.model_config = json.load(f)
                    logger.info("✓ Loaded model configuration")
                except Exception as e:
                    logger.debug(f"Failed to load config: {e}")

            # Load metrics
            metrics_file = self.model_path / 'dids_metrics.json'
            if metrics_file.exists():
                try:
                    with open(metrics_file, 'r') as f:
                        self.metrics = json.load(f)
                    logger.info("✓ Loaded model metrics")
                except Exception as e:
                    logger.debug(f"Failed to load metrics: {e}")

            logger.info("✓ AI Detection Service initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            import traceback
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return False

    def _create_fallback_label_encoder(self):
        """Create a fallback label encoder with common attack types"""
        try:
            from sklearn.preprocessing import LabelEncoder
            self.label_encoder = LabelEncoder()
            # Common attack types from CICIDS2017 dataset
            self.label_encoder.classes_ = np.array([
                'Benign', 'DDoS', 'PortScan', 'Bot', 'Infiltration',
                'Web Attack', 'Brute Force', 'DoS Hulk', 'DoS GoldenEye',
                'DoS slowloris', 'DoS Slowhttptest', 'FTP-Patator',
                'SSH-Patator', 'Heartbleed'
            ])
            logger.info(f"✓ Created fallback label encoder with {len(self.label_encoder.classes_)} classes")
        except Exception as e:
            logger.error(f"Failed to create fallback label encoder: {e}")

    def _create_fallback_features(self):
        """Create fallback feature list based on model input shape"""
        try:
            if self.model:
                # Get expected input shape from model
                input_shape = self.model.input_shape
                if input_shape and len(input_shape) > 1:
                    num_features = input_shape[1]
                    self.feature_names = [f'feature_{i}' for i in range(num_features)]
                    logger.info(f"✓ Created {num_features} fallback feature names")
                else:
                    logger.warning("Could not determine model input shape")
        except Exception as e:
            logger.error(f"Failed to create fallback features: {e}")
    
    def extract_flow_features(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """
        Extract network flow features from packet data.
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Dictionary of extracted features
        """
        try:
            # Extract basic features from packet
            features = {
                # Flow identifiers
                'src_ip': packet_data.get('source', '0.0.0.0'),
                'dst_ip': packet_data.get('destination', '0.0.0.0'),
                'protocol': self._encode_protocol(packet_data.get('protocol', 'TCP')),
                
                # Packet characteristics
                'packet_length': float(packet_data.get('size', 0)),
                'header_length': 20.0,  # Default IP header
                'payload_length': float(packet_data.get('size', 0)) - 20.0,
                
                # Port information (if available)
                'src_port': float(packet_data.get('src_port', 0)),
                'dst_port': float(packet_data.get('dst_port', 0)),
                
                # Flags (if available)
                'flag_syn': float(packet_data.get('syn', 0)),
                'flag_ack': float(packet_data.get('ack', 0)),
                'flag_psh': float(packet_data.get('psh', 0)),
                'flag_rst': float(packet_data.get('rst', 0)),
                'flag_fin': float(packet_data.get('fin', 0)),
                
                # Derived features
                'packets_per_second': 1.0,  # Will be calculated in flow aggregation
                'bytes_per_second': float(packet_data.get('size', 0)),
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def aggregate_flow_features(self, flow_key: str, window_size: int = 10) -> Optional[Dict[str, float]]:
        """
        Aggregate features from multiple packets in a flow.
        
        Args:
            flow_key: Unique identifier for flow (src-dst pair)
            window_size: Number of recent packets to consider
            
        Returns:
            Aggregated feature dictionary
        """
        try:
            # Get recent packets for this flow from traffic data
            # This would be implemented based on your packet storage
            
            # For now, return basic aggregated features
            aggregated = {
                'flow_duration': 1.0,
                'total_fwd_packets': 1.0,
                'total_bwd_packets': 0.0,
                'total_length_fwd_packets': 0.0,
                'total_length_bwd_packets': 0.0,
                'fwd_packet_length_max': 0.0,
                'fwd_packet_length_min': 0.0,
                'fwd_packet_length_mean': 0.0,
                'fwd_packet_length_std': 0.0,
                'bwd_packet_length_max': 0.0,
                'bwd_packet_length_min': 0.0,
                'bwd_packet_length_mean': 0.0,
                'bwd_packet_length_std': 0.0,
                'flow_bytes_per_second': 0.0,
                'flow_packets_per_second': 1.0,
                'flow_iat_mean': 0.0,
                'flow_iat_std': 0.0,
                'flow_iat_max': 0.0,
                'flow_iat_min': 0.0,
                'fwd_iat_total': 0.0,
                'fwd_iat_mean': 0.0,
                'fwd_iat_std': 0.0,
                'fwd_iat_max': 0.0,
                'fwd_iat_min': 0.0,
                'bwd_iat_total': 0.0,
                'bwd_iat_mean': 0.0,
                'bwd_iat_std': 0.0,
                'bwd_iat_max': 0.0,
                'bwd_iat_min': 0.0,
                'fwd_psh_flags': 0.0,
                'bwd_psh_flags': 0.0,
                'fwd_urg_flags': 0.0,
                'bwd_urg_flags': 0.0,
                'fwd_header_length': 20.0,
                'bwd_header_length': 0.0,
                'fwd_packets_per_second': 1.0,
                'bwd_packets_per_second': 0.0,
                'min_packet_length': 0.0,
                'max_packet_length': 1500.0,
                'packet_length_mean': 750.0,
                'packet_length_std': 0.0,
                'packet_length_variance': 0.0,
                'fin_flag_count': 0.0,
                'syn_flag_count': 0.0,
                'rst_flag_count': 0.0,
                'psh_flag_count': 0.0,
                'ack_flag_count': 0.0,
                'urg_flag_count': 0.0,
                'cwe_flag_count': 0.0,
                'ece_flag_count': 0.0,
                'down_up_ratio': 0.0,
                'average_packet_size': 750.0,
                'avg_fwd_segment_size': 0.0,
                'avg_bwd_segment_size': 0.0,
                'fwd_header_length_2': 20.0,
                'fwd_avg_bytes_bulk': 0.0,
                'fwd_avg_packets_bulk': 0.0,
                'fwd_avg_bulk_rate': 0.0,
                'bwd_avg_bytes_bulk': 0.0,
                'bwd_avg_packets_bulk': 0.0,
                'bwd_avg_bulk_rate': 0.0,
                'subflow_fwd_packets': 1.0,
                'subflow_fwd_bytes': 0.0,
                'subflow_bwd_packets': 0.0,
                'subflow_bwd_bytes': 0.0,
                'init_win_bytes_forward': 0.0,
                'init_win_bytes_backward': 0.0,
                'act_data_pkt_fwd': 0.0,
                'min_seg_size_forward': 0.0,
                'active_mean': 0.0,
                'active_std': 0.0,
                'active_max': 0.0,
                'active_min': 0.0,
                'idle_mean': 0.0,
                'idle_std': 0.0,
                'idle_max': 0.0,
                'idle_min': 0.0,
            }
            
            return aggregated
            
        except Exception as e:
            logger.error(f"Error aggregating flow features: {e}")
            return None
    
    def _encode_protocol(self, protocol: str) -> float:
        """Encode protocol string to numeric value"""
        protocol_map = {
            'TCP': 6.0,
            'UDP': 17.0,
            'ICMP': 1.0,
            'HTTP': 6.0,
            'HTTPS': 6.0,
            'DNS': 17.0,
            'SSH': 6.0,
            'FTP': 6.0
        }
        return protocol_map.get(protocol.upper(), 0.0)
    
    def preprocess_features(self, features: Dict[str, float]) -> Optional[np.ndarray]:
        """
        Preprocess features for model input.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Numpy array ready for model prediction
        """
        try:
            # Convert to DataFrame for easier manipulation
            if self.feature_names:
                # Ensure we have all required features
                feature_vector = []
                for feature_name in self.feature_names:
                    feature_vector.append(features.get(feature_name, 0.0))
                
                X = np.array(feature_vector).reshape(1, -1)
            else:
                # Use features as-is
                X = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features
            if self.scaler:
                X = self.scaler.transform(X)
            else:
                # Simple normalization if no scaler
                X = (X - np.mean(X)) / (np.std(X) + 1e-10)
            
            return X
            
        except Exception as e:
            logger.error(f"Error preprocessing features: {e}")
            return None
    
    def predict(self, features: Dict[str, float]) -> Optional[Tuple[str, float, np.ndarray]]:
        """
        Make prediction using the trained model.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Tuple of (attack_type, confidence, probabilities)
        """
        try:
            if self.model is None:
                logger.error("Model not loaded")
                return None
            
            # Preprocess features
            X = self.preprocess_features(features)
            if X is None:
                return None
            
            # Make prediction
            predictions = self.model.predict(X, verbose=0)
            
            # Get predicted class and confidence
            predicted_class_idx = np.argmax(predictions[0])
            confidence = float(predictions[0][predicted_class_idx])
            
            # Decode label
            if self.label_encoder:
                attack_type = self.label_encoder.classes_[predicted_class_idx]
            else:
                attack_type = f"Attack_{predicted_class_idx}"
            
            return attack_type, confidence, predictions[0]
            
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            return None
    
    def detect_threat(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect threats in network traffic using AI model.
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Detection result dictionary or None if no threat
        """
        try:
            # Extract features
            features = self.extract_flow_features(packet_data)
            if features is None:
                return None
            
            # Create flow key
            flow_key = f"{packet_data.get('source', '0.0.0.0')}-{packet_data.get('destination', '0.0.0.0')}"
            
            # Aggregate flow features
            aggregated_features = self.aggregate_flow_features(flow_key)
            if aggregated_features:
                features.update(aggregated_features)
            
            # Make prediction
            result = self.predict(features)
            if result is None:
                return None
            
            attack_type, confidence, probabilities = result
            
            # Filter false positives
            if not self._should_report_detection(attack_type, confidence, flow_key):
                return None
            
            # Skip benign traffic
            if attack_type.lower() == 'benign':
                return None
            
            # Create detection record
            detection = {
                'timestamp': datetime.now().isoformat(),
                'source': packet_data.get('source'),
                'destination': packet_data.get('destination'),
                'protocol': packet_data.get('protocol'),
                'attack_type': attack_type,
                'confidence': round(confidence * 100, 2),
                'severity': self.attack_severity.get(attack_type, 'medium'),
                'signature': f'AI Detection: {attack_type}',
                'action': self._determine_action(attack_type, confidence),
                'description': f'AI-based detection of {attack_type} with {confidence*100:.1f}% confidence',
                'model': 'CyberHawk IDS',
                'flow_key': flow_key
            }
            
            # Store detection
            self.detections.append(detection)
            
            # Keep only recent detections
            max_detections = getattr(self.config, 'AI_DETECTION_BUFFER', 50)
            if len(self.detections) > max_detections:
                self.detections = self.detections[-max_detections:]
            
            logger.warning(
                f"AI Threat Detected: {attack_type} ({confidence*100:.1f}% confidence) "
                f"from {packet_data.get('source')} to {packet_data.get('destination')}"
            )
            
            return detection
            
        except Exception as e:
            logger.error(f"Error detecting threat: {e}")
            return None
    
    def _should_report_detection(self, attack_type: str, confidence: float, flow_key: str) -> bool:
        """
        Determine if detection should be reported based on false positive filtering.
        
        Args:
            attack_type: Detected attack type
            confidence: Prediction confidence
            flow_key: Flow identifier
            
        Returns:
            True if detection should be reported
        """
        # Skip benign traffic
        if attack_type.lower() == 'benign':
            return False
        
        # Check confidence threshold
        if confidence < self.confidence_threshold:
            return False
        
        # Check detection cache to prevent duplicates
        cache_key = f"{flow_key}:{attack_type}"
        now = datetime.now()
        
        if cache_key in self.detection_cache:
            last_detection_time = self.detection_cache[cache_key]
            if (now - last_detection_time).total_seconds() < self.cache_ttl:
                return False
        
        # Update cache
        self.detection_cache[cache_key] = now
        
        # Implement consecutive detection threshold
        tracker = self.detection_tracker[cache_key]
        tracker['count'] += 1
        tracker['last_seen'] = now
        
        # Reset counter if too much time has passed
        if tracker['last_seen']:
            time_diff = (now - tracker['last_seen']).total_seconds()
            if time_diff > 30:  # Reset after 30 seconds
                tracker['count'] = 1
        
        # Require multiple consecutive detections for medium confidence
        if confidence < 0.85 and tracker['count'] < self.consecutive_threshold:
            return False
        
        # Clean up old trackers
        self._cleanup_detection_tracker()
        
        return True
    
    def _cleanup_detection_tracker(self):
        """Remove old entries from detection tracker"""
        now = datetime.now()
        keys_to_remove = []
        
        for key, data in self.detection_tracker.items():
            if data['last_seen']:
                time_diff = (now - data['last_seen']).total_seconds()
                if time_diff > 300:  # 5 minutes
                    keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.detection_tracker[key]
    
    def _determine_action(self, attack_type: str, confidence: float) -> str:
        """Determine action based on attack type and confidence"""
        severity = self.attack_severity.get(attack_type, 'medium')
        
        if confidence >= 0.95:
            if severity in ['critical', 'high']:
                return 'blocked'
            else:
                return 'alert'
        elif confidence >= 0.85:
            if severity == 'critical':
                return 'blocked'
            else:
                return 'alert'
        else:
            return 'logged'
    
    def get_recent_detections(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent AI detections"""
        return self.detections[-limit:]
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get AI detection statistics"""
        if not self.detections:
            return {
                'total_detections': 0,
                'by_attack_type': {},
                'by_severity': {},
                'by_action': {},
                'average_confidence': 0.0,
                'high_confidence_count': 0
            }
        
        # Count by attack type
        attack_counts = defaultdict(int)
        for detection in self.detections:
            attack_counts[detection['attack_type']] += 1
        
        # Count by severity
        severity_counts = defaultdict(int)
        for detection in self.detections:
            severity_counts[detection['severity']] += 1
        
        # Count by action
        action_counts = defaultdict(int)
        for detection in self.detections:
            action_counts[detection['action']] += 1
        
        # Calculate average confidence
        confidences = [d['confidence'] for d in self.detections]
        avg_confidence = sum(confidences) / len(confidences)
        high_confidence = sum(1 for c in confidences if c >= 90)
        
        return {
            'total_detections': len(self.detections),
            'by_attack_type': dict(attack_counts),
            'by_severity': dict(severity_counts),
            'by_action': dict(action_counts),
            'average_confidence': round(avg_confidence, 2),
            'high_confidence_count': high_confidence
        }
    
    def clear_old_detections(self, hours: int = 24) -> int:
        """Clear detections older than specified hours"""
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        original_count = len(self.detections)
        
        self.detections = [
            d for d in self.detections
            if datetime.fromisoformat(d['timestamp']).timestamp() > cutoff_time
        ]
        
        cleared = original_count - len(self.detections)
        if cleared > 0:
            logger.info(f"Cleared {cleared} old AI detections")
        
        return cleared
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model"""
        info = {
            'model_loaded': self.model is not None,
            'scaler_loaded': self.scaler is not None,
            'encoder_loaded': self.label_encoder is not None,
            'feature_count': len(self.feature_names) if self.feature_names else 0,
            'attack_types': list(self.label_encoder.classes_) if self.label_encoder else [],
            'confidence_threshold': self.confidence_threshold,
            'consecutive_threshold': self.consecutive_threshold
        }
        
        if self.metrics:
            info['accuracy'] = self.metrics.get('accuracy', 'N/A')
            info['precision'] = self.metrics.get('precision', 'N/A')
            info['recall'] = self.metrics.get('recall', 'N/A')
            info['f1_score'] = self.metrics.get('f1_score', 'N/A')
        
        if self.model_config:
            info.update(self.model_config)
        
        return info
    
    def set_confidence_threshold(self, threshold: float) -> bool:
        """Set minimum confidence threshold for detections"""
        if 0.0 <= threshold <= 1.0:
            self.confidence_threshold = threshold
            logger.info(f"Confidence threshold set to {threshold}")
            return True
        return False
    
    def is_ready(self) -> bool:
        """Check if AI detection service is ready"""
        # Only require model to be loaded, others can use fallbacks
        is_model_ready = self.model is not None
        has_encoder = self.label_encoder is not None
        has_features = self.feature_names is not None

        if is_model_ready and not has_encoder:
            logger.warning("Model ready but label encoder missing - using fallback")
        if is_model_ready and not has_features:
            logger.warning("Model ready but feature names missing - using fallback")

        return is_model_ready