"""
AI Detection Microservice
Handles ML-based threat detection
"""

import json
import logging
import pickle
import sys
from pathlib import Path

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

from shared.config import get_config
from shared.models import AIDetectionResult

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())
CORS(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config["LOG_LEVEL"]), format=app.config["LOG_FORMAT"]
)
logger = logging.getLogger(__name__)

# Model components
model = None
scaler = None
label_encoder = None
feature_names = None
model_loaded = False

statistics = {
    "total_predictions": 0,
    "detections": 0,
    "by_attack_type": {},
    "errors": 0,
}


def load_model():
    """Load trained ML model"""
    global model, scaler, label_encoder, feature_names, model_loaded

    try:
        import tensorflow as tf

        model_path = Path("/app/model")  # Will be mounted as volume in container

        # Load model
        model_file = model_path / "dids_final.keras"
        if model_file.exists():
            model = tf.keras.models.load_model(str(model_file))
            logger.info("✓ Loaded ML model")
        else:
            logger.warning("Model file not found")
            return False

        # Load scaler
        scaler_file = model_path / "scaler.pkl"
        if scaler_file.exists():
            with open(scaler_file, "rb") as f:
                scaler = pickle.load(f)
            logger.info("✓ Loaded scaler")

        # Load label encoder
        encoder_file = model_path / "label_encoder.pkl"
        if encoder_file.exists():
            with open(encoder_file, "rb") as f:
                label_encoder = pickle.load(f)
            logger.info(
                f"✓ Loaded label encoder ({len(label_encoder.classes_)} classes)"
            )

        # Load feature names
        features_file = model_path / "feature_names.json"
        if features_file.exists():
            with open(features_file, "r") as f:
                feature_names = json.load(f)
            logger.info(f"✓ Loaded {len(feature_names)} feature names")

        model_loaded = True
        return True

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


def extract_features(packet_data: dict) -> np.ndarray:
    """Extract features from packet data"""
    try:
        # Basic features
        features = {
            "protocol": encode_protocol(packet_data.get("protocol", "TCP")),
            "packet_length": float(packet_data.get("size", 0)),
            "src_port": float(packet_data.get("src_port", 0)),
            "dst_port": float(packet_data.get("dst_port", 0)),
            "flag_syn": float(packet_data.get("syn", 0)),
            "flag_ack": float(packet_data.get("ack", 0)),
            "flag_psh": float(packet_data.get("psh", 0)),
            "flag_rst": float(packet_data.get("rst", 0)),
            "flag_fin": float(packet_data.get("fin", 0)),
        }

        # Create feature vector
        if feature_names:
            feature_vector = []
            for feature_name in feature_names:
                feature_vector.append(features.get(feature_name, 0.0))
            X = np.array(feature_vector).reshape(1, -1)
        else:
            # Pad to expected size (77 features)
            feature_vector = list(features.values())
            while len(feature_vector) < 77:
                feature_vector.append(0.0)
            X = np.array(feature_vector[:77]).reshape(1, -1)

        # Scale features
        if scaler:
            X = scaler.transform(X)

        return X

    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return None


def encode_protocol(protocol: str) -> float:
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


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return (
        jsonify(
            {
                "service": "ai-detection",
                "status": "healthy",
                "model_loaded": model_loaded,
            }
        ),
        200,
    )


@app.route("/detect", methods=["POST"])
def detect_threat():
    """Detect threat using ML model"""
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    statistics["total_predictions"] += 1

    try:
        # Extract features
        features = extract_features(data)

        if features is None:
            return jsonify({"error": "Feature extraction failed"}), 500

        # Make prediction
        predictions = model.predict(features, verbose=0)

        # Get predicted class and confidence
        predicted_class_idx = np.argmax(predictions[0])
        confidence = float(predictions[0][predicted_class_idx])

        # Decode label
        if label_encoder:
            attack_type = label_encoder.classes_[predicted_class_idx]
        else:
            attack_type = f"Attack_{predicted_class_idx}"

        # Skip benign traffic
        if attack_type.lower() == "benign" or confidence < 0.7:
            return (
                jsonify(
                    {
                        "is_threat": False,
                        "attack_type": "Benign",
                        "confidence": confidence * 100,
                    }
                ),
                200,
            )

        # Determine severity
        severity_map = {
            "ddos": "critical",
            "bot": "high",
            "portscan": "high",
            "web attack": "high",
            "brute force": "medium",
            "infiltration": "critical",
        }
        severity = severity_map.get(attack_type.lower(), "medium")

        # Create probabilities dict
        probabilities = {}
        for i, class_name in enumerate(label_encoder.classes_):
            probabilities[class_name] = float(predictions[0][i])

        result = AIDetectionResult(
            attack_type=attack_type,
            confidence=confidence * 100,
            severity=severity,
            probabilities=probabilities,
            model="CyberHawk IDS",
        )

        # Update statistics
        statistics["detections"] += 1
        if attack_type not in statistics["by_attack_type"]:
            statistics["by_attack_type"][attack_type] = 0
        statistics["by_attack_type"][attack_type] += 1

        return jsonify({"is_threat": True, **result.to_dict()}), 200

    except Exception as e:
        logger.error(f"Error detecting threat: {e}")
        statistics["errors"] += 1
        return jsonify({"error": str(e)}), 500


@app.route("/model/info", methods=["GET"])
def model_info():
    """Get model information"""
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 503

    return (
        jsonify(
            {
                "model_loaded": model_loaded,
                "features_count": len(feature_names) if feature_names else 0,
                "classes": list(label_encoder.classes_) if label_encoder else [],
                "classes_count": len(label_encoder.classes_) if label_encoder else 0,
            }
        ),
        200,
    )


@app.route("/statistics", methods=["GET"])
def get_statistics():
    """Get detection statistics"""
    return (
        jsonify(
            {
                "total_predictions": statistics["total_predictions"],
                "detections": statistics["detections"],
                "by_attack_type": statistics["by_attack_type"],
                "errors": statistics["errors"],
            }
        ),
        200,
    )


@app.before_first_request
def initialize():
    """Initialize service on first request"""
    logger.info("Initializing AI Detection Service...")
    load_model()


if __name__ == "__main__":
    port = app.config["AI_DETECTION_PORT"]
    logger.info(f"Starting AI Detection Service on port {port}")

    # Try to load model at startup
    load_model()

    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
