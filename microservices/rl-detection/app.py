"""
RL Detection Microservice
Handles reinforcement learning-based decision making
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import sys
from pathlib import Path
import numpy as np
import pickle

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

from shared.config import get_config
from shared.models import RLDecision

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())
CORS(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format=app.config['LOG_FORMAT']
)
logger = logging.getLogger(__name__)

# RL Model components
rl_model = None
scaler = None
model_loaded = False

# Action mapping
ACTION_MAP = {
    0: 'allow',
    1: 'alert',
    2: 'block'
}

statistics = {
    'total_decisions': 0,
    'actions': {'allow': 0, 'alert': 0, 'block': 0},
    'errors': 0
}


def load_rl_model():
    """Load trained RL model"""
    global rl_model, scaler, model_loaded

    try:
        import tensorflow as tf

        model_path = Path('/app/model')  # Will be mounted as volume

        # Try Double DQN first
        model_file = model_path / 'double_dqn_final.keras'
        if not model_file.exists():
            model_file = model_path / 'dqn_final.keras'

        if model_file.exists():
            rl_model = tf.keras.models.load_model(str(model_file))
            logger.info(f"✓ Loaded RL model: {model_file.name}")
        else:
            logger.warning("RL model not found")
            return False

        # Load scaler
        scaler_file = model_path / 'scaler.pkl'
        if scaler_file.exists():
            with open(scaler_file, 'rb') as f:
                scaler = pickle.load(f)
            logger.info("✓ Loaded scaler")

        model_loaded = True
        return True

    except Exception as e:
        logger.error(f"Failed to load RL model: {e}")
        return False


def extract_features(packet_data: dict) -> np.ndarray:
    """Extract features from packet data"""
    try:
        features = {
            'protocol': encode_protocol(packet_data.get('protocol', 'TCP')),
            'packet_length': float(packet_data.get('size', 0)),
            'src_port': float(packet_data.get('src_port', 0)),
            'dst_port': float(packet_data.get('dst_port', 0)),
            'flag_syn': float(packet_data.get('syn', 0)),
            'flag_ack': float(packet_data.get('ack', 0)),
            'flag_psh': float(packet_data.get('psh', 0)),
            'flag_rst': float(packet_data.get('rst', 0)),
            'flag_fin': float(packet_data.get('fin', 0)),
        }

        # Pad to 77 features
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
        'TCP': 6.0,
        'UDP': 17.0,
        'ICMP': 1.0,
        'HTTP': 6.0,
        'HTTPS': 6.0,
        'DNS': 17.0
    }
    return protocol_map.get(protocol.upper(), 0.0)


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'service': 'rl-detection',
        'status': 'healthy',
        'model_loaded': model_loaded
    }), 200


@app.route('/decide', methods=['POST'])
def make_decision():
    """Make RL-based decision on network traffic"""
    if not model_loaded:
        # Fallback policy
        return jsonify({
            'action': 'allow',
            'confidence': 50.0,
            'q_values': {},
            'reason': 'RL model not loaded, using fallback policy',
            'rl_based': False
        }), 200

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    statistics['total_decisions'] += 1

    try:
        # Extract features
        features = extract_features(data.get('packet', {}))

        if features is None:
            return jsonify({'error': 'Feature extraction failed'}), 500

        # Get Q-values from RL model
        q_values = rl_model.predict(features, verbose=0)[0]

        # Select action with highest Q-value
        action_id = np.argmax(q_values)
        action = ACTION_MAP[action_id]

        # Calculate confidence (softmax of Q-values)
        exp_q = np.exp(q_values - np.max(q_values))
        confidence = exp_q[action_id] / np.sum(exp_q)

        # Create Q-values dict
        q_values_dict = {
            'allow': float(q_values[0]),
            'alert': float(q_values[1]),
            'block': float(q_values[2])
        }

        # Get AI detection context if provided
        ai_detection = data.get('ai_detection', {})
        reason = generate_reason(action, q_values, ai_detection)

        decision = RLDecision(
            action=action,
            confidence=float(confidence * 100),
            q_values=q_values_dict,
            reason=reason,
            rl_based=True
        )

        # Update statistics
        statistics['actions'][action] += 1

        return jsonify(decision.to_dict()), 200

    except Exception as e:
        logger.error(f"Error making decision: {e}")
        statistics['errors'] += 1
        return jsonify({'error': str(e)}), 500


def generate_reason(action: str, q_values: np.ndarray, ai_detection: dict) -> str:
    """Generate human-readable reason for action"""
    if ai_detection:
        attack_type = ai_detection.get('attack_type', 'Unknown')
        ai_confidence = ai_detection.get('confidence', 0)

        if action == 'block':
            return f"RL agent decided to block based on {attack_type} detection (AI confidence: {ai_confidence:.1f}%)"
        elif action == 'alert':
            return f"RL agent raised alert for suspicious {attack_type} activity"
        else:
            return f"RL agent assessed {attack_type} as low risk"

    if action == 'block':
        return f"RL agent detected high threat level (Q-value: {q_values[2]:.2f})"
    elif action == 'alert':
        return f"RL agent detected suspicious activity (Q-value: {q_values[1]:.2f})"
    else:
        return f"RL agent assessed traffic as benign (Q-value: {q_values[0]:.2f})"


@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get RL decision statistics"""
    return jsonify({
        'total_decisions': statistics['total_decisions'],
        'actions': statistics['actions'],
        'errors': statistics['errors']
    }), 200


@app.before_first_request
def initialize():
    """Initialize service on first request"""
    logger.info("Initializing RL Detection Service...")
    load_rl_model()


if __name__ == '__main__':
    port = app.config['RL_DETECTION_PORT']
    logger.info(f"Starting RL Detection Service on port {port}")

    # Try to load model at startup
    load_rl_model()

    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG']
    )
