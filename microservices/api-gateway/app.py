"""
API Gateway Microservice
Main orchestrator that routes requests to different microservices
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import sys
from pathlib import Path
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import time

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

from shared.config import get_config

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

# Service URLs
SERVICES = {
    'traffic_capture': app.config['TRAFFIC_CAPTURE_URL'],
    'signature_detection': app.config['SIGNATURE_DETECTION_URL'],
    'ai_detection': app.config['AI_DETECTION_URL'],
    'rl_detection': app.config['RL_DETECTION_URL']
}

# Request timeout
TIMEOUT = app.config['REQUEST_TIMEOUT']

# Statistics
statistics = {
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0,
    'service_calls': {service: 0 for service in SERVICES},
    'errors': {}
}


def handle_service_error(func):
    """Decorator to handle service communication errors"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.Timeout:
            logger.error(f"{func.__name__}: Service timeout")
            return None, 'timeout'
        except requests.exceptions.ConnectionError:
            logger.error(f"{func.__name__}: Service unavailable")
            return None, 'unavailable'
        except Exception as e:
            logger.error(f"{func.__name__}: {str(e)}")
            return None, 'error'
    return wrapper


@handle_service_error
def call_service(service_name: str, endpoint: str, method: str = 'GET', data: dict = None):
    """Call a microservice endpoint"""
    url = f"{SERVICES[service_name]}{endpoint}"
    statistics['service_calls'][service_name] += 1

    if method == 'GET':
        response = requests.get(url, timeout=TIMEOUT)
    elif method == 'POST':
        response = requests.post(url, json=data, timeout=TIMEOUT)
    else:
        raise ValueError(f"Unsupported method: {method}")

    response.raise_for_status()
    return response.json(), None


@app.route('/health', methods=['GET'])
def health():
    """API Gateway health check"""
    # Check all microservices
    services_health = {}

    for service_name, service_url in SERVICES.items():
        try:
            response = requests.get(f"{service_url}/health", timeout=5)
            services_health[service_name] = {
                'status': 'healthy' if response.status_code == 200 else 'degraded',
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            services_health[service_name] = {
                'status': 'unhealthy',
                'error': str(e)
            }

    overall_status = 'healthy' if all(
        s['status'] == 'healthy' for s in services_health.values()
    ) else 'degraded'

    return jsonify({
        'service': 'api-gateway',
        'status': overall_status,
        'services': services_health
    }), 200


@app.route('/analyze/packet', methods=['POST'])
def analyze_packet():
    """Analyze a single packet through all detection layers"""
    statistics['total_requests'] += 1

    data = request.get_json()
    if not data:
        statistics['failed_requests'] += 1
        return jsonify({'error': 'No data provided'}), 400

    try:
        results = {
            'packet': data,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'detections': []
        }

        # Parallel detection calls
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}

            # 1. Signature detection
            if app.config['ENABLE_SIGNATURE_DETECTION']:
                futures['signature'] = executor.submit(
                    call_service, 'signature_detection', '/detect', 'POST', data
                )

            # 2. AI detection
            if app.config['ENABLE_AI_DETECTION']:
                futures['ai'] = executor.submit(
                    call_service, 'ai_detection', '/detect', 'POST', data
                )

            # Wait for results
            signature_result = None
            ai_result = None

            for future_name, future in futures.items():
                try:
                    result, error = future.result(timeout=TIMEOUT)
                    if result:
                        if future_name == 'signature':
                            signature_result = result
                            if result.get('threats'):
                                results['detections'].extend(result['threats'])
                        elif future_name == 'ai':
                            ai_result = result
                            if result.get('is_threat'):
                                results['detections'].append({
                                    'detector': 'ai',
                                    **result
                                })
                except Exception as e:
                    logger.error(f"Error in {future_name} detection: {e}")

        # 3. RL decision (sequential, needs AI context)
        if app.config['ENABLE_RL_DETECTION']:
            rl_data = {
                'packet': data,
                'ai_detection': ai_result if ai_result else {}
            }
            rl_result, error = call_service('rl_detection', '/decide', 'POST', rl_data)

            if rl_result:
                results['rl_decision'] = rl_result
            else:
                # Fallback decision
                results['rl_decision'] = {
                    'action': 'allow',
                    'confidence': 50.0,
                    'reason': 'RL service unavailable'
                }

        # Determine final action
        final_action = determine_final_action(
            results.get('detections', []),
            results.get('rl_decision', {})
        )

        results['final_action'] = final_action
        statistics['successful_requests'] += 1

        return jsonify(results), 200

    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")
        statistics['failed_requests'] += 1
        return jsonify({'error': str(e)}), 500


def determine_final_action(detections: list, rl_decision: dict) -> dict:
    """Determine final action based on all detection layers"""

    # Priority 1: If RL says block, block
    if rl_decision.get('action') == 'block':
        return {
            'action': 'block',
            'reason': 'RL agent decision',
            'confidence': rl_decision.get('confidence', 0)
        }

    # Priority 2: If critical signature detected, block
    for detection in detections:
        if detection.get('severity') == 'critical' or detection.get('action') == 'block':
            return {
                'action': 'block',
                'reason': f"Critical threat: {detection.get('threat_type', 'Unknown')}",
                'confidence': detection.get('confidence', 100)
            }

    # Priority 3: If RL or any detector says alert
    if rl_decision.get('action') == 'alert' or any(d.get('action') == 'alert' for d in detections):
        return {
            'action': 'alert',
            'reason': 'Suspicious activity detected',
            'confidence': rl_decision.get('confidence', 80)
        }

    # Default: Allow
    return {
        'action': 'allow',
        'reason': 'No threats detected',
        'confidence': rl_decision.get('confidence', 100)
    }


@app.route('/traffic/recent', methods=['GET'])
def get_recent_traffic():
    """Get recent traffic from capture service"""
    limit = request.args.get('limit', 100, type=int)
    result, error = call_service('traffic_capture', f'/packets/recent?limit={limit}')

    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Traffic capture service unavailable'}), 503


@app.route('/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    result, error = call_service('traffic_capture', '/capture/start', 'POST')

    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Failed to start capture'}), 503


@app.route('/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    result, error = call_service('traffic_capture', '/capture/stop', 'POST')

    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Failed to stop capture'}), 503


@app.route('/capture/status', methods=['GET'])
def capture_status():
    """Get capture status"""
    result, error = call_service('traffic_capture', '/capture/status')

    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Traffic capture service unavailable'}), 503


@app.route('/detections/recent', methods=['GET'])
def get_recent_detections():
    """Get recent detections from signature service"""
    limit = request.args.get('limit', 20, type=int)
    result, error = call_service('signature_detection', f'/detections/recent?limit={limit}')

    if result:
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Signature detection service unavailable'}), 503


@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get aggregated statistics from all services"""
    stats = {
        'gateway': {
            'total_requests': statistics['total_requests'],
            'successful_requests': statistics['successful_requests'],
            'failed_requests': statistics['failed_requests'],
            'service_calls': statistics['service_calls']
        }
    }

    # Get stats from each service
    for service_name in SERVICES:
        result, error = call_service(service_name, '/statistics')
        if result:
            stats[service_name] = result

    return jsonify(stats), 200


@app.route('/services', methods=['GET'])
def list_services():
    """List all microservices and their status"""
    services_info = {}

    for service_name, service_url in SERVICES.items():
        result, error = call_service(service_name, '/health')

        if result:
            services_info[service_name] = {
                'url': service_url,
                'status': 'online',
                'info': result
            }
        else:
            services_info[service_name] = {
                'url': service_url,
                'status': 'offline',
                'error': error
            }

    return jsonify(services_info), 200


if __name__ == '__main__':
    port = app.config['API_GATEWAY_PORT']
    logger.info(f"Starting API Gateway on port {port}")
    logger.info(f"Services: {list(SERVICES.keys())}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG']
    )
