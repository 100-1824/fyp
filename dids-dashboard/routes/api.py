from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__, url_prefix='/api')


def init_api_routes(app, packet_service, threat_service, ai_service=None):
    """Initialize API routes with dependencies including AI service"""
    
    @api_bp.route('/current_user')
    @login_required
    def current_user_info():
        return jsonify({
            'name': current_user.full_name if hasattr(current_user, 'full_name') else current_user.username,
            'username': current_user.username,
            'role': current_user.role
        })
    
    @api_bp.route('/traffic')
    @login_required
    def traffic():
        """Get recent traffic data with AI detections"""
        return jsonify(packet_service.get_traffic_data(limit=100))
    
    @api_bp.route('/stats')
    @login_required
    def stats():
        """Get network statistics including AI detections"""
        stats_data = packet_service.get_stats()
        traffic_data = packet_service.get_traffic_data(limit=100)
        
        # Calculate packets per second
        now = datetime.now()
        pps = 0
        try:
            pps = sum(
                1 for p in traffic_data
                if (now - datetime.strptime(p['timestamp'], "%H:%M:%S.%f")) < timedelta(seconds=1)
            )
        except Exception as e:
            app.logger.error(f"Error calculating PPS: {e}")
        
        stats_data['pps'] = pps
        stats_data['flow_count'] = packet_service.get_flow_count()
        return jsonify(stats_data)
    
    @api_bp.route('/threats')
    @login_required
    def threats():
        """Get recent threat detections (signature-based)"""
        return jsonify(threat_service.get_recent_threats(limit=20))
    
    @api_bp.route('/threat-stats')
    @login_required
    def threat_stats():
        """Get threat statistics"""
        return jsonify(threat_service.get_threat_statistics())
    
    @api_bp.route('/ai-detections')
    @login_required
    def ai_detections():
        """Get recent AI-based threat detections"""
        if ai_service and ai_service.is_ready():
            return jsonify(ai_service.get_recent_detections(limit=20))
        return jsonify([])
    
    @api_bp.route('/ai-stats')
    @login_required
    def ai_stats():
        """Get AI detection statistics"""
        if ai_service and ai_service.is_ready():
            return jsonify(ai_service.get_detection_statistics())
        return jsonify({
            'total_detections': 0,
            'by_attack_type': {},
            'by_severity': {},
            'by_action': {},
            'average_confidence': 0.0,
            'high_confidence_count': 0
        })
    
    @api_bp.route('/ai-model-info')
    @login_required
    def ai_model_info():
        """Get AI model information"""
        if ai_service:
            return jsonify(ai_service.get_model_info())
        return jsonify({'model_loaded': False, 'error': 'AI service not available'})
    
    @api_bp.route('/combined-threats')
    @login_required
    def combined_threats():
        """Get combined threats from both signature and AI detection"""
        combined = []
        
        # Get signature-based threats
        sig_threats = threat_service.get_recent_threats(limit=20)
        for threat in sig_threats:
            threat['detection_method'] = 'signature'
            combined.append(threat)
        
        # Get AI-based threats
        if ai_service and ai_service.is_ready():
            ai_threats = ai_service.get_recent_detections(limit=20)
            for threat in ai_threats:
                threat['detection_method'] = 'ai'
                combined.append(threat)
        
        # Sort by timestamp (newest first)
        combined.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify(combined[:30])  # Return top 30
    
    @api_bp.route('/capture/status')
    @login_required
    def capture_status():
        """Get packet capture status"""
        return jsonify({
            'active': packet_service.get_capture_status(),
            'demo_mode': packet_service.is_demo_mode(),
            'flow_count': packet_service.get_flow_count()
        })
    
    @api_bp.route('/capture/toggle', methods=['POST'])
    @login_required
    def toggle_capture():
        """Toggle packet capture on/off"""
        new_status = packet_service.toggle_capture()
        return jsonify({'success': True, 'active': new_status})
    
    @api_bp.route('/network-health')
    @login_required
    def network_health():
        """Get network health metrics"""
        stats = packet_service.get_stats()
        threat_stats = threat_service.get_threat_statistics()
        
        # Include AI detection stats if available
        ai_detections = 0
        if ai_service and ai_service.is_ready():
            ai_stats = ai_service.get_detection_statistics()
            ai_detections = ai_stats.get('total_detections', 0)
        
        # Calculate health score (simple algorithm)
        total_packets = stats.get('total_packets', 0)
        threats_blocked = threat_stats.get('blocked_count', 0) + ai_detections
        
        if total_packets > 0:
            threat_ratio = threats_blocked / total_packets
            health_score = max(0, 100 - (threat_ratio * 1000))
        else:
            health_score = 100
        
        return jsonify({
            'health_score': round(health_score, 2),
            'status': 'healthy' if health_score > 80 else 'warning' if health_score > 50 else 'critical',
            'total_packets': total_packets,
            'threats_detected': threat_stats.get('total_threats', 0) + ai_detections,
            'threats_blocked': threats_blocked,
            'ai_detections': ai_detections
        })
    
    @api_bp.route('/signatures')
    @login_required
    def signatures():
        """Get all threat signatures"""
        return jsonify(threat_service.get_all_signatures())
    
    @api_bp.route('/ai-threshold', methods=['POST'])
    @login_required
    def set_ai_threshold():
        """Set AI detection confidence threshold"""
        if not ai_service or not ai_service.is_ready():
            return jsonify({'success': False, 'error': 'AI service not available'}), 400
        
        try:
            data = request.get_json()
            threshold = float(data.get('threshold', 0.75))
            
            if ai_service.set_confidence_threshold(threshold):
                return jsonify({'success': True, 'threshold': threshold})
            else:
                return jsonify({'success': False, 'error': 'Invalid threshold value'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    @api_bp.route('/detection-overview')
    @login_required
    def detection_overview():
        """Get overview of all detection methods"""
        sig_stats = threat_service.get_threat_statistics()
        
        overview = {
            'signature_based': {
                'total': sig_stats.get('total_threats', 0),
                'blocked': sig_stats.get('blocked_count', 0),
                'by_severity': sig_stats.get('by_severity', {})
            },
            'ai_based': {
                'enabled': ai_service is not None and ai_service.is_ready(),
                'total': 0,
                'high_confidence': 0,
                'by_attack_type': {}
            }
        }
        
        if ai_service and ai_service.is_ready():
            ai_stats = ai_service.get_detection_statistics()
            overview['ai_based'] = {
                'enabled': True,
                'total': ai_stats.get('total_detections', 0),
                'high_confidence': ai_stats.get('high_confidence_count', 0),
                'by_attack_type': ai_stats.get('by_attack_type', {}),
                'average_confidence': ai_stats.get('average_confidence', 0)
            }
        
        return jsonify(overview)
    
    return api_bp