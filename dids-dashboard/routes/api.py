from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__, url_prefix='/api')


def init_api_routes(app, packet_service, threat_service):
    """Initialize API routes with dependencies"""
    
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
        """Get recent traffic data"""
        return jsonify(packet_service.get_traffic_data(limit=100))
    
    @api_bp.route('/stats')
    @login_required
    def stats():
        """Get network statistics"""
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
        return jsonify(stats_data)
    
    @api_bp.route('/threats')
    @login_required
    def threats():
        """Get recent threat detections"""
        return jsonify(threat_service.get_recent_threats(limit=20))
    
    @api_bp.route('/threat-stats')
    @login_required
    def threat_stats():
        """Get threat statistics"""
        return jsonify(threat_service.get_threat_statistics())
    
    @api_bp.route('/capture/status')
    @login_required
    def capture_status():
        """Get packet capture status"""
        return jsonify({'active': packet_service.get_capture_status()})
    
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
        
        # Calculate health score (simple algorithm)
        total_packets = stats.get('total_packets', 0)
        threats_blocked = threat_stats.get('blocked_count', 0)
        
        if total_packets > 0:
            threat_ratio = threats_blocked / total_packets
            health_score = max(0, 100 - (threat_ratio * 1000))
        else:
            health_score = 100
        
        return jsonify({
            'health_score': round(health_score, 2),
            'status': 'healthy' if health_score > 80 else 'warning' if health_score > 50 else 'critical',
            'total_packets': total_packets,
            'threats_detected': threat_stats.get('total_threats', 0),
            'threats_blocked': threats_blocked
        })
    
    @api_bp.route('/signatures')
    @login_required
    def signatures():
        """Get all threat signatures"""
        return jsonify(threat_service.get_all_signatures())
    
    return api_bp