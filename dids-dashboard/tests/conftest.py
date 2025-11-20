"""
Pytest configuration and fixtures for DIDS tests
Provides shared test fixtures and setup/teardown
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock
import tempfile
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app
from config import TestingConfig


@pytest.fixture
def app():
    """Create and configure a test Flask application"""
    app = create_app('testing')
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    # Override services with mocks for testing
    app.packet_service = Mock()
    app.threat_service = Mock()
    app.ai_service = Mock()
    app.user_service = Mock()
    app.rule_manager = Mock()
    app.rule_engine = Mock()

    yield app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test CLI runner"""
    return app.test_cli_runner()


@pytest.fixture
def mock_packet_service():
    """Mock packet capture service"""
    service = Mock()
    service.stats = {
        'total_packets': 1000,
        'threats_blocked': 50,
        'pps': 100,
        'protocols': {'TCP': 500, 'UDP': 300, 'HTTP': 200},
        'top_talkers': {'192.168.1.100': 150, '192.168.1.101': 100}
    }
    service.packets = []
    service.is_capturing = True
    return service


@pytest.fixture
def mock_threat_service():
    """Mock threat detection service"""
    service = Mock()
    service.detections = []
    service.stats = {
        'threats_blocked': 50,
        'alerts_generated': 75
    }
    service.signature_detections = []
    service.is_whitelisted = Mock(return_value=False)
    service.check_port_scan = Mock(return_value=False)
    service.check_dns_flood = Mock(return_value=False)
    return service


@pytest.fixture
def mock_ai_service():
    """Mock AI detection service"""
    service = Mock()
    service.stats = {
        'total_detections': 25,
        'high_confidence_count': 20,
        'average_confidence': 85,
        'by_attack_type': {'DDoS': 10, 'PortScan': 8, 'Bot': 7},
        'by_severity': {'high': 15, 'medium': 7, 'low': 3}
    }
    service.detections = []
    service.is_ready = Mock(return_value=True)
    service.get_model_info = Mock(return_value={
        'model_loaded': True,
        'feature_count': 77,
        'attack_types': ['DDoS', 'PortScan', 'Bot', 'Web Attack', 'Brute Force'],
        'accuracy': 0.989,
        'precision': 0.985,
        'recall': 0.991,
        'confidence_threshold': 0.75
    })
    return service


@pytest.fixture
def mock_rule_manager():
    """Mock Suricata/Snort rule manager"""
    manager = Mock()
    manager.get_active_rules = Mock(return_value=[
        {
            'sid': '1000001',
            'msg': 'Test Rule 1',
            'action': 'alert',
            'protocol': 'tcp',
            'severity': 'high',
            'enabled': True,
            'hit_count': 10
        },
        {
            'sid': '1000002',
            'msg': 'Test Rule 2',
            'action': 'alert',
            'protocol': 'udp',
            'severity': 'medium',
            'enabled': True,
            'hit_count': 5
        }
    ])
    manager.get_rule_by_sid = Mock(return_value={
        'sid': '1000001',
        'msg': 'Test Rule 1',
        'action': 'alert',
        'protocol': 'tcp',
        'severity': 'high',
        'enabled': True
    })
    manager.get_statistics = Mock(return_value={
        'total_loaded': 50,
        'active_rules': 45,
        'disabled_rules': 5,
        'total_hits': 150
    })
    return manager


@pytest.fixture
def sample_packet():
    """Sample packet data for testing"""
    return {
        'timestamp': '2025-01-20 10:30:00',
        'source': '192.168.1.100',
        'destination': '10.0.0.5',
        'protocol': 'TCP',
        'src_port': 54321,
        'dst_port': 80,
        'size': 512,
        'threat': False
    }


@pytest.fixture
def sample_threat():
    """Sample threat data for testing"""
    return {
        'timestamp': '2025-01-20 10:30:00',
        'source': '192.168.1.100',
        'destination': '10.0.0.5',
        'signature': 'ET MALWARE C2 Communication',
        'action': 'blocked',
        'detection_method': 'signature'
    }


@pytest.fixture
def sample_ai_detection():
    """Sample AI detection data for testing"""
    return {
        'timestamp': '2025-01-20 10:30:00',
        'source': '192.168.1.100',
        'destination': '10.0.0.5',
        'attack_type': 'DDoS',
        'confidence': 95,
        'severity': 'high',
        'action': 'blocked',
        'detection_method': 'ai'
    }


@pytest.fixture
def auth_headers(client):
    """Get authentication headers for API requests"""
    # Mock authentication for testing
    def _get_headers(username='testuser'):
        with client.session_transaction() as sess:
            sess['_user_id'] = username
        return {'Content-Type': 'application/json'}

    return _get_headers


@pytest.fixture(autouse=True)
def reset_mocks(mock_packet_service, mock_threat_service, mock_ai_service, mock_rule_manager):
    """Reset all mocks before each test"""
    yield
    mock_packet_service.reset_mock()
    mock_threat_service.reset_mock()
    mock_ai_service.reset_mock()
    mock_rule_manager.reset_mock()


@pytest.fixture
def temp_rule_file():
    """Create a temporary rule file for testing"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as f:
        f.write('alert tcp any any -> any 80 (msg:"Test Rule"; sid:9999999; rev:1;)\n')
        f.write('alert udp any any -> any 53 (msg:"Test DNS Rule"; sid:9999998; rev:1;)\n')
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)
