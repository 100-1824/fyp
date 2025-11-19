from scapy.all import sniff, IP, TCP, UDP, DNS
from threading import Event, Thread
from datetime import datetime
from collections import defaultdict
import netifaces
import logging
import random
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class PacketCaptureService:
    """Service for capturing and analyzing network packets"""
    
    def __init__(self, config, threat_service=None):
        self.config = config
        self.threat_service = threat_service
        
        # Use get() method for Flask config object with defaults
        self.max_traffic_size = config.get('TRAFFIC_DATA_MAX_SIZE', 1000)
        self.stats_history_size = config.get('STATS_HISTORY_SIZE', 100)
        self.threat_buffer_size = config.get('THREAT_DETECTION_BUFFER', 20)
        self.default_interface = config.get('DEFAULT_INTERFACE', 'eth0')
        
        self.traffic_data = []
        self.stats = {
            'total_packets': 0,
            'protocol_dist': defaultdict(int),
            'top_talkers': defaultdict(int),
            'threats_blocked': 0
        }
        self.capture_event = Event()
        self.capture_active = True
        self.demo_mode = False
        self.demo_thread = None
    
    def get_active_interface(self) -> str:
        """
        Detect the active network interface.
        
        Returns:
            Interface name (e.g., 'eth0', 'wlan0')
        """
        try:
            # Try to get default gateway interface
            gw = netifaces.gateways()
            if 'default' in gw and netifaces.AF_INET in gw['default']:
                return gw['default'][netifaces.AF_INET][1]
        except Exception as e:
            logger.warning(f"Failed to detect active interface: {e}")
        
        # Try to find any active interface
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith(('eth', 'wlan', 'en', 'wl')):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        logger.info(f"Using interface: {iface}")
                        return iface
        except Exception as e:
            logger.warning(f"Failed to find active interface: {e}")
        
        return self.default_interface
    
    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Analyze a captured packet for threats and statistics.
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            Dictionary containing packet information or None
        """
        if IP not in pkt:
            return None
        
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt.sprintf("%IP.proto%")
        size = len(pkt)
        
        # Update statistics
        self.stats['total_packets'] += 1
        self.stats['protocol_dist'][proto] += 1
        self.stats['top_talkers'][src] += size
        
        # Check for threats if threat service is available
        threat_detected = False
        if self.threat_service:
            threat_detected = self._check_threats(pkt, src, dst)
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'source': src,
            'destination': dst,
            'protocol': proto,
            'size': size,
            'threat': threat_detected
        }
    
    def _check_threats(self, pkt, src: str, dst: str) -> bool:
        """
        Check packet against threat signatures.
        
        Args:
            pkt: Scapy packet object
            src: Source IP address
            dst: Destination IP address
            
        Returns:
            True if threat detected, False otherwise
        """
        threat_detected = False
        
        # Skip if whitelisted
        if self.threat_service.is_whitelisted(src) or self.threat_service.is_whitelisted(dst):
            return False
        
        # Check TCP packets
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            
            # Check for suspicious ports (malware C2, backdoors)
            suspicious_ports = [4444, 5555, 6666, 7777, 31337]
            if dst_port in suspicious_ports:
                self.threat_service.log_threat(
                    'ET MALWARE Reverse Shell',
                    src, dst,
                    {'port': dst_port, 'protocol': 'TCP'}
                )
                self.stats['threats_blocked'] += 1
                threat_detected = True
            
            # Check payload for attack patterns
            if pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(signature, src, dst, {'protocol': 'TCP'})
                    self.stats['threats_blocked'] += 1
                    threat_detected = True
            
            # Port scan detection
            if not self.threat_service.is_whitelisted(dst, dst_port):
                if self.threat_service.detect_port_scan(src, dst_port):
                    self.threat_service.log_threat(
                        'ET SCAN Aggressive Port Scan',
                        src, dst,
                        {'scanned_port': dst_port}
                    )
                    self.stats['threats_blocked'] += 1
                    threat_detected = True
        
        # Check UDP packets
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            
            # DNS anomaly detection
            if dst_port == 53 or DNS in pkt:
                if self.threat_service.detect_dns_anomaly(src):
                    self.threat_service.log_threat(
                        'ET DNS Excessive Queries',
                        src, dst,
                        {'queries': 'excessive'}
                    )
                    self.stats['threats_blocked'] += 1
                    threat_detected = True
            
            # Check payload for attack patterns
            if pkt[UDP].payload:
                payload = bytes(pkt[UDP].payload)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(signature, src, dst, {'protocol': 'UDP'})
                    self.stats['threats_blocked'] += 1
                    threat_detected = True
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777]
            if dst_port in suspicious_ports:
                self.threat_service.log_threat(
                    'ET MALWARE Reverse Shell',
                    src, dst,
                    {'port': dst_port, 'protocol': 'UDP'}
                )
                self.stats['threats_blocked'] += 1
                threat_detected = True
        
        return threat_detected
    
    def store_packet(self, record: Optional[Dict[str, Any]]) -> None:
        """
        Store packet record in traffic data buffer.
        
        Args:
            record: Packet information dictionary
        """
        if record:
            self.traffic_data.append(record)
            if len(self.traffic_data) > self.max_traffic_size:
                self.traffic_data.pop(0)
    
    def generate_demo_packet(self) -> Dict[str, Any]:
        """Generate a simulated packet for demo mode"""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH']
        sources = ['192.168.1.100', '192.168.1.101', '192.168.1.102', 
                   '10.0.0.5', '172.16.0.10', '8.8.8.8', '1.1.1.1']
        destinations = ['192.168.1.1', '8.8.8.8', '1.1.1.1', 
                        '172.217.16.142', '151.101.1.140', '13.107.42.14']
        
        protocol = random.choice(protocols)
        src = random.choice(sources)
        dst = random.choice(destinations)
        size = random.randint(64, 1500)
        
        # Occasionally generate a threat
        threat = random.random() < 0.05  # 5% chance of threat
        
        if threat and self.threat_service:
            threat_types = [
                'ET SCAN Aggressive Port Scan',
                'ET WEB SQL Injection Attempt',
                'ET DNS Excessive Queries'
            ]
            signature = random.choice(threat_types)
            self.threat_service.log_threat(signature, src, dst, {'protocol': protocol})
            self.stats['threats_blocked'] += 1
        
        # Update statistics
        self.stats['total_packets'] += 1
        self.stats['protocol_dist'][protocol] += 1
        self.stats['top_talkers'][src] += size
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'source': src,
            'destination': dst,
            'protocol': protocol,
            'size': size,
            'threat': threat
        }
    
    def run_demo_mode(self) -> None:
        """Run demo mode with simulated packets"""
        logger.info("Running in DEMO MODE - generating simulated traffic")
        self.demo_mode = True
        
        while not self.capture_event.is_set() and self.demo_mode:
            # Generate 1-5 packets per iteration
            num_packets = random.randint(1, 5)
            for _ in range(num_packets):
                packet = self.generate_demo_packet()
                self.store_packet(packet)
            
            # Sleep for a bit to simulate realistic traffic
            time.sleep(random.uniform(0.1, 0.5))
    
    def capture_packets(self) -> None:
        """Start packet capture on the active interface"""
        interface = self.get_active_interface()
        logger.info(f"Attempting to start packet capture on {interface}")
        
        try:
            # Try to start real packet capture
            logger.info("Starting real packet capture with Scapy...")
            sniff(
                iface=interface,
                prn=lambda p: self.store_packet(self.analyze_packet(p)),
                store=False,
                stop_filter=lambda p: self.capture_event.is_set(),
                timeout=5  # Test for 5 seconds first
            )
            logger.info("Real packet capture started successfully")
            
        except PermissionError as e:
            logger.error(f"Permission denied for packet capture: {e}")
            logger.info("Switching to DEMO MODE - please run with elevated privileges for real capture")
            self.run_demo_mode()
            
        except OSError as e:
            logger.error(f"OS error during packet capture: {e}")
            logger.info("Switching to DEMO MODE - network interface may not be accessible")
            self.run_demo_mode()
            
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            logger.info("Switching to DEMO MODE - unable to capture real packets")
            self.run_demo_mode()
    
    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.capture_event.set()
        self.capture_active = False
        self.demo_mode = False
        logger.info("Packet capture stopped")
    
    def toggle_capture(self) -> bool:
        """
        Toggle packet capture on/off.
        
        Returns:
            New capture state (True/False)
        """
        self.capture_active = not self.capture_active
        
        if not self.capture_active:
            self.capture_event.set()
            self.demo_mode = False
        else:
            self.capture_event.clear()
            # Start a new capture thread
            if self.demo_mode or True:  # Always start demo mode for now
                self.demo_thread = Thread(target=self.run_demo_mode, daemon=True)
                self.demo_thread.start()
        
        return self.capture_active
    
    def get_traffic_data(self, limit: int = 100) -> list:
        """
        Get recent traffic data.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of traffic records
        """
        return self.traffic_data[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current statistics.
        
        Returns:
            Dictionary containing statistics
        """
        return {
            'total_packets': self.stats['total_packets'],
            'threats_blocked': self.stats['threats_blocked'],
            'protocols': dict(self.stats['protocol_dist']),
            'top_talkers': dict(sorted(
                self.stats['top_talkers'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
        }
    
    def get_capture_status(self) -> bool:
        """Get current capture status"""
        return self.capture_active
    
    def is_demo_mode(self) -> bool:
        """Check if running in demo mode"""
        return self.demo_mode