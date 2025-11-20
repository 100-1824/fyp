from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, ICMP, get_if_list, conf
from threading import Event, Thread
from datetime import datetime
from collections import defaultdict
import netifaces
import logging
import random
import time
import platform
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class PacketCaptureService:
    """Service for capturing and analyzing network packets with AI detection"""
    
    def __init__(self, config, threat_service=None, ai_service=None):
        self.config = config
        self.threat_service = threat_service
        self.ai_service = ai_service
        
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
            'threats_blocked': 0,
            'ai_detections': 0
        }
        self.capture_event = Event()
        self.capture_active = True
        self.demo_mode = False
        self.demo_thread = None
        
        # Flow tracker for AI detection
        if self.ai_service and self.ai_service.is_ready():
            from services.flow_tracker import FlowTracker
            self.flow_tracker = FlowTracker(flow_timeout=120, max_flows=10000)
            logger.info("✓ Flow tracker initialized for AI detection")
        else:
            self.flow_tracker = None
    
    def get_active_interface(self) -> str:
        """
        Detect the active network interface cross-platform.
        Works on Linux, Windows, and macOS.

        Returns:
            Interface name (e.g., 'eth0' on Linux, GUID on Windows)
        """
        system = platform.system()
        logger.info(f"Detecting network interface on {system}")

        try:
            # Get all available interfaces from Scapy (cross-platform)
            scapy_interfaces = get_if_list()
            logger.info(f"Available interfaces: {scapy_interfaces}")

            # Try method 1: Use Scapy's default interface (usually the best choice)
            if hasattr(conf, 'iface') and conf.iface:
                logger.info(f"Using Scapy default interface: {conf.iface}")
                return conf.iface

            # Try method 2: Get default gateway interface via netifaces
            try:
                gw = netifaces.gateways()
                if 'default' in gw and netifaces.AF_INET in gw['default']:
                    interface = gw['default'][netifaces.AF_INET][1]
                    logger.info(f"Using default gateway interface: {interface}")
                    return interface
            except Exception as e:
                logger.debug(f"Could not get gateway interface: {e}")

            # Try method 3: Find any active interface with an IP address
            try:
                interfaces = netifaces.interfaces()

                # Platform-specific interface filtering
                if system == 'Windows':
                    # On Windows, accept GUID format interfaces
                    for iface in interfaces:
                        # Windows interfaces can be GUIDs or names
                        try:
                            addrs = netifaces.ifaddresses(iface)
                            if netifaces.AF_INET in addrs:
                                # Skip loopback
                                ip = addrs[netifaces.AF_INET][0].get('addr', '')
                                if not ip.startswith('127.'):
                                    logger.info(f"Using interface: {iface}")
                                    return iface
                        except Exception as e:
                            logger.debug(f"Error checking interface {iface}: {e}")
                            continue
                else:
                    # On Linux/macOS, prefer common interface naming patterns
                    for iface in interfaces:
                        if iface.startswith(('eth', 'wlan', 'en', 'wl', 'wlp', 'enp', 'ens')):
                            try:
                                addrs = netifaces.ifaddresses(iface)
                                if netifaces.AF_INET in addrs:
                                    logger.info(f"Using interface: {iface}")
                                    return iface
                            except Exception as e:
                                logger.debug(f"Error checking interface {iface}: {e}")
                                continue
            except Exception as e:
                logger.warning(f"Failed to enumerate interfaces: {e}")

            # Try method 4: Use first available Scapy interface (last resort)
            if scapy_interfaces and len(scapy_interfaces) > 0:
                # Filter out loopback if possible
                for iface in scapy_interfaces:
                    if not iface.lower().startswith(('lo', 'loopback')):
                        logger.info(f"Using first non-loopback Scapy interface: {iface}")
                        return iface

                # If all interfaces are loopback, use the first one
                logger.warning(f"Only loopback interfaces found, using: {scapy_interfaces[0]}")
                return scapy_interfaces[0]

        except Exception as e:
            logger.error(f"Failed to detect active interface: {e}")

        # Final fallback
        logger.warning(f"Could not detect interface, using default: {self.default_interface}")
        return self.default_interface
    
    def extract_packet_info(self, pkt) -> Optional[Dict[str, Any]]:
        """Extract comprehensive packet information including flags and ports"""
        if IP not in pkt:
            return None
        
        packet_info = {
            'source': pkt[IP].src,
            'destination': pkt[IP].dst,
            'size': len(pkt),
            'protocol': pkt.sprintf("%IP.proto%"),
            'src_port': 0,
            'dst_port': 0,
            'fin': 0,
            'syn': 0,
            'rst': 0,
            'psh': 0,
            'ack': 0,
            'urg': 0,
            'ece': 0,
            'cwr': 0
        }
        
        # Extract TCP information
        if TCP in pkt:
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = pkt[TCP].sport
            packet_info['dst_port'] = pkt[TCP].dport
            
            # Extract TCP flags
            flags = pkt[TCP].flags
            packet_info['fin'] = 1 if flags & 0x01 else 0
            packet_info['syn'] = 1 if flags & 0x02 else 0
            packet_info['rst'] = 1 if flags & 0x04 else 0
            packet_info['psh'] = 1 if flags & 0x08 else 0
            packet_info['ack'] = 1 if flags & 0x10 else 0
            packet_info['urg'] = 1 if flags & 0x20 else 0
            packet_info['ece'] = 1 if flags & 0x40 else 0
            packet_info['cwr'] = 1 if flags & 0x80 else 0
            
            # Identify common services
            if packet_info['dst_port'] == 80:
                packet_info['protocol'] = 'HTTP'
            elif packet_info['dst_port'] == 443:
                packet_info['protocol'] = 'HTTPS'
            elif packet_info['dst_port'] == 22:
                packet_info['protocol'] = 'SSH'
            elif packet_info['dst_port'] in [20, 21]:
                packet_info['protocol'] = 'FTP'
        
        # Extract UDP information
        elif UDP in pkt:
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = pkt[UDP].sport
            packet_info['dst_port'] = pkt[UDP].dport
            
            # Identify DNS
            if packet_info['dst_port'] == 53 or packet_info['src_port'] == 53:
                packet_info['protocol'] = 'DNS'
        
        # ICMP
        elif ICMP in pkt:
            packet_info['protocol'] = 'ICMP'
        
        return packet_info
    
    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Analyze a captured packet for threats using both signature and AI detection.
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            Dictionary containing packet information or None
        """
        if IP not in pkt:
            return None
        
        # Extract packet information
        packet_info = self.extract_packet_info(pkt)
        if not packet_info:
            return None
        
        src = packet_info['source']
        dst = packet_info['destination']
        proto = packet_info['protocol']
        size = packet_info['size']
        
        # Update statistics
        self.stats['total_packets'] += 1
        self.stats['protocol_dist'][proto] += 1
        self.stats['top_talkers'][src] += size
        
        # Initialize threat flags
        threat_detected = False
        ai_detection = None
        signature_detection = None
        
        # 1. Check signature-based threats if threat service is available
        if self.threat_service:
            signature_detection = self._check_signature_threats(pkt, packet_info, src, dst)
            if signature_detection:
                threat_detected = True
        
        # 2. Check AI-based threats if AI service is available and ready
        if self.ai_service and self.ai_service.is_ready() and self.flow_tracker:
            # Update flow tracker and get aggregated features
            flow_features = self.flow_tracker.update_flow(packet_info)
            
            if flow_features:
                # Run AI detection on flow features
                ai_detection = self.ai_service.detect_threat(packet_info)
                
                if ai_detection:
                    threat_detected = True
                    self.stats['ai_detections'] += 1
                    logger.info(f"🤖 AI Detection: {ai_detection['attack_type']} "
                               f"({ai_detection['confidence']}% confidence)")
        
        # Create packet record
        record = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'source': src,
            'destination': dst,
            'protocol': proto,
            'size': size,
            'threat': threat_detected,
            'ai_detection': ai_detection['attack_type'] if ai_detection else None,
            'ai_confidence': ai_detection['confidence'] if ai_detection else None,
            'signature_detection': signature_detection
        }
        
        return record
    
    def _check_signature_threats(self, pkt, packet_info: Dict[str, Any],
                                 src: str, dst: str) -> Optional[str]:
        """
        Check packet against signature-based threat detection.

        Args:
            pkt: Scapy packet object
            packet_info: Extracted packet information
            src: Source IP address
            dst: Destination IP address

        Returns:
            Threat signature name if detected, None otherwise
        """
        threat_signature = None

        # Skip if whitelisted
        if self.threat_service.is_whitelisted(src) or self.threat_service.is_whitelisted(dst):
            return None

        # First, check Suricata/Snort rules if available
        payload = None
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)

        rule_matches = self.threat_service.check_suricata_rules(packet_info, payload)
        if rule_matches:
            # Log the first matching rule as a threat
            for match in rule_matches:
                self.threat_service.log_threat(
                    match['rule_msg'],
                    src, dst,
                    {
                        'rule_sid': match['rule_sid'],
                        'action': match['action'],
                        'protocol': packet_info.get('protocol'),
                        'classtype': match.get('classtype', 'unknown')
                    }
                )
                self.stats['threats_blocked'] += 1

                # Return first high/critical severity match
                if match['severity'] in ['critical', 'high']:
                    if not threat_signature:
                        threat_signature = match['rule_msg']

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
                threat_signature = 'ET MALWARE Reverse Shell'
            
            # Check payload for attack patterns
            if pkt[TCP].payload and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(signature, src, dst, {'protocol': 'TCP'})
                    self.stats['threats_blocked'] += 1
                    if not threat_signature:
                        threat_signature = signature
            
            # Port scan detection
            if not self.threat_service.is_whitelisted(dst, dst_port):
                if self.threat_service.detect_port_scan(src, dst_port):
                    self.threat_service.log_threat(
                        'ET SCAN Aggressive Port Scan',
                        src, dst,
                        {'scanned_port': dst_port}
                    )
                    self.stats['threats_blocked'] += 1
                    threat_signature = 'ET SCAN Aggressive Port Scan'
        
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
                    threat_signature = 'ET DNS Excessive Queries'
            
            # Check payload for attack patterns
            if pkt[UDP].payload and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(signature, src, dst, {'protocol': 'UDP'})
                    self.stats['threats_blocked'] += 1
                    if not threat_signature:
                        threat_signature = signature
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777]
            if dst_port in suspicious_ports:
                self.threat_service.log_threat(
                    'ET MALWARE Reverse Shell',
                    src, dst,
                    {'port': dst_port, 'protocol': 'UDP'}
                )
                self.stats['threats_blocked'] += 1
                threat_signature = 'ET MALWARE Reverse Shell'
        
        return threat_signature
    
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
        """Generate a simulated packet for demo mode with realistic attack scenarios"""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH']
        sources = ['192.168.1.100', '192.168.1.101', '192.168.1.102', 
                   '10.0.0.5', '172.16.0.10', '8.8.8.8', '1.1.1.1']
        destinations = ['192.168.1.1', '8.8.8.8', '1.1.1.1', 
                        '172.217.16.142', '151.101.1.140', '13.107.42.14']
        
        protocol = random.choice(protocols)
        src = random.choice(sources)
        dst = random.choice(destinations)
        size = random.randint(64, 1500)
        
        # Occasionally generate threats for demonstration
        threat = random.random() < 0.08  # 8% chance of threat
        ai_detection_type = None
        ai_confidence = None
        
        if threat:
            # Mix of signature and AI detections
            if random.random() < 0.5 and self.threat_service:
                # Signature-based threat
                threat_types = [
                    'ET SCAN Aggressive Port Scan',
                    'ET WEB SQL Injection Attempt',
                    'ET DNS Excessive Queries'
                ]
                signature = random.choice(threat_types)
                self.threat_service.log_threat(signature, src, dst, {'protocol': protocol})
                self.stats['threats_blocked'] += 1
            
            else:
                # AI-based threat (for demo)
                attack_types = ['DDoS', 'PortScan', 'Bot', 'Web Attack', 'Brute Force']
                ai_detection_type = random.choice(attack_types)
                ai_confidence = random.uniform(75, 99)
                self.stats['ai_detections'] += 1
        
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
            'threat': threat,
            'ai_detection': ai_detection_type,
            'ai_confidence': ai_confidence,
            'signature_detection': None
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
        logger.info(f"Attempting to start packet capture on interface: {interface}")

        try:
            # Validate interface exists in Scapy's interface list
            available_interfaces = get_if_list()
            if interface not in available_interfaces:
                logger.warning(f"Interface '{interface}' not found in Scapy's interface list")
                logger.warning(f"Available interfaces: {available_interfaces}")
                raise OSError(f"Interface '{interface}' not found!")

            # Try to start real packet capture
            logger.info("Starting real packet capture with Scapy...")
            sniff(
                iface=interface,
                prn=lambda p: self.store_packet(self.analyze_packet(p)),
                store=False,
                stop_filter=lambda p: self.capture_event.is_set()
            )
            logger.info("✓ Real packet capture started successfully")

        except PermissionError as e:
            logger.error(f"Permission denied for packet capture: {e}")
            logger.info("Switching to DEMO MODE - please run with elevated privileges for real capture")
            logger.info("On Windows: Run as Administrator | On Linux/Mac: Use sudo")
            self.run_demo_mode()

        except OSError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                logger.error(f"Packet capture error: Interface '{interface}' not found!")
                logger.info(f"Available interfaces: {get_if_list()}")
            else:
                logger.error(f"OS error during packet capture: {e}")
            logger.info("Switching to DEMO MODE - unable to capture real packets")
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
            # Start a new capture thread - try real capture first, falls back to demo if needed
            capture_thread = Thread(target=self.capture_packets, daemon=True)
            capture_thread.start()
        
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
            'ai_detections': self.stats['ai_detections'],
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
    
    def get_flow_count(self) -> int:
        """Get number of tracked flows"""
        return self.flow_tracker.get_flow_count() if self.flow_tracker else 0