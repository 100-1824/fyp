import logging
import platform
import time
from collections import defaultdict
from datetime import datetime
from threading import Event, Thread
from typing import Any, Dict, Optional

import netifaces
from scapy.all import DNS, ICMP, IP, TCP, UDP, Raw, conf, get_if_list, sniff

logger = logging.getLogger(__name__)


class PacketCaptureService:
    """Service for capturing and analyzing network packets with AI and RL detection"""

    def __init__(self, config, threat_service=None, ai_service=None, rl_service=None):
        self.config = config
        self.threat_service = threat_service
        self.ai_service = ai_service
        self.rl_service = rl_service

        # Use get() method for Flask config object with defaults
        self.max_traffic_size = config.get("TRAFFIC_DATA_MAX_SIZE", 1000)
        self.stats_history_size = config.get("STATS_HISTORY_SIZE", 100)
        self.threat_buffer_size = config.get("THREAT_DETECTION_BUFFER", 20)
        self.default_interface = config.get("DEFAULT_INTERFACE", "eth0")

        self.traffic_data = []
        self.stats = {
            "total_packets": 0,
            "protocol_dist": defaultdict(int),
            "top_talkers": defaultdict(int),
            "threats_blocked": 0,
            "ai_detections": 0,
        }
        self.capture_event = Event()
        self.capture_active = True

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
            if hasattr(conf, "iface") and conf.iface:
                logger.info(f"Using Scapy default interface: {conf.iface}")
                return conf.iface

            # Try method 2: Get default gateway interface via netifaces
            try:
                gw = netifaces.gateways()
                if "default" in gw and netifaces.AF_INET in gw["default"]:
                    interface = gw["default"][netifaces.AF_INET][1]
                    logger.info(f"Using default gateway interface: {interface}")
                    return interface
            except Exception as e:
                logger.debug(f"Could not get gateway interface: {e}")

            # Try method 3: Find any active interface with an IP address
            try:
                interfaces = netifaces.interfaces()

                # Platform-specific interface filtering
                if system == "Windows":
                    # On Windows, accept GUID format interfaces
                    for iface in interfaces:
                        # Windows interfaces can be GUIDs or names
                        try:
                            addrs = netifaces.ifaddresses(iface)
                            if netifaces.AF_INET in addrs:
                                # Skip loopback
                                ip = addrs[netifaces.AF_INET][0].get("addr", "")
                                if not ip.startswith("127."):
                                    logger.info(f"Using interface: {iface}")
                                    return iface
                        except Exception as e:
                            logger.debug(f"Error checking interface {iface}: {e}")
                            continue
                else:
                    # On Linux/macOS, prefer common interface naming patterns
                    for iface in interfaces:
                        if iface.startswith(
                            ("eth", "wlan", "en", "wl", "wlp", "enp", "ens")
                        ):
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
                    if not iface.lower().startswith(("lo", "loopback")):
                        logger.info(
                            f"Using first non-loopback Scapy interface: {iface}"
                        )
                        return iface

                # If all interfaces are loopback, use the first one
                logger.warning(
                    f"Only loopback interfaces found, using: {scapy_interfaces[0]}"
                )
                return scapy_interfaces[0]

        except Exception as e:
            logger.error(f"Failed to detect active interface: {e}")

        # Final fallback
        logger.warning(
            f"Could not detect interface, using default: {self.default_interface}"
        )
        return self.default_interface

    def extract_packet_info(self, pkt) -> Optional[Dict[str, Any]]:
        """Extract comprehensive packet information including flags and ports"""
        if IP not in pkt:
            return None

        packet_info = {
            "source": pkt[IP].src,
            "destination": pkt[IP].dst,
            "size": len(pkt),
            "protocol": pkt.sprintf("%IP.proto%"),
            "src_port": 0,
            "dst_port": 0,
            "fin": 0,
            "syn": 0,
            "rst": 0,
            "psh": 0,
            "ack": 0,
            "urg": 0,
            "ece": 0,
            "cwr": 0,
        }

        # Extract TCP information
        if TCP in pkt:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = pkt[TCP].sport
            packet_info["dst_port"] = pkt[TCP].dport

            # Extract TCP flags
            flags = pkt[TCP].flags
            packet_info["fin"] = 1 if flags & 0x01 else 0
            packet_info["syn"] = 1 if flags & 0x02 else 0
            packet_info["rst"] = 1 if flags & 0x04 else 0
            packet_info["psh"] = 1 if flags & 0x08 else 0
            packet_info["ack"] = 1 if flags & 0x10 else 0
            packet_info["urg"] = 1 if flags & 0x20 else 0
            packet_info["ece"] = 1 if flags & 0x40 else 0
            packet_info["cwr"] = 1 if flags & 0x80 else 0

            # Identify common services
            if packet_info["dst_port"] == 80:
                packet_info["protocol"] = "HTTP"
            elif packet_info["dst_port"] == 443:
                packet_info["protocol"] = "HTTPS"
            elif packet_info["dst_port"] == 22:
                packet_info["protocol"] = "SSH"
            elif packet_info["dst_port"] in [20, 21]:
                packet_info["protocol"] = "FTP"

        # Extract UDP information
        elif UDP in pkt:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = pkt[UDP].sport
            packet_info["dst_port"] = pkt[UDP].dport

            # Identify DNS
            if packet_info["dst_port"] == 53 or packet_info["src_port"] == 53:
                packet_info["protocol"] = "DNS"

        # ICMP
        elif ICMP in pkt:
            packet_info["protocol"] = "ICMP"

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

        src = packet_info["source"]
        dst = packet_info["destination"]
        proto = packet_info["protocol"]
        size = packet_info["size"]

        # Update statistics
        self.stats["total_packets"] += 1
        self.stats["protocol_dist"][proto] += 1
        self.stats["top_talkers"][src] += size

        # Initialize threat flags
        threat_detected = False
        ai_detection = None
        signature_detection = None

        # 1. Check signature-based threats if threat service is available
        if self.threat_service:
            signature_detection = self._check_signature_threats(
                pkt, packet_info, src, dst
            )
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
                    self.stats["ai_detections"] += 1
                    logger.info(
                        f"🤖 AI Detection: {ai_detection['attack_type']} "
                        f"({ai_detection['confidence']}% confidence)"
                    )

        # Create packet record
        record = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": src,
            "destination": dst,
            "protocol": proto,
            "size": size,
            "threat": threat_detected,
            "ai_detection": ai_detection["attack_type"] if ai_detection else None,
            "ai_confidence": ai_detection["confidence"] if ai_detection else None,
            "signature_detection": signature_detection,
        }

        return record

    def _check_signature_threats(
        self, pkt, packet_info: Dict[str, Any], src: str, dst: str
    ) -> Optional[str]:
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
        if self.threat_service.is_whitelisted(
            src
        ) or self.threat_service.is_whitelisted(dst):
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
                    match["rule_msg"],
                    src,
                    dst,
                    {
                        "rule_sid": match["rule_sid"],
                        "action": match["action"],
                        "protocol": packet_info.get("protocol"),
                        "classtype": match.get("classtype", "unknown"),
                    },
                )
                self.stats["threats_blocked"] += 1

                # Return first high/critical severity match
                if match["severity"] in ["critical", "high"]:
                    if not threat_signature:
                        threat_signature = match["rule_msg"]

        # Check TCP packets
        if TCP in pkt:
            dst_port = pkt[TCP].dport

            # Check for suspicious ports (malware C2, backdoors)
            suspicious_ports = [4444, 5555, 6666, 7777, 31337]
            if dst_port in suspicious_ports:
                self.threat_service.log_threat(
                    "ET MALWARE Reverse Shell",
                    src,
                    dst,
                    {"port": dst_port, "protocol": "TCP"},
                )
                self.stats["threats_blocked"] += 1
                threat_signature = "ET MALWARE Reverse Shell"

            # Check payload for attack patterns
            if pkt[TCP].payload and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(
                        signature, src, dst, {"protocol": "TCP"}
                    )
                    self.stats["threats_blocked"] += 1
                    if not threat_signature:
                        threat_signature = signature

            # Port scan detection
            if not self.threat_service.is_whitelisted(dst, dst_port):
                if self.threat_service.detect_port_scan(src, dst_port):
                    self.threat_service.log_threat(
                        "ET SCAN Aggressive Port Scan",
                        src,
                        dst,
                        {"scanned_port": dst_port},
                    )
                    self.stats["threats_blocked"] += 1
                    threat_signature = "ET SCAN Aggressive Port Scan"

        # Check UDP packets
        elif UDP in pkt:
            dst_port = pkt[UDP].dport

            # DNS anomaly detection
            if dst_port == 53 or DNS in pkt:
                if self.threat_service.detect_dns_anomaly(src):
                    self.threat_service.log_threat(
                        "ET DNS Excessive Queries", src, dst, {"queries": "excessive"}
                    )
                    self.stats["threats_blocked"] += 1
                    threat_signature = "ET DNS Excessive Queries"

            # Check payload for attack patterns
            if pkt[UDP].payload and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                matches = self.threat_service.check_payload_signatures(payload)
                for signature in matches:
                    self.threat_service.log_threat(
                        signature, src, dst, {"protocol": "UDP"}
                    )
                    self.stats["threats_blocked"] += 1
                    if not threat_signature:
                        threat_signature = signature

            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777]
            if dst_port in suspicious_ports:
                self.threat_service.log_threat(
                    "ET MALWARE Reverse Shell",
                    src,
                    dst,
                    {"port": dst_port, "protocol": "UDP"},
                )
                self.stats["threats_blocked"] += 1
                threat_signature = "ET MALWARE Reverse Shell"

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

    def capture_packets(self) -> None:
        """Start packet capture on the active interface"""
        interface = self.get_active_interface()
        logger.info(f"Attempting to start packet capture on interface: {interface}")

        try:
            # Validate interface exists in Scapy's interface list
            available_interfaces = get_if_list()
            if interface not in available_interfaces:
                logger.warning(
                    f"Interface '{interface}' not found in Scapy's interface list"
                )
                logger.warning(f"Available interfaces: {available_interfaces}")
                raise OSError(f"Interface '{interface}' not found!")

            # Try to start real packet capture
            logger.info("Starting real packet capture with Scapy...")
            sniff(
                iface=interface,
                prn=lambda p: self.store_packet(self.analyze_packet(p)),
                store=False,
                stop_filter=lambda p: self.capture_event.is_set(),
            )
            logger.info("✓ Real packet capture started successfully")

        except PermissionError as e:
            logger.error(f"Permission denied for packet capture: {e}")
            logger.error("Please run with elevated privileges for packet capture")
            logger.error("On Windows: Run as Administrator | On Linux/Mac: Use sudo")

        except OSError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                logger.error(
                    f"Packet capture error: Interface '{interface}' not found!"
                )
                logger.error(f"Available interfaces: {get_if_list()}")
            else:
                logger.error(f"OS error during packet capture: {e}")

        except Exception as e:
            logger.error(f"Packet capture error: {e}")

    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.capture_event.set()
        self.capture_active = False
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
        else:
            self.capture_event.clear()
            # Start a new capture thread
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
            "total_packets": self.stats["total_packets"],
            "threats_blocked": self.stats["threats_blocked"],
            "ai_detections": self.stats["ai_detections"],
            "protocols": dict(self.stats["protocol_dist"]),
            "top_talkers": dict(
                sorted(
                    self.stats["top_talkers"].items(), key=lambda x: x[1], reverse=True
                )[:5]
            ),
        }

    def get_capture_status(self) -> bool:
        """Get current capture status"""
        return self.capture_active

    def get_flow_count(self) -> int:
        """Get number of tracked flows"""
        return self.flow_tracker.get_flow_count() if self.flow_tracker else 0

    def inject_simulated_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inject a simulated packet for testing ALL detection capabilities:
        1. Signature-based detection (Suricata/Snort rules)
        2. AI/ML-based detection (Neural Network model)
        3. Threat Intelligence (IBM X-Force & AlienVault OTX)

        Args:
            packet_data: Dictionary containing packet information

        Returns:
            Dictionary with detection results from ALL modules
        """
        logger.info(f"Injecting simulated packet: {packet_data.get('source')} -> {packet_data.get('destination')}")

        src = packet_data.get("source", "0.0.0.0")
        dst = packet_data.get("destination", "0.0.0.0")
        proto = packet_data.get("protocol", "TCP")
        src_port = packet_data.get("src_port", 0)
        dst_port = packet_data.get("dst_port", 0)
        size = packet_data.get("size", 64)
        attack_type = packet_data.get("attack_type")
        severity = packet_data.get("severity", "medium")

        # Convert hex payload if provided
        payload = None
        if packet_data.get("payload"):
            try:
                payload = bytes.fromhex(packet_data["payload"])
            except:
                payload = packet_data["payload"].encode() if isinstance(packet_data["payload"], str) else None

        # Update statistics
        self.stats["total_packets"] += 1
        self.stats["protocol_dist"][proto] += 1
        self.stats["top_talkers"][src] += size

        # Track detections from ALL modules
        detections = []
        threat_detected = False
        ai_detection_result = None
        signature_detection = None
        threat_intel_result = None

        # Build packet info for detection
        packet_info = {
            "source": src,
            "destination": dst,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "fin": packet_data.get("tcp_flags", {}).get("fin", 0),
            "syn": packet_data.get("tcp_flags", {}).get("syn", 0),
            "rst": packet_data.get("tcp_flags", {}).get("rst", 0),
            "psh": packet_data.get("tcp_flags", {}).get("psh", 0),
            "ack": packet_data.get("tcp_flags", {}).get("ack", 0),
            "urg": 0,
            "ece": 0,
            "cwr": 0,
        }

        # =====================================================================
        # 1. SIGNATURE-BASED DETECTION (Suricata/Snort Rules)
        # =====================================================================
        if self.threat_service:
            signature_detection = self._check_simulated_signature_threats(
                packet_info, src, dst, dst_port, payload, attack_type
            )
            if signature_detection:
                threat_detected = True
                detections.append({
                    "type": "signature",
                    "method": "Signature-Based Detection",
                    "signature": signature_detection,
                    "severity": severity,
                    "action": "blocked"
                })
                logger.info(f"[SIGNATURE] Detected: {signature_detection}")

        # =====================================================================
        # 2. AI/ML-BASED DETECTION (Neural Network Model)
        # =====================================================================
        if self.ai_service and self.ai_service.is_ready():
            try:
                ai_detection_result = self.ai_service.detect_threat(packet_info)

                if ai_detection_result and ai_detection_result.get("attack_type") not in [None, "Benign"]:
                    threat_detected = True
                    self.stats["ai_detections"] += 1

                    ai_attack_type = ai_detection_result.get("attack_type", "Unknown")
                    ai_confidence = ai_detection_result.get("confidence", 0)
                    ai_severity = ai_detection_result.get("severity", "medium")

                    detections.append({
                        "type": "ai",
                        "method": "AI/ML Detection",
                        "attack_type": ai_attack_type,
                        "confidence": ai_confidence,
                        "severity": ai_severity,
                        "action": "blocked" if ai_confidence > 80 else "alert"
                    })

                    # NOTE: Do NOT log to threat_service here - ai_service.detect_threat()
                    # already stores the detection in ai_service.detections which is
                    # fetched separately by /api/ai-detections and /api/combined-threats

                    logger.info(f"[AI] Detected: {ai_attack_type} ({ai_confidence}% confidence)")

            except Exception as e:
                logger.warning(f"AI detection error: {e}")

        # =====================================================================
        # 3. RL-BASED ADAPTIVE RESPONSE (Double DQN Agent)
        # =====================================================================
        rl_decision = None
        if self.rl_service and self.rl_service.is_ready():
            try:
                # Use RL agent to decide action based on traffic and AI detection
                rl_decision = self.rl_service.decide_action(packet_info, ai_detection_result)

                if rl_decision and rl_decision.get("action") in ["alert", "block"]:
                    threat_detected = True
                    rl_action = rl_decision.get("action", "alert")
                    rl_confidence = rl_decision.get("confidence", 0)

                    detections.append({
                        "type": "rl",
                        "method": "RL Adaptive Response",
                        "action": rl_action,
                        "confidence": rl_confidence,
                        "q_values": rl_decision.get("q_values", {}),
                        "reason": rl_decision.get("reason", "RL agent decision"),
                        "severity": "high" if rl_action == "block" else "medium"
                    })

                    logger.info(f"[RL] Decision: {rl_action} ({rl_confidence:.1f}% confidence)")

            except Exception as e:
                logger.warning(f"RL decision error: {e}")

        # =====================================================================
        # 4. THREAT INTELLIGENCE (IBM X-Force & AlienVault OTX)
        # =====================================================================
        if self.threat_service and hasattr(self.threat_service, 'threat_intel'):
            try:
                # Check source IP against threat intelligence
                threat_intel_result = self.threat_service.check_ip_threat_intel(src)

                if threat_intel_result and threat_intel_result.get("is_malicious"):
                    threat_detected = True
                    risk_score = threat_intel_result.get("risk_score", 0)
                    categories = threat_intel_result.get("categories", [])

                    detections.append({
                        "type": "threat_intel",
                        "method": "Threat Intelligence",
                        "ip": src,
                        "risk_score": risk_score,
                        "categories": categories,
                        "severity": "critical" if risk_score > 7 else "high",
                        "action": "blocked"
                    })

                    logger.info(f"[THREAT INTEL] Source IP {src} flagged (risk: {risk_score})")

                # Check destination IP
                dst_intel = self.threat_service.check_ip_threat_intel(dst)
                if dst_intel and dst_intel.get("is_malicious"):
                    threat_detected = True
                    detections.append({
                        "type": "threat_intel",
                        "method": "Threat Intelligence",
                        "ip": dst,
                        "risk_score": dst_intel.get("risk_score", 0),
                        "severity": "high",
                        "action": "blocked"
                    })
                    logger.info(f"[THREAT INTEL] Dest IP {dst} flagged")

            except Exception as e:
                logger.warning(f"Threat intel check error: {e}")

        # =====================================================================
        # 5. FALLBACK: Log attack_type if specified but no detection triggered
        # =====================================================================
        if attack_type and not detections:
            threat_detected = True
            detections.append({
                "type": "simulated",
                "method": "Simulated Attack",
                "attack_type": attack_type,
                "severity": severity,
                "action": "logged"
            })

        # Create comprehensive packet record
        record = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": src,
            "destination": dst,
            "protocol": proto,
            "size": size,
            "threat": threat_detected,
            "simulated": True,
            "detection_methods": [d.get("method") for d in detections],
            "ai_detection": ai_detection_result.get("attack_type") if ai_detection_result else None,
            "ai_confidence": ai_detection_result.get("confidence") if ai_detection_result else None,
            "rl_decision": rl_decision.get("action") if rl_decision else None,
            "rl_confidence": rl_decision.get("confidence") if rl_decision else None,
            "signature_detection": signature_detection,
            "threat_intel": threat_intel_result.get("is_malicious") if threat_intel_result else False,
            "attack_type": attack_type or (ai_detection_result.get("attack_type") if ai_detection_result else None),
        }

        self.store_packet(record)

        return {
            "success": True,
            "packet": record,
            "threat_detected": threat_detected,
            "detections": detections,
            "detection_summary": {
                "signature_based": signature_detection is not None,
                "ai_detected": ai_detection_result is not None and ai_detection_result.get("attack_type") not in [None, "Benign"],
                "rl_decision": rl_decision.get("action") if rl_decision else None,
                "threat_intel_flagged": threat_intel_result.get("is_malicious") if threat_intel_result else False,
                "total_detections": len(detections)
            },
            "stats": {
                "total_packets": self.stats["total_packets"],
                "threats_blocked": self.stats["threats_blocked"],
                "ai_detections": self.stats["ai_detections"]
            }
        }

    def _check_simulated_signature_threats(
        self,
        packet_info: Dict[str, Any],
        src: str,
        dst: str,
        dst_port: int,
        payload: Optional[bytes],
        attack_type: Optional[str]
    ) -> Optional[str]:
        """
        Check simulated packet against signature-based detection.
        This version DOES NOT check whitelist to allow testing with any IPs.

        Args:
            packet_info: Packet information dict
            src: Source IP
            dst: Destination IP
            dst_port: Destination port
            payload: Packet payload bytes
            attack_type: Pre-specified attack type for logging

        Returns:
            Detected signature name or None
        """
        threat_signature = None

        # Check for suspicious C2/backdoor ports
        suspicious_ports = [4444, 5555, 6666, 7777, 31337, 8888, 9999]
        if dst_port in suspicious_ports:
            self.threat_service.log_threat(
                "ET MALWARE Reverse Shell",
                src,
                dst,
                {"port": dst_port, "protocol": packet_info.get("protocol"), "simulated": True},
            )
            self.stats["threats_blocked"] += 1
            threat_signature = "ET MALWARE Reverse Shell"

        # Check payload for attack patterns
        if payload:
            matches = self.threat_service.check_payload_signatures(payload)
            for signature in matches:
                self.threat_service.log_threat(
                    signature, src, dst, {"protocol": packet_info.get("protocol"), "simulated": True}
                )
                self.stats["threats_blocked"] += 1
                if not threat_signature:
                    threat_signature = signature

        # Port scan detection
        if self.threat_service.detect_port_scan(src, dst_port):
            self.threat_service.log_threat(
                "ET SCAN Aggressive Port Scan",
                src,
                dst,
                {"scanned_port": dst_port, "simulated": True},
            )
            self.stats["threats_blocked"] += 1
            threat_signature = "ET SCAN Aggressive Port Scan"

        # DNS anomaly detection for UDP port 53
        if packet_info.get("protocol") == "UDP" and dst_port == 53:
            if self.threat_service.detect_dns_anomaly(src):
                self.threat_service.log_threat(
                    "ET DNS Excessive Queries", src, dst, {"queries": "excessive", "simulated": True}
                )
                self.stats["threats_blocked"] += 1
                threat_signature = "ET DNS Excessive Queries"

        # Log attack type if provided but no signature matched
        if attack_type and not threat_signature:
            # Map attack types to signatures
            attack_signature_map = {
                "DDoS": "ET DDOS Attack Detected",
                "PortScan": "ET SCAN Aggressive Port Scan",
                "Bot": "ET MALWARE C2 Communication",
                "Web Attack": "ET WEB Attack Detected",
                "Brute Force": "ET ATTACK Brute Force Detected",
                "Infiltration": "ET DNS Excessive Queries",
            }
            signature = attack_signature_map.get(attack_type, f"ET SIMULATED {attack_type}")
            self.threat_service.log_threat(
                signature,
                src,
                dst,
                {"attack_type": attack_type, "simulated": True},
            )
            self.stats["threats_blocked"] += 1
            threat_signature = signature

        return threat_signature
