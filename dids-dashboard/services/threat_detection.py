import logging
import random
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .threat_intelligence import ThreatIntelligenceService

logger = logging.getLogger(__name__)


class ThreatDetectionService:
    """Service for detecting and managing security threats"""

    def __init__(self, config, rule_engine=None):
        self.config = config
        self.signature_detections = []
        self.rule_engine = rule_engine  # Suricata/Snort rule engine

        # Initialize threat intelligence service
        self.threat_intel = ThreatIntelligenceService(config)

        # Track scanning activity per IP
        self.scan_tracker = defaultdict(
            lambda: {"ports": set(), "first_seen": None, "count": 0}
        )
        self.dns_tracker = defaultdict(lambda: {"queries": 0, "first_seen": None})

        # Whitelisted IPs (known good services)
        self.whitelisted_ips = {
            "1.1.1.1",  # Cloudflare DNS
            "1.0.0.1",  # Cloudflare DNS
            "8.8.8.8",  # Google DNS
            "8.8.4.4",  # Google DNS
            "9.9.9.9",  # Quad9 DNS
        }

        # Whitelisted ports (common legitimate services)
        self.whitelisted_ports = {
            20,  # FTP Data
            21,  # FTP Control
            22,  # SSH
            25,  # SMTP
            53,  # DNS
            80,  # HTTP
            110,  # POP3
            143,  # IMAP
            443,  # HTTPS
            465,  # SMTPS
            587,  # SMTP Submission
            993,  # IMAPS
            995,  # POP3S
            3306,  # MySQL
            5432,  # PostgreSQL
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
        }

        # Enhanced threat signatures with lower false positive rates
        self.threat_signatures = {
            "ET MALWARE C2 Communication": {
                "port": 4444,
                "pattern": b"\x90\x90\x90",
                "severity": "critical",
                "description": "Known malware command and control beacon pattern",
            },
            "ET MALWARE Reverse Shell": {
                "ports": [4444, 5555, 6666, 7777, 31337],
                "severity": "critical",
                "description": "Connection to common backdoor/reverse shell port",
            },
            "ET TROJAN Known C2 Server": {
                "suspicious_ips": ["192.168.1.100"],  # Example - add real threat IPs
                "severity": "high",
                "description": "Communication with known malicious IP address",
            },
            "ET WEB SQL Injection Attempt": {
                "patterns": [
                    b"' OR '1'='1",
                    b"' OR 1=1--",
                    b"'; DROP TABLE",
                    b"UNION SELECT",
                ],
                "severity": "high",
                "description": "SQL injection attack pattern detected",
            },
            "ET WEB XSS Attack": {
                "patterns": [
                    b"<script>",
                    b"javascript:",
                    b"onerror=",
                    b"onload=",
                ],
                "severity": "high",
                "description": "Cross-site scripting attack pattern",
            },
            "ET WEB Directory Traversal": {
                "patterns": [
                    b"../",
                    b"..\\",
                    b"%2e%2e%2f",
                    b"%252e%252e%252f",
                ],
                "severity": "medium",
                "description": "Directory traversal attempt detected",
            },
            "ET SCAN Aggressive Port Scan": {
                "scan_threshold": 15,  # 15+ different ports in 60 seconds
                "time_window": 60,
                "severity": "medium",
                "description": "Aggressive port scanning activity detected",
            },
            "ET DNS Excessive Queries": {
                "query_threshold": 100,  # 100+ queries in 60 seconds
                "time_window": 60,
                "severity": "low",
                "description": "Unusual number of DNS queries (possible DNS tunneling)",
            },
            "ET ATTACK Brute Force SSH": {
                "port": 22,
                "connection_threshold": 10,  # 10+ connections in 60 seconds
                "time_window": 60,
                "severity": "high",
                "description": "Potential SSH brute force attack",
            },
        }

    def is_whitelisted(self, ip: str, port: int = None) -> bool:
        """
        Check if IP or port is whitelisted.

        Args:
            ip: IP address to check
            port: Optional port number to check

        Returns:
            True if whitelisted, False otherwise
        """
        if ip in self.whitelisted_ips:
            return True

        if port and port in self.whitelisted_ports:
            return True

        # Whitelist private IP ranges (RFC 1918)
        if ip.startswith(("10.", "172.16.", "192.168.")):
            # Allow internal network traffic
            return True

        # Whitelist multicast addresses
        if ip.startswith("224."):
            return True

        return False

    def detect_port_scan(self, src: str, dst_port: int) -> bool:
        """
        Detect port scanning behavior.

        Args:
            src: Source IP address
            dst_port: Destination port

        Returns:
            True if port scan detected, False otherwise
        """
        now = datetime.now()
        tracker = self.scan_tracker[src]

        # Initialize first seen time
        if tracker["first_seen"] is None:
            tracker["first_seen"] = now

        # Check if within time window
        time_diff = (now - tracker["first_seen"]).total_seconds()

        # Reset if outside time window
        if time_diff > 60:  # 60 seconds window
            tracker["ports"] = {dst_port}
            tracker["first_seen"] = now
            tracker["count"] = 1
            return False

        # Add port to tracker
        tracker["ports"].add(dst_port)
        tracker["count"] += 1

        # Check if threshold exceeded
        if len(tracker["ports"]) >= 15:  # 15+ unique ports
            logger.warning(
                f"Port scan detected from {src}: {len(tracker['ports'])} ports in {time_diff:.1f}s"
            )
            # Reset after detection
            tracker["ports"] = set()
            tracker["first_seen"] = None
            return True

        return False

    def detect_dns_anomaly(self, src: str) -> bool:
        """
        Detect DNS query anomalies (possible DNS tunneling).

        Args:
            src: Source IP address

        Returns:
            True if anomaly detected, False otherwise
        """
        now = datetime.now()
        tracker = self.dns_tracker[src]

        # Initialize first seen time
        if tracker["first_seen"] is None:
            tracker["first_seen"] = now
            tracker["queries"] = 1
            return False

        # Check if within time window
        time_diff = (now - tracker["first_seen"]).total_seconds()

        # Reset if outside time window
        if time_diff > 60:  # 60 seconds window
            tracker["queries"] = 1
            tracker["first_seen"] = now
            return False

        # Increment query count
        tracker["queries"] += 1

        # Check if threshold exceeded
        if tracker["queries"] >= 100:  # 100+ queries in 60 seconds
            logger.warning(
                f"DNS anomaly detected from {src}: {tracker['queries']} queries in {time_diff:.1f}s"
            )
            # Reset after detection
            tracker["queries"] = 0
            tracker["first_seen"] = None
            return True

        return False

    def check_payload_signatures(self, payload: bytes) -> List[str]:
        """
        Check payload against known attack patterns.

        Args:
            payload: Packet payload bytes

        Returns:
            List of matching signature names
        """
        matches = []

        if not payload or len(payload) == 0:
            return matches

        # SQL Injection patterns
        sql_patterns = self.threat_signatures.get(
            "ET WEB SQL Injection Attempt", {}
        ).get("patterns", [])
        for pattern in sql_patterns:
            if pattern in payload:
                matches.append("ET WEB SQL Injection Attempt")
                break

        # XSS patterns
        xss_patterns = self.threat_signatures.get("ET WEB XSS Attack", {}).get(
            "patterns", []
        )
        for pattern in xss_patterns:
            if pattern in payload:
                matches.append("ET WEB XSS Attack")
                break

        # Directory traversal patterns
        traversal_patterns = self.threat_signatures.get(
            "ET WEB Directory Traversal", {}
        ).get("patterns", [])
        for pattern in traversal_patterns:
            if pattern in payload:
                matches.append("ET WEB Directory Traversal")
                break

        # Malware C2 pattern
        if b"\x90\x90\x90" in payload:
            matches.append("ET MALWARE C2 Communication")

        return matches

    def check_suricata_rules(
        self, packet_info: Dict[str, Any], payload: Optional[bytes] = None
    ) -> List[Dict[str, Any]]:
        """
        Check packet against Suricata/Snort rules using rule engine.

        Args:
            packet_info: Dictionary containing packet information
            payload: Raw packet payload bytes (optional)

        Returns:
            List of rule matches
        """
        if not self.rule_engine:
            return []

        try:
            # Match packet against all active rules
            matches = self.rule_engine.match_packet(packet_info, payload)

            # Log matches
            for match in matches:
                logger.info(
                    f"Suricata/Snort rule match: {match['rule_msg']} "
                    f"(SID: {match['rule_sid']}, Action: {match['action']}, "
                    f"Severity: {match['severity']})"
                )

            return matches
        except Exception as e:
            logger.error(f"Error checking Suricata rules: {e}")
            return []

    def log_threat(
        self, signature: str, src: str, dst: str, additional_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Log a detected threat.

        Args:
            signature: Threat signature name
            src: Source IP address
            dst: Destination IP address
            additional_info: Additional threat information

        Returns:
            Detection record dictionary
        """
        # Skip if whitelisted
        if self.is_whitelisted(src) and self.is_whitelisted(dst):
            return None

        action = self._determine_action(signature)

        detection = {
            "timestamp": datetime.now().isoformat(),
            "signature": signature,
            "source": src,
            "destination": dst,
            "action": action,
            "severity": self._get_severity(signature),
            "description": self._get_description(signature),
        }

        if additional_info:
            detection.update(additional_info)

        self.signature_detections.append(detection)

        # Keep only recent detections
        max_detections = getattr(self.config, "THREAT_DETECTION_BUFFER", 20) * 10
        if len(self.signature_detections) > max_detections:
            self.signature_detections = self.signature_detections[-max_detections:]

        logger.warning(
            f"Threat {action}: {signature} from {src} to {dst} "
            f"(Severity: {detection['severity']})"
        )

        return detection

    def _determine_action(self, signature: str) -> str:
        """
        Determine action to take for a threat.

        Args:
            signature: Threat signature name

        Returns:
            Action string ('blocked', 'alert', 'logged')
        """
        severity = self._get_severity(signature)

        if severity == "critical":
            return "blocked"
        elif severity == "high":
            return "blocked" if random.random() > 0.2 else "alert"
        elif severity == "medium":
            return "alert" if random.random() > 0.3 else "logged"
        else:
            return "logged"

    def _get_severity(self, signature: str) -> str:
        """Get severity level for a signature"""
        for name, sig in self.threat_signatures.items():
            if name == signature:
                return sig.get("severity", "medium")
        return "medium"

    def _get_description(self, signature: str) -> str:
        """Get description for a signature"""
        for name, sig in self.threat_signatures.items():
            if name == signature:
                return sig.get("description", "Unknown threat")
        return "Unknown threat"

    def get_recent_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent threat detections.

        Args:
            limit: Maximum number of threats to return

        Returns:
            List of threat detection records
        """
        return self.signature_detections[-limit:]

    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        Get threat statistics.

        Returns:
            Dictionary containing threat statistics
        """
        total_threats = len(self.signature_detections)

        # Count by severity
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for detection in self.signature_detections:
            severity = detection.get("severity", "medium")
            severity_count[severity] = severity_count.get(severity, 0) + 1

        # Count by action
        action_count = {}
        for detection in self.signature_detections:
            action = detection.get("action", "logged")
            action_count[action] = action_count.get(action, 0) + 1

        # Count by signature type
        signature_count = {}
        for detection in self.signature_detections:
            sig = detection.get("signature", "unknown")
            signature_count[sig] = signature_count.get(sig, 0) + 1

        # Get top attackers
        attacker_count = defaultdict(int)
        for detection in self.signature_detections:
            src = detection.get("source", "unknown")
            attacker_count[src] += 1

        top_attackers = dict(
            sorted(attacker_count.items(), key=lambda x: x[1], reverse=True)[:5]
        )

        return {
            "total_threats": total_threats,
            "by_severity": severity_count,
            "by_action": action_count,
            "by_signature": signature_count,
            "blocked_count": action_count.get("blocked", 0),
            "top_attackers": top_attackers,
        }

    def clear_old_detections(self, hours: int = 24) -> int:
        """
        Clear threat detections older than specified hours.

        Args:
            hours: Number of hours to retain

        Returns:
            Number of detections cleared
        """
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        original_count = len(self.signature_detections)

        self.signature_detections = [
            d
            for d in self.signature_detections
            if datetime.fromisoformat(d["timestamp"]).timestamp() > cutoff_time
        ]

        cleared = original_count - len(self.signature_detections)
        if cleared > 0:
            logger.info(f"Cleared {cleared} old threat detections")

        return cleared

    def add_custom_signature(self, name: str, signature_config: Dict[str, Any]) -> bool:
        """
        Add a custom threat signature.

        Args:
            name: Signature name
            signature_config: Signature configuration dictionary

        Returns:
            True if added successfully
        """
        if name in self.threat_signatures:
            logger.warning(f"Signature '{name}' already exists")
            return False

        self.threat_signatures[name] = signature_config
        logger.info(f"Added custom signature: {name}")
        return True

    def remove_signature(self, name: str) -> bool:
        """
        Remove a threat signature.

        Args:
            name: Signature name

        Returns:
            True if removed successfully
        """
        if name in self.threat_signatures:
            del self.threat_signatures[name]
            logger.info(f"Removed signature: {name}")
            return True
        return False

    def get_all_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Get all threat signatures"""
        return self.threat_signatures.copy()

    def add_to_whitelist(self, ip: str) -> None:
        """Add IP to whitelist"""
        self.whitelisted_ips.add(ip)
        logger.info(f"Added {ip} to whitelist")

    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist"""
        if ip in self.whitelisted_ips:
            self.whitelisted_ips.remove(ip)
            logger.info(f"Removed {ip} from whitelist")
            return True
        return False

    def get_whitelist(self) -> Dict[str, Any]:
        """Get current whitelist configuration"""
        return {
            "whitelisted_ips": list(self.whitelisted_ips),
            "whitelisted_ports": list(self.whitelisted_ports),
        }

    # =========================================================================
    # Threat Intelligence Integration (IBM X-Force & AlienVault OTX)
    # =========================================================================

    def check_ip_threat_intel(self, ip: str) -> Dict[str, Any]:
        """
        Check IP against threat intelligence sources (IBM X-Force & AlienVault OTX).

        Args:
            ip: IP address to check

        Returns:
            Dictionary with threat intelligence results
        """
        try:
            # Skip whitelisted and private IPs
            if self.is_whitelisted(ip):
                return {
                    "ip": ip,
                    "checked": False,
                    "reason": "IP is whitelisted",
                    "is_malicious": False,
                }

            # Check against threat intelligence
            result = self.threat_intel.check_ip(ip)

            # If malicious, log as threat
            if result.get("is_malicious"):
                self.log_threat(
                    signature="ET THREAT_INTEL Known Malicious IP",
                    src=ip,
                    dst="N/A",
                    additional_info={
                        "risk_score": result.get("risk_score", 0),
                        "categories": result.get("categories", []),
                        "sources": [s.get("provider") for s in result.get("sources", [])],
                        "detection_type": "threat_intelligence",
                    },
                )

            return result

        except Exception as e:
            logger.error(f"Error checking IP threat intelligence: {e}")
            return {"ip": ip, "error": str(e), "is_malicious": False}

    def check_url_threat_intel(self, url: str) -> Dict[str, Any]:
        """
        Check URL against threat intelligence sources.

        Args:
            url: URL to check

        Returns:
            Dictionary with threat intelligence results
        """
        try:
            result = self.threat_intel.check_url(url)

            if result.get("is_malicious"):
                self.log_threat(
                    signature="ET THREAT_INTEL Malicious URL",
                    src="N/A",
                    dst=url,
                    additional_info={
                        "risk_score": result.get("risk_score", 0),
                        "categories": result.get("categories", []),
                        "detection_type": "threat_intelligence",
                    },
                )

            return result

        except Exception as e:
            logger.error(f"Error checking URL threat intelligence: {e}")
            return {"url": url, "error": str(e), "is_malicious": False}

    def check_hash_threat_intel(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against threat intelligence sources.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with malware information
        """
        try:
            result = self.threat_intel.check_hash(file_hash)

            if result.get("is_malicious"):
                self.log_threat(
                    signature="ET THREAT_INTEL Known Malware Hash",
                    src="N/A",
                    dst="N/A",
                    additional_info={
                        "file_hash": file_hash,
                        "malware_families": result.get("malware_families", []),
                        "detection_type": "threat_intelligence",
                    },
                )

            return result

        except Exception as e:
            logger.error(f"Error checking hash threat intelligence: {e}")
            return {"hash": file_hash, "error": str(e), "is_malicious": False}

    def is_known_malicious_ip(self, ip: str) -> bool:
        """
        Quick check if IP is in local malicious cache.

        Args:
            ip: IP address to check

        Returns:
            True if known malicious
        """
        return self.threat_intel.is_known_malicious(ip, "ip")

    def bulk_check_ips_threat_intel(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple IPs against threat intelligence.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IPs to their reputation data
        """
        return self.threat_intel.bulk_check_ips(ips)

    def get_threat_intel_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence service statistics."""
        return self.threat_intel.get_statistics()

    def get_threat_intel_indicators(self) -> Dict[str, List[str]]:
        """Export all known malicious indicators from threat intelligence."""
        return self.threat_intel.export_indicators()

    def import_threat_intel_indicators(
        self,
        ips: List[str] = None,
        domains: List[str] = None,
        hashes: List[str] = None,
    ):
        """
        Import indicators into threat intelligence local cache.

        Args:
            ips: List of malicious IPs
            domains: List of malicious domains
            hashes: List of malicious file hashes
        """
        self.threat_intel.import_indicators(ips=ips, domains=domains, hashes=hashes)
