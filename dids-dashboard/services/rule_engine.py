"""
Suricata/Snort Rule Engine
Real-time packet matching against loaded IDS rules
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RuleEngine:
    """Engine for matching packets against Suricata/Snort rules"""

    def __init__(self, rule_manager):
        """
        Initialize rule engine.

        Args:
            rule_manager: RuleManager instance with loaded rules
        """
        self.rule_manager = rule_manager
        self.match_stats = {
            "total_packets": 0,
            "total_matches": 0,
            "matches_by_rule": {},
            "matches_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    def match_packet(
        self, packet_info: Dict[str, Any], payload: Optional[bytes] = None
    ) -> List[Dict[str, Any]]:
        """
        Match a packet against all active rules.

        Args:
            packet_info: Dictionary containing packet information
                - source: Source IP
                - destination: Destination IP
                - protocol: Protocol (TCP, UDP, etc.)
                - src_port: Source port
                - dst_port: Destination port
                - size: Packet size
                - tcp_flags: TCP flags dict (optional)
            payload: Raw packet payload bytes (optional)

        Returns:
            List of matching rules with match details
        """
        self.match_stats["total_packets"] += 1
        matches = []

        # Get active rules for this protocol
        protocol = packet_info.get("protocol", "").upper()

        # Normalize protocol names
        proto_map = {
            "HTTP": "tcp",
            "HTTPS": "tcp",
            "SSH": "tcp",
            "FTP": "tcp",
            "DNS": "udp",
            "TCP": "tcp",
            "UDP": "udp",
            "ICMP": "icmp",
        }

        normalized_protocol = proto_map.get(protocol, protocol.lower())

        # Get rules for this protocol and also 'ip' rules (match all)
        active_rules = self.rule_manager.get_active_rules(protocol=normalized_protocol)
        ip_rules = self.rule_manager.get_active_rules(protocol="ip")
        active_rules.extend(ip_rules)

        # Check each rule
        for rule in active_rules:
            match_result = self._match_rule(rule, packet_info, payload)
            if match_result:
                matches.append(match_result)

                # Update statistics
                self.match_stats["total_matches"] += 1
                rule_sid = rule.get("sid", "unknown")
                self.match_stats["matches_by_rule"][rule_sid] = (
                    self.match_stats["matches_by_rule"].get(rule_sid, 0) + 1
                )

                severity = rule.get("severity", "medium")
                self.match_stats["matches_by_severity"][severity] = (
                    self.match_stats["matches_by_severity"].get(severity, 0) + 1
                )

                # Increment hit count for the rule
                self.rule_manager.increment_hit_count(rule_sid)

        return matches

    def _match_rule(
        self,
        rule: Dict[str, Any],
        packet_info: Dict[str, Any],
        payload: Optional[bytes] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Match a single rule against packet.

        Args:
            rule: Parsed rule dictionary
            packet_info: Packet information
            payload: Raw payload bytes

        Returns:
            Match result dictionary or None
        """
        # Match IP addresses
        if not self._match_ip(rule["src_ip"], packet_info.get("source")):
            return None

        if not self._match_ip(rule["dst_ip"], packet_info.get("destination")):
            return None

        # Match ports
        if not self._match_port(rule["src_port"], packet_info.get("src_port", 0)):
            return None

        if not self._match_port(rule["dst_port"], packet_info.get("dst_port", 0)):
            return None

        # Match direction (for bidirectional rules)
        if rule["direction"] == "<>":
            # Bidirectional - also check reverse
            reverse_match = (
                self._match_ip(rule["src_ip"], packet_info.get("destination"))
                and self._match_ip(rule["dst_ip"], packet_info.get("source"))
                and self._match_port(rule["src_port"], packet_info.get("dst_port", 0))
                and self._match_port(rule["dst_port"], packet_info.get("src_port", 0))
            )
            if not reverse_match:
                # If neither direction matches, return None
                if not (
                    self._match_ip(rule["src_ip"], packet_info.get("source"))
                    and self._match_ip(rule["dst_ip"], packet_info.get("destination"))
                ):
                    return None

        # Match options (content patterns, TCP flags, etc.)
        options = rule.get("options", {})

        # Check content patterns if payload provided
        if payload and "content_patterns" in options:
            if not self._match_content_patterns(options["content_patterns"], payload):
                return None

        # Check PCRE patterns if payload provided
        if payload and "pcre_patterns" in options:
            if not self._match_pcre_patterns(options["pcre_patterns"], payload):
                return None

        # Check TCP flags if specified
        if "flags" in options:
            if not self._match_tcp_flags(
                options["flags"], packet_info.get("tcp_flags", {})
            ):
                return None

        # Check flow direction
        if "flow" in options:
            if not self._match_flow(options["flow"], packet_info):
                return None

        # Match successful - build result
        match_result = {
            "rule_sid": rule.get("sid"),
            "rule_msg": rule.get("msg", "Rule match"),
            "action": rule.get("action", "alert"),
            "severity": rule.get("severity", "medium"),
            "priority": rule.get("priority", 3),
            "classtype": rule.get("classtype", "unknown"),
            "protocol": rule.get("protocol"),
            "timestamp": datetime.now(),
            "packet_info": {
                "source": packet_info.get("source"),
                "destination": packet_info.get("destination"),
                "src_port": packet_info.get("src_port"),
                "dst_port": packet_info.get("dst_port"),
                "protocol": packet_info.get("protocol"),
            },
        }

        # Add reference if available
        if "reference" in rule:
            match_result["reference"] = rule["reference"]

        logger.info(
            f"Rule match: {rule.get('msg')} (SID: {rule.get('sid')}) - "
            f"{packet_info.get('source')}:{packet_info.get('src_port')} -> "
            f"{packet_info.get('destination')}:{packet_info.get('dst_port')}"
        )

        return match_result

    def _match_ip(self, rule_ip: str, packet_ip: str) -> bool:
        """
        Match IP address against rule specification.

        Args:
            rule_ip: IP specification from rule (can be IP, CIDR, 'any', variable)
            packet_ip: Actual packet IP address

        Returns:
            True if matches, False otherwise
        """
        if not packet_ip:
            return False

        rule_ip = rule_ip.strip()

        # Handle 'any'
        if rule_ip == "any":
            return True

        # Handle variables like $HOME_NET, $EXTERNAL_NET
        if rule_ip.startswith("$"):
            # For now, treat variables as 'any'
            # In production, these would be resolved from configuration
            return True

        # Handle negation
        if rule_ip.startswith("!"):
            result = self._match_ip(rule_ip[1:], packet_ip)
            return not result

        # Handle IP lists [ip1,ip2,ip3]
        if rule_ip.startswith("[") and rule_ip.endswith("]"):
            ip_list = rule_ip[1:-1].split(",")
            for ip in ip_list:
                if self._match_ip(ip.strip(), packet_ip):
                    return True
            return False

        # Handle CIDR notation
        if "/" in rule_ip:
            try:
                network = ipaddress.ip_network(rule_ip, strict=False)
                packet_addr = ipaddress.ip_address(packet_ip)
                return packet_addr in network
            except ValueError:
                logger.warning(f"Invalid CIDR notation: {rule_ip}")
                return False

        # Handle IP range (e.g., 192.168.1.1-192.168.1.100)
        if "-" in rule_ip and not rule_ip.count("-") > 1:
            try:
                start_ip, end_ip = rule_ip.split("-")
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                packet_addr = ipaddress.ip_address(packet_ip)
                return start <= packet_addr <= end
            except ValueError:
                logger.warning(f"Invalid IP range: {rule_ip}")
                return False

        # Exact IP match
        try:
            return ipaddress.ip_address(rule_ip) == ipaddress.ip_address(packet_ip)
        except ValueError:
            logger.warning(f"Invalid IP address: {rule_ip}")
            return False

    def _match_port(self, rule_port: str, packet_port: int) -> bool:
        """
        Match port against rule specification.

        Args:
            rule_port: Port specification from rule
            packet_port: Actual packet port

        Returns:
            True if matches, False otherwise
        """
        rule_port = str(rule_port).strip()

        # Handle 'any'
        if rule_port == "any":
            return True

        # Handle variables like $HTTP_PORTS
        if rule_port.startswith("$"):
            # Resolve common port variables
            port_vars = {
                "$HTTP_PORTS": [80, 8080, 8000, 8888],
                "$HTTPS_PORTS": [443, 8443],
                "$SSH_PORTS": [22],
                "$FTP_PORTS": [20, 21],
                "$DNS_PORTS": [53],
            }
            if rule_port.upper() in port_vars:
                return packet_port in port_vars[rule_port.upper()]
            return True  # Unknown variable, allow

        # Handle negation
        if rule_port.startswith("!"):
            result = self._match_port(rule_port[1:], packet_port)
            return not result

        # Handle port lists [port1,port2,port3]
        if rule_port.startswith("[") and rule_port.endswith("]"):
            port_list = rule_port[1:-1].split(",")
            for port in port_list:
                if self._match_port(port.strip(), packet_port):
                    return True
            return False

        # Handle port range (e.g., 1024:65535)
        if ":" in rule_port:
            try:
                parts = rule_port.split(":")
                if len(parts) == 2:
                    start = int(parts[0]) if parts[0] else 0
                    end = int(parts[1]) if parts[1] else 65535
                    return start <= packet_port <= end
            except ValueError:
                logger.warning(f"Invalid port range: {rule_port}")
                return False

        # Exact port match
        try:
            return int(rule_port) == packet_port
        except ValueError:
            logger.warning(f"Invalid port specification: {rule_port}")
            return False

    def _match_content_patterns(self, patterns: List[str], payload: bytes) -> bool:
        """
        Match content patterns against payload.

        Args:
            patterns: List of content patterns
            payload: Packet payload bytes

        Returns:
            True if all patterns match (AND logic)
        """
        for pattern in patterns:
            # Handle hex content (|XX XX XX|)
            if "|" in pattern:
                hex_pattern = self._parse_hex_content(pattern)
                if hex_pattern not in payload:
                    return False
            else:
                # Regular string content
                if pattern.encode("utf-8", errors="ignore") not in payload:
                    return False

        return True

    def _match_pcre_patterns(self, patterns: List[str], payload: bytes) -> bool:
        """
        Match PCRE patterns against payload.

        Args:
            patterns: List of PCRE patterns
            payload: Packet payload bytes

        Returns:
            True if any pattern matches
        """
        for pattern in patterns:
            try:
                # Clean PCRE pattern (remove delimiters and flags)
                clean_pattern = pattern.strip("/")
                flags = 0

                # Extract flags (i for case-insensitive, s for dotall, m for multiline)
                if clean_pattern.endswith(("i", "s", "m", "is", "im", "sm", "ism")):
                    flag_chars = (
                        clean_pattern.split("/")[-1] if "/" in clean_pattern else ""
                    )
                    if "i" in flag_chars:
                        flags |= re.IGNORECASE
                    if "s" in flag_chars:
                        flags |= re.DOTALL
                    if "m" in flag_chars:
                        flags |= re.MULTILINE
                    clean_pattern = (
                        clean_pattern.rsplit("/", 1)[0]
                        if "/" in clean_pattern
                        else clean_pattern[: -len(flag_chars)]
                    )

                regex = re.compile(
                    clean_pattern.encode("utf-8", errors="ignore"), flags
                )
                if regex.search(payload):
                    return True
            except re.error as e:
                logger.warning(f"Invalid PCRE pattern '{pattern}': {e}")
                continue

        return False

    def _match_tcp_flags(self, flag_spec: str, tcp_flags: Dict[str, int]) -> bool:
        """
        Match TCP flags.

        Args:
            flag_spec: Flag specification (e.g., 'S', 'SA', 'A+', etc.)
            tcp_flags: Dictionary of TCP flags from packet

        Returns:
            True if flags match
        """
        # Common flag specifications:
        # S = SYN, A = ACK, F = FIN, R = RST, P = PSH, U = URG
        # + means must be set, - means must not be set, no modifier means don't care

        flag_map = {
            "S": "syn",
            "A": "ack",
            "F": "fin",
            "R": "rst",
            "P": "psh",
            "U": "urg",
        }

        for char in flag_spec.upper():
            if char in flag_map:
                flag_name = flag_map[char]
                # Flag must be set
                if tcp_flags.get(flag_name, 0) != 1:
                    return False

        return True

    def _match_flow(self, flow_spec: str, packet_info: Dict[str, Any]) -> bool:
        """
        Match flow direction specification.

        Args:
            flow_spec: Flow specification (e.g., 'to_server', 'to_client', 'established')
            packet_info: Packet information

        Returns:
            True if flow matches
        """
        # Flow keywords:
        # to_server, to_client, from_server, from_client
        # established, stateless
        # only_stream, no_stream

        flow_spec = flow_spec.lower()

        # For basic implementation, we'll match based on common port numbers
        # In production, this would track actual connection state

        dst_port = packet_info.get("dst_port", 0)
        src_port = packet_info.get("src_port", 0)

        # Common server ports
        server_ports = {80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443}

        if "to_server" in flow_spec:
            return dst_port in server_ports
        elif "to_client" in flow_spec or "from_server" in flow_spec:
            return src_port in server_ports
        elif "established" in flow_spec:
            # Check for ACK flag (established connection)
            tcp_flags = packet_info.get("tcp_flags", {})
            return tcp_flags.get("ack", 0) == 1

        return True  # Default to match if we can't determine

    def _parse_hex_content(self, pattern: str) -> bytes:
        """
        Parse hex content pattern (e.g., |01 02 03|).

        Args:
            pattern: Hex pattern string

        Returns:
            Bytes representation
        """
        # Extract hex bytes between pipes
        hex_match = re.search(r"\|([0-9a-fA-F\s]+)\|", pattern)
        if hex_match:
            hex_str = hex_match.group(1).replace(" ", "")
            return bytes.fromhex(hex_str)
        return pattern.encode("utf-8", errors="ignore")

    def get_statistics(self) -> Dict[str, Any]:
        """Get matching statistics"""
        stats = self.match_stats.copy()

        if stats["total_packets"] > 0:
            stats["match_rate"] = (
                stats["total_matches"] / stats["total_packets"]
            ) * 100
        else:
            stats["match_rate"] = 0.0

        return stats

    def reset_statistics(self) -> None:
        """Reset matching statistics"""
        self.match_stats = {
            "total_packets": 0,
            "total_matches": 0,
            "matches_by_rule": {},
            "matches_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
