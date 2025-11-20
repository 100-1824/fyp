"""
Suricata/Snort Rule Parser
Parses and validates Suricata/Snort IDS rules for real-time packet analysis
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RuleParser:
    """Parser for Suricata/Snort rule format"""

    # Suricata/Snort rule format:
    # action protocol src_ip src_port direction dst_ip dst_port (options)
    RULE_PATTERN = re.compile(
        r"^(?P<action>\w+)\s+"
        r"(?P<protocol>\w+)\s+"
        r"(?P<src_ip>[\d\.\[\],:any\$\w]+)\s+"
        r"(?P<src_port>[\d:,any\$\w\[\]]+)\s+"
        r"(?P<direction>->|<>|<-)\s+"
        r"(?P<dst_ip>[\d\.\[\],:any\$\w]+)\s+"
        r"(?P<dst_port>[\d:,any\$\w\[\]]+)\s+"
        r"\((?P<options>.*)\)\s*$",
        re.IGNORECASE,
    )

    VALID_ACTIONS = {"alert", "log", "pass", "drop", "reject", "sdrop"}
    VALID_PROTOCOLS = {
        "tcp",
        "udp",
        "icmp",
        "ip",
        "http",
        "ftp",
        "tls",
        "smb",
        "dns",
        "ssh",
    }

    def __init__(self):
        self.parsed_rules = []
        self.rule_stats = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "by_action": {},
            "by_protocol": {},
            "by_severity": {},
        }

    def parse_rule(
        self, rule_string: str, rule_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single Suricata/Snort rule.

        Args:
            rule_string: Raw rule string
            rule_id: Optional rule identifier

        Returns:
            Parsed rule dictionary or None if invalid
        """
        # Skip comments and empty lines
        rule_string = rule_string.strip()
        if not rule_string or rule_string.startswith("#"):
            return None

        # Match rule pattern
        match = self.RULE_PATTERN.match(rule_string)
        if not match:
            logger.warning(f"Failed to parse rule: {rule_string[:100]}")
            self.rule_stats["invalid"] += 1
            return None

        # Extract rule components
        action = match.group("action").lower()
        protocol = match.group("protocol").lower()

        # Validate action and protocol
        if action not in self.VALID_ACTIONS:
            logger.warning(f"Invalid action '{action}' in rule")
            self.rule_stats["invalid"] += 1
            return None

        if protocol not in self.VALID_PROTOCOLS:
            logger.warning(f"Invalid protocol '{protocol}' in rule")
            self.rule_stats["invalid"] += 1
            return None

        # Parse options
        options_str = match.group("options")
        options = self._parse_options(options_str)

        # Build parsed rule
        parsed_rule = {
            "raw_rule": rule_string,
            "action": action,
            "protocol": protocol,
            "src_ip": match.group("src_ip"),
            "src_port": match.group("src_port"),
            "direction": match.group("direction"),
            "dst_ip": match.group("dst_ip"),
            "dst_port": match.group("dst_port"),
            "options": options,
            "enabled": True,
            "created_at": datetime.now(),
            "last_modified": datetime.now(),
            "hit_count": 0,
        }

        # Extract metadata from options
        if "sid" in options:
            parsed_rule["sid"] = options["sid"]
        else:
            parsed_rule["sid"] = rule_id or f"custom_{len(self.parsed_rules) + 1}"

        if "msg" in options:
            parsed_rule["msg"] = options["msg"]
        else:
            parsed_rule["msg"] = f"Rule {parsed_rule['sid']}"

        if "priority" in options:
            parsed_rule["priority"] = int(options["priority"])
        else:
            parsed_rule["priority"] = 3  # Default medium priority

        # Map priority to severity
        parsed_rule["severity"] = self._priority_to_severity(parsed_rule["priority"])

        if "classtype" in options:
            parsed_rule["classtype"] = options["classtype"]

        if "reference" in options:
            parsed_rule["reference"] = options["reference"]

        if "rev" in options:
            parsed_rule["rev"] = options["rev"]

        # Update statistics
        self.rule_stats["valid"] += 1
        self.rule_stats["by_action"][action] = (
            self.rule_stats["by_action"].get(action, 0) + 1
        )
        self.rule_stats["by_protocol"][protocol] = (
            self.rule_stats["by_protocol"].get(protocol, 0) + 1
        )
        self.rule_stats["by_severity"][parsed_rule["severity"]] = (
            self.rule_stats["by_severity"].get(parsed_rule["severity"], 0) + 1
        )

        return parsed_rule

    def _parse_options(self, options_str: str) -> Dict[str, Any]:
        """
        Parse rule options.

        Args:
            options_str: Options string from rule

        Returns:
            Dictionary of parsed options
        """
        options = {}

        # Split options by semicolon, but handle quoted strings
        option_list = []
        current = []
        in_quotes = False

        for char in options_str:
            if char == '"':
                in_quotes = not in_quotes
                current.append(char)
            elif char == ";" and not in_quotes:
                if current:
                    option_list.append("".join(current).strip())
                current = []
            else:
                current.append(char)

        if current:
            option_list.append("".join(current).strip())

        # Parse each option
        for option in option_list:
            if not option:
                continue

            # Handle options with values (key:value or key:"value")
            if ":" in option:
                key, value = option.split(":", 1)
                key = key.strip()
                value = value.strip().strip("\"'")

                # Store content patterns separately
                if key == "content":
                    if "content_patterns" not in options:
                        options["content_patterns"] = []
                    options["content_patterns"].append(value)
                elif key == "pcre":
                    if "pcre_patterns" not in options:
                        options["pcre_patterns"] = []
                    options["pcre_patterns"].append(value)
                else:
                    options[key] = value
            else:
                # Boolean options (flags)
                options[option.strip()] = True

        return options

    def _priority_to_severity(self, priority: int) -> str:
        """
        Convert Suricata priority to severity level.

        Args:
            priority: Priority value (1-4)

        Returns:
            Severity string
        """
        if priority == 1:
            return "critical"
        elif priority == 2:
            return "high"
        elif priority == 3:
            return "medium"
        else:
            return "low"

    def parse_rule_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a Suricata/Snort rule file.

        Args:
            file_path: Path to rule file

        Returns:
            List of parsed rules
        """
        rules = []
        self.rule_stats["total"] = 0

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    self.rule_stats["total"] += 1

                    parsed_rule = self.parse_rule(line, rule_id=f"file_{line_num}")
                    if parsed_rule:
                        parsed_rule["source_file"] = file_path
                        parsed_rule["line_number"] = line_num
                        rules.append(parsed_rule)
                        self.parsed_rules.append(parsed_rule)

            logger.info(f"Parsed {len(rules)} valid rules from {file_path}")
            logger.info(f"Statistics: {self.rule_stats}")

        except FileNotFoundError:
            logger.error(f"Rule file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error parsing rule file {file_path}: {e}")

        return rules

    def parse_rule_string_list(self, rule_strings: List[str]) -> List[Dict[str, Any]]:
        """
        Parse a list of rule strings.

        Args:
            rule_strings: List of rule strings

        Returns:
            List of parsed rules
        """
        rules = []
        self.rule_stats["total"] = len(rule_strings)

        for idx, rule_string in enumerate(rule_strings):
            parsed_rule = self.parse_rule(rule_string, rule_id=f"string_{idx}")
            if parsed_rule:
                rules.append(parsed_rule)
                self.parsed_rules.append(parsed_rule)

        logger.info(f"Parsed {len(rules)} valid rules from {len(rule_strings)} strings")
        logger.info(f"Statistics: {self.rule_stats}")

        return rules

    def validate_rule(self, rule: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate a parsed rule.

        Args:
            rule: Parsed rule dictionary

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required fields
        required_fields = [
            "action",
            "protocol",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "options",
        ]

        for field in required_fields:
            if field not in rule:
                return False, f"Missing required field: {field}"

        # Validate action
        if rule["action"] not in self.VALID_ACTIONS:
            return False, f"Invalid action: {rule['action']}"

        # Validate protocol
        if rule["protocol"] not in self.VALID_PROTOCOLS:
            return False, f"Invalid protocol: {rule['protocol']}"

        # Validate severity
        if "severity" in rule and rule["severity"] not in [
            "critical",
            "high",
            "medium",
            "low",
        ]:
            return False, f"Invalid severity: {rule['severity']}"

        return True, None

    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.rule_stats.copy()

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Get all parsed rules"""
        return self.parsed_rules.copy()

    def clear_rules(self) -> None:
        """Clear all parsed rules and reset statistics"""
        self.parsed_rules = []
        self.rule_stats = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "by_action": {},
            "by_protocol": {},
            "by_severity": {},
        }


class RuleManager:
    """Manages rule loading, storage, and retrieval"""

    def __init__(self, db=None):
        self.parser = RuleParser()
        self.db = db
        self.active_rules = []

    def load_rules_from_file(self, file_path: str) -> int:
        """
        Load rules from file and optionally store in database.

        Args:
            file_path: Path to rule file

        Returns:
            Number of rules loaded
        """
        rules = self.parser.parse_rule_file(file_path)

        if self.db:
            # Store rules in MongoDB
            for rule in rules:
                self._store_rule(rule)

        self.active_rules.extend(rules)
        return len(rules)

    def load_rules_from_strings(self, rule_strings: List[str]) -> int:
        """
        Load rules from string list.

        Args:
            rule_strings: List of rule strings

        Returns:
            Number of rules loaded
        """
        rules = self.parser.parse_rule_string_list(rule_strings)

        if self.db:
            for rule in rules:
                self._store_rule(rule)

        self.active_rules.extend(rules)
        return len(rules)

    def _store_rule(self, rule: Dict[str, Any]) -> bool:
        """Store rule in MongoDB"""
        if not self.db:
            return False

        try:
            # Check if rule exists
            existing = self.db.rules.find_one({"sid": rule["sid"]})

            if existing:
                # Update existing rule
                self.db.rules.update_one({"sid": rule["sid"]}, {"$set": rule})
                logger.debug(f"Updated rule: {rule['sid']}")
            else:
                # Insert new rule
                self.db.rules.insert_one(rule)
                logger.debug(f"Inserted rule: {rule['sid']}")

            return True
        except Exception as e:
            logger.error(f"Error storing rule {rule.get('sid')}: {e}")
            return False

    def get_active_rules(
        self, protocol: Optional[str] = None, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get active rules, optionally filtered by protocol and severity.

        Args:
            protocol: Filter by protocol (tcp, udp, etc.)
            severity: Filter by severity (critical, high, medium, low)

        Returns:
            List of active rules
        """
        rules = [r for r in self.active_rules if r.get("enabled", True)]

        if protocol:
            rules = [r for r in rules if r["protocol"] == protocol.lower()]

        if severity:
            rules = [r for r in rules if r.get("severity") == severity.lower()]

        return rules

    def get_rule_by_sid(self, sid: str) -> Optional[Dict[str, Any]]:
        """Get rule by SID"""
        for rule in self.active_rules:
            if rule.get("sid") == sid:
                return rule
        return None

    def enable_rule(self, sid: str) -> bool:
        """Enable a rule by SID"""
        rule = self.get_rule_by_sid(sid)
        if rule:
            rule["enabled"] = True
            if self.db:
                self.db.rules.update_one({"sid": sid}, {"$set": {"enabled": True}})
            return True
        return False

    def disable_rule(self, sid: str) -> bool:
        """Disable a rule by SID"""
        rule = self.get_rule_by_sid(sid)
        if rule:
            rule["enabled"] = False
            if self.db:
                self.db.rules.update_one({"sid": sid}, {"$set": {"enabled": False}})
            return True
        return False

    def increment_hit_count(self, sid: str) -> None:
        """Increment rule hit count"""
        rule = self.get_rule_by_sid(sid)
        if rule:
            rule["hit_count"] = rule.get("hit_count", 0) + 1
            if self.db:
                self.db.rules.update_one(
                    {"sid": sid},
                    {"$inc": {"hit_count": 1}, "$set": {"last_hit": datetime.now()}},
                )

    def get_statistics(self) -> Dict[str, Any]:
        """Get rule statistics"""
        stats = self.parser.get_stats()
        stats["active_rules"] = len(
            [r for r in self.active_rules if r.get("enabled", True)]
        )
        stats["total_loaded"] = len(self.active_rules)
        stats["disabled_rules"] = len(
            [r for r in self.active_rules if not r.get("enabled", True)]
        )

        # Calculate total hits
        stats["total_hits"] = sum(r.get("hit_count", 0) for r in self.active_rules)

        # Top rules by hits
        top_rules = sorted(
            self.active_rules, key=lambda r: r.get("hit_count", 0), reverse=True
        )[:10]
        stats["top_rules"] = [
            {"sid": r["sid"], "msg": r.get("msg", ""), "hits": r.get("hit_count", 0)}
            for r in top_rules
            if r.get("hit_count", 0) > 0
        ]

        return stats
