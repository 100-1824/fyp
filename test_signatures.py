#!/usr/bin/env python3
"""
Signature-based Detection Test Script
Tests all signature patterns in the DIDS system
"""

import socket
import time
import sys
from typing import List

class SignatureTest:
    def __init__(self, target_host='127.0.0.1', target_port=80):
        self.host = target_host
        self.port = target_port
        self.tests_passed = 0
        self.tests_failed = 0

    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        colors = {
            "INFO": "\033[94m",    # Blue
            "SUCCESS": "\033[92m", # Green
            "ERROR": "\033[91m",   # Red
            "WARNING": "\033[93m"  # Yellow
        }
        reset = "\033[0m"
        print(f"{colors.get(level, '')}{message}{reset}")

    def send_tcp_payload(self, payload: bytes, port: int = None) -> bool:
        """Send TCP payload to target"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.host, port or self.port))
            s.send(payload)
            s.close()
            return True
        except Exception as e:
            self.log(f"Connection error: {e}", "WARNING")
            return False

    def test_sql_injection(self):
        """Test SQL injection signature detection"""
        self.log("\n[TEST 1] Testing SQL Injection Detection", "INFO")

        payloads = [
            b"GET /' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n",
            b"POST /login HTTP/1.1\r\nHost: test\r\n\r\nusername=' OR 1=1--",
            b"GET /api?id=1'; DROP TABLE users-- HTTP/1.1\r\n\r\n",
            b"GET /search?q=test UNION SELECT * FROM users HTTP/1.1\r\n\r\n",
        ]

        for i, payload in enumerate(payloads, 1):
            self.log(f"  Sending SQL injection payload {i}/{len(payloads)}...", "INFO")
            if self.send_tcp_payload(payload):
                self.log(f"  ✓ Payload {i} sent successfully", "SUCCESS")
                self.tests_passed += 1
            else:
                self.tests_failed += 1
            time.sleep(0.5)

    def test_xss_attack(self):
        """Test XSS signature detection"""
        self.log("\n[TEST 2] Testing XSS Attack Detection", "INFO")

        payloads = [
            b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n\r\n",
            b"GET /page?redirect=javascript:alert(1) HTTP/1.1\r\n\r\n",
            b"GET /comment?text=<img src=x onerror=alert(1)> HTTP/1.1\r\n\r\n",
            b"POST /submit HTTP/1.1\r\n\r\n<body onload=alert('XSS')>",
        ]

        for i, payload in enumerate(payloads, 1):
            self.log(f"  Sending XSS payload {i}/{len(payloads)}...", "INFO")
            if self.send_tcp_payload(payload):
                self.log(f"  ✓ Payload {i} sent successfully", "SUCCESS")
                self.tests_passed += 1
            else:
                self.tests_failed += 1
            time.sleep(0.5)

    def test_directory_traversal(self):
        """Test directory traversal signature detection"""
        self.log("\n[TEST 3] Testing Directory Traversal Detection", "INFO")

        payloads = [
            b"GET /files?path=../../../../etc/passwd HTTP/1.1\r\n\r\n",
            b"GET /download?file=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1\r\n\r\n",
            b"GET /api/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n\r\n",
            b"GET /read?file=%252e%252e%252f%252e%252e%252f HTTP/1.1\r\n\r\n",
        ]

        for i, payload in enumerate(payloads, 1):
            self.log(f"  Sending traversal payload {i}/{len(payloads)}...", "INFO")
            if self.send_tcp_payload(payload):
                self.log(f"  ✓ Payload {i} sent successfully", "SUCCESS")
                self.tests_passed += 1
            else:
                self.tests_failed += 1
            time.sleep(0.5)

    def test_malware_c2(self):
        """Test malware C2 signature detection"""
        self.log("\n[TEST 4] Testing Malware C2 Detection", "INFO")

        # NOP sled pattern (common in exploits)
        nop_sled = b'\x90' * 100  # NOP sled
        payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n" + nop_sled

        self.log("  Sending NOP sled pattern...", "INFO")
        if self.send_tcp_payload(payload):
            self.log("  ✓ Malware pattern sent successfully", "SUCCESS")
            self.tests_passed += 1
        else:
            self.tests_failed += 1

    def test_reverse_shell_ports(self):
        """Test reverse shell port detection"""
        self.log("\n[TEST 5] Testing Reverse Shell Port Detection", "INFO")

        # Common reverse shell ports
        malicious_ports = [4444, 5555, 6666, 7777, 31337]

        for port in malicious_ports:
            self.log(f"  Attempting connection to port {port}...", "INFO")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.host, port))
                s.close()
                self.log(f"  ✓ Connected to port {port}", "SUCCESS")
                self.tests_passed += 1
            except (socket.timeout, ConnectionRefusedError):
                self.log(f"  ℹ Port {port} refused (expected) - trigger sent", "WARNING")
                self.tests_passed += 1
            except Exception as e:
                self.log(f"  ✗ Error on port {port}: {e}", "ERROR")
                self.tests_failed += 1
            time.sleep(0.3)

    def test_port_scan(self):
        """Test port scan detection (15+ ports in 60s)"""
        self.log("\n[TEST 6] Testing Port Scan Detection", "INFO")
        self.log("  Scanning 20 ports rapidly...", "INFO")

        scanned = 0
        for port in range(8000, 8020):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((self.host, port))
                s.close()
            except:
                pass  # Expected - most ports will be closed
            scanned += 1
            time.sleep(0.05)  # Rapid scanning

        self.log(f"  ✓ Scanned {scanned} ports", "SUCCESS")
        self.tests_passed += 1

    def test_ssh_brute_force(self):
        """Test SSH brute force detection (10+ attempts)"""
        self.log("\n[TEST 7] Testing SSH Brute Force Detection", "INFO")
        self.log("  Sending 12 rapid SSH connection attempts...", "INFO")

        attempts = 0
        for i in range(12):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((self.host, 22))
                s.close()
                attempts += 1
            except:
                attempts += 1  # Count even failed attempts
            time.sleep(0.1)

        self.log(f"  ✓ Sent {attempts} SSH connection attempts", "SUCCESS")
        self.tests_passed += 1

    def run_all_tests(self):
        """Run all signature tests"""
        self.log("=" * 60, "INFO")
        self.log("  SIGNATURE-BASED DETECTION TEST SUITE", "INFO")
        self.log("=" * 60, "INFO")
        self.log(f"Target: {self.host}:{self.port}", "INFO")
        self.log("\nStarting tests in 3 seconds...", "WARNING")
        time.sleep(3)

        # Run all tests
        self.test_sql_injection()
        self.test_xss_attack()
        self.test_directory_traversal()
        self.test_malware_c2()
        self.test_reverse_shell_ports()
        self.test_port_scan()
        self.test_ssh_brute_force()

        # Summary
        self.log("\n" + "=" * 60, "INFO")
        self.log("  TEST SUMMARY", "INFO")
        self.log("=" * 60, "INFO")
        self.log(f"Tests Passed: {self.tests_passed}", "SUCCESS")
        self.log(f"Tests Failed: {self.tests_failed}", "ERROR")
        self.log("\nCheck your DIDS dashboard 'Threats' module for detections!", "WARNING")
        self.log("=" * 60, "INFO")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = '127.0.0.1'

    tester = SignatureTest(target_host=target_host, target_port=5000)
    tester.run_all_tests()
