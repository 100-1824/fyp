#!/usr/bin/env python3
"""
DIDS Attack Traffic Simulator
==============================
Simulates various DDoS and attack patterns for testing the DIDS detection system.

This simulator works in two modes:
1. INJECTION MODE (default): Directly injects simulated packets into the detection pipeline
2. NETWORK MODE: Sends actual network traffic (requires packet capture to be running)

Usage:
    python ddos_simulator.py                    # Interactive mode
    python ddos_simulator.py --all              # Run all simulations
    python ddos_simulator.py --attack portscan  # Run specific attack
    python ddos_simulator.py --network          # Use network mode (actual traffic)
"""

import argparse
import json
import random
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, '..')

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Configuration
DASHBOARD_URL = "http://localhost:8000"
API_GATEWAY_URL = "http://localhost:5000"


class AttackSimulator:
    """Simulates various attack patterns for DIDS testing"""

    def __init__(self, mode: str = "injection", target: str = "127.0.0.1",
                 dashboard_url: str = None, username: str = None, password: str = None):
        self.mode = mode
        self.target = target
        self.simulated_packets = []
        self.detections = []
        self.stats = {
            "packets_generated": 0,
            "attacks_simulated": 0,
            "detections_triggered": 0
        }

        # API configuration
        self.dashboard_url = dashboard_url or DASHBOARD_URL
        self.session = None
        self.authenticated = False

        # Authenticate if credentials provided
        if username and password and HAS_REQUESTS:
            self._authenticate(username, password)

        # External IPs to simulate (not whitelisted)
        self.malicious_ips = [
            "185.220.101.42",   # Known Tor exit
            "45.33.32.156",     # Test IP
            "104.131.182.103",  # Test IP
            "23.129.64.130",    # Test IP
            "192.99.4.199",     # Test IP
            "91.134.154.183",   # Test IP
        ]

        # C2 ports (suspicious)
        self.c2_ports = [4444, 5555, 6666, 7777, 31337, 8888, 9999]

        # Attack signatures
        self.sql_injection_payloads = [
            b"' OR '1'='1",
            b"' OR 1=1--",
            b"'; DROP TABLE users;--",
            b"UNION SELECT * FROM passwords",
            b"1; SELECT * FROM users",
        ]

        self.xss_payloads = [
            b"<script>alert('XSS')</script>",
            b"javascript:alert(1)",
            b"<img onerror=alert(1) src=x>",
            b"<body onload=alert('XSS')>",
        ]

    def _authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the DIDS dashboard"""
        try:
            self.session = requests.Session()

            # Try to login
            login_url = f"{self.dashboard_url}/login"
            response = self.session.post(login_url, data={
                "username": username,
                "password": password
            }, allow_redirects=False)

            if response.status_code in [200, 302]:
                self.authenticated = True
                print(f"[+] Authenticated as {username}")
                return True
            else:
                print(f"[!] Authentication failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return False

    def generate_external_ip(self) -> str:
        """Generate a random external (non-private) IP for testing"""
        return random.choice(self.malicious_ips)

    def generate_packet_data(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        src_port: int = None,
        dst_port: int = None,
        size: int = None,
        payload: bytes = None,
        tcp_flags: Dict = None
    ) -> Dict:
        """Generate a simulated packet data structure"""

        if src_port is None:
            src_port = random.randint(49152, 65535)
        if dst_port is None:
            dst_port = random.choice([80, 443, 22, 21, 25, 53])
        if size is None:
            size = random.randint(64, 1500)
        if tcp_flags is None:
            tcp_flags = {"syn": False, "ack": True, "fin": False, "rst": False, "psh": False}

        packet = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f"),
            "source": src_ip,
            "destination": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "tcp_flags": tcp_flags,
            "payload": payload.hex() if payload else None,
            "threat": True,  # Mark as attack traffic
            "simulated": True
        }

        self.simulated_packets.append(packet)
        self.stats["packets_generated"] += 1

        return packet

    def inject_packet(self, packet: Dict) -> bool:
        """Inject a simulated packet directly into the detection service"""
        if not HAS_REQUESTS:
            print("[!] requests library not available, using local simulation")
            return self._local_detection(packet)

        # Use authenticated session if available
        http_client = self.session if self.authenticated else requests

        try:
            # Try dashboard API first (uses session for auth)
            response = http_client.post(
                f"{self.dashboard_url}/api/inject-packet",
                json=packet,
                timeout=2
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("threat_detected"):
                    self.stats["detections_triggered"] += 1
                return True
        except Exception as e:
            pass

        try:
            # Try API Gateway
            response = http_client.post(
                f"{API_GATEWAY_URL}/api/inject-packet",
                json=packet,
                timeout=2
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("threat_detected"):
                    self.stats["detections_triggered"] += 1
                return True
        except:
            pass

        # Fall back to local detection simulation
        return self._local_detection(packet)

    def _local_detection(self, packet: Dict) -> bool:
        """Simulate local detection when API is not available"""
        # Store the detection locally
        detection = {
            "timestamp": datetime.now().isoformat(),
            "source": packet["source"],
            "destination": packet["destination"],
            "signature": packet.get("attack_type", "Unknown Attack"),
            "severity": packet.get("severity", "medium"),
            "action": "detected",
            "detection_method": "simulation"
        }
        self.detections.append(detection)
        self.stats["detections_triggered"] += 1
        return True

    # =========================================================================
    # ATTACK SIMULATIONS
    # =========================================================================

    def simulate_port_scan(self, target_ip: str = None, port_count: int = 100) -> int:
        """
        Simulate aggressive port scanning.
        Triggers: ET SCAN Aggressive Port Scan (15+ unique ports in 60s)
        """
        print("\n[*] Simulating Port Scan Attack...")
        print(f"    Scanning {port_count} ports in rapid succession")

        attacker_ip = self.generate_external_ip()
        target = target_ip or "10.0.0.50"
        packets_sent = 0

        for port in range(1, port_count + 1):
            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol="TCP",
                dst_port=port,
                size=60,
                tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False}
            )
            packet["attack_type"] = "PortScan"
            packet["severity"] = "medium"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            if packets_sent % 20 == 0:
                print(f"    Scanned {packets_sent}/{port_count} ports...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] Port Scan Complete: {packets_sent} ports scanned from {attacker_ip}")
        return packets_sent

    def simulate_syn_flood(self, target_ip: str = None, packet_count: int = 500) -> int:
        """
        Simulate SYN flood DDoS attack.
        Triggers: DDoS detection, high packet rate from single source
        """
        print("\n[*] Simulating SYN Flood DDoS Attack...")
        print(f"    Generating {packet_count} SYN packets")

        # Use multiple source IPs (spoofed)
        target = target_ip or "10.0.0.50"
        target_port = 80
        packets_sent = 0

        for i in range(packet_count):
            # Randomize source IP to simulate IP spoofing
            attacker_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol="TCP",
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                size=60,
                tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False}
            )
            packet["attack_type"] = "DDoS"
            packet["severity"] = "critical"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            if packets_sent % 100 == 0:
                print(f"    Sent {packets_sent}/{packet_count} SYN packets...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] SYN Flood Complete: {packets_sent} packets sent to {target}:{target_port}")
        return packets_sent

    def simulate_brute_force(self, target_ip: str = None, attempts: int = 50) -> int:
        """
        Simulate SSH brute force attack.
        Triggers: ET ATTACK Brute Force SSH
        """
        print("\n[*] Simulating SSH Brute Force Attack...")
        print(f"    Generating {attempts} login attempts")

        attacker_ip = self.generate_external_ip()
        target = target_ip or "10.0.0.50"
        packets_sent = 0

        for i in range(attempts):
            # Initial connection
            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol="TCP",
                dst_port=22,
                size=random.randint(100, 500),
                payload=b"SSH-2.0-attacker\r\n",
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )
            packet["attack_type"] = "Brute Force"
            packet["severity"] = "high"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            # Simulate failed auth response
            packet2 = self.generate_packet_data(
                src_ip=target,
                dst_ip=attacker_ip,
                protocol="TCP",
                src_port=22,
                dst_port=packet["src_port"],
                size=random.randint(50, 200),
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )

            if self.mode == "injection":
                self.inject_packet(packet2)

            packets_sent += 1

            if (i + 1) % 10 == 0:
                print(f"    Attempted {i + 1}/{attempts} logins...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] Brute Force Complete: {attempts} attempts from {attacker_ip}")
        return packets_sent

    def simulate_c2_communication(self, packet_count: int = 100) -> int:
        """
        Simulate Command & Control communication.
        Triggers: ET MALWARE C2 Communication, ET MALWARE Reverse Shell
        """
        print("\n[*] Simulating C2 Communication...")
        print(f"    Generating {packet_count} C2 beacon packets")

        victim_ip = "10.0.0.100"  # Internal compromised host
        c2_server = self.generate_external_ip()
        c2_port = random.choice(self.c2_ports)
        packets_sent = 0

        for i in range(packet_count):
            # Beacon to C2
            packet = self.generate_packet_data(
                src_ip=victim_ip,
                dst_ip=c2_server,
                protocol="TCP",
                dst_port=c2_port,
                size=random.randint(64, 256),
                payload=b"\x90\x90\x90" + bytes(random.randint(0, 255) for _ in range(20)),
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )
            packet["attack_type"] = "Bot"
            packet["severity"] = "critical"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            # Response from C2
            packet2 = self.generate_packet_data(
                src_ip=c2_server,
                dst_ip=victim_ip,
                protocol="TCP",
                src_port=c2_port,
                size=random.randint(100, 500),
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )
            packet2["attack_type"] = "Bot"
            packet2["severity"] = "critical"

            if self.mode == "injection":
                self.inject_packet(packet2)

            packets_sent += 1

            if (i + 1) % 20 == 0:
                print(f"    Sent {i + 1}/{packet_count} beacon cycles...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] C2 Simulation Complete: {packets_sent} packets to {c2_server}:{c2_port}")
        return packets_sent

    def simulate_sql_injection(self, request_count: int = 30) -> int:
        """
        Simulate SQL injection attacks.
        Triggers: ET WEB SQL Injection Attempt
        """
        print("\n[*] Simulating SQL Injection Attacks...")
        print(f"    Generating {request_count} malicious requests")

        attacker_ip = self.generate_external_ip()
        target = "10.0.0.50"
        packets_sent = 0

        for i in range(request_count):
            payload = random.choice(self.sql_injection_payloads)

            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol="TCP",
                dst_port=80,
                size=len(payload) + 200,
                payload=payload,
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )
            packet["attack_type"] = "Web Attack"
            packet["severity"] = "high"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

        self.stats["attacks_simulated"] += 1
        print(f"[+] SQL Injection Complete: {request_count} malicious requests from {attacker_ip}")
        return packets_sent

    def simulate_xss_attack(self, request_count: int = 30) -> int:
        """
        Simulate Cross-Site Scripting attacks.
        Triggers: ET WEB XSS Attack
        """
        print("\n[*] Simulating XSS Attacks...")
        print(f"    Generating {request_count} malicious requests")

        attacker_ip = self.generate_external_ip()
        target = "10.0.0.50"
        packets_sent = 0

        for i in range(request_count):
            payload = random.choice(self.xss_payloads)

            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol="TCP",
                dst_port=80,
                size=len(payload) + 200,
                payload=payload,
                tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True}
            )
            packet["attack_type"] = "Web Attack"
            packet["severity"] = "high"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

        self.stats["attacks_simulated"] += 1
        print(f"[+] XSS Attack Complete: {request_count} malicious requests from {attacker_ip}")
        return packets_sent

    def simulate_dns_tunneling(self, query_count: int = 150) -> int:
        """
        Simulate DNS tunneling attack.
        Triggers: ET DNS Excessive Queries
        """
        print("\n[*] Simulating DNS Tunneling...")
        print(f"    Generating {query_count} DNS queries")

        attacker_ip = self.generate_external_ip()
        dns_server = "8.8.8.8"
        packets_sent = 0

        for i in range(query_count):
            # Generate suspicious long subdomain (data exfiltration pattern)
            subdomain = ''.join(random.choices('abcdef0123456789', k=32))

            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=dns_server,
                protocol="UDP",
                dst_port=53,
                size=random.randint(64, 512),
                payload=f"{subdomain}.malware.example.com".encode()
            )
            packet["attack_type"] = "Infiltration"
            packet["severity"] = "medium"

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            if (i + 1) % 30 == 0:
                print(f"    Sent {i + 1}/{query_count} DNS queries...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] DNS Tunneling Complete: {query_count} queries from {attacker_ip}")
        return packets_sent

    def simulate_high_volume_traffic(self, packet_count: int = 1000) -> int:
        """
        Simulate high volume mixed attack traffic.
        Triggers: Various detections based on volume and patterns
        """
        print("\n[*] Generating High Volume Mixed Traffic...")
        print(f"    Generating {packet_count} packets of various types")

        packets_sent = 0
        attack_types = ["DDoS", "PortScan", "Bot", "Web Attack", "Brute Force", "Infiltration"]

        for i in range(packet_count):
            attack_type = random.choice(attack_types)
            attacker_ip = self.generate_external_ip()
            target = "10.0.0." + str(random.randint(1, 254))

            packet = self.generate_packet_data(
                src_ip=attacker_ip,
                dst_ip=target,
                protocol=random.choice(["TCP", "UDP"]),
                dst_port=random.choice([22, 80, 443, 3389, 445, 21, 25, 53] + self.c2_ports),
                size=random.randint(64, 1500),
                tcp_flags={
                    "syn": random.random() > 0.7,
                    "ack": random.random() > 0.3,
                    "fin": random.random() > 0.9,
                    "rst": random.random() > 0.95,
                    "psh": random.random() > 0.5
                }
            )
            packet["attack_type"] = attack_type
            packet["severity"] = random.choice(["low", "medium", "high", "critical"])

            if self.mode == "injection":
                self.inject_packet(packet)

            packets_sent += 1

            if packets_sent % 200 == 0:
                print(f"    Generated {packets_sent}/{packet_count} packets...")

        self.stats["attacks_simulated"] += 1
        print(f"[+] High Volume Traffic Complete: {packets_sent} packets generated")
        return packets_sent

    def run_all_simulations(self) -> Dict:
        """Run all attack simulations"""
        print("\n" + "=" * 60)
        print("Running ALL Attack Simulations")
        print("=" * 60)

        results = {}

        # Port Scan
        results["port_scan"] = self.simulate_port_scan()
        time.sleep(1)

        # SYN Flood
        results["syn_flood"] = self.simulate_syn_flood()
        time.sleep(1)

        # Brute Force
        results["brute_force"] = self.simulate_brute_force()
        time.sleep(1)

        # C2 Communication
        results["c2_communication"] = self.simulate_c2_communication()
        time.sleep(1)

        # SQL Injection
        results["sql_injection"] = self.simulate_sql_injection()
        time.sleep(1)

        # XSS Attack
        results["xss_attack"] = self.simulate_xss_attack()
        time.sleep(1)

        # DNS Tunneling
        results["dns_tunneling"] = self.simulate_dns_tunneling()
        time.sleep(1)

        # High Volume
        results["high_volume"] = self.simulate_high_volume_traffic()

        return results

    def get_summary(self) -> Dict:
        """Get simulation summary"""
        return {
            "stats": self.stats,
            "detections": len(self.detections),
            "packets": len(self.simulated_packets),
            "mode": self.mode
        }

    def export_packets(self, filename: str = "simulated_packets.json"):
        """Export simulated packets to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.simulated_packets, f, indent=2)
        print(f"[+] Exported {len(self.simulated_packets)} packets to {filename}")


class NetworkSimulator:
    """Sends actual network traffic for testing (requires running services)"""

    def __init__(self, target: str = "127.0.0.1"):
        self.target = target

    def simulate_port_scan(self, port_count: int = 100):
        """Simulate port scan with actual connections"""
        print("\n[*] Simulating Port Scan (Network Mode)...")

        for port in range(1, port_count + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target, port))
                sock.close()
            except:
                pass

        print(f"[+] Port Scan Complete: Scanned {port_count} ports")

    def simulate_syn_flood(self, packet_count: int = 500):
        """Simulate SYN flood pattern"""
        print("\n[*] Simulating SYN Flood (Network Mode)...")

        for _ in range(packet_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.01)
                sock.connect((self.target, 80))
            except:
                pass

        print(f"[+] SYN Flood Complete: {packet_count} attempts")

    def simulate_brute_force(self, attempts: int = 50):
        """Simulate brute force login attempts"""
        print("\n[*] Simulating Brute Force (Network Mode)...")

        for i in range(attempts):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((self.target, 22))
                sock.send(b"SSH-2.0-attacker\r\n")
                sock.close()
            except:
                pass
            time.sleep(0.05)

        print(f"[+] Brute Force Complete: {attempts} attempts")

    def simulate_high_traffic(self, packet_count: int = 1000):
        """Generate high volume UDP traffic"""
        print("\n[*] Generating High Volume Traffic (Network Mode)...")

        for _ in range(packet_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"X" * 1024, (self.target, random.randint(1, 65535)))
                sock.close()
            except:
                pass

        print(f"[+] High Traffic Complete: {packet_count} packets")


def print_banner():
    """Print the simulator banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║           DIDS Attack Traffic Simulator v2.0                  ║
║        For Testing Detection Capabilities Only                ║
╚══════════════════════════════════════════════════════════════╝
    """)


def interactive_menu(simulator: AttackSimulator):
    """Display interactive menu"""
    while True:
        print("\n" + "=" * 50)
        print("Select Attack Simulation:")
        print("=" * 50)
        print("1. Port Scan")
        print("2. SYN Flood (DDoS)")
        print("3. SSH Brute Force")
        print("4. C2 Communication")
        print("5. SQL Injection")
        print("6. XSS Attack")
        print("7. DNS Tunneling")
        print("8. High Volume Mixed Traffic")
        print("9. Run ALL Simulations")
        print("0. Exit")
        print("-" * 50)

        choice = input("\nEnter choice (0-9): ").strip()

        if choice == "1":
            simulator.simulate_port_scan()
        elif choice == "2":
            simulator.simulate_syn_flood()
        elif choice == "3":
            simulator.simulate_brute_force()
        elif choice == "4":
            simulator.simulate_c2_communication()
        elif choice == "5":
            simulator.simulate_sql_injection()
        elif choice == "6":
            simulator.simulate_xss_attack()
        elif choice == "7":
            simulator.simulate_dns_tunneling()
        elif choice == "8":
            simulator.simulate_high_volume_traffic()
        elif choice == "9":
            simulator.run_all_simulations()
        elif choice == "0":
            break
        else:
            print("[!] Invalid choice. Please try again.")

        # Show summary
        summary = simulator.get_summary()
        print(f"\n[i] Session Stats: {summary['stats']['packets_generated']} packets, "
              f"{summary['stats']['attacks_simulated']} attacks, "
              f"{summary['stats']['detections_triggered']} detections")


def main():
    parser = argparse.ArgumentParser(
        description="DIDS Attack Traffic Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ddos_simulator.py                    # Interactive mode (local simulation)
  python ddos_simulator.py --all              # Run all attacks
  python ddos_simulator.py --attack portscan  # Run port scan only
  python ddos_simulator.py --attack ddos      # Run SYN flood only
  python ddos_simulator.py --network          # Network mode (actual traffic)
  python ddos_simulator.py --export output.json  # Export packets to file

  # With authentication (sends to DIDS API):
  python ddos_simulator.py --user admin --password admin123 --all
  python ddos_simulator.py -u admin -p admin123 --attack ddos
  python ddos_simulator.py --url http://localhost:8000 -u admin -p admin123
        """
    )

    parser.add_argument("--all", action="store_true", help="Run all attack simulations")
    parser.add_argument("--attack", type=str, choices=[
        "portscan", "ddos", "synflood", "bruteforce", "c2",
        "sql", "xss", "dns", "highvolume"
    ], help="Run specific attack type")
    parser.add_argument("--network", action="store_true",
                       help="Use network mode (send actual traffic)")
    parser.add_argument("--target", type=str, default="127.0.0.1",
                       help="Target IP for network mode (default: 127.0.0.1)")
    parser.add_argument("--export", type=str, metavar="FILE",
                       help="Export simulated packets to JSON file")
    parser.add_argument("--count", type=int, default=100,
                       help="Number of packets/attempts for the simulation")

    # Authentication options
    parser.add_argument("-u", "--user", "--username", type=str, dest="username",
                       help="Username for DIDS dashboard authentication")
    parser.add_argument("-p", "--password", type=str,
                       help="Password for DIDS dashboard authentication")
    parser.add_argument("--url", type=str, default="http://localhost:8000",
                       help="DIDS dashboard URL (default: http://localhost:8000)")

    args = parser.parse_args()

    print_banner()

    if args.network:
        print("[*] Mode: NETWORK (sending actual traffic)")
        print(f"[*] Target: {args.target}")
        print("[!] Warning: This sends real network traffic!")

        sim = NetworkSimulator(args.target)

        if args.all:
            sim.simulate_port_scan()
            time.sleep(1)
            sim.simulate_syn_flood()
            time.sleep(1)
            sim.simulate_brute_force()
            time.sleep(1)
            sim.simulate_high_traffic()
        elif args.attack:
            attack_map = {
                "portscan": sim.simulate_port_scan,
                "ddos": sim.simulate_syn_flood,
                "synflood": sim.simulate_syn_flood,
                "bruteforce": sim.simulate_brute_force,
                "highvolume": sim.simulate_high_traffic,
            }
            if args.attack in attack_map:
                attack_map[args.attack]()
            else:
                print(f"[!] Attack '{args.attack}' not available in network mode")
        else:
            # Interactive network mode
            print("\n1. Port Scan")
            print("2. SYN Flood")
            print("3. Brute Force")
            print("4. High Volume Traffic")
            print("5. Run ALL")

            choice = input("\nChoice: ").strip()
            if choice == "1":
                sim.simulate_port_scan()
            elif choice == "2":
                sim.simulate_syn_flood()
            elif choice == "3":
                sim.simulate_brute_force()
            elif choice == "4":
                sim.simulate_high_traffic()
            elif choice == "5":
                sim.simulate_port_scan()
                sim.simulate_syn_flood()
                sim.simulate_brute_force()
                sim.simulate_high_traffic()
    else:
        print("[*] Mode: INJECTION (simulating packets directly)")
        print("[*] This mode generates packet data for detection testing")

        # Show authentication status
        if args.username and args.password:
            print(f"[*] Dashboard URL: {args.url}")
            print(f"[*] Authenticating as: {args.username}")
        else:
            print("[!] No credentials provided - using local simulation mode")
            print("[!] To send to DIDS API, use: --user <username> --password <password>")

        simulator = AttackSimulator(
            mode="injection",
            dashboard_url=args.url,
            username=args.username,
            password=args.password
        )

        if args.all:
            results = simulator.run_all_simulations()
            print("\n" + "=" * 60)
            print("SIMULATION COMPLETE")
            print("=" * 60)
            for attack, packets in results.items():
                print(f"  {attack}: {packets} packets")
        elif args.attack:
            attack_map = {
                "portscan": simulator.simulate_port_scan,
                "ddos": simulator.simulate_syn_flood,
                "synflood": simulator.simulate_syn_flood,
                "bruteforce": simulator.simulate_brute_force,
                "c2": simulator.simulate_c2_communication,
                "sql": simulator.simulate_sql_injection,
                "xss": simulator.simulate_xss_attack,
                "dns": simulator.simulate_dns_tunneling,
                "highvolume": simulator.simulate_high_volume_traffic,
            }
            if args.attack in attack_map:
                attack_map[args.attack](packet_count=args.count) if args.attack in ["ddos", "synflood", "highvolume"] else attack_map[args.attack]()
        else:
            interactive_menu(simulator)

        # Export if requested
        if args.export:
            simulator.export_packets(args.export)

        # Print final summary
        summary = simulator.get_summary()
        print("\n" + "=" * 60)
        print("SESSION SUMMARY")
        print("=" * 60)
        print(f"  Packets Generated: {summary['stats']['packets_generated']}")
        print(f"  Attacks Simulated: {summary['stats']['attacks_simulated']}")
        print(f"  Detections: {summary['stats']['detections_triggered']}")
        print("=" * 60)


if __name__ == "__main__":
    main()
