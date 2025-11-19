#!/usr/bin/env python3
"""
Demo Mode Signature Detection Verification Script
Monitors the DIDS API to verify signature-based detections are working
"""

import requests
import time
import json
from datetime import datetime

class DemoModeMonitor:
    def __init__(self, api_url='http://localhost:5000'):
        self.api_url = api_url
        self.base_url = f"{api_url}/api"

    def check_connection(self):
        """Check if DIDS dashboard is running"""
        try:
            response = requests.get(f"{self.base_url}/stats", timeout=2)
            if response.status_code == 200:
                print("✓ DIDS Dashboard is running")
                return True
            else:
                print(f"✗ Dashboard returned status {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("✗ Cannot connect to DIDS Dashboard")
            print(f"  Make sure the app is running on {self.api_url}")
            return False
        except Exception as e:
            print(f"✗ Error: {e}")
            return False

    def get_capture_status(self):
        """Check packet capture status"""
        try:
            response = requests.get(f"{self.base_url}/capture/status")
            data = response.json()
            print(f"\nPacket Capture Status:")
            print(f"  Active: {data.get('active', False)}")
            print(f"  Demo Mode: {data.get('demo_mode', False)}")
            return data
        except Exception as e:
            print(f"Error getting capture status: {e}")
            return None

    def get_threats(self):
        """Get current threats"""
        try:
            response = requests.get(f"{self.base_url}/threats")
            data = response.json()
            return data.get('threats', [])
        except Exception as e:
            print(f"Error getting threats: {e}")
            return []

    def get_stats(self):
        """Get current statistics"""
        try:
            response = requests.get(f"{self.base_url}/stats")
            return response.json()
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {}

    def enable_capture(self):
        """Enable packet capture"""
        try:
            response = requests.post(f"{self.base_url}/capture/toggle")
            data = response.json()
            if data.get('active'):
                print("✓ Packet capture enabled")
                return True
            else:
                print("✗ Failed to enable packet capture")
                return False
        except Exception as e:
            print(f"Error enabling capture: {e}")
            return False

    def monitor_threats(self, duration=60):
        """Monitor threats for specified duration"""
        print(f"\n{'='*60}")
        print(f"  MONITORING SIGNATURE DETECTIONS FOR {duration} SECONDS")
        print(f"{'='*60}\n")

        start_time = time.time()
        last_threat_count = 0
        detected_signatures = set()

        while time.time() - start_time < duration:
            threats = self.get_threats()
            current_count = len(threats)

            # Display new threats
            if current_count > last_threat_count:
                new_threats = threats[last_threat_count:]
                for threat in new_threats:
                    signature = threat.get('signature')
                    if signature:
                        detected_signatures.add(signature)
                        print(f"\n🚨 NEW THREAT DETECTED:")
                        print(f"  Signature: {signature}")
                        print(f"  Source: {threat.get('source', 'N/A')}")
                        print(f"  Destination: {threat.get('destination', 'N/A')}")
                        print(f"  Action: {threat.get('action', 'N/A')}")
                        print(f"  Severity: {threat.get('severity', 'N/A')}")

                last_threat_count = current_count

            # Display progress
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            print(f"\rMonitoring... [{elapsed}s/{duration}s] | Threats: {current_count} | Signatures: {len(detected_signatures)}", end='', flush=True)

            time.sleep(2)

        print("\n")
        return detected_signatures

    def display_summary(self, signatures):
        """Display monitoring summary"""
        stats = self.get_stats()

        print(f"\n{'='*60}")
        print(f"  MONITORING SUMMARY")
        print(f"{'='*60}")

        print(f"\nPacket Statistics:")
        print(f"  Total Packets: {stats.get('total_packets', 0)}")
        print(f"  Threats Blocked: {stats.get('threats_blocked', 0)}")
        print(f"  AI Detections: {stats.get('ai_detections', 0)}")

        print(f"\nSignature-Based Detections:")
        if signatures:
            for sig in signatures:
                print(f"  ✓ {sig}")
        else:
            print("  ⚠ No signature-based threats detected")
            print("  This is normal if demo mode has low threat generation rate")

        print(f"\n{'='*60}\n")

    def run(self, monitor_duration=60):
        """Run the complete monitoring test"""
        print(f"\n{'='*60}")
        print(f"  DEMO MODE SIGNATURE DETECTION TEST")
        print(f"{'='*60}\n")

        # Step 1: Check connection
        if not self.check_connection():
            print("\n❌ FAILED: Dashboard is not running")
            print("\nPlease start the dashboard first:")
            print("  cd dids-dashboard")
            print("  python app.py")
            return False

        # Step 2: Check capture status
        status = self.get_capture_status()
        if not status:
            return False

        # Step 3: Enable capture if needed
        if not status.get('active'):
            print("\nCapture is not active. Enabling...")
            if not self.enable_capture():
                return False
            time.sleep(2)
            status = self.get_capture_status()

        # Step 4: Verify demo mode
        if not status.get('demo_mode'):
            print("\n⚠ WARNING: Not in demo mode")
            print("  Demo mode should activate automatically if no elevated privileges")
            print("  You may see fewer detections with real packet capture")

        # Step 5: Monitor for threats
        signatures = self.monitor_threats(duration=monitor_duration)

        # Step 6: Display summary
        self.display_summary(signatures)

        # Success criteria
        if signatures:
            print("✅ SUCCESS: Signature detection is working!")
            return True
        else:
            print("⚠ WARNING: No signatures detected during monitoring period")
            print("   Try running for longer or check demo mode is generating threats")
            return False


if __name__ == "__main__":
    import sys

    # Parse arguments
    api_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:5000'
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    # Run monitor
    monitor = DemoModeMonitor(api_url=api_url)
    success = monitor.run(monitor_duration=duration)

    sys.exit(0 if success else 1)
