"""
Traffic Capture Microservice
Handles packet sniffing and preprocessing
"""

import logging
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent))

import time
from collections import defaultdict
from threading import Event, Thread

from scapy.all import ICMP, IP, TCP, UDP, sniff
from shared.config import get_config
from shared.models import PacketData

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())
CORS(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config["LOG_LEVEL"]), format=app.config["LOG_FORMAT"]
)
logger = logging.getLogger(__name__)

# Capture state
capture_active = False
capture_event = Event()
traffic_buffer = []
MAX_BUFFER_SIZE = 1000
statistics = {"total_packets": 0, "protocol_dist": defaultdict(int), "errors": 0}


def extract_packet_info(pkt) -> PacketData:
    """Extract information from packet"""
    if IP not in pkt:
        return None

    packet_data = PacketData(
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        source=pkt[IP].src,
        destination=pkt[IP].dst,
        size=len(pkt),
        protocol="TCP",
        src_port=0,
        dst_port=0,
    )

    # Extract TCP info
    if TCP in pkt:
        packet_data.protocol = "TCP"
        packet_data.src_port = pkt[TCP].sport
        packet_data.dst_port = pkt[TCP].dport

        # Extract flags
        flags = pkt[TCP].flags
        packet_data.fin = 1 if flags & 0x01 else 0
        packet_data.syn = 1 if flags & 0x02 else 0
        packet_data.rst = 1 if flags & 0x04 else 0
        packet_data.psh = 1 if flags & 0x08 else 0
        packet_data.ack = 1 if flags & 0x10 else 0
        packet_data.urg = 1 if flags & 0x20 else 0
        packet_data.ece = 1 if flags & 0x40 else 0
        packet_data.cwr = 1 if flags & 0x80 else 0

    # Extract UDP info
    elif UDP in pkt:
        packet_data.protocol = "UDP"
        packet_data.src_port = pkt[UDP].sport
        packet_data.dst_port = pkt[UDP].dport

    # ICMP
    elif ICMP in pkt:
        packet_data.protocol = "ICMP"

    return packet_data


def packet_handler(pkt):
    """Handle captured packet"""
    try:
        packet_info = extract_packet_info(pkt)
        if packet_info:
            # Update statistics
            statistics["total_packets"] += 1
            statistics["protocol_dist"][packet_info.protocol] += 1

            # Add to buffer
            traffic_buffer.append(packet_info.to_dict())

            # Limit buffer size
            if len(traffic_buffer) > MAX_BUFFER_SIZE:
                traffic_buffer.pop(0)

    except Exception as e:
        logger.error(f"Error handling packet: {e}")
        statistics["errors"] += 1


def capture_packets():
    """Start packet capture"""
    global capture_active
    capture_active = True

    logger.info("Starting packet capture...")

    try:
        sniff(
            prn=packet_handler,
            store=False,
            stop_filter=lambda p: capture_event.is_set(),
        )
    except PermissionError:
        logger.error(
            "Permission denied for packet capture. Run with elevated privileges."
        )
        capture_active = False
    except Exception as e:
        logger.error(f"Packet capture error: {e}")
        capture_active = False


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return (
        jsonify(
            {
                "service": "traffic-capture",
                "status": "healthy",
                "capture_active": capture_active,
                "uptime": time.time(),
            }
        ),
        200,
    )


@app.route("/capture/start", methods=["POST"])
def start_capture():
    """Start packet capture"""
    global capture_active

    if capture_active:
        return jsonify({"error": "Capture already active"}), 400

    capture_active = True  # Set capture as active
    capture_event.clear()
    capture_thread = Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return jsonify({"message": "Packet capture started", "status": "active"}), 200


@app.route("/capture/stop", methods=["POST"])
def stop_capture():
    """Stop packet capture"""
    global capture_active

    if not capture_active:
        return jsonify({"error": "Capture not active"}), 400

    capture_event.set()
    capture_active = False

    return jsonify({"message": "Packet capture stopped", "status": "inactive"}), 200


@app.route("/capture/status", methods=["GET"])
def capture_status():
    """Get capture status"""
    return (
        jsonify(
            {
                "active": capture_active,
                "buffer_size": len(traffic_buffer),
                "total_packets": statistics["total_packets"],
                "protocol_distribution": dict(statistics["protocol_dist"]),
            }
        ),
        200,
    )


@app.route("/packets/recent", methods=["GET"])
def get_recent_packets():
    """Get recent packets from buffer"""
    limit = request.args.get("limit", 100, type=int)
    return (
        jsonify(
            {"packets": traffic_buffer[-limit:], "count": len(traffic_buffer[-limit:])}
        ),
        200,
    )


@app.route("/packets/stream", methods=["GET"])
def stream_packets():
    """Stream packets (Server-Sent Events)"""
    # TODO: Implement SSE for real-time packet streaming
    return jsonify({"error": "Not implemented yet"}), 501


@app.route("/statistics", methods=["GET"])
def get_statistics():
    """Get traffic statistics"""
    return (
        jsonify(
            {
                "total_packets": statistics["total_packets"],
                "protocol_distribution": dict(statistics["protocol_dist"]),
                "buffer_size": len(traffic_buffer),
                "errors": statistics["errors"],
            }
        ),
        200,
    )


@app.route("/clear", methods=["POST"])
def clear_buffer():
    """Clear traffic buffer"""
    traffic_buffer.clear()
    return jsonify({"message": "Buffer cleared"}), 200


if __name__ == "__main__":
    port = app.config["TRAFFIC_CAPTURE_PORT"]
    logger.info(f"Starting Traffic Capture Service on port {port}")

    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
