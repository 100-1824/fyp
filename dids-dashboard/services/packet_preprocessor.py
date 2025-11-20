"""
Comprehensive Packet Preprocessing Pipeline
Extracts 77 network flow features for ML/RL detection models
"""

import numpy as np
import time
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import logging
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw

logger = logging.getLogger(__name__)


class PacketPreprocessor:
    """
    Comprehensive packet preprocessing pipeline
    Extracts all 77 features required by AI/RL models
    """

    # Feature names (77 features matching CICIDS2017 dataset)
    FEATURE_NAMES = [
        # Flow basic features
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',

        # Flow rate features
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',

        # Forward/Backward IAT features
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',

        # TCP Flags
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s',

        # Packet length features
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',

        # Flag counts
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',

        # Average features
        'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',

        # Additional header features
        'Fwd Header Length.1',

        # Subflow features
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',

        # Subflow forward packets
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',

        # Init window size
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward',

        # Active/Idle times
        'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]

    def __init__(self):
        """Initialize packet preprocessor"""
        self.feature_count = len(self.FEATURE_NAMES)
        logger.info(f"Initialized PacketPreprocessor with {self.feature_count} features")

    def extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """
        Extract raw information from a Scapy packet

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary with packet information or None if invalid
        """
        try:
            if not packet.haslayer(IP):
                return None

            packet_info = {
                'timestamp': time.time(),
                'source': packet[IP].src,
                'destination': packet[IP].dst,
                'protocol': packet[IP].proto,
                'size': len(packet),
                'ttl': packet[IP].ttl,
                'ip_flags': packet[IP].flags,
                'ip_frag': packet[IP].frag
            }

            # TCP-specific fields
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info.update({
                    'protocol_name': 'TCP',
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'seq': tcp.seq,
                    'ack_num': tcp.ack,
                    'window': tcp.window,
                    'flags': {
                        'fin': int(tcp.flags.F),
                        'syn': int(tcp.flags.S),
                        'rst': int(tcp.flags.R),
                        'psh': int(tcp.flags.P),
                        'ack': int(tcp.flags.A),
                        'urg': int(tcp.flags.U),
                        'ece': int(tcp.flags.E),
                        'cwr': int(tcp.flags.C)
                    },
                    'header_length': tcp.dataofs * 4,
                    'payload_size': len(tcp.payload) if tcp.payload else 0
                })

            # UDP-specific fields
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info.update({
                    'protocol_name': 'UDP',
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'length': udp.len,
                    'header_length': 8,
                    'payload_size': len(udp.payload) if udp.payload else 0,
                    'flags': {
                        'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
                        'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0
                    }
                })

            # ICMP-specific fields
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info.update({
                    'protocol_name': 'ICMP',
                    'src_port': 0,
                    'dst_port': 0,
                    'icmp_type': icmp.type,
                    'icmp_code': icmp.code,
                    'header_length': 8,
                    'payload_size': len(icmp.payload) if icmp.payload else 0,
                    'flags': {
                        'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
                        'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0
                    }
                })

            else:
                # Other protocols
                packet_info.update({
                    'protocol_name': 'OTHER',
                    'src_port': 0,
                    'dst_port': 0,
                    'header_length': 20,  # IP header
                    'payload_size': len(packet[IP].payload) if packet[IP].payload else 0,
                    'flags': {
                        'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
                        'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0
                    }
                })

            # Add payload information
            if packet.haslayer(Raw):
                packet_info['payload'] = bytes(packet[Raw].load)
                packet_info['has_payload'] = True
            else:
                packet_info['has_payload'] = False

            return packet_info

        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None

    def extract_flow_features(self, flow_data: 'EnhancedFlowData') -> np.ndarray:
        """
        Extract all 77 features from flow data

        Args:
            flow_data: EnhancedFlowData object

        Returns:
            Numpy array of 77 features
        """
        features = flow_data.compute_all_features()

        # Ensure we have exactly 77 features
        feature_vector = np.zeros(77, dtype=np.float32)

        for i, feature_name in enumerate(self.FEATURE_NAMES):
            if feature_name in features:
                value = features[feature_name]
                # Handle inf and nan values
                if np.isnan(value) or np.isinf(value):
                    feature_vector[i] = 0.0
                else:
                    feature_vector[i] = float(value)
            else:
                feature_vector[i] = 0.0

        return feature_vector

    def normalize_features(self, features: np.ndarray, method: str = 'minmax') -> np.ndarray:
        """
        Normalize feature vector

        Args:
            features: Feature vector (77 features)
            method: Normalization method ('minmax' or 'standard')

        Returns:
            Normalized feature vector
        """
        if method == 'minmax':
            # Min-Max normalization to [0, 1]
            # Clip extreme values
            features = np.clip(features, -1e10, 1e10)

            min_val = np.min(features)
            max_val = np.max(features)

            if max_val - min_val > 0:
                normalized = (features - min_val) / (max_val - min_val)
            else:
                normalized = features

        elif method == 'standard':
            # Standardization (z-score)
            mean = np.mean(features)
            std = np.std(features)

            if std > 0:
                normalized = (features - mean) / std
            else:
                normalized = features

        else:
            normalized = features

        # Clip to reasonable range
        normalized = np.clip(normalized, -5.0, 5.0)

        return normalized

    def preprocess_packet(self, packet, flow_tracker: 'EnhancedFlowTracker') -> Tuple[Dict[str, Any], Optional[np.ndarray]]:
        """
        Complete preprocessing pipeline for a single packet

        Args:
            packet: Scapy packet
            flow_tracker: EnhancedFlowTracker instance

        Returns:
            Tuple of (packet_info dict, feature_vector array or None)
        """
        # Extract packet information
        packet_info = self.extract_packet_info(packet)

        if not packet_info:
            return None, None

        # Update flow and get flow data
        flow_data = flow_tracker.update_flow(packet_info)

        if not flow_data:
            return packet_info, None

        # Extract features from flow
        features = self.extract_flow_features(flow_data)

        # Normalize features
        normalized_features = self.normalize_features(features, method='minmax')

        # Add features to packet info
        packet_info['features'] = features.tolist()
        packet_info['normalized_features'] = normalized_features.tolist()
        packet_info['flow_id'] = flow_data.flow_id

        return packet_info, normalized_features


class EnhancedFlowData:
    """Enhanced flow data with comprehensive feature extraction (77 features)"""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 protocol: str, start_time: float):
        self.flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen = start_time

        # Packet lists: [(size, timestamp, flags, window, header_len, payload_len)]
        self.fwd_packets = []
        self.bwd_packets = []

        # Flag counters
        self.flags_count = {
            'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
            'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0
        }
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        # Window sizes
        self.init_win_bytes_forward = None
        self.init_win_bytes_backward = None

        # Active/Idle times
        self.active_times = []
        self.idle_times = []
        self.last_active = start_time
        self.active_threshold = 1.0  # 1 second

        # Bulk transfer tracking
        self.fwd_bulk_packets = 0
        self.fwd_bulk_bytes = 0
        self.bwd_bulk_packets = 0
        self.bwd_bulk_bytes = 0
        self.bulk_threshold = 4  # Minimum packets for bulk

    def add_packet(self, packet_info: Dict[str, Any], direction: str):
        """Add packet to flow"""
        timestamp = packet_info['timestamp']
        size = packet_info['size']
        flags = packet_info.get('flags', {})
        window = packet_info.get('window', 0)
        header_len = packet_info.get('header_length', 20)
        payload_len = packet_info.get('payload_size', 0)

        self.last_seen = timestamp

        # Track active/idle times
        time_diff = timestamp - self.last_active
        if time_diff > self.active_threshold:
            if len(self.fwd_packets) + len(self.bwd_packets) > 0:
                self.idle_times.append(time_diff)
        else:
            if time_diff > 0:
                self.active_times.append(time_diff)
        self.last_active = timestamp

        packet_data = (size, timestamp, flags, window, header_len, payload_len)

        if direction == 'forward':
            self.fwd_packets.append(packet_data)

            # Initial window size
            if self.init_win_bytes_forward is None and window > 0:
                self.init_win_bytes_forward = window

            # Flag counting
            if flags.get('psh', 0):
                self.fwd_psh_flags += 1
            if flags.get('urg', 0):
                self.fwd_urg_flags += 1

        else:  # backward
            self.bwd_packets.append(packet_data)

            # Initial window size
            if self.init_win_bytes_backward is None and window > 0:
                self.init_win_bytes_backward = window

            # Flag counting
            if flags.get('psh', 0):
                self.bwd_psh_flags += 1
            if flags.get('urg', 0):
                self.bwd_urg_flags += 1

        # Update overall flag counts
        for flag, count in flags.items():
            if flag in self.flags_count:
                self.flags_count[flag] += count

    def compute_all_features(self) -> Dict[str, float]:
        """Compute all 77 features"""
        features = {}

        # Basic counts
        total_fwd_packets = len(self.fwd_packets)
        total_bwd_packets = len(self.bwd_packets)
        total_packets = total_fwd_packets + total_bwd_packets

        # Duration
        duration = max(self.last_seen - self.start_time, 0.000001)
        features['Flow Duration'] = duration

        # Port
        features['Destination Port'] = float(self.dst_port)

        # Packet counts
        features['Total Fwd Packets'] = float(total_fwd_packets)
        features['Total Backward Packets'] = float(total_bwd_packets)

        # Packet lengths
        fwd_sizes = [p[0] for p in self.fwd_packets] if self.fwd_packets else [0]
        bwd_sizes = [p[0] for p in self.bwd_packets] if self.bwd_packets else [0]
        all_sizes = fwd_sizes + bwd_sizes

        features['Total Length of Fwd Packets'] = float(sum(fwd_sizes))
        features['Total Length of Bwd Packets'] = float(sum(bwd_sizes))

        # Forward packet stats
        features['Fwd Packet Length Max'] = float(max(fwd_sizes))
        features['Fwd Packet Length Min'] = float(min(fwd_sizes))
        features['Fwd Packet Length Mean'] = float(np.mean(fwd_sizes))
        features['Fwd Packet Length Std'] = float(np.std(fwd_sizes))

        # Backward packet stats
        features['Bwd Packet Length Max'] = float(max(bwd_sizes))
        features['Bwd Packet Length Min'] = float(min(bwd_sizes))
        features['Bwd Packet Length Mean'] = float(np.mean(bwd_sizes))
        features['Bwd Packet Length Std'] = float(np.std(bwd_sizes))

        # Flow rate
        total_bytes = sum(all_sizes)
        features['Flow Bytes/s'] = total_bytes / duration
        features['Flow Packets/s'] = total_packets / duration

        # Packet/sec per direction
        features['Fwd Packets/s'] = total_fwd_packets / duration
        features['Bwd Packets/s'] = total_bwd_packets / duration

        # IAT (Inter-Arrival Time) - Flow level
        all_timestamps = [p[1] for p in self.fwd_packets + self.bwd_packets]
        all_timestamps.sort()

        if len(all_timestamps) >= 2:
            iats = [all_timestamps[i+1] - all_timestamps[i] for i in range(len(all_timestamps)-1)]
            features['Flow IAT Mean'] = float(np.mean(iats))
            features['Flow IAT Std'] = float(np.std(iats))
            features['Flow IAT Max'] = float(max(iats))
            features['Flow IAT Min'] = float(min(iats))
        else:
            features['Flow IAT Mean'] = 0.0
            features['Flow IAT Std'] = 0.0
            features['Flow IAT Max'] = 0.0
            features['Flow IAT Min'] = 0.0

        # Forward IAT
        if len(self.fwd_packets) >= 2:
            fwd_times = [p[1] for p in self.fwd_packets]
            fwd_iats = [fwd_times[i+1] - fwd_times[i] for i in range(len(fwd_times)-1)]
            features['Fwd IAT Total'] = float(sum(fwd_iats))
            features['Fwd IAT Mean'] = float(np.mean(fwd_iats))
            features['Fwd IAT Std'] = float(np.std(fwd_iats))
            features['Fwd IAT Max'] = float(max(fwd_iats))
            features['Fwd IAT Min'] = float(min(fwd_iats))
        else:
            features['Fwd IAT Total'] = 0.0
            features['Fwd IAT Mean'] = 0.0
            features['Fwd IAT Std'] = 0.0
            features['Fwd IAT Max'] = 0.0
            features['Fwd IAT Min'] = 0.0

        # Backward IAT
        if len(self.bwd_packets) >= 2:
            bwd_times = [p[1] for p in self.bwd_packets]
            bwd_iats = [bwd_times[i+1] - bwd_times[i] for i in range(len(bwd_times)-1)]
            features['Bwd IAT Total'] = float(sum(bwd_iats))
            features['Bwd IAT Mean'] = float(np.mean(bwd_iats))
            features['Bwd IAT Std'] = float(np.std(bwd_iats))
            features['Bwd IAT Max'] = float(max(bwd_iats))
            features['Bwd IAT Min'] = float(min(bwd_iats))
        else:
            features['Bwd IAT Total'] = 0.0
            features['Bwd IAT Mean'] = 0.0
            features['Bwd IAT Std'] = 0.0
            features['Bwd IAT Max'] = 0.0
            features['Bwd IAT Min'] = 0.0

        # PSH and URG flags
        features['Fwd PSH Flags'] = float(self.fwd_psh_flags)
        features['Bwd PSH Flags'] = float(self.bwd_psh_flags)
        features['Fwd URG Flags'] = float(self.fwd_urg_flags)
        features['Bwd URG Flags'] = float(self.bwd_urg_flags)

        # Header lengths
        fwd_header_total = sum(p[4] for p in self.fwd_packets) if self.fwd_packets else 0
        bwd_header_total = sum(p[4] for p in self.bwd_packets) if self.bwd_packets else 0
        features['Fwd Header Length'] = float(fwd_header_total)
        features['Fwd Header Length.1'] = float(fwd_header_total)  # Duplicate feature in dataset
        features['Bwd Header Length'] = float(bwd_header_total)

        # Packet length statistics
        features['Min Packet Length'] = float(min(all_sizes))
        features['Max Packet Length'] = float(max(all_sizes))
        features['Packet Length Mean'] = float(np.mean(all_sizes))
        features['Packet Length Std'] = float(np.std(all_sizes))
        features['Packet Length Variance'] = float(np.var(all_sizes))

        # Flag counts
        features['FIN Flag Count'] = float(self.flags_count['fin'])
        features['SYN Flag Count'] = float(self.flags_count['syn'])
        features['RST Flag Count'] = float(self.flags_count['rst'])
        features['PSH Flag Count'] = float(self.flags_count['psh'])
        features['ACK Flag Count'] = float(self.flags_count['ack'])
        features['URG Flag Count'] = float(self.flags_count['urg'])
        features['CWE Flag Count'] = float(self.flags_count['cwr'])
        features['ECE Flag Count'] = float(self.flags_count['ece'])

        # Down/Up Ratio
        fwd_bytes = sum(fwd_sizes)
        bwd_bytes = sum(bwd_sizes)
        features['Down/Up Ratio'] = (bwd_bytes / fwd_bytes) if fwd_bytes > 0 else 0.0

        # Average sizes
        features['Average Packet Size'] = (total_bytes / total_packets) if total_packets > 0 else 0.0
        features['Avg Fwd Segment Size'] = (fwd_bytes / total_fwd_packets) if total_fwd_packets > 0 else 0.0
        features['Avg Bwd Segment Size'] = (bwd_bytes / total_bwd_packets) if total_bwd_packets > 0 else 0.0

        # Bulk features (simplified - need more complex logic for true bulk detection)
        features['Fwd Avg Bytes/Bulk'] = (self.fwd_bulk_bytes / max(self.fwd_bulk_packets, 1))
        features['Fwd Avg Packets/Bulk'] = float(self.fwd_bulk_packets)
        features['Fwd Avg Bulk Rate'] = (self.fwd_bulk_bytes / duration) if duration > 0 else 0.0
        features['Bwd Avg Bytes/Bulk'] = (self.bwd_bulk_bytes / max(self.bwd_bulk_packets, 1))
        features['Bwd Avg Packets/Bulk'] = float(self.bwd_bulk_packets)
        features['Bwd Avg Bulk Rate'] = (self.bwd_bulk_bytes / duration) if duration > 0 else 0.0

        # Subflow features
        features['Subflow Fwd Packets'] = float(total_fwd_packets)
        features['Subflow Fwd Bytes'] = float(fwd_bytes)
        features['Subflow Bwd Packets'] = float(total_bwd_packets)
        features['Subflow Bwd Bytes'] = float(bwd_bytes)

        # Initial window bytes
        features['Init_Win_bytes_forward'] = float(self.init_win_bytes_forward or 0)
        features['Init_Win_bytes_backward'] = float(self.init_win_bytes_backward or 0)

        # Active data packets forward (packets with payload)
        act_data_pkt_fwd = sum(1 for p in self.fwd_packets if p[5] > 0)
        features['act_data_pkt_fwd'] = float(act_data_pkt_fwd)

        # Min segment size forward (minimum payload size > 0)
        fwd_payloads = [p[5] for p in self.fwd_packets if p[5] > 0]
        features['min_seg_size_forward'] = float(min(fwd_payloads)) if fwd_payloads else 0.0

        # Active time statistics
        if self.active_times:
            features['Active Mean'] = float(np.mean(self.active_times))
            features['Active Std'] = float(np.std(self.active_times))
            features['Active Max'] = float(max(self.active_times))
            features['Active Min'] = float(min(self.active_times))
        else:
            features['Active Mean'] = 0.0
            features['Active Std'] = 0.0
            features['Active Max'] = 0.0
            features['Active Min'] = 0.0

        # Idle time statistics
        if self.idle_times:
            features['Idle Mean'] = float(np.mean(self.idle_times))
            features['Idle Std'] = float(np.std(self.idle_times))
            features['Idle Max'] = float(max(self.idle_times))
            features['Idle Min'] = float(min(self.idle_times))
        else:
            features['Idle Mean'] = 0.0
            features['Idle Std'] = 0.0
            features['Idle Max'] = 0.0
            features['Idle Min'] = 0.0

        return features


class EnhancedFlowTracker:
    """Enhanced flow tracker with 77-feature extraction"""

    def __init__(self, flow_timeout: int = 120, max_flows: int = 10000):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.flows = {}  # flow_key -> EnhancedFlowData
        self.last_cleanup = time.time()
        logger.info(f"Initialized EnhancedFlowTracker (timeout={flow_timeout}s, max_flows={max_flows})")

    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Generate bidirectional flow key"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"

    def update_flow(self, packet_info: Dict[str, Any]) -> Optional[EnhancedFlowData]:
        """Update flow with new packet"""
        try:
            src_ip = packet_info.get('source', '0.0.0.0')
            dst_ip = packet_info.get('destination', '0.0.0.0')
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            protocol = packet_info.get('protocol_name', 'TCP')
            timestamp = packet_info.get('timestamp', time.time())

            # Create flow keys
            fwd_key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            bwd_key = self.get_flow_key(dst_ip, src_ip, dst_port, src_port, protocol)

            # Find or create flow
            if fwd_key in self.flows:
                flow = self.flows[fwd_key]
                direction = 'forward'
            elif bwd_key in self.flows:
                flow = self.flows[bwd_key]
                fwd_key = bwd_key
                direction = 'backward'
            else:
                # Create new flow
                flow = EnhancedFlowData(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
                self.flows[fwd_key] = flow
                direction = 'forward'

            # Add packet to flow
            flow.add_packet(packet_info, direction)

            # Periodic cleanup
            if time.time() - self.last_cleanup > 60:
                self.cleanup_flows()

            return flow

        except Exception as e:
            logger.error(f"Error updating flow: {e}")
            return None

    def cleanup_flows(self):
        """Remove old/inactive flows"""
        current_time = time.time()
        to_remove = []

        for flow_key, flow in self.flows.items():
            if current_time - flow.last_seen > self.flow_timeout:
                to_remove.append(flow_key)

        for flow_key in to_remove:
            del self.flows[flow_key]

        # Limit max flows
        if len(self.flows) > self.max_flows:
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].last_seen)
            excess = len(self.flows) - self.max_flows
            for flow_key, _ in sorted_flows[:excess]:
                del self.flows[flow_key]

        self.last_cleanup = current_time

        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} old flows")

    def get_flow_count(self) -> int:
        """Get current number of tracked flows"""
        return len(self.flows)

    def get_all_flows(self) -> List[EnhancedFlowData]:
        """Get all tracked flows"""
        return list(self.flows.values())
