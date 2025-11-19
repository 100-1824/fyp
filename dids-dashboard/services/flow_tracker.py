import time
import numpy as np
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class FlowTracker:
    """Track and aggregate network flows for AI feature extraction"""
    
    def __init__(self, flow_timeout: int = 120, max_flows: int = 10000):
        """
        Initialize flow tracker.
        
        Args:
            flow_timeout: Timeout for inactive flows in seconds
            max_flows: Maximum number of flows to track
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.flows = {}  # flow_key -> FlowData
        self.last_cleanup = time.time()
    
    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int = 0, dst_port: int = 0, protocol: str = '') -> str:
        """Generate unique flow key"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
    
    def update_flow(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """
        Update flow with new packet and extract features.
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Dictionary of aggregated flow features
        """
        try:
            # Extract packet info
            src_ip = packet_data.get('source', '0.0.0.0')
            dst_ip = packet_data.get('destination', '0.0.0.0')
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            protocol = packet_data.get('protocol', 'TCP')
            size = packet_data.get('size', 0)
            timestamp = time.time()
            
            # Get TCP flags
            flags = {
                'fin': packet_data.get('fin', 0),
                'syn': packet_data.get('syn', 0),
                'rst': packet_data.get('rst', 0),
                'psh': packet_data.get('psh', 0),
                'ack': packet_data.get('ack', 0),
                'urg': packet_data.get('urg', 0),
                'ece': packet_data.get('ece', 0),
                'cwr': packet_data.get('cwr', 0)
            }
            
            # Create flow key (bidirectional)
            flow_key = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            reverse_key = self.get_flow_key(dst_ip, src_ip, dst_port, src_port, protocol)
            
            # Check if flow exists (forward or reverse)
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                direction = 'forward'
            elif reverse_key in self.flows:
                flow = self.flows[reverse_key]
                flow_key = reverse_key
                direction = 'backward'
            else:
                # Create new flow
                flow = FlowData(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
                self.flows[flow_key] = flow
                direction = 'forward'
            
            # Update flow with packet
            flow.add_packet(size, timestamp, direction, flags)
            
            # Cleanup old flows periodically
            if time.time() - self.last_cleanup > 60:  # Every minute
                self.cleanup_flows()
            
            # Extract features
            features = flow.extract_features()
            
            return features
            
        except Exception as e:
            logger.error(f"Error updating flow: {e}")
            return None
    
    def cleanup_flows(self):
        """Remove old/inactive flows"""
        current_time = time.time()
        flows_to_remove = []
        
        for flow_key, flow in self.flows.items():
            if current_time - flow.last_seen > self.flow_timeout:
                flows_to_remove.append(flow_key)
        
        for flow_key in flows_to_remove:
            del self.flows[flow_key]
        
        # Also remove oldest flows if we exceed max
        if len(self.flows) > self.max_flows:
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].last_seen)
            to_remove = len(self.flows) - self.max_flows
            for flow_key, _ in sorted_flows[:to_remove]:
                del self.flows[flow_key]
        
        self.last_cleanup = current_time
        
        if flows_to_remove:
            logger.debug(f"Cleaned up {len(flows_to_remove)} old flows")
    
    def get_flow_count(self) -> int:
        """Get current number of tracked flows"""
        return len(self.flows)


class FlowData:
    """Store and compute features for a network flow"""
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen = start_time
        
        # Packet tracking
        self.fwd_packets = []  # List of (size, timestamp)
        self.bwd_packets = []  # List of (size, timestamp)
        
        # Flag counts
        self.flags = {
            'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
            'ack': 0, 'urg': 0, 'ece': 0, 'cwr': 0
        }
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        
        # Header lengths (estimated)
        self.fwd_header_length = 0
        self.bwd_header_length = 0
    
    def add_packet(self, size: int, timestamp: float, direction: str, flags: Dict[str, int]):
        """Add packet to flow"""
        self.last_seen = timestamp
        
        # Add to appropriate direction
        if direction == 'forward':
            self.fwd_packets.append((size, timestamp))
            self.fwd_header_length += 20  # Estimate IP header
            if flags.get('psh', 0):
                self.fwd_psh_flags += 1
            if flags.get('urg', 0):
                self.fwd_urg_flags += 1
        else:
            self.bwd_packets.append((size, timestamp))
            self.bwd_header_length += 20
            if flags.get('psh', 0):
                self.bwd_psh_flags += 1
            if flags.get('urg', 0):
                self.bwd_urg_flags += 1
        
        # Update flag counts
        for flag, count in flags.items():
            if flag in self.flags:
                self.flags[flag] += count
    
    def extract_features(self) -> Dict[str, float]:
        """Extract 41 features matching the model's expected input"""
        features = {}
        
        # Flow duration
        duration = max(self.last_seen - self.start_time, 0.000001)  # Avoid division by zero
        features['Flow Duration'] = duration
        
        # Forward packet statistics
        if self.fwd_packets:
            fwd_sizes = [p[0] for p in self.fwd_packets]
            features['Fwd Packet Length Max'] = float(max(fwd_sizes))
            features['Fwd Packet Length Min'] = float(min(fwd_sizes))
            features['Fwd Packet Length Mean'] = float(np.mean(fwd_sizes))
            features['Fwd Packet Length Std'] = float(np.std(fwd_sizes))
        else:
            features['Fwd Packet Length Max'] = 0.0
            features['Fwd Packet Length Min'] = 0.0
            features['Fwd Packet Length Mean'] = 0.0
            features['Fwd Packet Length Std'] = 0.0
        
        # Backward packet statistics
        if self.bwd_packets:
            bwd_sizes = [p[0] for p in self.bwd_packets]
            features['Bwd Packet Length Max'] = float(max(bwd_sizes))
            features['Bwd Packet Length Min'] = float(min(bwd_sizes))
            features['Bwd Packet Length Mean'] = float(np.mean(bwd_sizes))
            features['Bwd Packet Length Std'] = float(np.std(bwd_sizes))
        else:
            features['Bwd Packet Length Max'] = 0.0
            features['Bwd Packet Length Min'] = 0.0
            features['Bwd Packet Length Mean'] = 0.0
            features['Bwd Packet Length Std'] = 0.0
        
        # Flow bytes/packets per second
        total_bytes = sum(p[0] for p in self.fwd_packets) + sum(p[0] for p in self.bwd_packets)
        total_packets = len(self.fwd_packets) + len(self.bwd_packets)
        features['Flow Bytes/s'] = total_bytes / duration
        features['Flow Packets/s'] = total_packets / duration
        
        # Inter-arrival times (IAT) - Flow level
        all_timestamps = [p[1] for p in self.fwd_packets] + [p[1] for p in self.bwd_packets]
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
            fwd_timestamps = [p[1] for p in self.fwd_packets]
            fwd_iats = [fwd_timestamps[i+1] - fwd_timestamps[i] for i in range(len(fwd_timestamps)-1)]
            features['Fwd IAT Mean'] = float(np.mean(fwd_iats))
            features['Fwd IAT Std'] = float(np.std(fwd_iats))
            features['Fwd IAT Max'] = float(max(fwd_iats))
            features['Fwd IAT Min'] = float(min(fwd_iats))
        else:
            features['Fwd IAT Mean'] = 0.0
            features['Fwd IAT Std'] = 0.0
            features['Fwd IAT Max'] = 0.0
            features['Fwd IAT Min'] = 0.0
        
        # Backward IAT
        if len(self.bwd_packets) >= 2:
            bwd_timestamps = [p[1] for p in self.bwd_packets]
            bwd_iats = [bwd_timestamps[i+1] - bwd_timestamps[i] for i in range(len(bwd_timestamps)-1)]
            features['Bwd IAT Mean'] = float(np.mean(bwd_iats))
            features['Bwd IAT Std'] = float(np.std(bwd_iats))
            features['Bwd IAT Max'] = float(max(bwd_iats))
            features['Bwd IAT Min'] = float(min(bwd_iats))
        else:
            features['Bwd IAT Mean'] = 0.0
            features['Bwd IAT Std'] = 0.0
            features['Bwd IAT Max'] = 0.0
            features['Bwd IAT Min'] = 0.0
        
        # Flag counts
        features['FIN Flag Count'] = float(self.flags['fin'])
        features['SYN Flag Count'] = float(self.flags['syn'])
        features['RST Flag Count'] = float(self.flags['rst'])
        features['PSH Flag Count'] = float(self.flags['psh'])
        features['ACK Flag Count'] = float(self.flags['ack'])
        features['URG Flag Count'] = float(self.flags['urg'])
        features['ECE Flag Count'] = float(self.flags['ece'])
        features['CWR Flag Count'] = float(self.flags['cwr'])
        
        # Direction-specific flags
        features['Fwd PSH Flags'] = float(self.fwd_psh_flags)
        features['Bwd PSH Flags'] = float(self.bwd_psh_flags)
        features['Fwd URG Flags'] = float(self.fwd_urg_flags)
        features['Bwd URG Flags'] = float(self.bwd_urg_flags)
        
        # Header lengths
        features['Fwd Header Length'] = float(self.fwd_header_length)
        features['Bwd Header Length'] = float(self.bwd_header_length)
        
        # Packet length statistics (all packets)
        if total_packets > 0:
            all_sizes = [p[0] for p in self.fwd_packets] + [p[0] for p in self.bwd_packets]
            features['Packet Length Mean'] = float(np.mean(all_sizes))
            features['Packet Length Std'] = float(np.std(all_sizes))
            features['Packet Length Variance'] = float(np.var(all_sizes))
        else:
            features['Packet Length Mean'] = 0.0
            features['Packet Length Std'] = 0.0
            features['Packet Length Variance'] = 0.0
        
        # Down/Up Ratio
        bwd_bytes = sum(p[0] for p in self.bwd_packets)
        fwd_bytes = sum(p[0] for p in self.fwd_packets)
        if fwd_bytes > 0:
            features['Down/Up Ratio'] = bwd_bytes / fwd_bytes
        else:
            features['Down/Up Ratio'] = 0.0
        
        # Average packet size
        if total_packets > 0:
            features['Average Packet Size'] = total_bytes / total_packets
        else:
            features['Average Packet Size'] = 0.0
        
        return features