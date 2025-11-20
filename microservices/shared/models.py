"""
Shared data models for microservices communication
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class PacketData:
    """Packet information"""

    timestamp: str
    source: str
    destination: str
    protocol: str
    size: int
    src_port: int = 0
    dst_port: int = 0

    # TCP flags
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0
    ece: int = 0
    cwr: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ThreatDetection:
    """Threat detection result"""

    timestamp: str
    source: str
    destination: str
    protocol: str
    threat_type: str
    severity: str
    signature: str
    confidence: float
    action: str  # allow, alert, block
    description: str
    detector: str  # signature, ai, rl

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AIDetectionResult:
    """AI detection result"""

    attack_type: str
    confidence: float
    severity: str
    probabilities: Dict[str, float]
    model: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class RLDecision:
    """RL agent decision"""

    action: str  # allow, alert, block
    confidence: float
    q_values: Dict[str, float]
    reason: str
    rl_based: bool

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FlowFeatures:
    """Network flow features for ML"""

    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    flow_bytes_per_sec: float
    flow_packets_per_sec: float
    features: Dict[str, float]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ServiceHealth:
    """Service health status"""

    service_name: str
    status: str  # healthy, degraded, unhealthy
    uptime: float
    requests_processed: int
    errors: int
    last_check: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Statistics:
    """System statistics"""

    total_packets: int
    total_threats: int
    threats_blocked: int
    ai_detections: int
    rl_decisions: int
    protocol_distribution: Dict[str, int]
    top_sources: Dict[str, int]

    def to_dict(self) -> Dict:
        return asdict(self)
