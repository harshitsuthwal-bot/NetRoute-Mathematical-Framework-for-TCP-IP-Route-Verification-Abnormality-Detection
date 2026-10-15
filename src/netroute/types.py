"""
Core mathematical and network domain data types for NetRoute.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class NodeType(str, Enum):
    """Categorical classification of network vertices."""
    HOST = "HOST"
    EDGE_ROUTER = "EDGE_ROUTER"
    CORE_ROUTER = "CORE_ROUTER"
    BGP_GATEWAY = "BGP_GATEWAY"
    LEAF = "LEAF"
    SPINE = "SPINE"


class ASRelationship(str, Enum):
    """
    Gao-Rexford inter-AS routing economic relationship:
    C2P: Customer-to-Provider (financial flow: Customer pays Provider)
    P2C: Provider-to-Customer
    P2P: Peer-to-Peer (settlement-free peering)
    INTRA: Intra-AS internal transit
    """
    CUSTOMER_TO_PROVIDER = "C2P"
    PROVIDER_TO_CUSTOMER = "P2C"
    PEER_TO_PEER = "P2P"
    INTRA = "INTRA"


class VerificationStatus(str, Enum):
    """Formal verification state of an inspected route path."""
    VALID = "VALID"
    LOOP_DETECTED = "LOOP_DETECTED"
    BLACK_HOLE = "BLACK_HOLE"
    MTU_VIOLATION = "MTU_VIOLATION"
    UNREACHABLE = "UNREACHABLE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ASYMMETRIC_FAILURE = "ASYMMETRIC_FAILURE"


class AnomalyType(str, Enum):
    """Classification of network route abnormalities."""
    ROUTE_FLAP = "ROUTE_FLAP"
    PATH_STRETCH = "PATH_STRETCH"
    BGP_VALLEY_FREE_VIOLATION = "BGP_VALLEY_FREE_VIOLATION"
    PREFIX_HIJACK = "PREFIX_HIJACK"
    ENTROPY_COLLAPSE = "ENTROPY_COLLAPSE"
    LATENCY_DRIFT = "LATENCY_DRIFT"
    JITTER_ANOMALY = "JITTER_ANOMALY"


class AnomalySeverity(str, Enum):
    """Severity magnitude for detected routing anomalies."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class IPPrefix:
    """
    Mathematical representation of an IP Prefix over the binary prefix lattice {0,1}*
    supporting partial order containment (sub-prefix / super-prefix relations).
    """
    network_str: str

    def __post_init__(self) -> None:
        try:
            net = ipaddress.ip_network(self.network_str, strict=False)
            object.__setattr__(self, "_network", net)
        except ValueError as err:
            raise ValueError(f"Invalid IP prefix specification '{self.network_str}': {err}") from err

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return object.__getattribute__(self, "_network")

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen

    @property
    def max_prefixlen(self) -> int:
        return self.network.max_prefixlen

    @property
    def num_addresses(self) -> int:
        return self.network.num_addresses

    def contains_ip(self, ip_str: str) -> bool:
        """Predicate: ip in prefix."""
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj in self.network

    def is_subprefix_of(self, other: "IPPrefix") -> bool:
        """
        Partial order relation: p_1 <= p_2 iff p_1 is a sub-prefix of p_2
        (i.e., p_1 represents a smaller or equal subset of the address space).
        """
        return self.network.subnet_of(other.network)

    def is_superprefix_of(self, other: "IPPrefix") -> bool:
        """Predicate: p_1 >= p_2 iff p_1 contains p_2 as a sub-prefix."""
        return self.network.supernet_of(other.network)

    def overlaps(self, other: "IPPrefix") -> bool:
        """Predicate: p_1 intersection p_2 != empty."""
        return self.network.overlaps(other.network)

    def __repr__(self) -> str:
        return f"IPPrefix({self.network_str})"

    def __str__(self) -> str:
        return str(self.network)


@dataclass(frozen=True)
class Node:
    """A vertex in the network topology graph G = (V, E)."""
    id: str
    asn: int = 65000
    node_type: NodeType = NodeType.CORE_ROUTER
    label: Optional[str] = None

    def __repr__(self) -> str:
        lbl = f" ({self.label})" if self.label else ""
        return f"Node({self.id}, AS{self.asn}{lbl})"


@dataclass(frozen=True)
class Edge:
    """
    A directed edge e = (u, v) in G = (V, E) with vector attribute vector:
    w(e) = (metric, delay_ms, capacity_mbps, loss_rate, mtu, relationship)
    """
    src: str
    dst: str
    metric: float = 1.0
    delay_ms: float = 1.0
    capacity_mbps: float = 10000.0
    loss_rate: float = 0.0
    mtu: int = 1500
    relationship: ASRelationship = ASRelationship.INTRA
    interface_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.metric < 0:
            raise ValueError(f"Edge metric must be non-negative, got {self.metric}")
        if self.delay_ms < 0:
            raise ValueError(f"Edge delay must be non-negative, got {self.delay_ms}")
        if self.capacity_mbps <= 0:
            raise ValueError(f"Edge capacity must be positive, got {self.capacity_mbps}")
        if not (0.0 <= self.loss_rate <= 1.0):
            raise ValueError(f"Edge loss_rate must be in [0, 1], got {self.loss_rate}")
        if self.mtu <= 0:
            raise ValueError(f"Edge MTU must be positive, got {self.mtu}")

    def __repr__(self) -> str:
        return (
            f"Edge({self.src} -> {self.dst}, cost={self.metric}, "
            f"delay={self.delay_ms}ms, mtu={self.mtu}, {self.relationship.value})"
        )


@dataclass
class RoutePath:
    """
    Formal representation of a forwarding path P = (v_0, e_1, v_1, ..., e_k, v_k).
    """
    nodes: List[str]
    edges: List[Edge] = field(default_factory=list)

    @property
    def hop_count(self) -> int:
        return max(0, len(self.nodes) - 1)

    @property
    def total_metric(self) -> float:
        return sum(e.metric for e in self.edges)

    @property
    def total_delay_ms(self) -> float:
        return sum(e.delay_ms for e in self.edges)

    @property
    def bottleneck_capacity_mbps(self) -> float:
        if not self.edges:
            return float("inf")
        return min(e.capacity_mbps for e in self.edges)

    @property
    def bottleneck_mtu(self) -> int:
        if not self.edges:
            return 65535
        return min(e.mtu for e in self.edges)

    @property
    def end_to_end_delivery_prob(self) -> float:
        """Product of (1 - loss_rate) along the path."""
        p = 1.0
        for e in self.edges:
            p *= (1.0 - e.loss_rate)
        return p

    def has_loop(self) -> bool:
        """Determines if the sequence of nodes contains any cyclic recurrence."""
        return len(self.nodes) != len(set(self.nodes))

    def detect_cycles(self) -> List[List[str]]:
        """Returns all cyclic subpaths found in this path."""
        visited: Dict[str, int] = {}
        cycles: List[List[str]] = []
        for idx, node in enumerate(self.nodes):
            if node in visited:
                first_idx = visited[node]
                cycle_subpath = self.nodes[first_idx : idx + 1]
                cycles.append(cycle_subpath)
            visited[node] = idx
        return cycles

    def __repr__(self) -> str:
        return f"RoutePath({' -> '.join(self.nodes)}, cost={self.total_metric:.2f}, delay={self.total_delay_ms:.2f}ms)"


@dataclass
class ForwardingRule:
    """
    A single FIB rule at a router matching a prefix to a set of next-hops.
    """
    prefix: IPPrefix
    next_hops: List[str]
    metric: float = 1.0
    priority: int = 100
    installed_protocol: str = "BGP"

    def __repr__(self) -> str:
        return f"Rule({self.prefix} -> {self.next_hops}, prio={self.priority})"


@dataclass
class ForwardingTable:
    """
    FIB (Forwarding Information Base) model per network node.
    Implements Longest Prefix Match (LPM) partial order resolution.
    """
    node_id: str
    rules: List[ForwardingRule] = field(default_factory=list)

    def add_rule(self, rule: ForwardingRule) -> None:
        self.rules.append(rule)

    def match(self, destination: str | IPPrefix) -> Optional[ForwardingRule]:
        """
        Computes Longest Prefix Match (LPM) argmax_{r in FIB} r.prefixlen
        such that destination is in r.prefix.
        Ties in prefix length are resolved by priority (lower priority value = more preferred).
        """
        target_ip = ipaddress.ip_network(str(destination), strict=False)
        candidates: List[ForwardingRule] = []

        for r in self.rules:
            if target_ip.subnet_of(r.prefix.network) or target_ip == r.prefix.network:
                candidates.append(r)

        if not candidates:
            return None

        # Sort by prefix length descending (LPM), then priority ascending
        candidates.sort(key=lambda r: (-r.prefix.prefixlen, r.priority, r.metric))
        return candidates[0]


@dataclass
class VerificationResult:
    """
    Formal certificate of route check outcome with diagnostics and proofs.
    """
    status: VerificationStatus
    src: str
    dst: str
    prefix: IPPrefix
    forward_path: Optional[RoutePath] = None
    reverse_path: Optional[RoutePath] = None
    tcp_handshake_feasible: bool = False
    estimated_rtt_ms: float = 0.0
    path_mtu: int = 0
    cycle_detected: Optional[List[str]] = None
    black_hole_node: Optional[str] = None
    details: str = ""
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return self.status == VerificationStatus.VALID

    def __repr__(self) -> str:
        return (
            f"VerificationResult(status={self.status.value}, "
            f"src={self.src}, dst={self.dst}, prefix={self.prefix}, "
            f"tcp_ok={self.tcp_handshake_feasible}, RTT={self.estimated_rtt_ms:.2f}ms)"
        )


@dataclass
class AnomalyRecord:
    """
    Detailed anomaly occurrence telemetry record.
    """
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    target_id: str
    affected_prefix: Optional[IPPrefix] = None
    metric_value: float = 0.0
    threshold_value: float = 0.0
    score: float = 0.0
    timestamp_sec: float = 0.0
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"AnomalyRecord([{self.severity.value}] {self.anomaly_type.value} "
            f"on {self.target_id}: score={self.score:.3f}, {self.description})"
        )
