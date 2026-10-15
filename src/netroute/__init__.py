"""
NetRoute: Mathematical Framework for TCP/IP Route Verification and Abnormality Detection.

A rigorous, semiring-theoretic and information-theoretic toolkit for network route
correctness proofs, forwarding verification, loop/black-hole detection, BGP valley-free
auditing, and statistical route anomaly detection.
"""

__version__ = "1.0.0"
__author__ = "NetRoute Research Group"
__license__ = "MIT"

from netroute.types import (
    IPPrefix,
    Node,
    Edge,
    NodeType,
    ASRelationship,
    RoutePath,
    ForwardingRule,
    ForwardingTable,
    VerificationStatus,
    VerificationResult,
    AnomalyType,
    AnomalySeverity,
    AnomalyRecord,
)
from netroute.algebra.semiring import (
    RoutingSemiring,
    ShortestPathSemiring,
    WidestPathSemiring,
    LexicographicSemiring,
    GaoRexfordPolicySemiring,
)
from netroute.graph.topology import NetworkTopology
from netroute.graph.fib import RouterFIB
from netroute.checker.route_checker import RouteChecker
from netroute.anomaly.detector import RouteAnomalyDetector

__all__ = [
    "__version__",
    "IPPrefix",
    "Node",
    "Edge",
    "NodeType",
    "ASRelationship",
    "RoutePath",
    "ForwardingRule",
    "ForwardingTable",
    "VerificationStatus",
    "VerificationResult",
    "AnomalyType",
    "AnomalySeverity",
    "AnomalyRecord",
    "RoutingSemiring",
    "ShortestPathSemiring",
    "WidestPathSemiring",
    "LexicographicSemiring",
    "GaoRexfordPolicySemiring",
    "NetworkTopology",
    "RouterFIB",
    "RouteChecker",
    "RouteAnomalyDetector",
]
