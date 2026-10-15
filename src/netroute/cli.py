"""
NetRoute Command-Line Interface (CLI).
Provides terminal commands for route verification, anomaly audits, and benchmark executions.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict

from netroute import __version__
from netroute.anomaly.detector import RouteAnomalyDetector
from netroute.checker.route_checker import RouteChecker
from netroute.graph.topology import NetworkTopology
from netroute.simulator.faults import FaultInjector
from netroute.simulator.topologies import (
    build_fat_tree,
    build_hierarchical_bgp_topology,
    build_synthetic_loop_topology,
)
from netroute.types import ForwardingRule, IPPrefix


def cmd_verify(args: argparse.Namespace) -> int:
    """Runs formal route verification."""
    topo = build_hierarchical_bgp_topology()
    checker = RouteChecker(topo)
    pfx = IPPrefix(args.prefix)
    rev_pfx = IPPrefix(args.rev_prefix) if args.rev_prefix else None

    print("=" * 70)
    print("NetRoute Formal Route Verification Engine")
    print("=" * 70)
    print(f"Topology       : {topo.name} (|V|={len(topo.nodes)}, |E|={sum(len(l) for l in topo.edges.values())})")
    print(f"Source Node    : {args.src}")
    print(f"Dest Node      : {args.dst}")
    print(f"Forward Prefix : {pfx}")
    print(f"Reverse Prefix : {rev_pfx}")
    print(f"Required MTU   : {args.mtu}")
    print("-" * 70)

    t0 = time.perf_counter()
    res = checker.verify_route(
        src=args.src,
        dst=args.dst,
        prefix=pfx,
        reverse_prefix=rev_pfx,
        required_mtu=args.mtu,
        enforce_valley_free=args.valley_free,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    print(f"Verification Status : {res.status.value}")
    print(f"TCP Handshake Feas. : {'PASS' if res.tcp_handshake_feasible else 'FAIL'}")
    print(f"Estimated RTT       : {res.estimated_rtt_ms:.3f} ms")
    print(f"Path Bottleneck MTU : {res.path_mtu} bytes")
    if res.forward_path:
        print(f"Forward Path        : {' -> '.join(res.forward_path.nodes)}")
    if res.reverse_path:
        print(f"Reverse Path        : {' -> '.join(res.reverse_path.nodes)}")
    if res.cycle_detected:
        print(f"CYCLE DETECTED      : {' -> '.join(res.cycle_detected)}")
    if res.black_hole_node:
        print(f"BLACK HOLE NODE     : {res.black_hole_node}")
    print(f"Diagnostics Details : {res.details}")
    print(f"Verification Time   : {elapsed_ms:.4f} ms")
    print("=" * 70)

    return 0 if res.is_valid() else 1


def cmd_scan_anomalies(args: argparse.Namespace) -> int:
    """Scans for routing abnormalities and BGP policy leaks."""
    topo = build_hierarchical_bgp_topology()
    detector = RouteAnomalyDetector(topo)
    injector = FaultInjector(topo)

    print("=" * 70)
    print("NetRoute Mathematical Abnormality Scan")
    print("=" * 70)

    # 1. Simulate ECMP Entropy Collapse
    print("\n[*] Auditing ECMP Flow Entropy...")
    # Balanced flows
    res_balanced = detector.check_ecmp_entropy("R_Core_1", [2500, 2480, 2520, 2500])
    print(f"  - Balanced ECMP (4x ~2500 flows) : {'ANOMALY' if res_balanced else 'NORMAL (Entropy ~1.0)'}")

    # Collapsed flows (polarization)
    res_collapsed = detector.check_ecmp_entropy("R_Core_2", [9800, 150, 40, 10])
    if res_collapsed:
        print(f"  - Collapsed ECMP (Polarization) : [{res_collapsed.severity.value}] {res_collapsed.description}")

    # 2. Simulate BGP Route Hijack
    print("\n[*] Auditing Autonomous System Prefix Ownership...")
    auth_registry = {IPPrefix("198.51.100.0/24"): 600}
    hijack_record = detector.check_prefix_hijack(
        announced_prefix=IPPrefix("198.51.100.0/24"),
        originating_as=666,  # Rogue AS
        authoritative_registry=auth_registry,
    )
    if hijack_record:
        print(f"  - Exact Prefix Hijack Scan     : [{hijack_record.severity.value}] {hijack_record.description}")

    # 3. Simulate Route Flap Damping
    print("\n[*] Auditing Route Flap Damping (RFC 2439 Dynamic Penalty)...")
    t_sim = 1000.0
    for i in range(4):
        t_sim += 10.0
        rec = detector.register_route_flap("198.51.100.0/24", t_sim)
        if rec:
            print(f"  - Flap #{i+1} at t={t_sim}s             : [{rec.severity.value}] {rec.description}")
        else:
            print(f"  - Flap #{i+1} at t={t_sim}s             : Penalty accumulated (below suppress)")

    # 4. Statistical Latency Drift (KL-Divergence)
    print("\n[*] Auditing Telemetry Latency Drift via KL Divergence...")
    baseline = [12.0, 12.5, 11.8, 12.2, 12.1, 12.4, 11.9, 12.3]
    drifted = [35.2, 42.1, 38.6, 50.1, 39.4, 45.0, 41.2, 37.8]
    drift_rec = detector.check_latency_drift_kl("FLOW_T2C_TO_T2D", baseline, drifted)
    if drift_rec:
        print(f"  - Telemetry KL-Divergence Drift: [{drift_rec.severity.value}] {drift_rec.description}")

    print("\n" + "=" * 70)
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Executes high-throughput scalability benchmark."""
    k = args.k
    print("=" * 70)
    print(f"NetRoute Performance Benchmark: Fat-Tree Topology (k={k})")
    print("=" * 70)

    t0 = time.perf_counter()
    topo = build_fat_tree(k=k)
    t_build = (time.perf_counter() - t0) * 1000.0

    num_nodes = len(topo.nodes)
    num_edges = sum(len(l) for l in topo.edges.values())
    print(f"Topology constructed in {t_build:.2f} ms:")
    print(f"  Vertices |V| : {num_nodes}")
    print(f"  Edges    |E| : {num_edges}")

    # Compute Spectral Laplacian Connectivity
    print("\n[*] Computing Spectral Graph Laplacian & Algebraic Connectivity (lambda_2)...")
    t_spec = time.perf_counter()
    l2, fiedler = topo.compute_laplacian_spectrum()
    spec_ms = (time.perf_counter() - t_spec) * 1000.0
    print(f"  Algebraic Connectivity lambda_2 = {l2:.4f} (computed in {spec_ms:.2f} ms)")
    print(f"  Graph Partition Status          = {'CONNECTED & ROBUST' if l2 > 0.01 else 'PARTITIONED / WEAK'}")

    # Benchmark Dijkstra shortest path calculations
    nodes_sample = list(topo.nodes.keys())[: min(20, num_nodes)]
    print(f"\n[*] Benchmarking All-Pairs Paths across {len(nodes_sample)} sample nodes...")
    t_path = time.perf_counter()
    path_count = 0
    for u in nodes_sample:
        for v in nodes_sample:
            if u != v:
                p = topo.shortest_path_dijkstra(u, v)
                if p:
                    path_count += 1
    total_path_time = time.perf_counter() - t_path
    rate = path_count / max(1e-6, total_path_time)
    print(f"  Computed {path_count} shortest paths in {total_path_time * 1000.0:.2f} ms")
    print(f"  Throughput: {rate:,.0f} path computations/sec")
    print("=" * 70)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netroute",
        description="Mathematical Framework for TCP/IP Route Verification & Abnormality Detection",
    )
    parser.add_argument("--version", action="version", version=f"netroute {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Verify subcommand
    p_verify = subparsers.add_parser("verify", help="Run formal route verification")
    p_verify.add_argument("--src", default="R_Stub_E", help="Source node ID")
    p_verify.add_argument("--dst", default="R_Stub_F", help="Destination node ID")
    p_verify.add_argument("--prefix", default="198.51.100.0/24", help="Destination IP prefix (forward flow)")
    p_verify.add_argument("--rev-prefix", default="203.0.113.0/24", help="Source IP prefix (reverse TCP return flow)")
    p_verify.add_argument("--mtu", type=int, default=1500, help="Required path MTU")
    p_verify.add_argument("--valley-free", action="store_true", default=True, help="Enforce AS valley-free rule")
    p_verify.set_defaults(func=cmd_verify)

    # Anomaly Scan subcommand
    p_scan = subparsers.add_parser("scan-anomalies", help="Execute route abnormality detection suite")
    p_scan.set_defaults(func=cmd_scan_anomalies)

    # Benchmark subcommand
    p_bench = subparsers.add_parser("benchmark", help="Run scalability and spectral benchmarks")
    p_bench.add_argument("--k", type=int, default=4, help="Fat-Tree k parameter (even integer)")
    p_bench.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
