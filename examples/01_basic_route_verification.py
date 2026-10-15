"""
Example 1: Basic Route Verification, Loop Detection, and Black-Hole Analysis.
"""

from netroute.checker.route_checker import RouteChecker
from netroute.simulator.topologies import build_hierarchical_bgp_topology, build_synthetic_loop_topology
from netroute.simulator.faults import FaultInjector
from netroute.types import IPPrefix, VerificationStatus


def main():
    print("=" * 70)
    print("Example 1: End-to-End Route Verification & Fault Analysis")
    print("=" * 70)

    # 1. Verification on Healthy Topology
    topo = build_hierarchical_bgp_topology()
    checker = RouteChecker(topo)
    dst_prefix = IPPrefix("198.51.100.0/24")
    src_prefix = IPPrefix("203.0.113.0/24")

    print("\n[Scenario A] Healthy Internet Path:")
    res_healthy = checker.verify_route(
        src="R_Stub_E",
        dst="R_Stub_F",
        prefix=dst_prefix,
        reverse_prefix=src_prefix,
    )
    print(f"  Result Status         : {res_healthy.status.value}")
    print(f"  Forward Forwarding    : {' -> '.join(res_healthy.forward_path.nodes)}")
    print(f"  Reverse Forwarding    : {' -> '.join(res_healthy.reverse_path.nodes)}")
    print(f"  TCP Handshake OK      : {res_healthy.tcp_handshake_feasible}")
    print(f"  Estimated RTT         : {res_healthy.estimated_rtt_ms:.2f} ms")

    # 2. Loop Detection on Cyclic FIB configuration
    print("\n[Scenario B] Cyclic Routing Microloop Detection:")
    loop_topo = build_synthetic_loop_topology()
    loop_checker = RouteChecker(loop_topo)
    res_loop = loop_checker.verify_route(src="A", dst="D", prefix=IPPrefix("10.0.0.0/24"))
    print(f"  Result Status         : {res_loop.status.value}")
    print(f"  Cycle Detected        : {' -> '.join(res_loop.cycle_detected)}")
    print(f"  Diagnostic Details    : {res_loop.details}")

    # 3. Black-hole Detection on Severed Egress Link
    print("\n[Scenario C] Link Failure & Black-Hole Discovery:")
    injector = FaultInjector(topo)
    injector.inject_link_cut("R_T2_C", "R_T2_D")
    res_bh = checker.verify_route(src="R_Stub_E", dst="R_Stub_F", prefix=dst_prefix)
    print(f"  Result Status         : {res_bh.status.value}")
    print(f"  Black-Hole Router     : {res_bh.black_hole_node}")
    print(f"  Diagnostic Details    : {res_bh.details}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
