"""
Example 2: BGP Valley-Free Policy Auditing and Prefix Hijack Detection.
"""

from netroute.anomaly.detector import RouteAnomalyDetector
from netroute.checker.route_checker import RouteChecker
from netroute.simulator.topologies import build_hierarchical_bgp_topology
from netroute.types import ForwardingRule, IPPrefix, VerificationStatus


def main():
    print("=" * 70)
    print("Example 2: BGP Valley-Free Route Leak & Hijack Detection")
    print("=" * 70)

    topo = build_hierarchical_bgp_topology()
    checker = RouteChecker(topo)
    detector = RouteAnomalyDetector(topo)
    target_prefix = IPPrefix("198.51.100.0/24")

    # 1. Valley-Free Violation (Route Leak)
    # Force Tier-2 router C to route through Tier-1 A instead of peer D,
    # causing Provider-to-Customer followed by Customer-to-Provider leak
    print("\n[Scenario A] AS Route Leak Detection (Gao-Rexford Violation):")
    topo.get_fib("R_T2_C").insert(
        ForwardingRule(prefix=target_prefix, next_hops=["R_T1_A"], priority=1)
    )
    res_leak = checker.verify_route(
        src="R_Stub_E",
        dst="R_Stub_F",
        prefix=target_prefix,
        enforce_valley_free=True,
    )
    print(f"  Verification Status   : {res_leak.status.value}")
    print(f"  Diagnostic Details    : {res_leak.details}")

    # 2. MOAS (Multiple Origin AS) Exact Prefix Hijacking
    print("\n[Scenario B] BGP Exact Prefix Hijacking (MOAS Conflict):")
    auth_registry = {IPPrefix("198.51.100.0/24"): 600}  # AS600 is legitimate owner
    rec_exact = detector.check_prefix_hijack(
        announced_prefix=IPPrefix("198.51.100.0/24"),
        originating_as=666,  # Rogue AS
        authoritative_registry=auth_registry,
    )
    if rec_exact:
        print(f"  Anomaly Detected      : [{rec_exact.severity.value}] {rec_exact.anomaly_type.value}")
        print(f"  Description           : {rec_exact.description}")

    # 3. Sub-Prefix De-aggregation Hijack
    print("\n[Scenario C] Sub-Prefix De-aggregation Hijacking (/25 within /24):")
    rec_sub = detector.check_prefix_hijack(
        announced_prefix=IPPrefix("198.51.100.0/25"),
        originating_as=777,
        authoritative_registry=auth_registry,
    )
    if rec_sub:
        print(f"  Anomaly Detected      : [{rec_sub.severity.value}] {rec_sub.anomaly_type.value}")
        print(f"  Description           : {rec_sub.description}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
