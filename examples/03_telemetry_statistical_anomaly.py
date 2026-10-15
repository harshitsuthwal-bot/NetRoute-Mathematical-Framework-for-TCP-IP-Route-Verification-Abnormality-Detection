"""
Example 3: Statistical Telemetry Anomaly Detection (Flap Decay, Entropy Collapse, KL-Divergence).
"""

from netroute.anomaly.detector import RouteAnomalyDetector
from netroute.simulator.topologies import build_hierarchical_bgp_topology


def main():
    print("=" * 70)
    print("Example 3: Telemetry & Information-Theoretic Abnormality Checking")
    print("=" * 70)

    topo = build_hierarchical_bgp_topology()
    detector = RouteAnomalyDetector(
        topo,
        half_life_sec=900.0,
        suppress_threshold=2000.0,
        reuse_threshold=750.0,
        flap_penalty=1000.0,
    )

    # 1. Route Flap Damping Penalty Accumulator
    print("\n[Scenario A] RFC 2439 Route Flap Dynamics:")
    route_id = "198.51.100.0/24"
    t = 0.0
    for flap_num in range(1, 5):
        t += 15.0
        rec = detector.register_route_flap(route_id, current_time_sec=t)
        if rec:
            print(f"  Flap {flap_num} at t={t:5.1f}s -> Penalty SUPPRESSED! Score: {rec.score:.2f}")
            print(f"    Evidence: {rec.description}")
        else:
            print(f"  Flap {flap_num} at t={t:5.1f}s -> Penalty accumulated below suppress threshold.")

    # 2. ECMP Shannon Entropy Collapse
    print("\n[Scenario B] Information-Theoretic ECMP Entropy Audit:")
    # Normal balanced 4-way ECMP
    flow_healthy = [2510, 2490, 2505, 2495]
    res_healthy = detector.check_ecmp_entropy("CoreRouter-1", flow_healthy)
    print(f"  Uniform ECMP Flow Distribution : {'NORMAL' if not res_healthy else 'ANOMALY'}")

    # Hash polarization / silent link drop
    flow_degraded = [9700, 200, 80, 20]
    res_degraded = detector.check_ecmp_entropy("CoreRouter-1", flow_degraded)
    if res_degraded:
        print(f"  Degraded Flow Distribution     : [{res_degraded.severity.value}] {res_degraded.anomaly_type.value}")
        print(f"    {res_degraded.description}")

    # 3. Statistical Latency Drift (Kullback-Leibler Divergence)
    print("\n[Scenario C] Telemetry Latency Shift (Gaussian KL-Divergence):")
    baseline_rtt = [14.1, 14.3, 13.9, 14.0, 14.2, 14.1, 14.4]
    observed_rtt = [42.5, 48.1, 45.3, 51.0, 44.2, 47.9, 49.3]
    res_kl = detector.check_latency_drift_kl("TCP_SESSION_101", baseline_rtt, observed_rtt, kl_divergence_threshold=1.5)
    if res_kl:
        print(f"  Statistical Drift Status       : [{res_kl.severity.value}] {res_kl.anomaly_type.value}")
        print(f"    {res_kl.description}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
