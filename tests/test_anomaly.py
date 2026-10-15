"""
Unit tests for Route Abnormality Detection Engine.
"""

import unittest
from netroute.anomaly.detector import RouteAnomalyDetector
from netroute.simulator.topologies import build_hierarchical_bgp_topology
from netroute.types import AnomalySeverity, AnomalyType, IPPrefix, RoutePath, Edge


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.topo = build_hierarchical_bgp_topology()
        self.detector = RouteAnomalyDetector(
            self.topo,
            half_life_sec=900.0,
            suppress_threshold=2000.0,
            reuse_threshold=750.0,
            flap_penalty=1000.0,
        )

    def test_route_flap_damping_penalty_and_suppression(self):
        """Verifies RFC 2439 flap penalty accumulation and suppress threshold trigger."""
        pfx_id = "198.51.100.0/24"
        t0 = 100.0

        # Flap 1 (penalty = 1000, below suppress 2000)
        rec1 = self.detector.register_route_flap(pfx_id, t0)
        self.assertIsNone(rec1)

        # Flap 2 after 10s (penalty = 992.3 + 1000 = 1992.3, still below 2000)
        rec2 = self.detector.register_route_flap(pfx_id, t0 + 10.0)
        self.assertIsNone(rec2)

        # Flap 3 after another 10s (penalty = 1976.9 + 1000 = 2976.9 >= 2000 -> SUPPRESS!)
        rec3 = self.detector.register_route_flap(pfx_id, t0 + 20.0)
        self.assertIsNotNone(rec3)
        self.assertEqual(rec3.anomaly_type, AnomalyType.ROUTE_FLAP)
        self.assertEqual(rec3.severity, AnomalySeverity.HIGH)
        self.assertTrue(rec3.evidence["suppressed"])

    def test_path_stretch_anomaly(self):
        """Tests geometric path stretch computation against threshold."""
        # Shortest optimal path cost between Stub_E and Stub_F is 5 + 25 + 5 = 35
        # Simulate a bloated detoured path with high metric
        detour_path = RoutePath(
            nodes=["R_Stub_E", "R_T2_C", "R_T1_A", "R_T1_B", "R_T2_D", "R_Stub_F"],
            edges=[
                Edge("R_Stub_E", "R_T2_C", metric=5.0),
                Edge("R_T2_C", "R_T1_A", metric=20.0),
                Edge("R_T1_A", "R_T1_B", metric=40.0),
                Edge("R_T1_B", "R_T2_D", metric=20.0),
                Edge("R_T2_D", "R_Stub_F", metric=5.0),
            ],
        )
        rec = self.detector.check_path_stretch("R_Stub_E", "R_Stub_F", detour_path, stretch_threshold=1.5)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.anomaly_type, AnomalyType.PATH_STRETCH)
        self.assertGreaterEqual(rec.metric_value, 1.5)

    def test_prefix_hijacking_exact_moas(self):
        """Tests detection of exact MOAS prefix hijack."""
        auth_registry = {IPPrefix("198.51.100.0/24"): 600}
        rec = self.detector.check_prefix_hijack(
            announced_prefix=IPPrefix("198.51.100.0/24"),
            originating_as=666,  # Rogue AS
            authoritative_registry=auth_registry,
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec.anomaly_type, AnomalyType.PREFIX_HIJACK)
        self.assertEqual(rec.severity, AnomalySeverity.CRITICAL)

    def test_subprefix_deaggregation_hijack(self):
        """Tests detection of more-specific sub-prefix hijack (/25 inside /24)."""
        auth_registry = {IPPrefix("198.51.100.0/24"): 600}
        rec = self.detector.check_prefix_hijack(
            announced_prefix=IPPrefix("198.51.100.128/25"),
            originating_as=999,  # Rogue AS
            authoritative_registry=auth_registry,
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec.anomaly_type, AnomalyType.PREFIX_HIJACK)
        self.assertIn("Sub-prefix de-aggregation", rec.description)

    def test_ecmp_entropy_collapse(self):
        """Verifies information-theoretic normalized Shannon entropy calculation."""
        # Balanced: 4 paths with 25% each -> H = 2 bits, H_norm = 1.0
        rec_balanced = self.detector.check_ecmp_entropy("router_1", [1000, 1000, 1000, 1000])
        self.assertIsNone(rec_balanced)

        # Severely collapsed: 99% on one path, 1% on rest
        rec_skewed = self.detector.check_ecmp_entropy("router_1", [9900, 50, 30, 20], min_normalized_entropy=0.7)
        self.assertIsNotNone(rec_skewed)
        self.assertEqual(rec_skewed.anomaly_type, AnomalyType.ENTROPY_COLLAPSE)
        self.assertLess(rec_skewed.metric_value, 0.5)

    def test_latency_drift_kl_divergence(self):
        """Tests statistical Gaussian KL-divergence telemetry shift detector."""
        baseline = [10.0, 10.2, 9.8, 10.1, 10.0, 9.9, 10.3]
        normal_variation = [10.1, 9.9, 10.2, 10.0, 10.1, 10.3, 9.7]
        shifted_variation = [35.0, 42.0, 38.0, 50.0, 45.0, 48.0, 39.0]

        # Normal should not trigger
        rec_normal = self.detector.check_latency_drift_kl("FLOW1", baseline, normal_variation)
        self.assertIsNone(rec_normal)

        # Shifted should trigger with high KL divergence
        rec_drift = self.detector.check_latency_drift_kl("FLOW1", baseline, shifted_variation, kl_divergence_threshold=2.0)
        self.assertIsNotNone(rec_drift)
        self.assertEqual(rec_drift.anomaly_type, AnomalyType.LATENCY_DRIFT)


if __name__ == "__main__":
    unittest.main()
