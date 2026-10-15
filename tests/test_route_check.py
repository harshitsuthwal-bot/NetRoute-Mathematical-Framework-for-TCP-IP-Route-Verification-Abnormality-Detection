"""
Unit tests for Route Verification Engine (Reachability, Loops, Black-Holes, MTU, TCP Handshake).
"""

import unittest
from netroute.checker.route_checker import RouteChecker
from netroute.simulator.topologies import (
    build_hierarchical_bgp_topology,
    build_synthetic_loop_topology,
)
from netroute.simulator.faults import FaultInjector
from netroute.types import IPPrefix, VerificationStatus


class TestRouteChecker(unittest.TestCase):

    def setUp(self):
        self.bgp_topo = build_hierarchical_bgp_topology()
        self.checker = RouteChecker(self.bgp_topo)
        self.injector = FaultInjector(self.bgp_topo)
        self.dst_pfx = IPPrefix("198.51.100.0/24")
        self.src_pfx = IPPrefix("203.0.113.0/24")

    def test_valid_route_and_tcp_handshake(self):
        """Tests that a properly configured BGP path passes reachability & TCP handshake."""
        res = self.checker.verify_route(
            src="R_Stub_E",
            dst="R_Stub_F",
            prefix=self.dst_pfx,
            reverse_prefix=self.src_pfx,
        )
        self.assertEqual(res.status, VerificationStatus.VALID)
        self.assertTrue(res.tcp_handshake_feasible)
        self.assertGreater(res.estimated_rtt_ms, 0.0)
        self.assertEqual(res.forward_path.nodes, ["R_Stub_E", "R_T2_C", "R_T2_D", "R_Stub_F"])
        self.assertEqual(res.reverse_path.nodes, ["R_Stub_F", "R_T2_D", "R_T2_C", "R_Stub_E"])

    def test_loop_detection(self):
        """Tests cycle detection on a topology with an intentional microloop."""
        loop_topo = build_synthetic_loop_topology()
        checker = RouteChecker(loop_topo)
        pfx = IPPrefix("10.0.0.0/24")

        res = checker.verify_route(src="A", dst="D", prefix=pfx)
        self.assertEqual(res.status, VerificationStatus.LOOP_DETECTED)
        self.assertIsNotNone(res.cycle_detected)
        self.assertIn("A", res.cycle_detected)
        self.assertIn("B", res.cycle_detected)
        self.assertIn("C", res.cycle_detected)

    def test_black_hole_detection_on_link_cut(self):
        """Tests black-hole identification when an active link is severed."""
        self.injector.inject_link_cut("R_T2_C", "R_T2_D")

        res = self.checker.verify_route(
            src="R_Stub_E",
            dst="R_Stub_F",
            prefix=self.dst_pfx,
        )
        self.assertEqual(res.status, VerificationStatus.BLACK_HOLE)
        self.assertEqual(res.black_hole_node, "R_T2_C")

    def test_mtu_violation_detection(self):
        """Tests MTU bottleneck rejection when link MTU < required packet MTU."""
        self.injector.inject_mtu_bottleneck("R_T2_C", "R_T2_D", restricted_mtu=1200)

        res = self.checker.verify_route(
            src="R_Stub_E",
            dst="R_Stub_F",
            prefix=self.dst_pfx,
            required_mtu=1500,
        )
        self.assertEqual(res.status, VerificationStatus.MTU_VIOLATION)
        self.assertEqual(res.path_mtu, 1200)

    def test_asymmetric_tcp_failure(self):
        """Tests asymmetric routing failure when reverse return path is severed."""
        # Cut reverse path link R_T2_D -> R_T2_C only
        self.bgp_topo.set_link_state("R_T2_D", "R_T2_C", active=False)

        res = self.checker.verify_route(
            src="R_Stub_E",
            dst="R_Stub_F",
            prefix=self.dst_pfx,
            reverse_prefix=self.src_pfx,
        )
        self.assertEqual(res.status, VerificationStatus.ASYMMETRIC_FAILURE)
        self.assertFalse(res.tcp_handshake_feasible)


if __name__ == "__main__":
    unittest.main()
