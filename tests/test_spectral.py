"""
Unit tests for Spectral Graph Laplacian and Algebraic Connectivity.
"""

import unittest
from netroute.graph.topology import NetworkTopology
from netroute.types import Edge, Node
from netroute.simulator.topologies import build_fat_tree


class TestSpectralConnectivity(unittest.TestCase):

    def test_connected_graph_has_positive_lambda2(self):
        """Connected graph must yield algebraic connectivity lambda_2 > 0."""
        topo = build_fat_tree(k=4)
        lambda_2, fiedler = topo.compute_laplacian_spectrum()
        self.assertGreater(lambda_2, 0.0)
        self.assertEqual(len(fiedler), len(topo.nodes))

    def test_disconnected_graph_has_zero_lambda2(self):
        """Graph with isolated components must yield lambda_2 == 0."""
        topo = NetworkTopology(name="Disconnected-Test")
        # Component 1
        topo.add_edge(Edge("A", "B"), bidirectional=True)
        # Component 2 (completely detached)
        topo.add_edge(Edge("C", "D"), bidirectional=True)

        lambda_2, fiedler = topo.compute_laplacian_spectrum()
        self.assertAlmostEqual(lambda_2, 0.0, places=4)


if __name__ == "__main__":
    unittest.main()
