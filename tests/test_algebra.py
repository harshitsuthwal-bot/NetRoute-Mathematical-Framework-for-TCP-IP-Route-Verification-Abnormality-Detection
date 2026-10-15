"""
Unit tests for Routing Semirings and Sobrinho Monotonicity Axioms.
"""

import unittest
from netroute.algebra.semiring import (
    ShortestPathSemiring,
    WidestPathSemiring,
    LexicographicSemiring,
    LexicographicMetric,
    GaoRexfordPolicySemiring,
    GaoRexfordState,
)
from netroute.types import ASRelationship


class TestRoutingSemirings(unittest.TestCase):

    def test_shortest_path_semiring_axioms(self):
        """Verifies tropical min-plus semiring satisfies semiring axioms."""
        s = ShortestPathSemiring()
        a, b, c = 5.0, 10.0, 3.0

        # Identity
        self.assertEqual(s.plus(a, s.zero), a)
        self.assertEqual(s.times(a, s.one), a)
        self.assertEqual(s.times(a, s.zero), s.zero)

        # Commutativity of plus
        self.assertEqual(s.plus(a, b), s.plus(b, a))

        # Idempotence of plus
        self.assertEqual(s.plus(a, a), a)

        # Distributivity: a * (b + c) = (a * b) + (a * c)
        left = s.times(a, s.plus(b, c))
        right = s.plus(s.times(a, b), s.times(a, c))
        self.assertEqual(left, right)

        # Sobrinho Strictly Increasing condition
        self.assertTrue(s.is_strictly_increasing(a, 2.0))

    def test_widest_path_semiring(self):
        """Tests max-min bottleneck bandwidth semiring."""
        s = WidestPathSemiring()
        # Plus is max, Times is min
        self.assertEqual(s.plus(100.0, 500.0), 500.0)
        self.assertEqual(s.times(100.0, 500.0), 100.0)
        self.assertEqual(s.times(100.0, s.one), 100.0)
        self.assertEqual(s.times(100.0, s.zero), s.zero)

    def test_lexicographic_semiring(self):
        """Tests multi-metric lexicographic priority semiring."""
        s = LexicographicSemiring(dimensions=2)
        m1 = LexicographicMetric((100.0, -5.0))  # higher pref, higher igp cost
        m2 = LexicographicMetric((50.0, -1.0))   # lower pref, lower igp cost

        # m1 has higher first component, so m1 is preferred
        self.assertEqual(s.plus(m1, m2), m1)

        # Vector addition under times
        m3 = LexicographicMetric((10.0, -2.0))
        prod = s.times(m1, m3)
        self.assertEqual(prod.components, (110.0, -7.0))

    def test_gao_rexford_valley_free(self):
        """Verifies Gao-Rexford AS policy semiring valley-free FSM."""
        s = GaoRexfordPolicySemiring()

        # Valid valley-free sequence: C2P -> P2P -> P2C
        st0 = s.one
        st1 = s.times(st0, ASRelationship.CUSTOMER_TO_PROVIDER)
        self.assertTrue(st1.is_valid())
        self.assertEqual(st1.current_phase, "UP")

        st2 = s.times(st1, ASRelationship.PEER_TO_PEER)
        self.assertTrue(st2.is_valid())
        self.assertEqual(st2.current_phase, "PEER")

        st3 = s.times(st2, ASRelationship.PROVIDER_TO_CUSTOMER)
        self.assertTrue(st3.is_valid())
        self.assertEqual(st3.current_phase, "DOWN")

        # Invalid valley: P2C followed by C2P
        st_invalid = s.times(st3, ASRelationship.CUSTOMER_TO_PROVIDER)
        self.assertFalse(st_invalid.is_valid())
        self.assertEqual(st_invalid, s.zero)

        # Invalid: Peer-to-Peer after Provider-to-Customer
        st_peer_after_down = s.times(st3, ASRelationship.PEER_TO_PEER)
        self.assertFalse(st_peer_after_down.is_valid())


if __name__ == "__main__":
    unittest.main()
