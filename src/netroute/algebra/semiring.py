"""
Algebraic Routing Framework: Semirings, Path Algebras, and Sobrinho Monotonicity.

Provides the foundational algebraic structures for proving route convergence,
loop-freeness, policy compliance, and multi-metric path composition.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Generic, List, Optional, Tuple, TypeVar

from netroute.types import ASRelationship

T = TypeVar("T")


class RoutingSemiring(ABC, Generic[T]):
    """
    Abstract Base Class for an algebraic routing semiring:
    (S, ⊕, ⊗, 0̄, 1̄)

    Axioms:
    1. (S, ⊕, 0̄) is a commutative, idempotent monoid:
       - a ⊕ b = b ⊕ a
       - (a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)
       - a ⊕ 0̄ = a
       - a ⊕ a = a  (induces partial order: a ≤ b <=> a ⊕ b = a)
    2. (S, ⊗, 1̄) is a monoid with absorbing element 0̄:
       - (a ⊗ b) ⊗ c = a ⊗ (b ⊗ c)
       - a ⊗ 1̄ = 1̄ ⊗ a = a
       - a ⊗ 0̄ = 0̄ ⊗ a = 0̄
    3. ⊗ distributes over ⊕:
       - a ⊗ (b ⊕ c) = (a ⊗ b) ⊕ (a ⊗ c)
       - (a ⊕ b) ⊗ c = (a ⊗ c) ⊕ (b ⊗ c)
    """

    @property
    @abstractmethod
    def zero(self) -> T:
        """The 0̄ element (represents unreachable / worst candidate)."""
        pass

    @property
    @abstractmethod
    def one(self) -> T:
        """The 1̄ element (represents trivial empty path)."""
        pass

    @abstractmethod
    def plus(self, a: T, b: T) -> T:
        """⊕ operator: Choice / selection between two paths (returns the preferred path)."""
        pass

    @abstractmethod
    def times(self, a: T, b: T) -> T:
        """⊗ operator: Concatenation / extension of a path with a link attribute."""
        pass

    def order(self, a: T, b: T) -> bool:
        """
        Partial order relation: a <= b iff a ⊕ b = a.
        True means 'a' is at least as preferred as 'b'.
        """
        return self.plus(a, b) == a

    def is_monotonic(self, a: T, b: T, c: T) -> bool:
        """
        Monotonicity check:
        a <= b implies (a ⊗ c <= b ⊗ c) and (c ⊗ a <= c ⊗ b).
        """
        if not self.order(a, b):
            return True  # Vacuously true if a is not <= b
        ac = self.times(a, c)
        bc = self.times(b, c)
        ca = self.times(c, a)
        cb = self.times(c, b)
        return self.order(ac, bc) and self.order(ca, cb)

    def is_strictly_increasing(self, a: T, b: T) -> bool:
        """
        Sobrinho strictly increasing condition:
        For all a != 0̄ and b != 1̄, a < a ⊗ b.
        Guarantees strict convergence and absolute loop-freeness.
        """
        if a == self.zero or b == self.one:
            return True
        extended = self.times(a, b)
        # a < extended means a <= extended and a != extended
        return self.order(a, extended) and (a != extended)


class ShortestPathSemiring(RoutingSemiring[float]):
    """
    Tropical Min-Plus Semiring: (R+ U {inf}, min, +, inf, 0).
    Underlies OSPF (Dijkstra) and RIP (Bellman-Ford).
    """

    @property
    def zero(self) -> float:
        return float("inf")

    @property
    def one(self) -> float:
        return 0.0

    def plus(self, a: float, b: float) -> float:
        return min(a, b)

    def times(self, a: float, b: float) -> float:
        if a == float("inf") or b == float("inf"):
            return float("inf")
        return a + b


class WidestPathSemiring(RoutingSemiring[float]):
    """
    Max-Min Capacity Semiring: (R+ U {-inf}, max, min, -inf, inf).
    Computes maximum bottleneck capacity paths.
    """

    @property
    def zero(self) -> float:
        return float("-inf")

    @property
    def one(self) -> float:
        return float("inf")

    def plus(self, a: float, b: float) -> float:
        return max(a, b)

    def times(self, a: float, b: float) -> float:
        return min(a, b)


@dataclass(frozen=True)
class LexicographicMetric:
    """
    Tuple metric for hierarchical routing choices.
    e.g., (local_pref, -as_path_len, -igp_cost).
    Values are compared lexicographically: higher values preferred.
    """
    components: Tuple[float, ...]

    def __lt__(self, other: "LexicographicMetric") -> bool:
        return self.components < other.components

    def __le__(self, other: "LexicographicMetric") -> bool:
        return self.components <= other.components

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, LexicographicMetric):
            return False
        return self.components == other.components


class LexicographicSemiring(RoutingSemiring[LexicographicMetric]):
    """
    Lexicographic Product Semiring S_1 x S_2 x ... x S_k.
    Models multi-criteria routing decisions such as BGP decision steps.
    """

    def __init__(self, dimensions: int = 3):
        self.dims = dimensions

    @property
    def zero(self) -> LexicographicMetric:
        # Lowest priority (negative infinity across all dimensions)
        return LexicographicMetric(tuple(float("-inf") for _ in range(self.dims)))

    @property
    def one(self) -> LexicographicMetric:
        # Neutral empty path identity (zeros across all dimensions)
        return LexicographicMetric(tuple(0.0 for _ in range(self.dims)))

    def plus(self, a: LexicographicMetric, b: LexicographicMetric) -> LexicographicMetric:
        # Higher lexicographical rank is preferred
        return a if a.components >= b.components else b

    def times(self, a: LexicographicMetric, b: LexicographicMetric) -> LexicographicMetric:
        if a == self.zero or b == self.zero:
            return self.zero
        # Vector addition of additive components
        added = tuple(x + y for x, y in zip(a.components, b.components))
        return LexicographicMetric(added)


@dataclass(frozen=True)
class GaoRexfordState:
    """
    State representing path progression through Gao-Rexford commercial hierarchy:
    Valid sequences:
       (C2P)* -> (P2P)? -> (P2C)*
    An invalid valley (e.g., P2C followed by C2P or P2P) transitions to INVALID (0̄).
    """
    current_phase: str  # "UP" (Customer->Provider), "PEER", "DOWN" (Provider->Customer), "INVALID"
    as_path_length: int = 0
    preference_weight: int = 100  # Customer=300, Peer=200, Provider=100

    def is_valid(self) -> bool:
        return self.current_phase != "INVALID"


class GaoRexfordPolicySemiring(RoutingSemiring[GaoRexfordState]):
    """
    Gao-Rexford AS-Policy Routing Semiring.
    Guarantees BGP Valley-Free compliance and economic revenue maximization:
    - Customer route preferred over Peer route (300 vs 200).
    - Peer route preferred over Provider route (200 vs 100).
    - Valley path (C2P after P2C, or P2P after P2C) evaluates to zero (0̄, invalid).
    """

    @property
    def zero(self) -> GaoRexfordState:
        return GaoRexfordState(current_phase="INVALID", as_path_length=999999, preference_weight=-1)

    @property
    def one(self) -> GaoRexfordState:
        return GaoRexfordState(current_phase="UP", as_path_length=0, preference_weight=300)

    def plus(self, a: GaoRexfordState, b: GaoRexfordState) -> GaoRexfordState:
        """Choose route with higher preference weight; break ties by shorter AS path length."""
        if not a.is_valid() and not b.is_valid():
            return self.zero
        if not a.is_valid():
            return b
        if not b.is_valid():
            return a

        if a.preference_weight != b.preference_weight:
            return a if a.preference_weight > b.preference_weight else b
        # Shorter AS path preferred
        if a.as_path_length != b.as_path_length:
            return a if a.as_path_length < b.as_path_length else b
        return a

    def times(self, state: GaoRexfordState, link_rel: ASRelationship) -> GaoRexfordState:
        """
        State transition when extending a path across an AS relationship link.
        Implements the Valley-Free Finite State Machine (FSM):
        """
        if not state.is_valid():
            return self.zero

        phase = state.current_phase
        new_len = state.as_path_length + 1

        if link_rel == ASRelationship.INTRA:
            return GaoRexfordState(
                current_phase=phase,
                as_path_length=new_len,
                preference_weight=state.preference_weight
            )

        if link_rel == ASRelationship.CUSTOMER_TO_PROVIDER:
            # Can only traverse C2P while still in the "UP" phase
            if phase == "UP":
                return GaoRexfordState(current_phase="UP", as_path_length=new_len, preference_weight=100)
            else:
                # Valley violation! (C2P after PEER or DOWN is forbidden)
                return self.zero

        elif link_rel == ASRelationship.PEER_TO_PEER:
            # Can only traverse PEER if we were in "UP" phase
            if phase == "UP":
                return GaoRexfordState(current_phase="PEER", as_path_length=new_len, preference_weight=200)
            else:
                # Valley violation! (Peer link cannot follow another Peer or Provider link)
                return self.zero

        elif link_rel == ASRelationship.PROVIDER_TO_CUSTOMER:
            # P2C can happen from UP, PEER, or already DOWN
            if phase in ("UP", "PEER", "DOWN"):
                return GaoRexfordState(current_phase="DOWN", as_path_length=new_len, preference_weight=300)
            else:
                return self.zero

        return self.zero
