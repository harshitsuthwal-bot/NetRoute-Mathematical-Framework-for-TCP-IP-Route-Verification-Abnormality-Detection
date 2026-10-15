"""
Formal Route Checker Engine: Reachability, Loop Verification, Black-Holes, and TCP Handshake Feasibility.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from netroute.algebra.semiring import GaoRexfordPolicySemiring, GaoRexfordState
from netroute.graph.topology import NetworkTopology
from netroute.types import (
    ASRelationship,
    Edge,
    ForwardingRule,
    IPPrefix,
    RoutePath,
    VerificationResult,
    VerificationStatus,
)


class RouteChecker:
    """
    Formal Route Verification Engine for distributed IP forwarding planes.
    Proves deterministically whether packets reach their destination, detect
    microloops, identify black-holes, check MTU consistency, and verify
    TCP 3-way handshake round-trip liveness.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology: NetworkTopology = topology
        self.gao_rexford_semiring = GaoRexfordPolicySemiring()

    def verify_route(
        self,
        src: str,
        dst: str,
        prefix: IPPrefix,
        reverse_prefix: Optional[IPPrefix] = None,
        required_mtu: int = 1500,
        max_hops: int = 64,
        enforce_valley_free: bool = True,
    ) -> VerificationResult:
        """
        Executes formal end-to-end verification for a flow from src to dst.
        Traces forward forwarding path, reverse handshake path, detects loops,
        black-holes, MTU bottlenecks, and AS policy violations.
        """
        if src not in self.topology.nodes:
            return VerificationResult(
                status=VerificationStatus.UNREACHABLE,
                src=src,
                dst=dst,
                prefix=prefix,
                details=f"Source node '{src}' does not exist in topology.",
            )
        if dst not in self.topology.nodes:
            return VerificationResult(
                status=VerificationStatus.UNREACHABLE,
                src=src,
                dst=dst,
                prefix=prefix,
                details=f"Destination node '{dst}' does not exist in topology.",
            )

        # 1. Trace Forward Path
        fwd_status, fwd_path, fwd_diag = self._trace_path(src, dst, prefix, max_hops)
        if fwd_status != VerificationStatus.VALID:
            return VerificationResult(
                status=fwd_status,
                src=src,
                dst=dst,
                prefix=prefix,
                forward_path=fwd_path,
                cycle_detected=fwd_diag.get("cycle"),
                black_hole_node=fwd_diag.get("black_hole"),
                details=fwd_diag.get("reason", "Forward path verification failed."),
                diagnostics=fwd_diag,
            )

        # 2. Check MTU Bottleneck on Forward Path
        if fwd_path.bottleneck_mtu < required_mtu:
            return VerificationResult(
                status=VerificationStatus.MTU_VIOLATION,
                src=src,
                dst=dst,
                prefix=prefix,
                forward_path=fwd_path,
                path_mtu=fwd_path.bottleneck_mtu,
                details=(
                    f"Forward path bottleneck MTU ({fwd_path.bottleneck_mtu}) "
                    f"is less than required MTU ({required_mtu})."
                ),
                diagnostics={"bottleneck_mtu": fwd_path.bottleneck_mtu, "required_mtu": required_mtu},
            )

        # 3. Policy Semiring: Valley-Free Check
        if enforce_valley_free:
            policy_ok, policy_diag = self._check_valley_free(fwd_path)
            if not policy_ok:
                return VerificationResult(
                    status=VerificationStatus.POLICY_VIOLATION,
                    src=src,
                    dst=dst,
                    prefix=prefix,
                    forward_path=fwd_path,
                    details=policy_diag,
                    diagnostics={"policy_error": policy_diag},
                )

        # 4. Trace Reverse Path for TCP Handshake (SYN-ACK)
        rev_prefix = reverse_prefix or prefix
        rev_status, rev_path, rev_diag = self._trace_path(dst, src, rev_prefix, max_hops)
        tcp_ok = (rev_status == VerificationStatus.VALID)

        if not tcp_ok:
            return VerificationResult(
                status=VerificationStatus.ASYMMETRIC_FAILURE,
                src=src,
                dst=dst,
                prefix=prefix,
                forward_path=fwd_path,
                reverse_path=rev_path,
                tcp_handshake_feasible=False,
                cycle_detected=rev_diag.get("cycle"),
                black_hole_node=rev_diag.get("black_hole"),
                details=(
                    f"TCP 3-way handshake impossible: forward path succeeds but "
                    f"reverse path from {dst} to {src} failed ({rev_status.value})."
                ),
                diagnostics={"reverse_failure": rev_diag},
            )

        # 5. Successful Verification Certificate
        estimated_rtt = fwd_path.total_delay_ms + rev_path.total_delay_ms
        path_mtu = min(fwd_path.bottleneck_mtu, rev_path.bottleneck_mtu)

        return VerificationResult(
            status=VerificationStatus.VALID,
            src=src,
            dst=dst,
            prefix=prefix,
            forward_path=fwd_path,
            reverse_path=rev_path,
            tcp_handshake_feasible=True,
            estimated_rtt_ms=estimated_rtt,
            path_mtu=path_mtu,
            details="Route verified: Forward & Reverse reachability confirmed with zero loops/blackholes.",
            diagnostics={
                "forward_hops": fwd_path.hop_count,
                "reverse_hops": rev_path.hop_count,
                "forward_metric": fwd_path.total_metric,
                "delivery_probability": fwd_path.end_to_end_delivery_prob * rev_path.end_to_end_delivery_prob,
            },
        )

    def _trace_path(
        self,
        src: str,
        dst: str,
        prefix: IPPrefix,
        max_hops: int,
    ) -> Tuple[VerificationStatus, RoutePath, Dict[str, Any]]:
        """
        Traces actual packet traversal using each node's installed FIB.
        Employs cycle detection and black-hole discovery.
        """
        curr = src
        visited_nodes: List[str] = [curr]
        node_pos_map: Dict[str, int] = {curr: 0}
        path_edges: List[Edge] = []

        while curr != dst:
            if len(visited_nodes) > max_hops:
                return (
                    VerificationStatus.LOOP_DETECTED,
                    RoutePath(nodes=visited_nodes, edges=path_edges),
                    {"reason": f"Hop count exceeded threshold ({max_hops})", "cycle": visited_nodes[-5:]},
                )

            fib = self.topology.get_fib(curr)
            matched_rule = fib.match(prefix)

            if matched_rule is None or not matched_rule.next_hops:
                return (
                    VerificationStatus.BLACK_HOLE,
                    RoutePath(nodes=visited_nodes, edges=path_edges),
                    {"reason": f"No FIB entry matching {prefix} at router '{curr}'", "black_hole": curr},
                )

            # Select first active next-hop (deterministic primary hop or ECMP primary)
            next_hop = None
            selected_edge = None

            for nh in matched_rule.next_hops:
                if self.topology.is_link_active(curr, nh):
                    next_hop = nh
                    # Find matching edge in topology
                    edges = self.topology.edges.get((curr, nh), [])
                    if edges:
                        selected_edge = edges[0]
                    else:
                        selected_edge = Edge(src=curr, dst=nh)
                    break

            if next_hop is None:
                return (
                    VerificationStatus.BLACK_HOLE,
                    RoutePath(nodes=visited_nodes, edges=path_edges),
                    {
                        "reason": f"All next-hops {matched_rule.next_hops} from '{curr}' are down/unreachable.",
                        "black_hole": curr,
                    },
                )

            # Check for forwarding cycle / loop
            if next_hop in node_pos_map:
                cycle_start_idx = node_pos_map[next_hop]
                cycle = visited_nodes[cycle_start_idx:] + [next_hop]
                visited_nodes.append(next_hop)
                path_edges.append(selected_edge)
                return (
                    VerificationStatus.LOOP_DETECTED,
                    RoutePath(nodes=visited_nodes, edges=path_edges),
                    {"reason": f"Forwarding loop detected at node '{next_hop}'", "cycle": cycle},
                )

            # Advance
            path_edges.append(selected_edge)
            node_pos_map[next_hop] = len(visited_nodes)
            visited_nodes.append(next_hop)
            curr = next_hop

        return (
            VerificationStatus.VALID,
            RoutePath(nodes=visited_nodes, edges=path_edges),
            {"reason": "Destination reached successfully."},
        )

    def _check_valley_free(self, path: RoutePath) -> Tuple[bool, str]:
        """
        Algebraic Gao-Rexford Valley-Free proof on the AS path.
        Traverses links and applies the GaoRexfordPolicySemiring transition operator.
        """
        curr_state = self.gao_rexford_semiring.one

        for edge in path.edges:
            next_state = self.gao_rexford_semiring.times(curr_state, edge.relationship)
            if not next_state.is_valid():
                return False, (
                    f"Valley-free violation between '{edge.src}' and '{edge.dst}' "
                    f"(Link type: {edge.relationship.value}, Previous state: {curr_state.current_phase})"
                )
            curr_state = next_state

        return True, "Valid valley-free AS route."

    def all_pairs_reachability_matrix(
        self, prefix: IPPrefix
    ) -> Dict[Tuple[str, str], VerificationStatus]:
        """
        Computes reachability tensor R in {VALID, LOOP, BLACK_HOLE, ...}^(|V| x |V|)
        for a given prefix across all pairs of network nodes.
        """
        node_ids = list(self.topology.nodes.keys())
        results: Dict[Tuple[str, str], VerificationStatus] = {}

        for u in node_ids:
            for v in node_ids:
                if u == v:
                    results[(u, v)] = VerificationStatus.VALID
                    continue
                res = self.verify_route(u, v, prefix, max_hops=len(node_ids) + 2)
                results[(u, v)] = res.status

        return results
