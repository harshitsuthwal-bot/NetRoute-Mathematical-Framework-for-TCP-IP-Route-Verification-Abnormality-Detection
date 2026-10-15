"""
Fault injection mechanisms for simulating real-world routing abnormalities and failures.
"""

from __future__ import annotations

import time
from typing import List, Tuple

from netroute.graph.topology import NetworkTopology
from netroute.types import ForwardingRule, IPPrefix


class FaultInjector:
    """Injects synthetic routing defects, hijacks, and physical layer impairments."""

    def __init__(self, topology: NetworkTopology):
        self.topology: NetworkTopology = topology

    def inject_link_cut(self, src: str, dst: str) -> None:
        """Simulates physical fiber cut or link interface failure."""
        self.topology.set_link_state(src, dst, active=False)

    def restore_link(self, src: str, dst: str) -> None:
        """Restores severed link."""
        self.topology.set_link_state(src, dst, active=True)

    def inject_subprefix_hijack(
        self,
        rogue_node: str,
        superprefix_str: str,
        subprefix_str: str,
        sink_node: str,
    ) -> IPPrefix:
        """
        Injects a rogue more-specific sub-prefix into the FIB of rogue_node,
        diverting traffic away from legitimate destination.
        """
        sub_pfx = IPPrefix(subprefix_str)
        rule = ForwardingRule(prefix=sub_pfx, next_hops=[sink_node], priority=10)
        self.topology.get_fib(rogue_node).insert(rule)
        return sub_pfx

    def inject_route_valley_leak(
        self,
        transit_node: str,
        target_prefix: IPPrefix,
        provider_or_peer_next_hop: str,
    ) -> None:
        """
        Forces an AS node to leak routes learned from a provider/peer
        to another provider/peer, creating a valley violation.
        """
        fib = self.topology.get_fib(transit_node)
        fib.insert(ForwardingRule(prefix=target_prefix, next_hops=[provider_or_peer_next_hop]))

    def inject_mtu_bottleneck(self, src: str, dst: str, restricted_mtu: int = 1280) -> None:
        """Simulates tunnel encapsulation / PPPoE MTU drop on link."""
        edges = self.topology.edges.get((src, dst), [])
        if edges:
            original = edges[0]
            # Replace with degraded MTU edge
            edges[0] = type(original)(
                src=original.src,
                dst=original.dst,
                metric=original.metric,
                delay_ms=original.delay_ms,
                capacity_mbps=original.capacity_mbps,
                loss_rate=original.loss_rate,
                mtu=restricted_mtu,
                relationship=original.relationship,
                interface_id=original.interface_id,
            )
