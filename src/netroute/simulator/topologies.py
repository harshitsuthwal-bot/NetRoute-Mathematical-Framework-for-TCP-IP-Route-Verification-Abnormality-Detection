"""
Standard and synthetic network topology generators for benchmarks and verification.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from netroute.graph.topology import NetworkTopology
from netroute.types import (
    ASRelationship,
    Edge,
    ForwardingRule,
    IPPrefix,
    Node,
    NodeType,
)


def build_fat_tree(k: int = 4) -> NetworkTopology:
    """
    Builds a k-ary Fat-Tree data center Clos network topology.
    Parameters:
      k: port count of switches (must be an even integer).
    Structure:
      - (k/2)^2 Core switches
      - k Pods, each with (k/2) Aggr switches and (k/2) Edge switches
      - (k/2) hosts per edge switch
    """
    if k % 2 != 0:
        raise ValueError("k must be an even integer for Fat-Tree topologies.")

    topo = NetworkTopology(name=f"FatTree-k{k}")
    num_core = (k // 2) ** 2
    num_aggr_per_pod = k // 2
    num_edge_per_pod = k // 2

    # 1. Add Core switches
    core_switches: List[str] = []
    for i in range(num_core):
        cid = f"core_{i}"
        topo.add_node(Node(id=cid, node_type=NodeType.SPINE, asn=65001))
        core_switches.append(cid)

    # 2. Add Pods
    for p in range(k):
        aggr_switches: List[str] = []
        edge_switches: List[str] = []

        for a in range(num_aggr_per_pod):
            aid = f"pod_{p}_aggr_{a}"
            topo.add_node(Node(id=aid, node_type=NodeType.CORE_ROUTER, asn=65001))
            aggr_switches.append(aid)

            # Connect Aggr to (k/2) Core switches
            for c in range(k // 2):
                core_idx = a * (k // 2) + c
                core_id = core_switches[core_idx]
                topo.add_edge(Edge(src=aid, dst=core_id, metric=1.0, delay_ms=0.05, capacity_mbps=40000), bidirectional=True)

        for e in range(num_edge_per_pod):
            eid = f"pod_{p}_edge_{e}"
            topo.add_node(Node(id=eid, node_type=NodeType.LEAF, asn=65001))
            edge_switches.append(eid)

            # Connect Edge to all Aggr switches in the pod (Bipartite pod mesh)
            for aid in aggr_switches:
                topo.add_edge(Edge(src=eid, dst=aid, metric=1.0, delay_ms=0.05, capacity_mbps=10000), bidirectional=True)

    return topo


def build_hierarchical_bgp_topology() -> NetworkTopology:
    """
    Constructs a multi-tier Internet Autonomous System (AS) topology:
    - Tier-1 ASes (AS100, AS200) peered via P2P
    - Tier-2 Regional ASes (AS300, AS400) customer to Tier-1, peered to each other
    - Stub Enterprise ASes (AS500, AS600) customer to Tier-2
    """
    topo = NetworkTopology(name="Hierarchical-BGP")

    # Nodes
    nodes = [
        Node("R_T1_A", asn=100, node_type=NodeType.BGP_GATEWAY, label="Tier1-A"),
        Node("R_T1_B", asn=200, node_type=NodeType.BGP_GATEWAY, label="Tier1-B"),
        Node("R_T2_C", asn=300, node_type=NodeType.BGP_GATEWAY, label="Tier2-C"),
        Node("R_T2_D", asn=400, node_type=NodeType.BGP_GATEWAY, label="Tier2-D"),
        Node("R_Stub_E", asn=500, node_type=NodeType.EDGE_ROUTER, label="Customer-E"),
        Node("R_Stub_F", asn=600, node_type=NodeType.EDGE_ROUTER, label="Customer-F"),
    ]
    for n in nodes:
        topo.add_node(n)

    # 1. Tier-1 Peer-to-Peer Link
    topo.add_edge(
        Edge("R_T1_A", "R_T1_B", metric=10.0, delay_ms=15.0, relationship=ASRelationship.PEER_TO_PEER),
        bidirectional=True,
    )

    # 2. Customer-to-Provider links between Tier-2 and Tier-1
    topo.add_edge(
        Edge("R_T2_C", "R_T1_A", metric=20.0, delay_ms=10.0, relationship=ASRelationship.CUSTOMER_TO_PROVIDER)
    )
    topo.add_edge(
        Edge("R_T1_A", "R_T2_C", metric=20.0, delay_ms=10.0, relationship=ASRelationship.PROVIDER_TO_CUSTOMER)
    )

    topo.add_edge(
        Edge("R_T2_D", "R_T1_B", metric=20.0, delay_ms=10.0, relationship=ASRelationship.CUSTOMER_TO_PROVIDER)
    )
    topo.add_edge(
        Edge("R_T1_B", "R_T2_D", metric=20.0, delay_ms=10.0, relationship=ASRelationship.PROVIDER_TO_CUSTOMER)
    )

    # 3. Peering between Tier-2s
    topo.add_edge(
        Edge("R_T2_C", "R_T2_D", metric=25.0, delay_ms=12.0, relationship=ASRelationship.PEER_TO_PEER),
        bidirectional=True,
    )

    # 4. Customer-to-Provider links between Stubs and Tier-2s
    topo.add_edge(
        Edge("R_Stub_E", "R_T2_C", metric=5.0, delay_ms=2.0, relationship=ASRelationship.CUSTOMER_TO_PROVIDER)
    )
    topo.add_edge(
        Edge("R_T2_C", "R_Stub_E", metric=5.0, delay_ms=2.0, relationship=ASRelationship.PROVIDER_TO_CUSTOMER)
    )

    topo.add_edge(
        Edge("R_Stub_F", "R_T2_D", metric=5.0, delay_ms=2.0, relationship=ASRelationship.CUSTOMER_TO_PROVIDER)
    )
    topo.add_edge(
        Edge("R_T2_D", "R_Stub_F", metric=5.0, delay_ms=2.0, relationship=ASRelationship.PROVIDER_TO_CUSTOMER)
    )

    # Install canonical valley-free forwarding rules for destination prefix 198.51.100.0/24 at Customer-F
    target_pfx = IPPrefix("198.51.100.0/24")

    topo.get_fib("R_Stub_E").insert(ForwardingRule(prefix=target_pfx, next_hops=["R_T2_C"]))
    topo.get_fib("R_T2_C").insert(ForwardingRule(prefix=target_pfx, next_hops=["R_T2_D"]))  # Uses peering
    topo.get_fib("R_T2_D").insert(ForwardingRule(prefix=target_pfx, next_hops=["R_Stub_F"]))
    topo.get_fib("R_Stub_F").insert(ForwardingRule(prefix=target_pfx, next_hops=[]))  # Local delivery

    # Reverse routes for return traffic 203.0.113.0/24 at Customer-E
    source_pfx = IPPrefix("203.0.113.0/24")
    topo.get_fib("R_Stub_F").insert(ForwardingRule(prefix=source_pfx, next_hops=["R_T2_D"]))
    topo.get_fib("R_T2_D").insert(ForwardingRule(prefix=source_pfx, next_hops=["R_T2_C"]))
    topo.get_fib("R_T2_C").insert(ForwardingRule(prefix=source_pfx, next_hops=["R_Stub_E"]))
    topo.get_fib("R_Stub_E").insert(ForwardingRule(prefix=source_pfx, next_hops=[]))

    return topo


def build_synthetic_loop_topology() -> NetworkTopology:
    """
    Creates a 4-node topology (A, B, C, D) with a forwarding loop A -> B -> C -> A.
    """
    topo = NetworkTopology(name="Loop-Topology")
    for n in ["A", "B", "C", "D"]:
        topo.add_node(Node(id=n))

    topo.add_edge(Edge("A", "B"), bidirectional=True)
    topo.add_edge(Edge("B", "C"), bidirectional=True)
    topo.add_edge(Edge("C", "A"), bidirectional=True)
    topo.add_edge(Edge("C", "D"), bidirectional=True)

    pfx = IPPrefix("10.0.0.0/24")
    # Intentional loop in FIBs: A -> B -> C -> A
    topo.get_fib("A").insert(ForwardingRule(prefix=pfx, next_hops=["B"]))
    topo.get_fib("B").insert(ForwardingRule(prefix=pfx, next_hops=["C"]))
    topo.get_fib("C").insert(ForwardingRule(prefix=pfx, next_hops=["A"]))
    topo.get_fib("D").insert(ForwardingRule(prefix=pfx, next_hops=[]))

    return topo
