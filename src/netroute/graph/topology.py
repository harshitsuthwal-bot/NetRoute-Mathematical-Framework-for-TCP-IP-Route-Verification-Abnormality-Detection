"""
Graph representation of network topologies with algebraic matrix operations.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from netroute.algebra.semiring import RoutingSemiring, ShortestPathSemiring
from netroute.graph.fib import RouterFIB
from netroute.types import Edge, IPPrefix, Node, NodeType, RoutePath


class NetworkTopology:
    """
    A mathematical directed multigraph G = (V, E) representing the routed network.
    Maintains graph structure, FIB configurations, link failure state, and spectral matrices.
    """

    def __init__(self, name: str = "Topology"):
        self.name: str = name
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str], List[Edge]] = {}
        self.fibs: Dict[str, RouterFIB] = {}
        self._disabled_edges: Set[Tuple[str, str]] = set()

    def add_node(self, node: Node) -> None:
        """Adds a vertex v in V."""
        self.nodes[node.id] = node
        if node.id not in self.fibs:
            self.fibs[node.id] = RouterFIB(node.id)

    def add_edge(self, edge: Edge, bidirectional: bool = False) -> None:
        """Adds directed link e = (u, v) in E."""
        if edge.src not in self.nodes:
            self.add_node(Node(id=edge.src))
        if edge.dst not in self.nodes:
            self.add_node(Node(id=edge.dst))

        key = (edge.src, edge.dst)
        if key not in self.edges:
            self.edges[key] = []
        self.edges[key].append(edge)

        if bidirectional:
            rev_edge = Edge(
                src=edge.dst,
                dst=edge.src,
                metric=edge.metric,
                delay_ms=edge.delay_ms,
                capacity_mbps=edge.capacity_mbps,
                loss_rate=edge.loss_rate,
                mtu=edge.mtu,
                relationship=edge.relationship,
                interface_id=edge.interface_id,
            )
            rev_key = (rev_edge.src, rev_edge.dst)
            if rev_key not in self.edges:
                self.edges[rev_key] = []
            self.edges[rev_key].append(rev_edge)

    def set_link_state(self, src: str, dst: str, active: bool) -> None:
        """Dynamically simulates link up/down operational events."""
        pair = (src, dst)
        if active:
            self._disabled_edges.discard(pair)
        else:
            self._disabled_edges.add(pair)

    def is_link_active(self, src: str, dst: str) -> bool:
        return (src, dst) not in self._disabled_edges and (src, dst) in self.edges

    def get_out_edges(self, u: str) -> List[Edge]:
        """Returns all active outgoing edges leaving vertex u."""
        out: List[Edge] = []
        for (src, dst), edge_list in self.edges.items():
            if src == u and (src, dst) not in self._disabled_edges:
                out.extend(edge_list)
        return out

    def get_fib(self, node_id: str) -> RouterFIB:
        """Accesses or initializes FIB for node."""
        if node_id not in self.fibs:
            self.fibs[node_id] = RouterFIB(node_id)
        return self.fibs[node_id]

    def shortest_path_dijkstra(
        self,
        src: str,
        dst: str,
        weight_fn: Optional[Callable[[Edge], float]] = None,
    ) -> Optional[RoutePath]:
        """
        Dijkstra's Shortest Path algorithm over the positive real field (R+, +).
        """
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return RoutePath(nodes=[src], edges=[])

        if weight_fn is None:
            weight_fn = lambda e: e.metric

        dist: Dict[str, float] = {n: float("inf") for n in self.nodes}
        prev_node: Dict[str, Optional[str]] = {n: None for n in self.nodes}
        prev_edge: Dict[str, Optional[Edge]] = {n: None for n in self.nodes}
        dist[src] = 0.0

        pq: List[Tuple[float, str]] = [(0.0, src)]
        visited: Set[str] = set()

        while pq:
            curr_dist, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)

            if u == dst:
                break

            for edge in self.get_out_edges(u):
                v = edge.dst
                w = weight_fn(edge)
                new_cost = curr_dist + w
                if new_cost < dist[v]:
                    dist[v] = new_cost
                    prev_node[v] = u
                    prev_edge[v] = edge
                    heapq.heappush(pq, (new_cost, v))

        if dist[dst] == float("inf"):
            return None

        # Reconstruct path
        path_nodes: List[str] = []
        path_edges: List[Edge] = []
        curr = dst
        while curr is not None:
            path_nodes.append(curr)
            edge = prev_edge[curr]
            if edge is not None:
                path_edges.append(edge)
            curr = prev_node[curr]

        path_nodes.reverse()
        path_edges.reverse()
        return RoutePath(nodes=path_nodes, edges=path_edges)

    def algebraic_all_pairs(
        self,
        semiring: RoutingSemiring[Any],
        edge_weight_map: Callable[[Edge], Any],
    ) -> Tuple[List[str], List[List[Any]]]:
        """
        Computes all-pairs optimal path closures using the generalized
        algebraic Floyd-Warshall algorithm over any arbitrary closed semiring (S, ⊕, ⊗, 0̄, 1̄).
        Time complexity: O(|V|^3) operations in semiring S.
        """
        node_list = sorted(list(self.nodes.keys()))
        n = len(node_list)
        idx_map = {node_list[i]: i for i in range(n)}

        # Initialize distance matrix with 0̄ (off-diagonal) and 1̄ (diagonal)
        dist = [[semiring.zero for _ in range(n)] for _ in range(n)]
        for i in range(n):
            dist[i][i] = semiring.one

        for (u, v), edge_list in self.edges.items():
            if (u, v) in self._disabled_edges:
                continue
            if u in idx_map and v in idx_map:
                ui, vi = idx_map[u], idx_map[v]
                for edge in edge_list:
                    w = edge_weight_map(edge)
                    dist[ui][vi] = semiring.plus(dist[ui][vi], w)

        # Semiring transitive closure
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    # dist[i][j] = dist[i][j] ⊕ (dist[i][k] ⊗ dist[k][j])
                    extended = semiring.times(dist[i][k], dist[k][j])
                    dist[i][j] = semiring.plus(dist[i][j], extended)

        return node_list, dist

    def compute_laplacian_spectrum(self) -> Tuple[float, List[float]]:
        """
        Calculates Graph Laplacian L = D - A for the underlying undirected graph.
        Returns:
            (algebraic_connectivity_lambda2, fiedler_vector)
        By the Matrix-Tree Theorem & Spectral Graph Theory, lambda_2 == 0.0 iff
        the graph is disconnected or partitioned into multiple components.
        """
        node_list = sorted(list(self.nodes.keys()))
        n = len(node_list)
        if n < 2:
            return 0.0, [1.0] * n

        idx_map = {node_list[i]: i for i in range(n)}
        adj = [[0.0 for _ in range(n)] for _ in range(n)]
        degrees = [0.0 for _ in range(n)]

        for (u, v) in self.edges:
            if (u, v) in self._disabled_edges:
                continue
            if u in idx_map and v in idx_map and u != v:
                i, j = idx_map[u], idx_map[v]
                adj[i][j] = 1.0
                adj[j][i] = 1.0  # Undirected projection

        for i in range(n):
            degrees[i] = sum(adj[i])

        # Check topological connectivity via BFS
        visited = set()
        queue = [0]
        visited.add(0)
        while queue:
            curr = queue.pop(0)
            for neighbor in range(n):
                if adj[curr][neighbor] > 0 and neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        # If graph is disconnected, lambda_2 is identically 0
        if len(visited) < n:
            return 0.0, [0.0] * n

        # Construct Laplacian L = D - A
        A = [[degrees[i] if i == j else -adj[i][j] for j in range(n)] for i in range(n)]
        V = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]

        # Jacobi eigenvalue algorithm for symmetric real matrix
        for _ in range(100):
            # Find largest off-diagonal element
            p, q = 0, 1
            max_val = abs(A[0][1])
            for i in range(n):
                for j in range(i + 1, n):
                    if abs(A[i][j]) > max_val:
                        max_val = abs(A[i][j])
                        p, q = i, j

            if max_val < 1e-10:
                break

            app = A[p][p]
            aqq = A[q][q]
            apq = A[p][q]

            if abs(apq) < 1e-12:
                continue

            theta = 0.5 * math.atan2(2.0 * apq, (aqq - app))
            c = math.cos(theta)
            s = math.sin(theta)

            # Update matrix A in-place: A' = J^T A J
            for i in range(n):
                if i != p and i != q:
                    aip = A[i][p]
                    aiq = A[i][q]
                    A[i][p] = A[p][i] = c * aip - s * aiq
                    A[i][q] = A[q][i] = s * aip + c * aiq

            A[p][p] = c * c * app - 2.0 * s * c * apq + s * s * aqq
            A[q][q] = s * s * app + 2.0 * s * c * apq + c * c * aqq
            A[p][q] = A[q][p] = 0.0

            # Accumulate eigenvectors
            for i in range(n):
                vip = V[i][p]
                viq = V[i][q]
                V[i][p] = c * vip - s * viq
                V[i][q] = s * vip + c * viq

        eigenvalues = [(A[i][i], [V[r][i] for r in range(n)]) for i in range(n)]
        eigenvalues.sort(key=lambda item: item[0])

        lambda_2 = max(0.0, eigenvalues[1][0])
        fiedler_vector = eigenvalues[1][1]
        return lambda_2, fiedler_vector

    def __repr__(self) -> str:
        return f"NetworkTopology('{self.name}', |V|={len(self.nodes)}, |E|={sum(len(l) for l in self.edges.values())})"
