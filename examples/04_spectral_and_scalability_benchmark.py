"""
Example 4: Spectral Graph Laplacian Analysis and Scaling Benchmark.
"""

import time
from netroute.algebra.semiring import ShortestPathSemiring, WidestPathSemiring
from netroute.simulator.topologies import build_fat_tree


def main():
    print("=" * 70)
    print("Example 4: Spectral Laplacian & Semiring All-Pairs Scalability")
    print("=" * 70)

    for k in [4, 6]:
        print(f"\nEvaluating Fat-Tree Topology (k={k}):")
        t0 = time.perf_counter()
        topo = build_fat_tree(k=k)
        t_build = (time.perf_counter() - t0) * 1000.0

        n_nodes = len(topo.nodes)
        n_edges = sum(len(l) for l in topo.edges.values())
        print(f"  Graph Scale: |V| = {n_nodes} switches, |E| = {n_edges} directed links")
        print(f"  Topology Construction Time: {t_build:.2f} ms")

        # Spectral Graph Laplacian Analysis
        t_spec = time.perf_counter()
        lambda_2, fiedler = topo.compute_laplacian_spectrum()
        t_spec_ms = (time.perf_counter() - t_spec) * 1000.0
        print(f"  Algebraic Connectivity lambda_2 = {lambda_2:.4f} (computed in {t_spec_ms:.2f} ms)")
        print(f"  Network Robustness Evaluation   = {'HIGH (Fault Tolerant)' if lambda_2 > 0.5 else 'MODERATE'}")

        # Sample Semiring Dijkstra throughput
        sample_nodes = list(topo.nodes.keys())[: min(25, n_nodes)]
        t_dijk = time.perf_counter()
        computed = 0
        for u in sample_nodes:
            for v in sample_nodes:
                if u != v:
                    path = topo.shortest_path_dijkstra(u, v)
                    if path:
                        computed += 1
        dijk_time = time.perf_counter() - t_dijk
        rate = computed / max(1e-6, dijk_time)
        print(f"  Path Computation Throughput     = {rate:,.0f} queries/sec ({computed} paths in {dijk_time*1000:.2f} ms)")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
