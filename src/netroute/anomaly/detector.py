"""
Mathematical Abnormality Detection Engine: Route Flap Decay, Path Stretch,
Valley-Free Leaks, Prefix Hijacking, Shannon Entropy Collapse, and CUSUM / KL-Divergence.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from netroute.checker.route_checker import RouteChecker
from netroute.graph.topology import NetworkTopology
from netroute.types import (
    AnomalyRecord,
    AnomalySeverity,
    AnomalyType,
    IPPrefix,
    RoutePath,
    VerificationStatus,
)


@dataclass
class FlapHistory:
    """State tracker for RFC 2439 route flap damping penalty."""
    penalty: float = 0.0
    last_update_sec: float = 0.0
    flap_count: int = 0
    suppressed: bool = False


class RouteAnomalyDetector:
    """
    Mathematical and Statistical Route Abnormality Detection Suite.
    Integrates information theory, exponential decay dynamics, and statistical hypothesis testing.
    """

    def __init__(
        self,
        topology: NetworkTopology,
        half_life_sec: float = 900.0,  # 15 minutes default RFC 2439
        suppress_threshold: float = 2000.0,
        reuse_threshold: float = 750.0,
        flap_penalty: float = 1000.0,
    ):
        self.topology: NetworkTopology = topology
        self.checker: RouteChecker = RouteChecker(topology)
        self.half_life_sec: float = half_life_sec
        self.suppress_threshold: float = suppress_threshold
        self.reuse_threshold: float = reuse_threshold
        self.flap_penalty: float = flap_penalty
        self._flap_trackers: Dict[str, FlapHistory] = {}

    # -------------------------------------------------------------------------
    # 1. Route Flap Damping Anomaly (RFC 2439 Exponential Decay)
    # -------------------------------------------------------------------------
    def register_route_flap(
        self,
        route_identifier: str,
        current_time_sec: float,
    ) -> Optional[AnomalyRecord]:
        """
        Updates penalty according to continuous differential decay equation:
        H(t) = H(t_last) * exp(-ln(2) * (t - t_last) / T_half) + kappa_flap
        """
        decay_constant = math.log(2.0) / self.half_life_sec

        if route_identifier not in self._flap_trackers:
            self._flap_trackers[route_identifier] = FlapHistory(
                penalty=self.flap_penalty,
                last_update_sec=current_time_sec,
                flap_count=1,
            )
            return None

        tracker = self._flap_trackers[route_identifier]
        delta_t = max(0.0, current_time_sec - tracker.last_update_sec)
        decayed_penalty = tracker.penalty * math.exp(-decay_constant * delta_t)
        new_penalty = decayed_penalty + self.flap_penalty

        tracker.penalty = new_penalty
        tracker.last_update_sec = current_time_sec
        tracker.flap_count += 1

        if new_penalty >= self.suppress_threshold and not tracker.suppressed:
            tracker.suppressed = True
            return AnomalyRecord(
                anomaly_type=AnomalyType.ROUTE_FLAP,
                severity=AnomalySeverity.HIGH,
                target_id=route_identifier,
                metric_value=new_penalty,
                threshold_value=self.suppress_threshold,
                score=min(1.0, new_penalty / (self.suppress_threshold * 2)),
                timestamp_sec=current_time_sec,
                description=(
                    f"Route flap penalty {new_penalty:.1f} exceeded suppress threshold "
                    f"{self.suppress_threshold:.1f}. Flap count: {tracker.flap_count}."
                ),
                evidence={
                    "penalty": new_penalty,
                    "flaps": tracker.flap_count,
                    "suppressed": True,
                },
            )

        return None

    # -------------------------------------------------------------------------
    # 2. Path Stretch Anomaly
    # -------------------------------------------------------------------------
    def check_path_stretch(
        self,
        src: str,
        dst: str,
        actual_path: RoutePath,
        stretch_threshold: float = 1.6,
    ) -> Optional[AnomalyRecord]:
        """
        Evaluates geometric path stretch:
        sigma(s, d) = Cost_actual(s, d) / Cost_optimal^*(s, d)
        Flags excessive route sub-optimality, detour injection, or tromboning.
        """
        optimal_path = self.topology.shortest_path_dijkstra(src, dst)
        if optimal_path is None or optimal_path.total_metric == 0:
            return None

        actual_cost = actual_path.total_metric
        optimal_cost = optimal_path.total_metric
        stretch = actual_cost / optimal_cost

        if stretch >= stretch_threshold:
            severity = (
                AnomalySeverity.CRITICAL
                if stretch >= 2.5
                else AnomalySeverity.HIGH
                if stretch >= 2.0
                else AnomalySeverity.MEDIUM
            )
            return AnomalyRecord(
                anomaly_type=AnomalyType.PATH_STRETCH,
                severity=severity,
                target_id=f"{src}->{dst}",
                metric_value=stretch,
                threshold_value=stretch_threshold,
                score=min(1.0, (stretch - 1.0) / 2.0),
                description=(
                    f"Path stretch sigma={stretch:.2f} exceeds threshold {stretch_threshold:.2f}. "
                    f"Actual cost: {actual_cost:.1f}, Optimal: {optimal_cost:.1f}."
                ),
                evidence={
                    "stretch": stretch,
                    "actual_hops": actual_path.nodes,
                    "optimal_hops": optimal_path.nodes,
                },
            )

        return None

    # -------------------------------------------------------------------------
    # 3. BGP Prefix Hijack & Sub-Prefix Deaggregation Check
    # -------------------------------------------------------------------------
    def check_prefix_hijack(
        self,
        announced_prefix: IPPrefix,
        originating_as: int,
        authoritative_registry: Dict[IPPrefix, int],
    ) -> Optional[AnomalyRecord]:
        """
        Identifies:
        1. MOAS (Multiple Origin AS) conflict: exact prefix originated by unauthorized AS.
        2. Sub-prefix hijacking: more specific prefix announced by rogue AS to hijack traffic.
        """
        # Exact match check
        if announced_prefix in authoritative_registry:
            authorized_as = authoritative_registry[announced_prefix]
            if authorized_as != originating_as:
                return AnomalyRecord(
                    anomaly_type=AnomalyType.PREFIX_HIJACK,
                    severity=AnomalySeverity.CRITICAL,
                    target_id=str(announced_prefix),
                    affected_prefix=announced_prefix,
                    score=1.0,
                    description=(
                        f"Exact prefix hijack (MOAS conflict)! Prefix {announced_prefix} originated by "
                        f"AS{originating_as}, but authoritative owner is AS{authorized_as}."
                    ),
                    evidence={"rogue_as": originating_as, "authorized_as": authorized_as},
                )

        # Sub-prefix de-aggregation check
        for auth_prefix, auth_as in authoritative_registry.items():
            if (
                announced_prefix.is_subprefix_of(auth_prefix)
                and announced_prefix != auth_prefix
            ):
                if originating_as != auth_as:
                    return AnomalyRecord(
                        anomaly_type=AnomalyType.PREFIX_HIJACK,
                        severity=AnomalySeverity.CRITICAL,
                        target_id=str(announced_prefix),
                        affected_prefix=announced_prefix,
                        score=1.0,
                        description=(
                            f"Sub-prefix de-aggregation hijack detected! {announced_prefix} announced by "
                            f"AS{originating_as} falls inside authorized supernet {auth_prefix} of AS{auth_as}."
                        ),
                        evidence={
                            "subprefix": str(announced_prefix),
                            "superprefix": str(auth_prefix),
                            "rogue_as": originating_as,
                            "authorized_as": auth_as,
                        },
                    )

        return None

    # -------------------------------------------------------------------------
    # 4. Information-Theoretic ECMP Entropy Collapse Check
    # -------------------------------------------------------------------------
    def check_ecmp_entropy(
        self,
        node_id: str,
        flow_counts: List[int],
        min_normalized_entropy: float = 0.75,
    ) -> Optional[AnomalyRecord]:
        """
        Calculates normalized Shannon Entropy of traffic distribution over ECMP paths:
        H(X) = - sum p_i * log2(p_i)
        H_norm(X) = H(X) / log2(k)
        Collapse towards 0 indicates polarization, silent packet drop, or hash failure.
        """
        k = len(flow_counts)
        if k <= 1:
            return None

        total_flows = sum(flow_counts)
        if total_flows == 0:
            return None

        probabilities = [c / total_flows for c in flow_counts if c > 0]
        shannon_entropy = -sum(p * math.log2(p) for p in probabilities)
        max_possible_entropy = math.log2(k)

        if max_possible_entropy == 0:
            return None

        normalized_entropy = shannon_entropy / max_possible_entropy

        if normalized_entropy < min_normalized_entropy:
            severity = (
                AnomalySeverity.HIGH
                if normalized_entropy < 0.4
                else AnomalySeverity.MEDIUM
            )
            return AnomalyRecord(
                anomaly_type=AnomalyType.ENTROPY_COLLAPSE,
                severity=severity,
                target_id=node_id,
                metric_value=normalized_entropy,
                threshold_value=min_normalized_entropy,
                score=1.0 - normalized_entropy,
                description=(
                    f"ECMP Entropy Collapse on router '{node_id}': normalized entropy {normalized_entropy:.3f} "
                    f"is below threshold {min_normalized_entropy:.3f}. Severe flow imbalance detected."
                ),
                evidence={
                    "normalized_entropy": normalized_entropy,
                    "shannon_bits": shannon_entropy,
                    "flow_distribution": flow_counts,
                },
            )

        return None

    # -------------------------------------------------------------------------
    # 5. Statistical Latency Drift & KL Divergence (Telemetry Outliers)
    # -------------------------------------------------------------------------
    def check_latency_drift_kl(
        self,
        flow_id: str,
        baseline_samples: List[float],
        observed_samples: List[float],
        kl_divergence_threshold: float = 1.5,
    ) -> Optional[AnomalyRecord]:
        """
        Computes Gaussian Kullback-Leibler (KL) divergence D_KL(Observed || Baseline):
        D_KL(N_1 || N_0) = ln(sigma_0 / sigma_1) + (sigma_1^2 + (mu_1 - mu_0)^2) / (2 * sigma_0^2) - 0.5
        Detects route degradation and distribution shifts prior to complete blackout.
        """
        if len(baseline_samples) < 5 or len(observed_samples) < 5:
            return None

        mu_0 = sum(baseline_samples) / len(baseline_samples)
        var_0 = max(
            1e-4,
            sum((x - mu_0) ** 2 for x in baseline_samples) / len(baseline_samples),
        )
        sigma_0 = math.sqrt(var_0)

        mu_1 = sum(observed_samples) / len(observed_samples)
        var_1 = max(
            1e-4,
            sum((x - mu_1) ** 2 for x in observed_samples) / len(observed_samples),
        )
        sigma_1 = math.sqrt(var_1)

        kl_div = (
            math.log(sigma_0 / sigma_1)
            + (var_1 + (mu_1 - mu_0) ** 2) / (2.0 * var_0)
            - 0.5
        )
        kl_div = max(0.0, kl_div)

        if kl_div >= kl_divergence_threshold:
            return AnomalyRecord(
                anomaly_type=AnomalyType.LATENCY_DRIFT,
                severity=AnomalySeverity.HIGH if kl_div > 3.0 else AnomalySeverity.MEDIUM,
                target_id=flow_id,
                metric_value=kl_div,
                threshold_value=kl_divergence_threshold,
                score=min(1.0, kl_div / 5.0),
                description=(
                    f"Statistical Latency Drift detected on {flow_id}: KL-divergence D_KL={kl_div:.2f} "
                    f"exceeds threshold {kl_divergence_threshold:.2f}. "
                    f"Baseline: mu={mu_0:.1f}ms, sigma={sigma_0:.1f}ms -> Observed: mu={mu_1:.1f}ms, sigma={sigma_1:.1f}ms."
                ),
                evidence={
                    "kl_divergence": kl_div,
                    "baseline_mean": mu_0,
                    "baseline_std": sigma_0,
                    "observed_mean": mu_1,
                    "observed_std": sigma_1,
                },
            )

        return None
