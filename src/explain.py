"""Explainability: why did the model raise this forecast?

The PS is blunt that black-box output is not acceptable, so every prediction
this system emits carries three complementary explanations:

  1. Feature attribution - integrated gradients on the observation. Answers
     "which traffic measurements drove this score".
  2. Temporal attention - the causal attention weights the heads actually
     consumed. Answers "which earlier windows mattered".
  3. Predicted state delta - the decoder's imagined future observation minus
     the current one, in real units. Answers "what does the model think is
     about to change", which is the one a defender can act on.

Integrated gradients rather than plain gradient x input, for a reason found the
hard way: on a genuinely compromised host the model's logit sits deep in
saturation, the local gradient collapses to ~1e-3, and every feature comes back
looking equally irrelevant - precisely when an explanation is most needed.
Integrating along a path from a baseline recovers the signal and satisfies
completeness, so the reported shares are comparable across features.

Integrated gradients rather than SHAP because 32 backward passes run inside an
interactive request while thousands of forward passes do not. `shap_values` is
provided for offline reporting as an independent cross-check.
"""

from __future__ import annotations

import numpy as np
import torch

from .features.packet import PACKET_FEATURE_COLUMNS
from .features.windows import FLOW_FEATURE_COLUMNS

# Human-readable names. The dashboard shows these, never the raw column names -
# a defender should not have to decode `frac_syn_only`.
FEATURE_LABELS: dict[str, str] = {
    "n_flows": "Flow count",
    "n_unique_dst": "Distinct destinations",
    "n_unique_dport": "Distinct destination ports",
    "n_unique_sport": "Distinct source ports",
    "dur_mean": "Mean flow duration",
    "dur_std": "Flow duration spread",
    "dur_max": "Longest flow",
    "tot_bytes": "Total bytes",
    "src_bytes": "Bytes sent",
    "dst_bytes": "Bytes received",
    "tot_pkts": "Total packets",
    "bytes_per_flow": "Bytes per flow",
    "pkts_per_flow": "Packets per flow",
    "bytes_per_pkt": "Mean packet size",
    "egress_ratio": "Outbound byte ratio",
    "fan_out_ratio": "Destination fan-out",
    "port_fan_ratio": "Port fan-out",
    "frac_internal_dst": "Share of internal destinations",
    "frac_lateral_port": "Share on admin/remote ports",
    "frac_c2_port": "Share on known C2 ports",
    "frac_high_port": "Share on high ports",
    "frac_tcp": "TCP share",
    "frac_udp": "UDP share",
    "frac_icmp": "ICMP share",
    "frac_bidirectional": "Bidirectional share",
    "frac_syn": "SYN flag rate",
    "frac_ack": "ACK flag rate",
    "frac_fin": "FIN flag rate",
    "frac_rst": "RST flag rate",
    "frac_psh": "PSH flag rate",
    "frac_urg": "URG flag rate",
    "frac_handshake": "Completed handshake rate",
    "frac_syn_only": "Unanswered SYN rate",
    "frac_reset": "Connection reset rate",
    "iat_mean": "Mean inter-flow gap",
    "iat_std": "Inter-flow gap spread",
    "beacon_regularity": "Beaconing regularity",
    "dst_entropy": "Destination entropy",
    "dport_entropy": "Destination port entropy",
    "pkt_count": "Packet count",
    "pkt_ttl_mean": "Mean TTL",
    "pkt_ttl_std": "TTL variance",
    "pkt_ttl_nunique": "Distinct TTL values",
    "pkt_win_mean": "Mean TCP window size",
    "pkt_win_std": "TCP window variance",
    "pkt_win_zero_frac": "Zero-window rate",
    "pkt_frag_frac": "IP fragmentation rate",
    "pkt_payload_mean": "Mean payload size",
    "pkt_payload_std": "Payload size spread",
    "pkt_payload_p90": "90th pct payload size",
    "pkt_payload_zero_frac": "Empty-payload rate",
    "pkt_retrans_frac": "Retransmission rate",
    "pkt_syn_frac": "Packet-level SYN rate",
    "pkt_rst_frac": "Packet-level RST rate",
    "pkt_iat_mean": "Mean packet gap",
    "pkt_iat_std": "Packet gap spread",
    "pkt_iat_cv": "Packet timing regularity",
    "pkt_port_entropy": "Packet port entropy",
    "pkt_dst_entropy": "Packet destination entropy",
    "pkt_seq_scan_score": "Sequential port-scan score",
    "pkt_nunique_dport": "Distinct ports (packet level)",
    "pkt_nunique_dst": "Distinct destinations (packet level)",
    "has_packet_features": "Packet-level data available",
}


def label_for(column: str) -> str:
    return FEATURE_LABELS.get(column, column)


def feature_level(column: str) -> str:
    """Which of the PS's two required feature levels a column belongs to."""
    if column in PACKET_FEATURE_COLUMNS:
        return "packet"
    if column in FLOW_FEATURE_COLUMNS:
        return "flow"
    return "meta"


def attribute_features(
    model,
    obs: torch.Tensor,
    step: int = -1,
    top_k: int = 8,
    columns: list[str] | None = None,
    ig_steps: int = 32,
) -> list[dict]:
    """Integrated-gradients attribution for the infiltration score at one step.

    Plain gradient x input was the first implementation here and it broke on
    exactly the cases that matter. Once the model is confident - which on a
    genuinely compromised host means a logit far into saturation - the local
    gradient collapses to ~1e-3 and every feature looks equally irrelevant. The
    ranking survived but the magnitudes were meaningless.

    Integrated gradients fixes this by accumulating gradients along a straight
    path from a baseline to the real observation, so the attribution reflects
    the whole journey rather than the flat point at the end. It also satisfies
    completeness: the attributions sum to F(x) - F(baseline), which is why the
    returned `share` values are directly comparable.

    The baseline is the zero vector in *scaled* space, which after
    standardisation is the mean of the training distribution - i.e. "an average
    host". So every attribution reads as "how this host differs from a typical
    one", which is the comparison a defender is already making.

    Args:
        model: a trained WorldModel.
        obs: (1, T, F) scaled observation sequence.
        step: which timestep's score to explain; -1 means the latest.
        top_k: how many features to return.
        columns: feature names, in model order.
        ig_steps: Riemann steps along the path. 32 is plenty at this scale.

    Returns:
        Ranked list of dicts with the feature name, its signed contribution,
        its share of total attribution mass, and its feature level.
    """
    model.eval()
    baseline = torch.zeros_like(obs)
    total_grad = torch.zeros_like(obs[0, step])

    for i in range(ig_steps):
        # Midpoint rule: alpha at the centre of each of ig_steps intervals.
        alpha = (i + 0.5) / ig_steps
        point = (baseline + alpha * (obs - baseline)).detach().requires_grad_(True)

        out = model.observe(point, sample=False)
        score = out["infiltration_logit"][0, step]

        model.zero_grad(set_to_none=True)
        score.backward()
        total_grad += point.grad[0, step].detach()

    avg_grad = (total_grad / ig_steps).cpu().numpy()
    value = obs[0, step].detach().cpu().numpy()
    contribution = avg_grad * value          # (x - baseline) with baseline = 0

    magnitude = np.abs(contribution).sum()
    order = np.argsort(-np.abs(contribution))[:top_k]
    names = columns or [f"f{i}" for i in range(len(contribution))]

    return [
        {
            "feature": names[i],
            "label": label_for(names[i]),
            "level": feature_level(names[i]),
            "contribution": float(contribution[i]),
            # Share of total attribution mass - stable regardless of how
            # saturated the logit is, and the value the dashboard displays.
            "share": float(abs(contribution[i]) / magnitude) if magnitude > 0 else 0.0,
            "scaled_value": float(value[i]),
            "direction": "increases risk" if contribution[i] > 0 else "reduces risk",
        }
        for i in order
    ]


def attention_summary(
    attention: torch.Tensor, step: int = -1, top_k: int = 5
) -> list[dict]:
    """Which past windows the model attended to when scoring `step`.

    Args:
        attention: (B, T, T) weights from `WorldModel.observe`.
        step: query step to explain.
        top_k: how many attended windows to report.
    """
    weights = attention[0, step].detach().cpu().numpy()
    t = len(weights)
    query = step if step >= 0 else t + step

    order = np.argsort(-weights)[:top_k]
    return [
        {
            "window_offset": int(i - query),  # negative = that many windows back
            "weight": float(weights[i]),
        }
        for i in order
        if weights[i] > 1e-4
    ]


def predicted_state_delta(
    current_obs: np.ndarray,
    predicted_obs: np.ndarray,
    scaler,
    columns: list[str],
    top_k: int = 6,
) -> list[dict]:
    """Largest expected changes between now and the forecast, in real units.

    This is the explanation defenders respond to best: not "risk is 0.81" but
    "distinct destination ports is expected to go from 12 to 240".
    """
    cur = scaler.inverse_standardise(current_obs.reshape(1, -1))[0]
    nxt = scaler.inverse_standardise(predicted_obs.reshape(1, -1))[0]

    # Rank by relative change so a jump from 2 to 40 outranks 10000 to 10500.
    denom = np.maximum(np.abs(cur), 1.0)
    relative = (nxt - cur) / denom
    order = np.argsort(-np.abs(relative))[:top_k]

    return [
        {
            "feature": columns[i],
            "label": label_for(columns[i]),
            "level": feature_level(columns[i]),
            "current": float(cur[i]),
            "predicted": float(nxt[i]),
            "relative_change": float(relative[i]),
        }
        for i in order
    ]


def shap_values(
    model,
    obs: torch.Tensor,
    background: torch.Tensor,
    step: int = -1,
    n_samples: int = 64,
    columns: list[str] | None = None,
    top_k: int = 8,
    seed: int = 0,
) -> list[dict]:
    """Sampled Shapley values for offline reporting.

    Uses the standard permutation estimator: repeatedly interpolate between a
    background observation and the real one in random feature order, and credit
    each feature with the change in score when it is switched on. Slower than
    gradient x input but model-agnostic, so it serves as an independent check
    that the fast attribution is not misleading.
    """
    rng = np.random.default_rng(seed)
    model.eval()
    n_features = obs.shape[-1]
    total = np.zeros(n_features, dtype=np.float64)

    with torch.no_grad():
        for _ in range(n_samples):
            bg = background[rng.integers(len(background))].unsqueeze(0)
            perm = rng.permutation(n_features)

            work = bg.clone()
            work[:, :step if step >= 0 else None] = obs[:, :step if step >= 0 else None]
            prev = model.observe(work, sample=False)["infiltration_logit"][0, step].item()

            for f in perm:
                work[0, step, f] = obs[0, step, f]
                cur = model.observe(work, sample=False)["infiltration_logit"][0, step].item()
                total[f] += cur - prev
                prev = cur

    values = total / n_samples
    order = np.argsort(-np.abs(values))[:top_k]
    names = columns or [f"f{i}" for i in range(n_features)]
    return [
        {
            "feature": names[i],
            "label": label_for(names[i]),
            "level": feature_level(names[i]),
            "shap_value": float(values[i]),
        }
        for i in order
    ]
