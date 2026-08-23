"""Turn raw flows into the time-windowed network state the world model consumes.

This is the module that defines what "network state" means in this project.
A state S_t is one (host, window) cell: everything a single internal host did
during one 60-second window, summarised into a fixed-width feature vector.

Choosing the host as the unit rather than the whole network is deliberate.
"Will the network be attacked" is not an actionable question; "is THIS host on
a trajectory towards exfiltration" is. It also multiplies the number of
training sequences by the host count, which matters on a dataset this size.

Everything here is vectorised over pandas groupby. A per-group Python loop over
CTU-13's 2.8M flows takes minutes; these aggregations take seconds.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from ..config import (
    C2_PORTS,
    INTERNAL_PREFIXES,
    LATERAL_PORTS,
    LOOKAHEAD_WINDOWS,
    MIN_FLOWS_PER_CELL,
    WINDOW_SECONDS,
)
from ..mitre import BENIGN, LATERAL_MOVEMENT, derive_stage
from .flow import LABEL_BOTNET

log = logging.getLogger(__name__)


def _dominant_stage_per_cell(df: pd.DataFrame, cell: pd.Series) -> pd.Series:
    """The stage the host spent most of its malicious flows in, per cell.

    Using the *dominant* stage rather than the furthest-along one matters more
    than it looks. A spam bot emits a handful of C2 flows and then thousands of
    spam deliveries every single window; taking the maximum stage would label
    every window from the first spam onward as Exfiltration and the kill chain
    would appear to teleport to its end and freeze there. The dominant stage
    answers the question a defender actually asks - what was this host mostly
    doing in this minute - and leaves the progression visible.

    Ties break towards the later stage, so a window evenly split between C2 and
    exfiltration is reported as the more serious of the two.
    """
    bot_mask = (df["is_botnet"] == 1) & (df["botnet_stage"] >= 0)
    if not bot_mask.any():
        return pd.Series(dtype=np.int64)

    counts = (
        df.loc[bot_mask]
        .groupby([cell[bot_mask], df.loc[bot_mask, "botnet_stage"]], observed=True)
        .size()
        .rename("n")
        .reset_index()
    )
    counts.columns = ["_cell", "stage", "n"]
    counts = counts.sort_values(
        ["_cell", "n", "stage"], ascending=[True, False, False], kind="stable"
    )
    return counts.groupby("_cell", observed=True).first()["stage"]


def _entropy_per_cell(df: pd.DataFrame, cell: pd.Series, column: str) -> pd.Series:
    """Shannon entropy of `column` within each cell, fully vectorised.

    Computed as -sum(p log2 p) where p is the share of each distinct value
    inside the cell. Used for destination and port dispersion, which is the
    cleanest single indicator separating scanning from normal traffic.
    """
    counts = df.groupby([cell, df[column]], observed=True).size().rename("n")
    totals = counts.groupby(level=0, observed=True).transform("sum")
    p = counts / totals
    return (-p * np.log2(p)).groupby(level=0, observed=True).sum()


def build_state_cells(
    flows: pd.DataFrame,
    window_seconds: float = WINDOW_SECONDS,
    min_flows: int = MIN_FLOWS_PER_CELL,
    internal_only: bool = True,
) -> pd.DataFrame:
    """Aggregate a flow table into per-(host, window) state vectors.

    Args:
        flows: output of `features.flow.load_binetflow`.
        window_seconds: observation cadence.
        min_flows: drop cells thinner than this; their statistics are noise.
        internal_only: keep only hosts inside the monitored range. External
            hosts are peers, not assets we are defending.

    Returns:
        One row per (src, window) with flow-level features, the malicious
        label, and the derived MITRE stage.
    """
    df = flows
    if internal_only:
        mask = np.zeros(len(df), dtype=bool)
        for prefix in INTERNAL_PREFIXES:
            mask |= df["src"].str.startswith(prefix).to_numpy()
        df = df.loc[mask]
        if df.empty:
            raise ValueError(
                "No flows originate inside INTERNAL_PREFIXES; check config."
            )

    df = df.reset_index(drop=True)
    # Absolute window grid (epoch // width) so flow-derived and packet-derived
    # cells for the same capture line up on (host, window). See packet.py.
    df["window"] = (df["ts"] // window_seconds).astype(np.int64)

    # Derived per-flow indicators the aggregations below sum over.
    df["is_internal_dst"] = np.zeros(len(df), dtype=np.int8)
    for prefix in INTERNAL_PREFIXES:
        df["is_internal_dst"] |= df["dst"].str.startswith(prefix).astype(np.int8)
    df["is_lateral_port"] = df["dport"].isin(LATERAL_PORTS).astype(np.int8)
    df["is_c2_port"] = df["dport"].isin(C2_PORTS).astype(np.int8)
    df["is_high_port"] = (df["dport"] >= 1024).astype(np.int8)
    df["is_tcp"] = (df["proto"] == "tcp").astype(np.int8)
    df["is_udp"] = (df["proto"] == "udp").astype(np.int8)
    df["is_icmp"] = (df["proto"] == "icmp").astype(np.int8)
    df["is_botnet"] = (df["label_class"] == LABEL_BOTNET).astype(np.int8)

    # Stage annotation carried by malicious flows only. Benign flows get -1 so
    # a max() over the cell picks the furthest-along malicious behaviour and
    # ignores everything benign. The stage constants are numbered in kill-chain
    # order, so max() is the same as "latest stage reached in this window".
    df["botnet_stage"] = np.where(
        df["is_botnet"] == 1, df.get("stage_hint", -1), -1
    ).astype(np.int8)

    # Inter-flow arrival gaps within a cell, for the beaconing signal.
    df = df.sort_values(["src", "window", "ts"], kind="stable")
    cell_key = df["src"].astype(str) + "|" + df["window"].astype(str)
    df["_cell"] = pd.Categorical(cell_key)
    df["iat"] = df.groupby("_cell", observed=True)["ts"].diff()

    g = df.groupby("_cell", observed=True)

    agg = g.agg(
        src=("src", "first"),
        window=("window", "first"),
        ts_start=("ts", "min"),
        n_flows=("ts", "size"),
        n_unique_dst=("dst", "nunique"),
        n_unique_dport=("dport", "nunique"),
        n_unique_sport=("sport", "nunique"),
        dur_mean=("duration", "mean"),
        dur_std=("duration", "std"),
        dur_max=("duration", "max"),
        tot_bytes=("tot_bytes", "sum"),
        src_bytes=("src_bytes", "sum"),
        dst_bytes=("dst_bytes", "sum"),
        tot_pkts=("tot_pkts", "sum"),
        frac_internal_dst=("is_internal_dst", "mean"),
        frac_lateral_port=("is_lateral_port", "mean"),
        frac_c2_port=("is_c2_port", "mean"),
        frac_high_port=("is_high_port", "mean"),
        frac_tcp=("is_tcp", "mean"),
        frac_udp=("is_udp", "mean"),
        frac_icmp=("is_icmp", "mean"),
        frac_bidirectional=("bidirectional", "mean"),
        frac_syn=("src_syn", "mean"),
        frac_ack=("src_ack", "mean"),
        frac_fin=("src_fin", "mean"),
        frac_rst=("src_rst", "mean"),
        frac_psh=("src_psh", "mean"),
        frac_urg=("src_urg", "mean"),
        frac_handshake=("handshake_complete", "mean"),
        frac_syn_only=("syn_only", "mean"),
        frac_reset=("reset", "mean"),
        iat_mean=("iat", "mean"),
        iat_std=("iat", "std"),
        n_botnet_flows=("is_botnet", "sum"),
        # Furthest point down the kill chain touched in this window. Kept
        # alongside the dominant stage for reporting "peak severity".
        peak_stage=("botnet_stage", "max"),
    )

    agg["dst_entropy"] = _entropy_per_cell(df, df["_cell"], "dst")
    agg["dport_entropy"] = _entropy_per_cell(df, df["_cell"], "dport")
    agg["label_stage"] = (
        _dominant_stage_per_cell(df, df["_cell"]).reindex(agg.index).fillna(-1).astype(np.int64)
    )

    agg = agg[agg["n_flows"] >= min_flows].copy()
    if agg.empty:
        raise ValueError("No cells survived the min_flows filter.")

    # Ratios that are more stable than the raw counters they come from.
    agg["bytes_per_flow"] = agg["tot_bytes"] / agg["n_flows"]
    agg["pkts_per_flow"] = agg["tot_pkts"] / agg["n_flows"]
    agg["bytes_per_pkt"] = agg["tot_bytes"] / agg["tot_pkts"].clip(lower=1)
    agg["egress_ratio"] = agg["src_bytes"] / agg["tot_bytes"].clip(lower=1)
    agg["fan_out_ratio"] = agg["n_unique_dst"] / agg["n_flows"]
    agg["port_fan_ratio"] = agg["n_unique_dport"] / agg["n_flows"]

    # Beaconing: metronomic traffic has near-zero coefficient of variation in
    # its inter-arrival gaps. Mapped to 0..1 where 1 is perfectly regular.
    cv = (agg["iat_std"] / agg["iat_mean"].replace(0, np.nan)).fillna(0.0)
    agg["beacon_regularity"] = (1.0 / (1.0 + cv)).clip(0.0, 1.0)

    agg = agg.fillna(0.0)
    agg["is_malicious"] = (agg["n_botnet_flows"] > 0).astype(np.int8)

    agg = _assign_stages(agg)

    agg = agg.reset_index(drop=True).sort_values(["src", "window"]).reset_index(drop=True)
    log.info(
        "state cells: %d over %d hosts, %.2f%% malicious",
        len(agg), agg["src"].nunique(), 100.0 * agg["is_malicious"].mean(),
    )
    return agg


def _assign_stages(agg: pd.DataFrame) -> pd.DataFrame:
    """Attach a MITRE stage to every malicious cell.

    Two sources, in order of authority:

      1. The dataset's own flow annotation, aggregated to the cell as the
         furthest-along stage seen in that window. This is ground truth from
         the capture authors and wins wherever it exists.
      2. The behavioural rules in `src.mitre.derive_stage`, used only for
         malicious cells whose labels carried no annotation.

    One deliberate exception: when the behavioural rules identify lateral
    movement - internal-to-internal traffic on administrative ports, a narrow
    and specific signal - we take the later of the two stages. CTU-13's labels
    have no vocabulary for lateral movement at all, so trusting the label alone
    would make that stage permanently invisible.

    Benign cells are stage 0 by definition and never touch either path, so a
    rule misfire cannot invent an attack stage on a clean host.
    """
    stages = np.zeros(len(agg), dtype=np.int64)
    mal_idx = np.flatnonzero(agg["is_malicious"].to_numpy() == 1)
    n_from_label = 0

    if len(mal_idx):
        sub = agg.iloc[mal_idx]
        resolved = []
        for r in sub.itertuples():
            behavioural = derive_stage(
                n_flows=int(r.n_flows),
                n_unique_dst_ips=int(r.n_unique_dst),
                n_unique_dst_ports=int(r.n_unique_dport),
                mean_duration=float(r.dur_mean),
                src_bytes=float(r.src_bytes),
                total_bytes=float(r.tot_bytes),
                frac_internal_dst=float(r.frac_internal_dst),
                frac_lateral_ports=float(r.frac_lateral_port),
                frac_c2_ports=float(r.frac_c2_port),
                frac_syn_only=float(r.frac_syn_only),
                beacon_regularity=float(r.beacon_regularity),
            )
            labelled = int(getattr(r, "label_stage", -1))

            if labelled > BENIGN:
                n_from_label += 1
                if behavioural == LATERAL_MOVEMENT:
                    resolved.append(max(labelled, behavioural))
                else:
                    resolved.append(labelled)
            else:
                resolved.append(behavioural)

        stages[mal_idx] = resolved

    agg["stage"] = stages
    if len(mal_idx):
        log.info(
            "stages: %d/%d malicious cells from dataset labels, %d from behaviour",
            n_from_label, len(mal_idx), len(mal_idx) - n_from_label,
        )
    return agg


def build_edges(
    flows: pd.DataFrame,
    window_seconds: float = WINDOW_SECONDS,
    min_flows: int = 2,
    top_n: int = 4000,
) -> pd.DataFrame:
    """Who talked to whom, aggregated per (source, destination).

    The state cells deliberately collapse each host's traffic into aggregates,
    which throws away the peer on the other end. That is right for the model -
    it should learn behaviour, not memorise addresses - but it leaves nothing to
    draw a topology from, so the graph view is built from this separate table.

    Capped at `top_n` busiest pairs: a capture contains tens of thousands of
    distinct pairs, and past a few thousand edges a force-directed graph is an
    unreadable hairball anyway.

    Args:
        flows: output of `features.flow.load_binetflow`.
        window_seconds: same grid the state cells use.
        min_flows: drop pairs seen fewer times than this.
        top_n: keep only the busiest pairs.

    Returns:
        One row per (src, dst) with flow/byte totals, whether the pair carried
        malicious traffic, and the window range it was active over.
    """
    df = flows.copy()
    df["window"] = (df["ts"] // window_seconds).astype(np.int64)
    df["is_botnet"] = (df["label_class"] == LABEL_BOTNET).astype(np.int8)

    agg = (
        df.groupby(["src", "dst"], observed=True)
        .agg(
            n_flows=("ts", "size"),
            tot_bytes=("tot_bytes", "sum"),
            n_botnet=("is_botnet", "sum"),
            first_window=("window", "min"),
            last_window=("window", "max"),
            n_ports=("dport", "nunique"),
        )
        .reset_index()
    )

    agg = agg[agg["n_flows"] >= min_flows]
    agg["is_malicious"] = (agg["n_botnet"] > 0).astype(np.int8)

    # Keep every malicious pair regardless of volume - those are the ones the
    # graph exists to show - then fill the remaining budget with the busiest.
    malicious = agg[agg["is_malicious"] == 1]
    benign = agg[agg["is_malicious"] == 0].nlargest(
        max(0, top_n - len(malicious)), "n_flows"
    )
    out = pd.concat([malicious, benign], ignore_index=True)

    log.info(
        "edges: %d pairs kept (%d malicious) from %d distinct pairs",
        len(out), int(out["is_malicious"].sum()), len(agg),
    )
    return out


def attach_packet_features(
    cells: pd.DataFrame, packet_cells: pd.DataFrame
) -> pd.DataFrame:
    """Left-join packet-level features onto the flow-level state cells.

    Windows are aligned by index, which requires both extractions to have used
    the same `window_seconds` and the same capture start. Cells with no packet
    coverage get zeros and a `has_packet_features` flag of 0, so the model can
    learn to fall back on flow features when the packet level is unavailable -
    exactly the situation when only NetFlow is exported.
    """
    from .packet import PACKET_FEATURE_COLUMNS

    if packet_cells is None or packet_cells.empty:
        for c in PACKET_FEATURE_COLUMNS:
            cells[c] = 0.0
        cells["has_packet_features"] = 0.0
        return cells

    merged = cells.merge(packet_cells, on=["src", "window"], how="left")
    merged["has_packet_features"] = merged["pkt_count"].notna().astype(np.float64)
    for c in PACKET_FEATURE_COLUMNS:
        if c not in merged.columns:
            merged[c] = 0.0
    merged[PACKET_FEATURE_COLUMNS] = merged[PACKET_FEATURE_COLUMNS].fillna(0.0)

    log.info(
        "packet coverage: %.1f%% of cells",
        100.0 * merged["has_packet_features"].mean(),
    )
    return merged


def add_forecast_targets(
    cells: pd.DataFrame, lookahead: int = LOOKAHEAD_WINDOWS
) -> pd.DataFrame:
    """Add the forward-looking labels that make this forecasting, not detection.

    `infiltration_next` is 1 when the same host is malicious in any of the next
    `lookahead` windows. A model scored on this cannot succeed by recognising
    an attack that is already visible; it has to anticipate one.

    `next_stage` is the stage the host actually reaches in that horizon - the
    supervision signal for progression prediction.
    """
    out = []
    for host, grp in cells.groupby("src", sort=False):
        grp = grp.sort_values("window").copy()
        mal = grp["is_malicious"].to_numpy()
        stage = grp["stage"].to_numpy()
        n = len(grp)

        future_mal = np.zeros(n, dtype=np.int8)
        future_stage = np.zeros(n, dtype=np.int64)

        for i in range(n):
            # Window indices are not necessarily contiguous (quiet windows are
            # dropped), so step over positions rather than window numbers.
            hi = min(n, i + 1 + lookahead)
            fut = mal[i + 1: hi]
            if fut.size and fut.max() > 0:
                future_mal[i] = 1
                fut_stages = stage[i + 1: hi]
                active = fut_stages[fut_stages > BENIGN]
                if active.size:
                    # The furthest point down the kill chain reached.
                    future_stage[i] = int(active.max())

        grp["infiltration_next"] = future_mal
        grp["next_stage"] = future_stage
        out.append(grp)

    res = pd.concat(out, ignore_index=True)
    log.info(
        "forecast targets: %.2f%% of cells precede an infiltration within %d windows",
        100.0 * res["infiltration_next"].mean(), lookahead,
    )
    return res


# Flow-level columns fed to the model, in fixed order.
FLOW_FEATURE_COLUMNS = [
    "n_flows", "n_unique_dst", "n_unique_dport", "n_unique_sport",
    "dur_mean", "dur_std", "dur_max",
    "tot_bytes", "src_bytes", "dst_bytes", "tot_pkts",
    "bytes_per_flow", "pkts_per_flow", "bytes_per_pkt", "egress_ratio",
    "fan_out_ratio", "port_fan_ratio",
    "frac_internal_dst", "frac_lateral_port", "frac_c2_port", "frac_high_port",
    "frac_tcp", "frac_udp", "frac_icmp", "frac_bidirectional",
    "frac_syn", "frac_ack", "frac_fin", "frac_rst", "frac_psh", "frac_urg",
    "frac_handshake", "frac_syn_only", "frac_reset",
    "iat_mean", "iat_std", "beacon_regularity",
    "dst_entropy", "dport_entropy",
]


def feature_columns(include_packet: bool | None = None) -> list[str]:
    """Ordered feature list: flow level, optionally followed by packet level.

    Packet features are opt-in, and the reason is a leak worth understanding.

    The only PCAP CTU-13 publishes at a convenient size for scenario 1 is
    `botnet-capture-...-neris.pcap`, which contains *only* the infected host's
    traffic and only part of the timeline. Join that onto the state cells and
    `has_packet_features` becomes a perfect label proxy: it is 1 exactly when
    the host is the bot and the window is early. A model handed that column
    scores 0.9995 on training windows and 0.003 on every later window of the
    same host - it learned the metadata, not the behaviour.

    So packet features are only included when the capture's packet coverage is
    label-independent, which in practice means a full-traffic capture. The
    extractor itself is unaffected and always runs for uploaded PCAPs, where
    the user's capture covers their whole network.

    Args:
        include_packet: override the config default.
    """
    from ..config import USE_PACKET_FEATURES
    from .packet import PACKET_FEATURE_COLUMNS

    use = USE_PACKET_FEATURES if include_packet is None else include_packet
    if not use:
        return list(FLOW_FEATURE_COLUMNS)
    return FLOW_FEATURE_COLUMNS + PACKET_FEATURE_COLUMNS + ["has_packet_features"]
