"""Sequence dataset construction and feature scaling.

The world model consumes fixed-length sequences of consecutive network states
belonging to a single host. Sequences never span two hosts: mixing them would
teach the dynamics model transitions that never happen.

Scaling deserves a note. Network features are wildly heavy-tailed - a host can
send 200 bytes or 200 MB in a window - so raw values would let a handful of
dimensions dominate the reconstruction loss. We apply a signed log1p transform
to the unbounded columns before standardising, which compresses the tail while
leaving the already-bounded fractions and entropies alone.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

from .config import SEQUENCE_LENGTH

log = logging.getLogger(__name__)

# Columns that are counts or byte totals: unbounded and heavy-tailed, so they
# get a log transform. Everything else (fractions, entropies, ratios) is
# already on a sane scale.
_LOG_PREFIXES = ("n_", "tot_", "src_bytes", "dst_bytes", "bytes_", "pkts_",
                 "dur_", "iat_", "pkt_count", "pkt_ttl_", "pkt_win_",
                 "pkt_payload_", "pkt_iat_", "pkt_nunique_")


def _needs_log(column: str) -> bool:
    return any(column.startswith(p) for p in _LOG_PREFIXES)


class FeatureScaler:
    """Signed log1p on heavy-tailed columns, then per-column standardisation."""

    def __init__(self, columns: list[str]):
        self.columns = list(columns)
        self.log_mask = np.array([_needs_log(c) for c in self.columns])
        self.mean = np.zeros(len(self.columns), dtype=np.float32)
        self.std = np.ones(len(self.columns), dtype=np.float32)

    def _pre(self, x: np.ndarray) -> np.ndarray:
        x = x.astype(np.float32, copy=True)
        if self.log_mask.any():
            cols = x[:, self.log_mask]
            x[:, self.log_mask] = np.sign(cols) * np.log1p(np.abs(cols))
        return x

    def fit(self, x: np.ndarray) -> "FeatureScaler":
        z = self._pre(x)
        self.mean = z.mean(axis=0)
        # Guard against constant columns producing division by zero.
        self.std = np.maximum(z.std(axis=0), 1e-6)
        return self

    def transform(self, x: np.ndarray) -> np.ndarray:
        z = self._pre(x)
        out = (z - self.mean) / self.std
        # Clip extreme outliers; a single pathological window should not blow
        # up the reconstruction loss for a whole batch.
        return np.clip(out, -10.0, 10.0).astype(np.float32)

    def fit_transform(self, x: np.ndarray) -> np.ndarray:
        return self.fit(x).transform(x)

    def inverse_standardise(self, z: np.ndarray) -> np.ndarray:
        """Undo standardisation only - used to report predicted feature values
        in units a defender recognises, before the log transform is reversed."""
        x = z * self.std + self.mean
        out = x.copy()
        if self.log_mask.any():
            cols = out[..., self.log_mask]
            out[..., self.log_mask] = np.sign(cols) * np.expm1(np.abs(cols))
        return out

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({
            "columns": self.columns,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "FeatureScaler":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        s = cls(d["columns"])
        s.mean = np.asarray(d["mean"], dtype=np.float32)
        s.std = np.asarray(d["std"], dtype=np.float32)
        return s


def temporal_split(
    cells: pd.DataFrame,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    guard_windows: int = 16,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split each capture by wall-clock time: past trains, future tests.

    This is the deployment-shaped evaluation. An enterprise installs the system
    on its own network, it learns that network's hosts and rhythms, and it
    forecasts forward from there. Train on the first 70% of every capture,
    validate on the next 15%, test on the final 15%, with a guard band between
    the splits so no sequence straddles a boundary and leaks its own future.

    This is deliberately a *different* question from the family-holdout split in
    `config.TRAIN_SCENARIOS` and friends. That one asks whether the model
    transfers to malware it has never seen; this one asks whether it can
    forecast the network it is watching. Both are reported.

    Args:
        cells: state cells from any number of scenarios.
        train_frac: share of each capture's timeline used for training.
        val_frac: share used for validation.
        guard_windows: windows dropped either side of each boundary.

    Returns:
        (train, validation, test) frames.
    """
    train_parts, val_parts, test_parts = [], [], []

    group_key = "scenario" if "scenario" in cells.columns else None
    groups = cells.groupby(group_key, sort=True) if group_key else [(None, cells)]

    for name, grp in groups:
        lo, hi = grp["window"].min(), grp["window"].max()
        span = hi - lo
        if span <= 0:
            continue
        t_end = lo + span * train_frac
        v_end = lo + span * (train_frac + val_frac)

        w = grp["window"]
        train_parts.append(grp[w <= t_end - guard_windows])
        val_parts.append(grp[(w > t_end) & (w <= v_end - guard_windows)])
        test_parts.append(grp[w > v_end])

    def _cat(parts):
        frames = [p for p in parts if not p.empty]
        return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=cells.columns)

    tr, va, te = _cat(train_parts), _cat(val_parts), _cat(test_parts)
    log.info(
        "temporal split: train %d / val %d / test %d cells "
        "(malicious %.2f%% / %.2f%% / %.2f%%)",
        len(tr), len(va), len(te),
        100 * tr["is_malicious"].mean() if len(tr) else 0.0,
        100 * va["is_malicious"].mean() if len(va) else 0.0,
        100 * te["is_malicious"].mean() if len(te) else 0.0,
    )
    return tr, va, te


def build_sequences(
    cells: pd.DataFrame,
    feature_columns: list[str],
    scaler: FeatureScaler,
    sequence_length: int = SEQUENCE_LENGTH,
    stride: int = 4,
    malicious_stride: int = 1,
) -> dict[str, np.ndarray]:
    """Slice per-host state cells into fixed-length training sequences.

    Args:
        cells: state cells with targets already attached.
        feature_columns: ordered feature names.
        scaler: fitted scaler applied to the observations.
        sequence_length: T.
        stride: hop between consecutive sequences for quiet hosts.
        malicious_stride: hop for hosts that show any malicious activity.
            CTU-13 contains roughly one infected host per scenario, so the
            informative sequences are a rounding error at a uniform stride.
            Sliding by one window over those hosts is the cheapest way to
            recover positives; the sequences overlap heavily, so this raises
            coverage of the transitions rather than adding new information,
            and it is paired with regularisation in the training config.

    Returns:
        dict of arrays: obs (N,T,F), infiltration (N,T), stage (N,T),
        host_index (N,), start_window (N,).
    """
    obs_list, inf_list, stage_list, hosts, starts = [], [], [], [], []
    host_names: list[str] = []

    for host, grp in cells.groupby("src", sort=False):
        grp = grp.sort_values("window")
        if len(grp) < sequence_length:
            continue

        host_stride = (
            malicious_stride
            if ("is_malicious" in grp.columns and grp["is_malicious"].max() > 0)
            else stride
        )

        x = scaler.transform(grp[feature_columns].to_numpy(dtype=np.float32))
        y_inf = grp["infiltration_next"].to_numpy(dtype=np.int64)
        y_stage = grp["next_stage"].to_numpy(dtype=np.int64)
        w = grp["window"].to_numpy()

        host_id = len(host_names)
        host_names.append(host)

        for s in range(0, len(grp) - sequence_length + 1, host_stride):
            e = s + sequence_length
            obs_list.append(x[s:e])
            inf_list.append(y_inf[s:e])
            stage_list.append(y_stage[s:e])
            hosts.append(host_id)
            starts.append(int(w[s]))

    if not obs_list:
        raise ValueError(
            f"No host produced {sequence_length} consecutive cells. "
            "Lower SEQUENCE_LENGTH or MIN_FLOWS_PER_CELL."
        )

    out = {
        "obs": np.stack(obs_list).astype(np.float32),
        "infiltration": np.stack(inf_list).astype(np.int64),
        "stage": np.stack(stage_list).astype(np.int64),
        "host_index": np.asarray(hosts, dtype=np.int64),
        "start_window": np.asarray(starts, dtype=np.int64),
        "host_names": np.asarray(host_names, dtype=object),
    }
    log.info(
        "sequences: %d of length %d over %d hosts, %.2f%% positive steps",
        len(out["obs"]), sequence_length, len(host_names),
        100.0 * out["infiltration"].mean(),
    )
    return out


class NetworkSequenceDataset(Dataset):
    """Torch dataset over pre-built sequence arrays."""

    def __init__(self, arrays: dict[str, np.ndarray]):
        self.obs = torch.from_numpy(arrays["obs"])
        self.infiltration = torch.from_numpy(arrays["infiltration"])
        self.stage = torch.from_numpy(arrays["stage"])

    def __len__(self) -> int:
        return self.obs.shape[0]

    def __getitem__(self, i: int):
        return self.obs[i], self.infiltration[i], self.stage[i]


def sequence_sampler_weights(
    infiltration: np.ndarray, stage: np.ndarray, target_positive_share: float = 0.4
) -> np.ndarray:
    """Sampling weights that put real signal in every batch.

    The raw sequence pool is pathologically imbalanced: on CTU-13 roughly 1% of
    sequences contain any malicious window at all, so a uniformly sampled batch
    of 128 usually contains none and the model spends almost all of its updates
    confirming that quiet hosts stay quiet.

    Three tiers, most informative first:
      - sequences containing a *stage change*, which are the only ones that
        teach kill-chain dynamics rather than persistence;
      - sequences containing malicious activity without a transition;
      - everything else.

    Weights are set so the informative tiers together make up roughly
    `target_positive_share` of each epoch's draws.

    Args:
        infiltration: (N, T) binary targets.
        stage: (N, T) stage targets.
        target_positive_share: intended share of informative sequences.

    Returns:
        (N,) float64 weights for `torch.utils.data.WeightedRandomSampler`.
    """
    has_positive = infiltration.sum(axis=1) > 0
    changes_stage = np.array([len(np.unique(row[row > 0])) > 1 for row in stage])

    tier_transition = changes_stage
    tier_positive = has_positive & ~changes_stage
    tier_negative = ~has_positive & ~changes_stage

    n = len(infiltration)
    weights = np.ones(n, dtype=np.float64)

    n_trans, n_pos, n_neg = (
        int(tier_transition.sum()), int(tier_positive.sum()), int(tier_negative.sum())
    )
    if n_neg == 0 or (n_trans + n_pos) == 0:
        return weights  # nothing to rebalance

    # Split the informative budget: transitions get twice the mass of plain
    # positives, because they carry the dynamics the world model exists to learn.
    budget = target_positive_share
    trans_share = budget * (2 / 3) if n_trans else 0.0
    pos_share = budget - trans_share

    if n_trans:
        weights[tier_transition] = trans_share / n_trans
    if n_pos:
        weights[tier_positive] = pos_share / n_pos
    weights[tier_negative] = (1.0 - budget) / n_neg

    log.info(
        "sampler tiers: %d with stage transitions, %d malicious-only, %d quiet "
        "(target informative share %.0f%%)",
        n_trans, n_pos, n_neg, 100 * target_positive_share,
    )
    return weights


def positive_weight(infiltration: np.ndarray) -> float:
    """pos_weight for BCE so the rare positive class is not ignored.

    Infiltration windows are a small minority; without reweighting the model
    reaches high accuracy by predicting "safe" everywhere, which is exactly the
    failure mode a security tool cannot have.
    """
    pos = float(infiltration.sum())
    neg = float(infiltration.size - pos)
    if pos <= 0:
        return 1.0
    # Capped: an unbounded weight makes early training unstable.
    return float(np.clip(neg / pos, 1.0, 25.0))
