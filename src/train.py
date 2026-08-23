"""Train the world model on CTU-13 state cells.

Run as:
    python -m src.train
    python -m src.train --epochs 10 --scenarios-train 1 4

The split is by malware family, not random. Sequences from the same scenario
are highly autocorrelated, so a random split would leak: the model would see
window t in training and window t+1 in test and score beautifully while having
learned nothing transferable. Holding out entire families is the only split
that answers the question the PS actually asks - does this generalise to an
attack pattern it has never seen?
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, f1_score
from torch.utils.data import DataLoader, WeightedRandomSampler

from .config import (
    CHECKPOINT_DIR,
    PROCESSED_DIR,
    SEQUENCE_LENGTH,
    TEST_SCENARIOS,
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    ModelConfig,
    RunConfig,
    TrainConfig,
)
from .dataset import (
    FeatureScaler,
    NetworkSequenceDataset,
    build_sequences,
    positive_weight,
    sequence_sampler_weights,
    temporal_split,
)
from .features.windows import feature_columns
from .model.world_model import WorldModel

log = logging.getLogger(__name__)


def load_cells(scenarios, processed_dir: Path = PROCESSED_DIR) -> pd.DataFrame:
    """Concatenate the prepared parquet files for a set of scenarios."""
    frames = []
    for s in scenarios:
        path = processed_dir / f"scenario_{s:02d}.parquet"
        if not path.exists():
            log.warning("missing %s, skipping scenario %d", path.name, s)
            continue
        frames.append(pd.read_parquet(path))
    if not frames:
        raise SystemExit(
            f"No prepared data for scenarios {list(scenarios)}. "
            "Run `python -m src.prepare_data` first."
        )
    df = pd.concat(frames, ignore_index=True)
    # Host identity is only unique within a scenario, so qualify it before any
    # grouping - otherwise sequences would splice two different machines.
    df["src"] = df["scenario"].astype(str) + ":" + df["src"].astype(str)
    return df


@torch.no_grad()
def evaluate_epoch(model: WorldModel, loader: DataLoader, cfg: TrainConfig,
                   pos_weight: torch.Tensor, device) -> dict:
    """Validation losses plus the ranking metrics used for model selection.

    Selecting on validation BCE turns out to be actively wrong here. The
    positive class is ~0.5% of validation steps, and as the model sharpens its
    predictions a handful of confident mistakes dominate the cross-entropy - so
    BCE rises from the first epoch even while the model's *ranking* of hosts by
    risk keeps improving. Average precision measures the ranking, ignores
    calibration, and is the standard choice on a class balance like this.
    """
    model.eval()
    totals: dict[str, float] = {}
    n = 0
    probs, targets, stage_pred, stage_true = [], [], [], []

    for obs, inf, stage in loader:
        obs, inf, stage = obs.to(device), inf.to(device), stage.to(device)
        _, metrics = model.compute_losses(obs, inf, stage, cfg, pos_weight)
        out = model.observe(obs, sample=False)

        probs.append(torch.sigmoid(out["infiltration_logit"]).cpu().numpy().ravel())
        targets.append(inf.cpu().numpy().ravel())
        stage_pred.append(out["stage_logits"].argmax(-1).cpu().numpy().ravel())
        stage_true.append(stage.cpu().numpy().ravel())

        b = obs.size(0)
        for k, v in metrics.items():
            totals[k] = totals.get(k, 0.0) + v * b
        n += b

    model.train()
    result = {k: v / max(n, 1) for k, v in totals.items()}

    y = np.concatenate(targets)
    p = np.concatenate(probs)
    st = np.concatenate(stage_true)
    sp = np.concatenate(stage_pred)

    # average_precision_score needs both classes present.
    result["average_precision"] = (
        float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else 0.0
    )
    result["stage_macro_f1"] = float(
        f1_score(st, sp, labels=list(range(model.cfg.n_stages)),
                 average="macro", zero_division=0)
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--sequence-length", type=int, default=SEQUENCE_LENGTH)
    parser.add_argument("--stride", type=int, default=4)
    parser.add_argument("--positive-share", type=float, default=0.4,
                        help="share of each epoch drawn from informative sequences")
    parser.add_argument("--scenarios-train", type=int, nargs="*", default=list(TRAIN_SCENARIOS))
    parser.add_argument("--scenarios-val", type=int, nargs="*", default=list(VAL_SCENARIOS))
    parser.add_argument("--split", choices=("family", "temporal"), default="temporal",
                        help="'temporal' learns each capture's past and forecasts "
                             "its future; 'family' holds out unseen malware families")
    parser.add_argument("--scenarios-all", type=int, nargs="*", default=[],
                        help="extra scenarios to include when --split temporal")
    parser.add_argument("--out", type=Path, default=CHECKPOINT_DIR / "world_model.pt")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    run = RunConfig()
    if args.epochs is not None:
        run.train.epochs = args.epochs
    if args.batch_size is not None:
        run.train.batch_size = args.batch_size
    if args.lr is not None:
        run.train.learning_rate = args.lr
    run.sequence_length = args.sequence_length

    torch.manual_seed(run.train.seed)
    np.random.seed(run.train.seed)
    device = torch.device("cpu")

    # -- data --------------------------------------------------------------
    cols = feature_columns()

    if args.split == "temporal":
        # Deployment-shaped split: learn the past of every capture, forecast
        # its future. See `temporal_split` for why both splits are reported.
        every = sorted(set(args.scenarios_train) | set(args.scenarios_val)
                       | set(TEST_SCENARIOS) | set(args.scenarios_all))
        all_cells = load_cells(every)
        train_cells, val_cells, _ = temporal_split(all_cells)
        split_meta = {"mode": "temporal", "scenarios": every}
    else:
        train_cells = load_cells(args.scenarios_train)
        val_cells = load_cells(args.scenarios_val)
        split_meta = {
            "mode": "family",
            "train": args.scenarios_train,
            "val": args.scenarios_val,
        }

    log.info("train cells %d | val cells %d | %d features",
             len(train_cells), len(val_cells), len(cols))

    # The scaler is fitted on training data only. Fitting on everything would
    # leak test-set statistics into the normalisation.
    scaler = FeatureScaler(cols)
    scaler.fit(train_cells[cols].to_numpy(dtype=np.float32))

    train_seq = build_sequences(train_cells, cols, scaler, run.sequence_length, args.stride)
    # Validation keeps a uniform stride: oversampling there would distort the
    # class balance the model is being selected on.
    val_seq = build_sequences(
        val_cells, cols, scaler, run.sequence_length, args.stride, malicious_stride=args.stride
    )

    pw = positive_weight(train_seq["infiltration"])
    log.info("positive weight: %.2f", pw)
    pos_weight = torch.tensor(pw, device=device)

    # Weighted sampling rather than shuffling. Roughly 1% of CTU-13 sequences
    # contain any malicious window, so a uniform batch of 128 typically holds
    # none and the model learns only that quiet hosts stay quiet.
    weights = sequence_sampler_weights(
        train_seq["infiltration"], train_seq["stage"],
        target_positive_share=args.positive_share,
    )
    sampler = WeightedRandomSampler(
        torch.from_numpy(weights), num_samples=len(weights), replacement=True
    )
    train_loader = DataLoader(
        NetworkSequenceDataset(train_seq), batch_size=run.train.batch_size,
        sampler=sampler, drop_last=True,
    )
    val_loader = DataLoader(
        NetworkSequenceDataset(val_seq), batch_size=run.train.batch_size, shuffle=False
    )

    # -- model -------------------------------------------------------------
    run.model = ModelConfig(obs_dim=len(cols))
    model = WorldModel(run.model).to(device)
    log.info("world model: %s parameters", f"{model.count_parameters():,}")

    opt = torch.optim.AdamW(
        model.parameters(), lr=run.train.learning_rate,
        weight_decay=run.train.weight_decay,
    )
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=run.train.epochs)

    best_val = float("inf")
    best_epoch = -1
    history = []
    args.out.parent.mkdir(parents=True, exist_ok=True)

    for epoch in range(run.train.epochs):
        t0 = time.time()
        model.train()
        agg: dict[str, float] = {}
        n = 0

        for obs, inf, stage in train_loader:
            obs, inf, stage = obs.to(device), inf.to(device), stage.to(device)
            if run.train.input_noise > 0:
                obs = obs + run.train.input_noise * torch.randn_like(obs)
            loss, metrics = model.compute_losses(obs, inf, stage, run.train, pos_weight)

            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), run.train.grad_clip)
            opt.step()

            b = obs.size(0)
            for k, v in metrics.items():
                agg[k] = agg.get(k, 0.0) + v * b
            n += b

        sched.step()
        train_metrics = {k: v / max(n, 1) for k, v in agg.items()}
        val_metrics = evaluate_epoch(model, val_loader, run.train, pos_weight, device)

        log.info(
            "epoch %2d/%d (%.0fs) train loss %.4f (recon %.3f kl %.3f inf %.3f imag %.3f) "
            "| val AP %.4f stage-F1 %.4f",
            epoch + 1, run.train.epochs, time.time() - t0,
            train_metrics["loss"], train_metrics["recon"], train_metrics["kl"],
            train_metrics["infiltration"], train_metrics["imagination"],
            val_metrics["average_precision"], val_metrics["stage_macro_f1"],
        )
        history.append({"epoch": epoch + 1, "train": train_metrics, "val": val_metrics})

        # Selection maximises ranking quality on validation, not likelihood.
        # Both terms matter: average precision for "which host is at risk", and
        # stage macro-F1 for the kill-chain dynamics that are the headline task
        # on this dataset. Negated so the comparison below stays a minimisation.
        score = -(
            val_metrics["average_precision"] + val_metrics["stage_macro_f1"]
        )
        if score < best_val:
            best_val = score
            best_epoch = epoch + 1
            torch.save({
                "model_state": model.state_dict(),
                "config": run.to_dict(),
                "feature_columns": cols,
                "scaler": {
                    "columns": scaler.columns,
                    "mean": scaler.mean.tolist(),
                    "std": scaler.std.tolist(),
                },
                "epoch": best_epoch,
                "val_score": best_val,
                "split": split_meta,
                "train_scenarios": args.scenarios_train,
                "val_scenarios": args.scenarios_val,
                "test_scenarios": list(TEST_SCENARIOS),
                "positive_weight": pw,
                "val_metrics": val_metrics,
            }, args.out)
            log.info("  -> new best (AP+stageF1 %.4f), saved %s", -best_val, args.out.name)
        elif epoch + 1 - best_epoch >= run.train.early_stop_patience:
            log.info("early stopping: no improvement for %d epochs",
                     run.train.early_stop_patience)
            break

    scaler.save(args.out.parent / "scaler.json")
    (args.out.parent / "training_history.json").write_text(
        json.dumps(history, indent=2), encoding="utf-8"
    )
    log.info("done. best epoch %d, val score %.4f -> %s", best_epoch, best_val, args.out)


if __name__ == "__main__":
    main()
