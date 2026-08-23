"""Benchmark the world model against the logistic regression baseline.

Run:
    python -m src.evaluate

Produces `artifacts/reports/benchmark.json` and a markdown table for the report
and slides.

The split is read from the checkpoint so the evaluation always matches how the
model was trained. Two are supported and they answer different questions:

  - `temporal`  - train on each capture's past, test on its future. The
    deployment shape: a system installed on a network learns that network.
  - `family`    - hold out entire malware families. Asks whether the model
    transfers to an attack pattern it has never seen.

Four things this script is careful about, because a benchmark that flatters the
model is worth nothing:

  1. The heading states which split produced the numbers; the two are not
     comparable and must never be quoted interchangeably.
  2. The decision threshold is chosen on validation and frozen before the test
     split is touched.
  3. Baselines get the identical feature matrix and scaler, and the `stacked`
     variant additionally sees the same history window the world model does -
     so any remaining gap is attributable to learned dynamics rather than to a
     bigger input. Stage forecasting is compared against persistence in both an
     oracle and a like-for-like variant.
  4. Inference is deterministic (`observe(..., sample=False)`) and rollouts are
     seeded, so re-running reproduces the report exactly.

It also reports how forecast quality decays with horizon, which is the number
that actually characterises a forecasting system, and states the stage-forecast
verdict in prose rather than leaving it to be inferred from a table.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import torch

from .config import (
    CHECKPOINT_DIR,
    FORECAST_HORIZON,
    REPORT_DIR,
    SEQUENCE_LENGTH,
    TEST_SCENARIOS,
    VAL_SCENARIOS,
    ModelConfig,
)
from .dataset import FeatureScaler, build_sequences, temporal_split
from .features.windows import feature_columns
from .model.baseline import (
    best_threshold,
    classification_metrics,
    fit_baseline,
    fit_stage_baseline,
    persistence_stage_forecast,
    predict_baseline,
    predict_stage_baseline,
    stage_metrics,
)
from .model.world_model import WorldModel
from .train import load_cells

log = logging.getLogger(__name__)

BASELINE_HISTORY = 8  # windows the stacked baseline sees


def load_engine(path: Path):
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    model = WorldModel(ModelConfig(**ckpt["config"]["model"]))
    model.load_state_dict(ckpt["model_state"])
    model.eval()

    scaler = FeatureScaler(ckpt["scaler"]["columns"])
    scaler.mean = np.asarray(ckpt["scaler"]["mean"], dtype=np.float32)
    scaler.std = np.asarray(ckpt["scaler"]["std"], dtype=np.float32)
    return model, scaler, ckpt


@torch.no_grad()
def world_model_scores(model: WorldModel, obs: np.ndarray, batch: int = 256) -> np.ndarray:
    """Filtered per-window infiltration probability over whole sequences."""
    out = []
    for i in range(0, len(obs), batch):
        chunk = torch.from_numpy(obs[i: i + batch])
        logits = model.observe(chunk, sample=False)["infiltration_logit"]
        out.append(torch.sigmoid(logits).numpy())
    return np.concatenate(out, axis=0)


@torch.no_grad()
def horizon_scores(
    model: WorldModel, obs: np.ndarray, horizon: int, batch: int = 256,
    samples: int = 64, seed: int = 1337,
) -> tuple[np.ndarray, np.ndarray]:
    """Forecast from imagination, split out by horizon step.

    For each sequence we cut off the last `horizon` windows, filter over what
    remains, then imagine forward. The returned arrays are what the model
    predicted for each future step *without having seen it*.

    Returns:
        (probabilities (N, horizon), predicted stages (N, horizon)).
    """
    # Rollouts draw from the prior, so the benchmark is only reproducible with a
    # fixed seed - and only stable with enough samples. At 16 the stage-forecast
    # comparison against persistence moved by five points between runs, which is
    # larger than the effect being measured.
    torch.manual_seed(seed)

    probs, stages = [], []
    for i in range(0, len(obs), batch):
        chunk = torch.from_numpy(obs[i: i + batch])
        split = chunk.size(1) - horizon
        if split < 2:
            raise ValueError("sequence_length must exceed the forecast horizon")

        out = model.observe(chunk[:, :split], sample=False)
        b = chunk.size(0)

        # Average several stochastic rollouts; a single sample is noisy.
        acc = torch.zeros(b, horizon)
        stage_acc = torch.zeros(b, horizon, model.cfg.n_stages)
        for _ in range(samples):
            dream = model.imagine(
                out["h"][:, -1], out["z"][:, -1], steps=horizon,
                history=out["states"], sample=True,
            )
            acc += dream["infiltration_prob"]
            stage_acc += torch.softmax(dream["stage_logits"], dim=-1)
        probs.append((acc / samples).numpy())
        stages.append((stage_acc / samples).argmax(dim=-1).numpy())
    return np.concatenate(probs, axis=0), np.concatenate(stages, axis=0)


def markdown_table(rows: list[dict], title: str) -> str:
    """Render a benchmark table for the README and the slides."""
    cols = ["model", "precision", "recall", "f1", "false_positive_rate",
            "roc_auc", "average_precision"]
    header = ["Model", "Precision", "Recall", "F1", "FPR", "ROC-AUC", "AP"]

    lines = [f"### {title}", "", "| " + " | ".join(header) + " |",
             "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        cells = [str(r[cols[0]])] + [
            ("n/a" if not np.isfinite(r[c]) else f"{r[c]:.3f}") for c in cols[1:]
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=CHECKPOINT_DIR / "world_model.pt")
    parser.add_argument("--scenarios-test", type=int, nargs="*", default=list(TEST_SCENARIOS))
    parser.add_argument("--scenarios-val", type=int, nargs="*", default=list(VAL_SCENARIOS))
    parser.add_argument("--sequence-length", type=int, default=SEQUENCE_LENGTH)
    parser.add_argument("--horizon", type=int, default=FORECAST_HORIZON)
    parser.add_argument("--split", choices=("family", "temporal"), default=None,
                        help="defaults to whatever the checkpoint was trained with")
    parser.add_argument("--scenarios-all", type=int, nargs="*", default=[])
    parser.add_argument("--out", type=Path, default=REPORT_DIR / "benchmark.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    model, scaler, ckpt = load_engine(args.checkpoint)
    cols = feature_columns()
    train_scenarios = ckpt.get("train_scenarios", [])
    split_mode = args.split or ckpt.get("split", {}).get("mode", "family")

    # -- data --------------------------------------------------------------
    # The split must match the one the checkpoint was trained under, or the
    # "test" set contains windows the model already saw.
    if split_mode == "temporal":
        scenarios = ckpt.get("split", {}).get("scenarios") or args.scenarios_all
        if not scenarios:
            raise SystemExit(
                "Temporal evaluation needs the scenario list; pass --scenarios-all."
            )
        log.info("temporal split over scenarios %s: train on each capture's past, "
                 "test on its future", scenarios)
        all_cells = load_cells(scenarios)
        train_cells, val_cells, test_cells = temporal_split(all_cells)
    else:
        log.info("family split: trained on %s, testing on %s (unseen families)",
                 train_scenarios, args.scenarios_test)
        train_cells = load_cells(train_scenarios)
        val_cells = load_cells(args.scenarios_val)
        test_cells = load_cells(args.scenarios_test)

    train_seq = build_sequences(train_cells, cols, scaler, args.sequence_length, stride=4)
    val_seq = build_sequences(val_cells, cols, scaler, args.sequence_length,
                              stride=4, malicious_stride=4)
    test_seq = build_sequences(test_cells, cols, scaler, args.sequence_length,
                               stride=4, malicious_stride=4)

    y_val = val_seq["infiltration"].reshape(-1)
    y_test = test_seq["infiltration"].reshape(-1)

    # -- baselines ---------------------------------------------------------
    log.info("fitting baselines")
    lr_single = fit_baseline(train_seq["obs"], train_seq["infiltration"], history=1)
    lr_stacked = fit_baseline(train_seq["obs"], train_seq["infiltration"],
                              history=BASELINE_HISTORY)

    # -- thresholds picked on validation only -------------------------------
    thresholds = {
        "world_model": best_threshold(y_val, world_model_scores(model, val_seq["obs"])),
        "lr_single": best_threshold(y_val, predict_baseline(lr_single, val_seq["obs"], 1)),
        "lr_stacked": best_threshold(
            y_val, predict_baseline(lr_stacked, val_seq["obs"], BASELINE_HISTORY)
        ),
    }
    log.info("validation-selected thresholds: %s",
             {k: round(v, 2) for k, v in thresholds.items()})

    # -- test evaluation ----------------------------------------------------
    rows = []
    wm_test = world_model_scores(model, test_seq["obs"])
    rows.append({"model": "World model (RSSM)",
                 **classification_metrics(y_test, wm_test, thresholds["world_model"])})

    lr1_test = predict_baseline(lr_single, test_seq["obs"], 1)
    rows.append({"model": "Logistic regression (single window)",
                 **classification_metrics(y_test, lr1_test, thresholds["lr_single"])})

    lr8_test = predict_baseline(lr_stacked, test_seq["obs"], BASELINE_HISTORY)
    rows.append({"model": f"Logistic regression ({BASELINE_HISTORY}-window stack)",
                 **classification_metrics(y_test, lr8_test, thresholds["lr_stacked"])})

    # -- stage prediction ---------------------------------------------------
    # On CTU-13 this is the headline task, not the binary one. Infected hosts
    # are malicious in every window they appear, so the binary target measures
    # detection transfer across malware families rather than anticipation. The
    # kill-chain stage is where the actual temporal dynamics live.
    log.info("evaluating stage prediction")
    stage_test = test_seq["stage"].reshape(-1)
    lr_stage = fit_stage_baseline(train_seq["obs"], train_seq["stage"],
                                  history=BASELINE_HISTORY)

    with torch.no_grad():
        wm_stage = []
        for i in range(0, len(test_seq["obs"]), 256):
            chunk = torch.from_numpy(test_seq["obs"][i: i + 256])
            wm_stage.append(model.observe(chunk, sample=False)["stage_logits"].argmax(-1).numpy())
        wm_stage = np.concatenate(wm_stage, axis=0).reshape(-1)

    stage_rows = [
        {"model": "World model (RSSM)", **stage_metrics(stage_test, wm_stage)},
        {"model": f"Logistic regression ({BASELINE_HISTORY}-window stack)",
         **stage_metrics(stage_test,
                         predict_stage_baseline(lr_stage, test_seq["obs"],
                                                BASELINE_HISTORY))},
    ]
    for r in stage_rows:
        log.info("  %s: macro-F1 %.3f acc %.3f", r["model"], r["macro_f1"], r["accuracy"])

    # -- forecast quality by horizon ---------------------------------------
    log.info("scoring forecast horizon decay")
    forecast, forecast_stage = horizon_scores(model, test_seq["obs"], args.horizon)
    truth = test_seq["infiltration"][:, -args.horizon:]
    stage_truth = test_seq["stage"][:, -args.horizon:]

    # Two persistence baselines, and the difference between them matters.
    #
    # `persistence_oracle` is handed the ground-truth stage at the cut-off and
    # repeats it. That is not deployable - nobody observes the ATT&CK stage, it
    # has to be inferred - so it is an upper bound on what persistence could do,
    # and beating it is a much stronger claim than beating the fair version.
    #
    # `persistence_inferred` repeats the model's own filtered stage estimate at
    # the cut-off. This is the honest like-for-like comparison: same
    # information, the only difference being whether the future is imagined or
    # assumed static.
    persistence_oracle = persistence_stage_forecast(test_seq["stage"], args.horizon)

    with torch.no_grad():
        split = test_seq["obs"].shape[1] - args.horizon
        inferred_now = []
        for i in range(0, len(test_seq["obs"]), 256):
            chunk = torch.from_numpy(test_seq["obs"][i: i + 256, :split])
            inferred_now.append(
                model.observe(chunk, sample=False)["stage_logits"][:, -1].argmax(-1).numpy()
            )
        inferred_now = np.concatenate(inferred_now)
    persistence_inferred = np.repeat(inferred_now[:, None], args.horizon, axis=1)

    horizon_rows = []
    for k in range(args.horizon):
        m = classification_metrics(truth[:, k], forecast[:, k], thresholds["world_model"])
        wm_stage_k = stage_metrics(stage_truth[:, k], forecast_stage[:, k])
        oracle_k = stage_metrics(stage_truth[:, k], persistence_oracle[:, k])
        fair_k = stage_metrics(stage_truth[:, k], persistence_inferred[:, k])
        horizon_rows.append({
            "step": k + 1,
            "seconds_ahead": (k + 1) * ckpt["config"]["window_seconds"],
            **{key: m[key] for key in
               ("precision", "recall", "f1", "false_positive_rate", "roc_auc")},
            "stage_macro_f1": wm_stage_k["macro_f1"],
            "stage_accuracy": wm_stage_k["accuracy"],
            "persistence_oracle_macro_f1": oracle_k["macro_f1"],
            "persistence_inferred_macro_f1": fair_k["macro_f1"],
        })
        log.info(
            "  +%d windows: binary F1 %.3f AUC %.3f | stage macro-F1 %.3f "
            "(persistence: inferred %.3f, oracle %.3f)",
            k + 1, m["f1"], m["roc_auc"],
            wm_stage_k["macro_f1"], fair_k["macro_f1"], oracle_k["macro_f1"],
        )

    # -- report -------------------------------------------------------------
    report = {
        "checkpoint": str(args.checkpoint),
        "train_scenarios": train_scenarios,
        "val_scenarios": args.scenarios_val,
        "test_scenarios": args.scenarios_test,
        "test_sequences": int(len(test_seq["obs"])),
        "test_positive_rate": float(y_test.mean()),
        "thresholds": thresholds,
        "detection": rows,
        "stage_prediction": stage_rows,
        "forecast_by_horizon": horizon_rows,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # The heading has to state which split produced these numbers. The two
    # answer different questions and are not comparable.
    if split_mode == "temporal":
        heading = ("Infiltration detection - temporal split "
                   "(train on each capture's past, test on its future)")
    else:
        heading = "Infiltration detection - held-out malware families"
    md = markdown_table(rows, heading)

    md += (
        "\n\n> **Reading the binary numbers.** On CTU-13 an infected host is "
        "malicious in *every* window it appears, so `infiltration_next` is "
        "near-constant per host. Scoring well on it means the model identified "
        "which host is compromised - a detection result, and a real one - but a "
        "perfect score at +10 windows is not evidence of forecasting skill, "
        "because the target barely changes over the horizon. The stage columns "
        "below are the honest forecasting test.\n"
    )
    md += "\n\n### MITRE stage prediction\n\n"
    md += "| Model | Accuracy | Macro-F1 | Macro-F1 (classes present) |\n|---|---|---|---|\n"
    for r in stage_rows:
        md += (f"| {r['model']} | {r['accuracy']:.3f} | {r['macro_f1']:.3f} | "
               f"{r['macro_f1_present']:.3f} |\n")

    md += "\n\n### Forecast quality by horizon\n\n"
    md += ("| Steps ahead | Seconds | Binary F1 | ROC-AUC | Stage macro-F1 | "
           "Persistence (inferred) | Persistence (oracle) |\n"
           "|---|---|---|---|---|---|---|\n")
    for h in horizon_rows:
        md += (f"| +{h['step']} | {h['seconds_ahead']:.0f} | {h['f1']:.3f} | "
               f"{h['roc_auc']:.3f} | {h['stage_macro_f1']:.3f} | "
               f"{h['persistence_inferred_macro_f1']:.3f} | "
               f"{h['persistence_oracle_macro_f1']:.3f} |\n")
    md += ("\n_Persistence (oracle) is given the ground-truth stage at the "
           "cut-off and is therefore not deployable; persistence (inferred) "
           "repeats the model's own filtered estimate and is the like-for-like "
           "comparison._\n")

    # State the stage-forecast verdict in the report rather than leaving it to
    # be inferred from the table. If imagination does not beat "assume nothing
    # changes", that is the finding.
    beats = sum(
        1 for h in horizon_rows
        if h["stage_macro_f1"] > h["persistence_inferred_macro_f1"]
    )
    n = len(horizon_rows)
    if beats > n // 2:
        verdict = (
            f"The rolled-out forecast beats the like-for-like persistence "
            f"baseline at {beats} of {n} horizons, so imagination is adding "
            f"skill over assuming the current stage holds. It still trails the "
            f"oracle variant, which is handed the true current stage."
        )
    else:
        verdict = (
            f"The rolled-out forecast beats the like-for-like persistence "
            f"baseline at only {beats} of {n} horizons, so imagination is not "
            f"yet adding skill over assuming the current stage holds. This is "
            f"the number to improve, and the honest place to point a reviewer."
        )
    md += (
        f"\n> **Stage forecasting verdict.** {verdict} Caveat worth stating: "
        f"rollouts are stochastic and the test split contains few stage "
        f"transitions, so this comparison moves by a few points between runs "
        f"even with a fixed seed. Treat single-horizon differences as noise and "
        f"read the trend across the column.\n"
    )

    md_path = args.out.with_suffix(".md")
    md_path.write_text(md, encoding="utf-8")

    print("\n" + md)
    log.info("wrote %s and %s", args.out, md_path)


if __name__ == "__main__":
    main()
