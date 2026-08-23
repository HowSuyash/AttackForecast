"""Logistic regression baseline for the benchmark the PS requires.

The comparison has to be fair to be worth anything, so the baseline gets the
*same* features, the same scaling, the same train/test split and the same
forward-looking label. The only thing it lacks is temporal structure: it sees
each window in isolation, which is precisely the limitation the PS describes
when it says traditional classifiers "treat each flow in isolation".

Two baselines are provided:
  - `single_window`: the honest classical setup, one window in, one score out.
  - `stacked_window`: the same model given the last K windows concatenated.
    This is the stronger, more sceptical comparison - it gives the baseline
    access to history without giving it a learned dynamics model. If the world
    model only beat `single_window`, a reviewer could fairly say the gain came
    from seeing more data rather than from modelling transitions.
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

log = logging.getLogger(__name__)


def stack_history(obs: np.ndarray, k: int) -> np.ndarray:
    """Concatenate each step with the k-1 steps before it.

    Args:
        obs: (N, T, F) sequences.
        k: history depth.

    Returns:
        (N*T, F*k) matrix, left-padded by repeating the first step.
    """
    n, t, f = obs.shape
    padded = np.concatenate([np.repeat(obs[:, :1], k - 1, axis=1), obs], axis=1)
    out = np.empty((n, t, f * k), dtype=np.float32)
    for i in range(t):
        out[:, i] = padded[:, i: i + k].reshape(n, f * k)
    return out.reshape(n * t, f * k)


def fit_baseline(
    train_obs: np.ndarray,
    train_y: np.ndarray,
    history: int = 1,
    seed: int = 1337,
) -> LogisticRegression:
    """Fit logistic regression on flattened window features."""
    if history > 1:
        x = stack_history(train_obs, history)
    else:
        x = train_obs.reshape(-1, train_obs.shape[-1])
    y = train_y.reshape(-1)

    model = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",  # matches the pos_weight the world model gets
        C=1.0,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(x, y)
    log.info("baseline fitted: history=%d, features=%d", history, x.shape[1])
    return model


def predict_baseline(
    model: LogisticRegression, obs: np.ndarray, history: int = 1
) -> np.ndarray:
    if history > 1:
        x = stack_history(obs, history)
    else:
        x = obs.reshape(-1, obs.shape[-1])
    return model.predict_proba(x)[:, 1]


def classification_metrics(
    y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5
) -> dict:
    """The metric set the PS names, plus the ones that actually matter here.

    False positive rate is reported explicitly: in a SOC, a detector with great
    recall and a 20% FPR is unusable, and average precision is included because
    it is the honest summary statistic on an imbalanced problem.
    """
    y_true = np.asarray(y_true).reshape(-1)
    y_prob = np.asarray(y_prob).reshape(-1)
    y_pred = (y_prob >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # roc_auc_score raises when only one class is present in y_true.
    both_classes = len(np.unique(y_true)) > 1

    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fpr),
        "roc_auc": float(roc_auc_score(y_true, y_prob)) if both_classes else float("nan"),
        "average_precision": (
            float(average_precision_score(y_true, y_prob)) if both_classes else float("nan")
        ),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "n_samples": int(len(y_true)),
        "positive_rate": float(y_true.mean()),
        "threshold": float(threshold),
    }


def fit_stage_baseline(
    train_obs: np.ndarray, train_stage: np.ndarray, history: int = 1, seed: int = 1337
) -> LogisticRegression:
    """Multinomial logistic regression over the same features, for stage."""
    x = (stack_history(train_obs, history) if history > 1
         else train_obs.reshape(-1, train_obs.shape[-1]))
    y = train_stage.reshape(-1)

    model = LogisticRegression(
        max_iter=2000, class_weight="balanced", C=1.0, random_state=seed, n_jobs=-1
    )
    model.fit(x, y)
    log.info("stage baseline fitted on %d classes", len(model.classes_))
    return model


def predict_stage_baseline(
    model: LogisticRegression, obs: np.ndarray, history: int = 1
) -> np.ndarray:
    x = (stack_history(obs, history) if history > 1
         else obs.reshape(-1, obs.shape[-1]))
    return model.predict(x)


def persistence_stage_forecast(stage: np.ndarray, horizon: int) -> np.ndarray:
    """The baseline any forecaster has to beat: assume nothing changes.

    Predicts that the stage observed at the cut-off point persists through the
    whole forecast horizon. On a dataset where hosts mostly stay in one stage
    this is a genuinely strong baseline, which is exactly why it belongs in the
    comparison - beating it is the only evidence that the model learned
    transition dynamics rather than the marginal distribution of stages.

    Args:
        stage: (N, T) stage targets.
        horizon: number of future windows.

    Returns:
        (N, horizon) predicted stages.
    """
    last_observed = stage[:, -horizon - 1]
    return np.repeat(last_observed[:, None], horizon, axis=1)


def stage_metrics(y_true: np.ndarray, y_pred: np.ndarray, n_stages: int = 6) -> dict:
    """Accuracy plus macro-F1 over stages.

    Macro-F1 is the number that matters: accuracy is dominated by the benign
    class, so a model that predicts "benign" everywhere scores well on accuracy
    and near zero on macro-F1.
    """
    y_true = np.asarray(y_true).reshape(-1)
    y_pred = np.asarray(y_pred).reshape(-1)
    labels = list(range(n_stages))

    per_class = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    present = sorted(set(y_true.tolist()))

    return {
        "accuracy": float((y_true == y_pred).mean()),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels,
                                   average="macro", zero_division=0)),
        # Restricted to classes that actually occur in the split, which is the
        # fairer summary when a test capture simply contains no lateral movement.
        "macro_f1_present": float(f1_score(y_true, y_pred, labels=present,
                                           average="macro", zero_division=0)),
        "per_class_f1": {int(i): float(v) for i, v in enumerate(per_class)},
        "n_samples": int(len(y_true)),
    }


def best_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    """Threshold maximising F1 on the given split.

    Selected on validation and then frozen for the test report - picking it on
    test would inflate every number in the benchmark table.
    """
    y_true = np.asarray(y_true).reshape(-1)
    y_prob = np.asarray(y_prob).reshape(-1)
    candidates = np.linspace(0.05, 0.95, 91)
    scores = [f1_score(y_true, (y_prob >= t).astype(int), zero_division=0) for t in candidates]
    return float(candidates[int(np.argmax(scores))])
