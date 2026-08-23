"""Forecast engine: the runtime that the API and CLI both sit on.

Everything a defender sees comes out of `ForecastEngine.analyse`:
  - the filtered risk timeline over observed traffic,
  - a K-step forward simulation with an uncertainty band,
  - the predicted MITRE stage trajectory and whether it constitutes progression,
  - and the three explanation channels from `src.explain`.

The uncertainty band is not decoration. A single rollout is one sample from the
learned prior; running many and taking percentiles is what turns the world model
from a point predictor into something that can say "I am not sure yet".
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from .config import CHECKPOINT_DIR, FORECAST_HORIZON, ModelConfig
from .dataset import FeatureScaler
from .explain import attention_summary, attribute_features, predicted_state_delta
from .mitre import BENIGN, STAGE_NAMES, describe, is_progression
from .model.world_model import WorldModel

log = logging.getLogger(__name__)

# Number of independent rollouts averaged into a forecast. 32 is enough for a
# stable band and still returns in well under a second on CPU.
DEFAULT_ROLLOUT_SAMPLES = 32


class ForecastEngine:
    """Loads a trained checkpoint and answers questions about a host."""

    def __init__(self, checkpoint_path: str | Path | None = None, device: str = "cpu"):
        path = Path(checkpoint_path or (CHECKPOINT_DIR / "world_model.pt"))
        if not path.exists():
            raise FileNotFoundError(
                f"No checkpoint at {path}. Train one with `python -m src.train`."
            )

        self.device = torch.device(device)
        ckpt = torch.load(path, map_location=self.device, weights_only=False)

        self.feature_columns: list[str] = ckpt["feature_columns"]
        self.config = ckpt["config"]

        model_cfg = ModelConfig(**self.config["model"])
        self.model = WorldModel(model_cfg).to(self.device)
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval()

        self.scaler = FeatureScaler(ckpt["scaler"]["columns"])
        self.scaler.mean = np.asarray(ckpt["scaler"]["mean"], dtype=np.float32)
        self.scaler.std = np.asarray(ckpt["scaler"]["std"], dtype=np.float32)

        self.metadata = {
            "epoch": ckpt.get("epoch"),
            "train_scenarios": ckpt.get("train_scenarios"),
            "test_scenarios": ckpt.get("test_scenarios"),
            "parameters": self.model.count_parameters(),
            "window_seconds": self.config["window_seconds"],
            "features": len(self.feature_columns),
        }
        log.info("loaded world model: %s params, %d features",
                 f"{self.metadata['parameters']:,}", len(self.feature_columns))

    # ------------------------------------------------------------------

    def _to_tensor(self, cells: pd.DataFrame) -> torch.Tensor:
        x = self.scaler.transform(cells[self.feature_columns].to_numpy(dtype=np.float32))
        return torch.from_numpy(x).unsqueeze(0).to(self.device)

    @torch.no_grad()
    def surprise(self, out: dict, obs: torch.Tensor) -> torch.Tensor:
        """How badly the model's own prior predicted what actually happened.

        The prior p(z_t | h_t) is the model's expectation *before* seeing window
        t; decode it and compare with the real observation. Large error means
        the network did something the learned dynamics did not anticipate. It
        needs no labels at all, which is why it is worth surfacing.

        **It is not an attack detector on this data, and the direction is the
        opposite of the obvious one.** Measured on the held-out period:

            supervised head   ROC-AUC 1.000   AP 1.000
            model surprise    ROC-AUC 0.375   AP 0.006   (random: 0.500 / 0.008)

        Mean surprise is 0.494 on benign windows and 0.349 on malicious ones -
        botnet traffic is *more* predictable than human traffic, not less.
        That is not a defect: beaconing and spam are machine-generated and
        highly regular, while a university network's real users are erratic. So
        low surprise on a host the supervised head scores highly is itself
        corroborating evidence of automation.

        The dashboard therefore presents this as a novelty channel with that
        reading spelled out, and never blends it into the risk score. An earlier
        version of this docstring quoted AUC 0.66 for surprise; that measurement
        came from the checkpoint with the `has_packet_features` leak, and did
        not survive removing it.

        Args:
            out: the dict returned by `WorldModel.observe`.
            obs: the (B, T, F) observations that produced it.

        Returns:
            (B, T) mean squared prediction error per window.
        """
        prior_state = torch.cat([out["h"], out["prior"].mean], dim=-1)
        predicted = self.model.decoder(prior_state)
        return ((predicted - obs) ** 2).mean(dim=-1)

    @torch.no_grad()
    def _rollout(
        self, h: torch.Tensor, z: torch.Tensor, history: torch.Tensor,
        horizon: int, samples: int,
    ) -> dict:
        """Run `samples` independent imagined trajectories and summarise them."""
        # Repeat the starting state across the sample dimension so all rollouts
        # run as one batch - far faster than looping on CPU.
        h_b = h.repeat(samples, 1)
        z_b = z.repeat(samples, 1)
        hist_b = history.repeat(samples, 1, 1)

        dream = self.model.imagine(h_b, z_b, steps=horizon, history=hist_b, sample=True)

        probs = dream["infiltration_prob"].cpu().numpy()          # (S, H)
        stage_probs = torch.softmax(dream["stage_logits"], dim=-1).cpu().numpy()
        pred_obs = dream["pred_obs"].cpu().numpy()                # (S, H, F)

        return {
            "prob_mean": probs.mean(axis=0),
            "prob_p10": np.percentile(probs, 10, axis=0),
            "prob_p90": np.percentile(probs, 90, axis=0),
            "stage_probs": stage_probs.mean(axis=0),              # (H, n_stages)
            "pred_obs_mean": pred_obs.mean(axis=0),               # (H, F)
        }

    def analyse(
        self,
        cells: pd.DataFrame,
        horizon: int = FORECAST_HORIZON,
        samples: int = DEFAULT_ROLLOUT_SAMPLES,
        alert_threshold: float = 0.5,
        explain: bool = True,
    ) -> dict:
        """Full analysis of one host's consecutive state cells.

        Args:
            cells: rows for a single host, sorted by window, with all feature
                columns present.
            horizon: how many windows ahead to forecast.
            samples: rollouts to average.
            alert_threshold: probability above which a window counts as an alert.
            explain: compute attribution and attention (adds one backward pass).

        Returns:
            A JSON-serialisable dict consumed directly by the dashboard.
        """
        if cells.empty:
            raise ValueError("No state cells supplied.")

        cells = cells.sort_values("window").reset_index(drop=True)
        obs = self._to_tensor(cells)

        with torch.no_grad():
            out = self.model.observe(obs, sample=False)
            observed_prob = torch.sigmoid(out["infiltration_logit"])[0].cpu().numpy()
            observed_stage = torch.softmax(out["stage_logits"], dim=-1)[0].cpu().numpy()
            observed_surprise = self.surprise(out, obs)[0].cpu().numpy()

            forecast = self._rollout(
                out["h"][:, -1], out["z"][:, -1], out["states"], horizon, samples
            )

        current_stage = int(observed_stage[-1].argmax())
        stage_path = [int(s.argmax()) for s in forecast["stage_probs"]]
        peak_stage = max(stage_path) if stage_path else BENIGN

        # First forecast step whose mean probability crosses the alert line.
        crossings = np.flatnonzero(forecast["prob_mean"] >= alert_threshold)
        window_seconds = float(self.config["window_seconds"])
        if crossings.size:
            steps_ahead = int(crossings[0]) + 1
            eta_seconds = steps_ahead * window_seconds
        else:
            steps_ahead, eta_seconds = None, None

        result = {
            "host": str(cells["src"].iloc[0]),
            "n_windows_observed": int(len(cells)),
            "window_seconds": window_seconds,
            "timeline": [
                {
                    "window": int(r.window),
                    "risk": float(observed_prob[i]),
                    "surprise": float(observed_surprise[i]),
                    "stage": int(observed_stage[i].argmax()),
                    "is_malicious": int(getattr(r, "is_malicious", 0)),
                    "n_flows": float(getattr(r, "n_flows", 0.0)),
                }
                for i, r in enumerate(cells.itertuples())
            ],
            "forecast": [
                {
                    "step": i + 1,
                    "seconds_ahead": (i + 1) * window_seconds,
                    "risk": float(forecast["prob_mean"][i]),
                    "risk_low": float(forecast["prob_p10"][i]),
                    "risk_high": float(forecast["prob_p90"][i]),
                    "stage": stage_path[i],
                    "stage_name": STAGE_NAMES[stage_path[i]],
                    "stage_confidence": float(forecast["stage_probs"][i].max()),
                }
                for i in range(horizon)
            ],
            "current": {
                "risk": float(observed_prob[-1]),
                "stage": describe(current_stage),
                "stage_confidence": float(observed_stage[-1].max()),
            },
            "prediction": {
                "peak_risk": float(forecast["prob_mean"].max()),
                "peak_stage": describe(peak_stage),
                "is_progression": is_progression(current_stage, peak_stage),
                "alert": bool(forecast["prob_mean"].max() >= alert_threshold),
                "steps_to_alert": steps_ahead,
                "seconds_to_alert": eta_seconds,
                "threshold": alert_threshold,
            },
        }

        if explain:
            result["explanation"] = self._explain(obs, out, forecast, cells)

        return result

    @torch.no_grad()
    def replay(
        self,
        cells: pd.DataFrame,
        horizon: int = 10,
        samples: int = 12,
        context: int = 16,
    ) -> dict:
        """Per-minute frames for stepping through a capture as if it were live.

        A static chart shows the forecast once, from the end of the capture.
        Replay shows it being made: at every minute the model emits a forecast,
        then time advances and you can see whether it was right. That is the
        claim this project actually makes, and it is far easier to believe when
        you watch it happen than when you read a number.

        Computed in one batched pass rather than one call per frame. `observe`
        already produces the latent state at every timestep, so the rollouts for
        all frames are a single batch - a 120-window host costs about the same
        as one `analyse` call instead of 120 of them.

        Each frame's attention history is the fixed trailing `context` windows
        before it, which keeps the batch rectangular and matches the sequence
        length the model was trained on.

        Args:
            cells: one host's consecutive state cells.
            horizon: windows to forecast at each frame.
            samples: rollouts averaged per frame.
            context: trailing windows of history each frame may attend over.

        Returns:
            dict with `frames`, each carrying the observed risk and stage at
            that minute plus the forecast made from it.
        """
        cells = cells.sort_values("window").reset_index(drop=True)
        obs = self._to_tensor(cells)
        n_windows = obs.size(1)
        if n_windows < context:
            raise ValueError(
                f"Need at least {context} windows to replay, got {n_windows}."
            )

        out = self.model.observe(obs, sample=False)
        observed_prob = torch.sigmoid(out["infiltration_logit"])[0].cpu().numpy()
        observed_stage = out["stage_logits"][0].argmax(-1).cpu().numpy()
        surprise = self.surprise(out, obs)[0].cpu().numpy()

        # One frame per window from the first with full context onwards.
        starts = list(range(context - 1, n_windows))
        history = torch.stack(
            [out["states"][0, t - context + 1: t + 1] for t in starts]
        )
        h = out["h"][0, starts]
        z = out["z"][0, starts]

        n_frames = len(starts)
        acc = torch.zeros(n_frames, horizon, device=self.device)
        stage_acc = torch.zeros(
            n_frames, horizon, self.model.cfg.n_stages, device=self.device
        )
        for _ in range(samples):
            dream = self.model.imagine(
                h, z, steps=horizon, history=history, sample=True
            )
            acc += dream["infiltration_prob"]
            stage_acc += torch.softmax(dream["stage_logits"], dim=-1)

        forecast_prob = (acc / samples).cpu().numpy()
        forecast_stage = (stage_acc / samples).argmax(-1).cpu().numpy()

        windows = cells["window"].to_numpy()
        malicious = (
            cells["is_malicious"].to_numpy()
            if "is_malicious" in cells.columns
            else np.zeros(n_windows, dtype=int)
        )

        frames = []
        for i, t in enumerate(starts):
            frames.append({
                "index": int(t),
                "window": int(windows[t]),
                "risk": float(observed_prob[t]),
                "stage": int(observed_stage[t]),
                "surprise": float(surprise[t]),
                "is_malicious": int(malicious[t]),
                "forecast": [float(v) for v in forecast_prob[i]],
                "forecast_stage": [int(v) for v in forecast_stage[i]],
            })

        return {
            "host": str(cells["src"].iloc[0]),
            "window_seconds": float(self.config["window_seconds"]),
            "horizon": horizon,
            "context": context,
            "n_frames": len(frames),
            # The full observed series, so the UI can draw the whole timeline
            # greyed out and reveal it as replay advances.
            "timeline": [
                {
                    "window": int(windows[t]),
                    "risk": float(observed_prob[t]),
                    "stage": int(observed_stage[t]),
                    "is_malicious": int(malicious[t]),
                }
                for t in range(n_windows)
            ],
            "frames": frames,
        }

    def _explain(self, obs, out, forecast, cells) -> dict:
        """Assemble the three explanation channels."""
        attribution = attribute_features(
            self.model, obs, step=-1, top_k=8, columns=self.feature_columns
        )
        attention = attention_summary(out["attention"], step=-1, top_k=5)

        current_scaled = obs[0, -1].detach().cpu().numpy()
        # Compare against the furthest-out imagined state: that is where the
        # forecast is making its strongest claim.
        future_scaled = forecast["pred_obs_mean"][-1]
        delta = predicted_state_delta(
            current_scaled, future_scaled, self.scaler, self.feature_columns, top_k=6
        )

        levels = {"flow": 0, "packet": 0}
        for a in attribution:
            if a["level"] in levels:
                levels[a["level"]] += abs(a["contribution"])
        total = sum(levels.values()) or 1.0

        return {
            "feature_attribution": attribution,
            "temporal_attention": attention,
            "predicted_state_change": delta,
            "level_contribution": {
                "flow": levels["flow"] / total,
                "packet": levels["packet"] / total,
            },
            "narrative": _narrative(attribution, delta),
        }


def _narrative(attribution: list[dict], delta: list[dict]) -> str:
    """One plain-English sentence a SOC analyst can read at a glance."""
    risers = [a for a in attribution if a["contribution"] > 0][:2]
    if not risers:
        return "No feature is currently pushing risk upward."

    drivers = " and ".join(a["label"].lower() for a in risers)
    growing = [d for d in delta if d["relative_change"] > 0.25][:2]

    if growing:
        changes = "; ".join(
            f"{d['label'].lower()} {d['current']:.0f} to {d['predicted']:.0f}"
            for d in growing
        )
        return f"Risk is driven by {drivers}. Model expects {changes}."
    return f"Risk is driven by {drivers}."


def analyse_host(
    cells: pd.DataFrame, host: str, engine: ForecastEngine, **kwargs
) -> dict:
    """Convenience wrapper: filter a multi-host frame to one host and analyse."""
    sub = cells[cells["src"] == host]
    if sub.empty:
        raise ValueError(f"Host {host!r} has no state cells.")
    return engine.analyse(sub, **kwargs)


@torch.no_grad()
def rank_hosts(
    cells: pd.DataFrame,
    engine: ForecastEngine,
    min_windows: int = 16,
    horizon: int = 6,
    samples: int = 8,
    batch: int = 512,
) -> list[dict]:
    """Score every host in one batched pass and order them by forecast risk.

    This is the triage view: a defender opens the dashboard and needs to know
    which machine to look at first. Doing it host-by-host through `analyse`
    took ~2.4 s each, so a 200-host capture stalled for eight minutes. Every
    host gets the same fixed-length window, so they stack into one tensor and
    the whole sweep becomes a couple of forward passes.

    Args:
        cells: state cells for any number of hosts.
        engine: loaded forecast engine.
        min_windows: hosts with fewer consecutive windows are skipped.
        horizon: rollout length used for the ranking forecast.
        samples: rollouts averaged per host - fewer than `analyse` uses, since
            ranking only needs the ordering.
        batch: hosts scored per forward pass.

    Returns:
        Hosts sorted by peak forecast risk, descending.
    """
    # Every host is cut into fixed-length slices covering its whole timeline,
    # not just its most recent window. Triage wants "has this machine ever
    # looked compromised", and scoring only the tail misses a host that was
    # loud an hour ago and has gone quiet. Slices from every host go into one
    # tensor, so the sweep is a couple of forward passes rather than a loop.
    slices, slice_host, hosts, sizes = [], [], [], []
    stride = max(1, min_windows // 2)

    for host, grp in cells.groupby("src", sort=False):
        if len(grp) < min_windows:
            continue
        ordered = grp.sort_values("window")
        x = engine.scaler.transform(
            ordered[engine.feature_columns].to_numpy(dtype=np.float32)
        )
        h_idx = len(hosts)
        hosts.append(host)
        sizes.append(int(len(ordered)))

        starts = list(range(0, len(x) - min_windows + 1, stride))
        # Always include the final window so "current risk" is really current.
        if starts[-1] != len(x) - min_windows:
            starts.append(len(x) - min_windows)
        for s in starts:
            slices.append(x[s: s + min_windows])
            slice_host.append(h_idx)

    if not hosts:
        return []

    slice_host = np.asarray(slice_host)

    # Two readings per slice. `risk_last` is the score at the slice's final
    # window - "risk now". `risk_peak` is the highest score in the slice's
    # settled region.
    #
    # Ranking on the final step alone hides the hosts triage exists to find: a
    # machine whose risk spikes mid-slice and settles back reports as 0.0 and
    # sinks down the list. But taking a plain max over the slice is worse,
    # because every slice starts the recurrent state from zero and the model's
    # first few outputs are warm-up noise. Measured on one quiet host, mean risk
    # per step-in-slice ran 0.117, 0.061, 0.059, 0.058, 0.044, 0.049, 0.029,
    # 0.001, then 0.000 from step 8 on - while the same host scored max 0.002
    # over the full sequence. A naive max would have promoted it to the top of
    # the triage list on pure warm-up artefact.
    #
    # So the peak ignores the first half of each slice. With stride = context/2
    # every window still lands in some slice's settled region, so nothing real
    # is missed.
    warmup = min_windows // 2

    risk_last = np.zeros(len(slices), dtype=np.float32)
    risk_peak = np.zeros(len(slices), dtype=np.float32)
    surprise = np.zeros(len(slices), dtype=np.float32)
    stage = np.zeros(len(slices), dtype=np.int64)

    for start in range(0, len(slices), batch):
        obs = torch.from_numpy(
            np.stack(slices[start: start + batch])
        ).to(engine.device)
        out = engine.model.observe(obs, sample=False)
        end = start + obs.size(0)
        probs = torch.sigmoid(out["infiltration_logit"])
        risk_last[start:end] = probs[:, -1].cpu().numpy()
        risk_peak[start:end] = probs[:, warmup:].max(dim=1).values.cpu().numpy()
        surprise[start:end] = (
            engine.surprise(out, obs)[:, warmup:].max(dim=1).values.cpu().numpy()
        )
        stage[start:end] = out["stage_logits"][:, -1].argmax(-1).cpu().numpy()

    # Roll forward only from each host's most recent slice - the forecast is
    # about where it is heading now, not where it once was.
    last_slice = np.zeros(len(hosts), dtype=np.int64)
    for i, h in enumerate(slice_host):
        last_slice[h] = i

    peak_forecast = np.zeros(len(hosts), dtype=np.float32)
    peak_stage = np.zeros(len(hosts), dtype=np.int64)
    for start in range(0, len(hosts), batch):
        idx = last_slice[start: start + batch]
        obs = torch.from_numpy(np.stack([slices[i] for i in idx])).to(engine.device)
        out = engine.model.observe(obs, sample=False)
        b = obs.size(0)

        acc = torch.zeros(b, horizon, device=engine.device)
        stage_acc = torch.zeros(b, horizon, engine.model.cfg.n_stages, device=engine.device)
        for _ in range(samples):
            dream = engine.model.imagine(
                out["h"][:, -1], out["z"][:, -1], steps=horizon,
                history=out["states"], sample=True,
            )
            acc += dream["infiltration_prob"]
            stage_acc += torch.softmax(dream["stage_logits"], dim=-1)
        peak_forecast[start: start + b] = (acc / samples).max(dim=1).values.cpu().numpy()
        peak_stage[start: start + b] = (
            (stage_acc / samples).mean(dim=1).argmax(-1).cpu().numpy()
        )

    host_surprise = np.array(
        [float(surprise[slice_host == h].max()) for h in range(len(hosts))]
    )

    # Surprise is scored relative to the rest of *this* capture. Its absolute
    # scale means nothing across networks - a busy enterprise and a quiet lab
    # sit at different baselines - but a host several deviations above its own
    # neighbourhood is anomalous by construction. Median and MAD rather than
    # mean and standard deviation, because a handful of extreme hosts is exactly
    # what we are looking for and would otherwise inflate the spread that hides
    # them.
    median = float(np.median(host_surprise))
    mad = float(np.median(np.abs(host_surprise - median)))
    scale = mad * 1.4826 if mad > 1e-9 else (host_surprise.std() or 1.0)
    surprise_z = (host_surprise - median) / scale

    rows = []
    for h in range(len(hosts)):
        mask = slice_host == h
        observed_peak = float(risk_peak[mask].max())
        current = float(risk_last[last_slice[h]])
        current_stage = int(stage[last_slice[h]])
        z = float(surprise_z[h])

        # Two channels that fail in opposite regimes, so a host is worth
        # attention if *either* fires. Measured per capture:
        #   scenario 1  (one host, 284 malicious windows)
        #       supervised ROC-AUC 1.000, surprise 0.270
        #   scenario 10 (ten hosts, ~20 malicious windows each)
        #       supervised ROC-AUC 0.926, surprise 1.000 - all ten ranked 1-10
        #   scenario 12 supervised 0.482, surprise 0.881
        # Sustained compromise is predictable and therefore unsurprising; a
        # short burst of new behaviour is the opposite. Ranking on the
        # supervised head alone missed every short-burst host in scenario 10.
        anomaly = float(np.clip(z / 6.0, 0.0, 1.0))
        if observed_peak >= 0.5 and z >= 3.0:
            reason = "risk + anomaly"
        elif observed_peak >= 0.5:
            reason = "risk"
        elif z >= 3.0:
            reason = "anomaly"
        else:
            reason = ""

        rows.append({
            "host": hosts[h],
            "current_risk": current,
            "observed_peak_risk": observed_peak,
            "peak_forecast_risk": float(peak_forecast[h]),
            "surprise": float(host_surprise[h]),
            "surprise_z": z,
            "score": max(observed_peak, float(peak_forecast[h]), anomaly),
            "flag_reason": reason,
            "current_stage": STAGE_NAMES[current_stage],
            "predicted_stage": STAGE_NAMES[int(peak_stage[h])],
            "is_progression": is_progression(current_stage, int(peak_stage[h])),
            "n_windows": sizes[h],
        })

    return sorted(rows, key=lambda r: -r["score"])
