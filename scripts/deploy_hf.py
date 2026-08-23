"""Publish the dashboard to a Hugging Face Space.

Run:
    set HF_TOKEN=hf_...            # PowerShell: $env:HF_TOKEN = "hf_..."
    python scripts/deploy_hf.py

The token is read from the environment and never written to disk. Do not pass
it as a literal here - anything committed to the repository is public the moment
the repository is.

Why a Space rather than a generic PaaS: torch plus pandas plus scikit-learn is
roughly 800 MB installed, which does not fit the free tiers that assume a web
app. Spaces are built for exactly this shape of workload and do not idle out.

The Space README needs YAML front matter to configure the runtime, and GitHub
renders front matter as a table at the top of the page. So the Space README is
generated here and uploaded on its own, leaving the repository's README clean -
the two files serve different readers anyway.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parent.parent

SPACE_README = """---
title: Network Attack Forecasting
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: World-model forecasting of network attack progression
---

# Network Attack Forecasting from Traffic Telemetry

**Smart India Hackathon 2026 · Problem Statement 26153 · NTRO**
**Team: Git with It**

Instead of classifying each flow as benign or malicious, this system learns the
transition dynamics of a network — `P(S_t+1 | S_t)` over 60-second states — and
rolls that model forward to forecast where a host is heading before the kill
chain completes.

## What you can do here

- **Forecast tab** — pick a host and press **Play**. The chart replays the
  capture minute by minute: at each step the model emits a forecast, then time
  advances past it. Left of the divider it sees traffic; right of it, nothing —
  every point is rolled forward through the learned prior.
- **Kill-chain timeline** — the whole capture as one block per minute, coloured
  by the predicted MITRE ATT&CK stage, with the dataset's own labels ticked
  underneath.
- **Topology tab** — the compromised host and its malicious fan-out.
- **Benchmark tab** — measured against logistic regression given identical
  features, and against a persistence baseline for stage forecasting.
- **Upload** — bring your own `.pcap` or `.binetflow`; flows are reconstructed
  from raw packets and both feature levels are computed.

The first scenario load scores every host and takes around a minute; everything
after that is cached.

## Results

Temporal split — trained on the first 70% of each capture, tested on its future.

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| **World model (RSSM)** | **0.968** | **1.000** | **0.984** | **0.000** |
| Logistic regression, 8-window | 0.628 | 0.912 | 0.744 | 0.004 |
| Logistic regression, 1 window | 0.409 | 0.842 | 0.550 | 0.009 |

MITRE stage macro-F1 0.455 against 0.353 for the baseline; the rolled-out
forecast beats a like-for-like persistence baseline at 9 of 10 horizons.

## Honest notes

CTU-13 contains no pre-infection baseline — infected hosts are malicious in
every window they appear — so kill-chain **progression** is the forecastable
signal, not binary "will this host be attacked". And a PCAP covering only botnet
traffic once made "packet data present" a perfect label proxy; removing that
leak took detection F1 from 0.23 to 0.98.

Full write-up, architecture document and reproduction steps are in the source
repository.

Dataset: [CTU-13](https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/),
Stratosphere IPS, CTU Prague (CC BY).
"""

# Only what the container needs. Documentation, slides, the virtualenv and the
# 54 GB of raw captures stay out.
ALLOW = [
    "Dockerfile",
    "requirements.txt",
    "src/**",
    "server/**",
    "artifacts/checkpoints/**",
    "artifacts/reports/**",
    "data/processed/**",
]
IGNORE = ["**/__pycache__/**", "**/*.pyc"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--space", default=None,
                        help="repo id, e.g. user/network-attack-forecasting")
    parser.add_argument("--name", default="network-attack-forecasting")
    parser.add_argument("--private", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit("Set HF_TOKEN in the environment first.")

    api = HfApi(token=token)
    user = api.whoami()["name"]
    repo_id = args.space or f"{user}/{args.name}"

    print(f"target space: {repo_id}")
    api.create_repo(
        repo_id=repo_id, repo_type="space", space_sdk="docker",
        private=args.private, exist_ok=True,
    )

    readme = ROOT / ".hf_readme.md"
    readme.write_text(SPACE_README, encoding="utf-8")
    try:
        api.upload_file(
            path_or_fileobj=str(readme), path_in_repo="README.md",
            repo_id=repo_id, repo_type="space",
            commit_message="Space README",
        )
    finally:
        readme.unlink(missing_ok=True)

    print("uploading application files...")
    api.upload_folder(
        folder_path=str(ROOT), repo_id=repo_id, repo_type="space",
        allow_patterns=ALLOW, ignore_patterns=IGNORE,
        commit_message="Deploy dashboard",
    )

    url = f"https://huggingface.co/spaces/{repo_id}"
    print(f"\ndone: {url}")
    print("The first build takes a few minutes - torch is a large install.")


if __name__ == "__main__":
    main()
