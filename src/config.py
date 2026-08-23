"""Central configuration for the network attack forecasting world model.

Every tunable lives here so that training runs are reproducible from a single
file. `RUN_CONFIG` is serialised into the checkpoint next to the weights.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
ARTIFACT_DIR = ROOT / "artifacts"
CHECKPOINT_DIR = ARTIFACT_DIR / "checkpoints"
REPORT_DIR = ARTIFACT_DIR / "reports"

for _d in (PROCESSED_DIR, CHECKPOINT_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Windowing
# --------------------------------------------------------------------------

# Width of one observation window in seconds. The world model learns
# P(S_t+1 | S_t) at this cadence, so it is also the forecast step size.
WINDOW_SECONDS = 60.0

# A (host, window) cell is only emitted when the host originated at least this
# many flows; below that the aggregate statistics are too noisy to be useful.
MIN_FLOWS_PER_CELL = 3

# Whether packet-level features are fed to the model during training.
#
# Off by default, and this is a correctness decision rather than a preference.
# CTU-13's conveniently sized PCAP for scenario 1 contains only the infected
# host's traffic, so `has_packet_features` is a perfect proxy for the label and
# the model happily learns that instead of any behaviour. See the docstring on
# `features.windows.feature_columns` for the measurements.
#
# Turn this on only when the capture's packet coverage is independent of the
# label - i.e. a full-traffic PCAP such as CTU-13's `.truncated.pcap`. The
# extractor always runs for uploaded captures regardless of this flag.
USE_PACKET_FEATURES = False

# Length of the observation sequence fed to the model during training.
#
# 16 windows = 16 minutes of context. Set from the data rather than by taste:
# at 32 the short CTU-13 captures (scenarios 5 and 7, both around an hour)
# produce zero hosts with enough consecutive windows, which would have silently
# dropped two malware families - including Virut, one of the held-out test
# families. At 16 every scenario contributes.
SEQUENCE_LENGTH = 16

# How many windows ahead the model is asked to imagine during evaluation and
# in the dashboard. 10 windows x 60s = 10 minutes of lookahead.
FORECAST_HORIZON = 10

# A window is treated as a positive "infiltration" target when malicious
# activity occurs within this many windows after it. This is what turns the
# problem from detection into forecasting.
LOOKAHEAD_WINDOWS = 5


# --------------------------------------------------------------------------
# Network address handling
# --------------------------------------------------------------------------

# CTU-13 was captured inside the CVUT university network. Flows whose peer sits
# outside these prefixes are treated as egress, which matters for telling
# lateral movement apart from exfiltration.
INTERNAL_PREFIXES = ("147.32.",)

# Ports that indicate host-to-host administrative access inside a network.
LATERAL_PORTS = frozenset({135, 137, 138, 139, 445, 3389, 5985, 5986, 22, 23})

# Ports commonly abused for command-and-control channels.
C2_PORTS = frozenset({6667, 6668, 6669, 7000, 1863, 8080, 8000, 443, 53})


# --------------------------------------------------------------------------
# Model architecture
# --------------------------------------------------------------------------


@dataclass
class ModelConfig:
    """Recurrent state-space world model dimensions.

    The split between a deterministic recurrent state (`hidden_dim`) and a
    stochastic latent (`latent_dim`) is what allows the model to be rolled
    forward without observations: the GRU carries context, the stochastic prior
    supplies the uncertainty that makes multi-step imagination meaningful.
    """

    # Sizes are set by how little supervision CTU-13 actually contains, not by
    # what fits in memory. There is roughly one infected host per scenario, so
    # the informative sequence count is in the hundreds; a 500k-parameter model
    # memorised them inside a single epoch and validation loss rose from there.
    obs_dim: int = 0          # filled in from the feature matrix at train time
    embed_dim: int = 64       # encoder output width
    hidden_dim: int = 96      # GRU deterministic state
    latent_dim: int = 16      # stochastic latent per step
    head_hidden: int = 48     # width of the prediction heads
    attention_heads: int = 4  # temporal attention heads used for explanations
    dropout: float = 0.25
    n_stages: int = 6         # 5 MITRE stages + BENIGN, see src/mitre.py


@dataclass
class TrainConfig:
    epochs: int = 40
    batch_size: int = 128
    learning_rate: float = 1e-3
    weight_decay: float = 1e-3
    grad_clip: float = 5.0

    # Gaussian noise added to observations during training only. With so few
    # distinct malicious hosts the model otherwise latches onto their exact
    # feature values; jittering the inputs forces it to rely on the shape of a
    # trajectory rather than on one host's fingerprint.
    input_noise: float = 0.15

    # Loss weights. Reconstruction and KL train the dynamics; the supervised
    # heads train the decision outputs. Keeping recon meaningful is what stops
    # the model collapsing into a plain classifier.
    w_reconstruction: float = 1.0
    w_kl: float = 0.6
    w_infiltration: float = 3.0
    w_stage: float = 1.5

    # Free-nats floor: KL below this is not penalised, which stops the
    # posterior collapsing onto the prior early in training. This is a TOTAL
    # over the latent, not per-dimension - the per-dimension reading gives the
    # prior so much slack it never learns to match the posterior, and an
    # unfitted prior makes imagination worthless.
    free_nats: float = 3.0

    # Number of imagined steps supervised during training. Training the model
    # on its own rollouts is what makes multi-step forecasting reliable.
    imagination_steps: int = 5
    w_imagination: float = 2.0

    early_stop_patience: int = 6
    seed: int = 1337


@dataclass
class RunConfig:
    model: ModelConfig = field(default_factory=ModelConfig)
    train: TrainConfig = field(default_factory=TrainConfig)
    window_seconds: float = WINDOW_SECONDS
    sequence_length: int = SEQUENCE_LENGTH
    lookahead_windows: int = LOOKAHEAD_WINDOWS
    forecast_horizon: int = FORECAST_HORIZON

    def to_dict(self) -> dict:
        return asdict(self)


RUN_CONFIG = RunConfig()


# --------------------------------------------------------------------------
# Dataset split
# --------------------------------------------------------------------------

# CTU-13 scenario -> malware family. Splitting by *family* rather than randomly
# is deliberate: the PS asks the model to generalise to unseen attack patterns,
# so the test families must never appear during training.
CTU13_FAMILIES = {
    1: "Neris", 2: "Neris", 3: "Rbot", 4: "Rbot", 5: "Virut",
    6: "Menti", 7: "Sogou", 8: "Murlo", 9: "Neris", 10: "Rbot",
    11: "Rbot", 12: "NSIS.ay", 13: "Virut",
}

TRAIN_SCENARIOS = (1, 2, 3, 4, 6, 7, 9, 10, 11)   # Neris, Rbot, Menti, Sogou
VAL_SCENARIOS = (12,)                              # NSIS.ay - unseen family
TEST_SCENARIOS = (5, 8, 13)                        # Virut, Murlo - unseen families
