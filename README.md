# Network Attack Forecasting from Traffic Telemetry

**SIH 2026 · Problem Statement 26153 · NTRO · Blockchain & Cybersecurity**

A world-model approach to proactive cyber defence: instead of classifying each
flow as benign or malicious, the system learns the *transition dynamics* of a
network — `P(S_t+1 | S_t)` — and rolls that model forward to forecast where a
host's trajectory is heading before the kill chain completes.

> **New here?** Read [`docs/TUTORIAL.md`](docs/TUTORIAL.md) first — a
> plain-language walkthrough that assumes no background, with screenshots of
> every output and a map of which file does what. This README is the technical
> reference; the tutorial is the explanation.

---

## What makes this a world model and not a classifier

A classifier maps an observation to a label. This model learns a latent
simulator of network state that can be run **with no observations at all**:

```
obs x_t ──[encoder]──▶ e_t
                        │
   h_t = GRU(h_t-1, z_t-1)          deterministic state, carries context
                        │
   posterior  q(z_t | h_t, e_t)     used while traffic is visible
   prior      p(z_t | h_t)          used when it is not — i.e. the future
                        │
              S_t = [h_t ; z_t]
                 ╱      │      ╲
          decoder    heads    causal temporal attention
```

Training fits the prior to the posterior. Once they agree, the prior alone is a
learned simulator: sample `z`, feed it back through the GRU, and you get a
trajectory of network states the model has never seen. `WorldModel.imagine()`
does this, and the K-step forecast is read directly off it.

The prediction heads sit on the **latent state**, not the raw observation, so
they apply unchanged to imagined states. That is the whole mechanism —
forecasting attacker progression is running the same heads over dreamed states.

A smoke test asserts this property directly: an imagination-only loss must
produce **zero gradient** in the encoder. If the rollout were secretly peeking
at observations, that test fails (`tests/smoke_model.py`).

---

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows;  source .venv/bin/activate on Linux
pip install -r requirements.txt

# 1. Get the data (CTU-13, ~1.9 GB — open access, no registration)
curl -L -o data/raw/CTU-13-Dataset.tar.bz2 \
  https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2
tar -xjf data/raw/CTU-13-Dataset.tar.bz2 -C data/raw

# optional: a real PCAP so the packet-level path has data to work on
curl -L -o data/raw/neris-botnet.pcap \
  https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap

# 2. Build state cells, train, benchmark
python -m src.prepare_data
python -m src.train
python -m src.evaluate

# 3. Dashboard (fully offline)
python -m uvicorn server.app:app --port 8000
# open http://127.0.0.1:8000
```

`python -m tests.smoke_model` checks shapes, gradients and the causal mask
without needing data.

---

## Pipeline

| Stage | Module | What it does |
|---|---|---|
| Flow ingest | `src/features/flow.py` | CTU-13 `.binetflow` → normalised flows; TCP flags recovered from the Argus `State` field |
| Packet ingest | `src/features/packet.py` | PCAP → TTL/window/fragment/retransmission/timing features; also reconstructs flows from raw packets |
| State construction | `src/features/windows.py` | 60-second (host, window) cells; 63 features across both levels |
| Stage labelling | `src/mitre.py` | ATT&CK stage from CTU-13's own flow annotations, behavioural rules where they are silent |
| World model | `src/model/world_model.py` | RSSM: encoder, GRU dynamics, prior/posterior, decoder, heads, causal attention |
| Forecast engine | `src/inference.py` | K-step rollouts with an uncertainty band, stage trajectory, explanations |
| Explainability | `src/explain.py` | Gradient×input attribution, attention weights, predicted state deltas, sampled SHAP |
| Benchmark | `src/evaluate.py` | vs logistic regression (single and stacked) and a persistence baseline |

### Both feature levels, as the PS requires

**Flow level (39 features)** — address/port fan-out, protocol mix, byte and
packet counters, duration statistics, TCP flag rates recovered from Argus state
strings, inter-flow timing, destination and port entropy, beaconing regularity.

**Packet level (23 features)** — TTL mean/variance/distinct-count, TCP window
size and zero-window rate, IP fragmentation rate, payload size distribution,
retransmission rate, per-packet inter-arrival timing and its coefficient of
variation, sequential port-scan score, packet-level port and destination entropy.

They are joined on an **absolute** window grid (`epoch // width`), not one
relative to each file's first record — a PCAP and a flow export of the same
capture start at different timestamps, and a relative grid silently misaligns
them.

Cells with no packet coverage get zeros plus an explicit
`has_packet_features` flag, so the model can learn to fall back on flow
features alone — which is the real situation whenever only NetFlow is exported.

### Packet features are opt-in, and that is a correctness decision

`USE_PACKET_FEATURES` defaults to **off** for training. The reason is a leak we
caught in our own pipeline and think is worth stating plainly.

The conveniently sized PCAP CTU-13 publishes for scenario 1
(`botnet-capture-…-neris.pcap`, 55 MB) contains **only the infected host's
traffic**, and only part of the timeline. Joined onto the state cells,
`has_packet_features` became a perfect proxy for the label — it was 1 exactly
when the host was the bot and the window was early. Measured on the infected
host:

| Period | `has_packet_features` | Model risk |
|---|---|---|
| Training windows | 1.00 | **0.9995** |
| Validation windows | 0.00 | 0.0029 |
| Test windows | 0.00 | 0.0030 |

The cliff sits exactly on the split boundary. The model had learned the
metadata, not the behaviour, and the shortcut crowded out the real features
entirely. Removing it raised validation average precision from 0.35 to near 1.0
— the leak was actively making the model worse.

The extractor itself is unaffected and always runs for uploaded PCAPs, where a
user's capture covers their whole network. Turn the flag on only for a
full-traffic capture such as CTU-13's `.truncated.pcap`, where packet coverage
is independent of the label.

---

## MITRE ATT&CK stage mapping

CTU-13 does not ship ATT&CK annotations, but its flow labels are far richer than
the usual Background/Normal/Botnet summary. The capture authors annotated the
behaviour of each malicious flow, consistently across every malware family:

```
flow=From-Botnet-V42-TCP-CC16-HTTP-Not-Encrypted      → Command & Control
flow=From-Botnet-V45-TCP-CC106-IRC-Not-Encrypted      → Command & Control
flow=From-Botnet-V42-TCP-Attempt-SPAM                 → Exfiltration
flow=From-Botnet-V46-TCP-...-SMTP-Private-Proxy       → Exfiltration
flow=From-Botnet-V49-TCP-...-HTTP-Binary-Download     → Initial Access
flow=From-Botnet-V42-UDP-DNS / -TCP-Attempt / -ICMP   → Reconnaissance
```

So stage supervision comes from the dataset's own ground truth wherever it
exists, and from documented behavioural rules only where it does not — in
practice, lateral movement, which CTU-13's spam-oriented botnets barely
exercise. The full table is `_LABEL_STAGE_RULES` in `src/mitre.py`; the
interpretation of that vocabulary onto ATT&CK's five stages is ours, and it is
in one place so it can be challenged line by line.

A cell's stage is the **dominant** stage among its malicious flows, not the
furthest-along one. That choice matters: a spam bot emits a few C2 flows and
then thousands of spam deliveries every window, so taking the maximum would
mark every window from the first spam onward as Exfiltration and the kill chain
would appear to teleport to its end and freeze. The dominant stage keeps the
progression visible:

```
host 147.32.84.165, scenario 1, one digit per minute:
111111111555555555555155555555555555555555555555
└── Reconnaissance ──┘└──────── Exfiltration ────────┘
```

---

## An honest finding about CTU-13

**Every infected host in CTU-13 is malicious in every window it appears.**
Measured across all seven prepared scenarios: 856 malicious cells, **zero**
benign windows belonging to an infected host.

That is not a bug in the pipeline — it is how the dataset was made. The capture
authors ran live malware and recorded the result, so there is no pre-infection
baseline for the compromised machines.

The consequence is important and we state it rather than hide it: **on CTU-13,
a binary "will this host be attacked" target is close to degenerate.** Only 101
of 11,388 training sequences contain any positive window, and 98 of those are
positive in *every* step. A model scored purely on that target is mostly
learning which host is infected, not anticipating anything.

What *is* genuinely forecastable on this data is **kill-chain progression**.
There are 138 real stage transitions between consecutive windows:

| Transition | Count |
|---|---|
| Reconnaissance → Lateral Movement | 32 |
| Lateral Movement → Reconnaissance | 29 |
| Reconnaissance → Command & Control | 15 |
| Command & Control → Reconnaissance | 14 |
| Reconnaissance → Initial Access | 12 |
| Reconnaissance → Exfiltration | 10 |

So the headline task is **stage forecasting** — given the trajectory so far,
which kill-chain stage will this host occupy K windows from now — with binary
infiltration reported as a secondary measure of *detection transfer to unseen
malware families*.

To demonstrate true pre-compromise forecasting you need a capture where the
same host is observed benign and then attacked (CIC-IDS2017's morning/afternoon
structure, or the LANL authentication dataset). CIC-IDS2017's direct download is
now gated behind a UNB registration form, which is why this build uses CTU-13 —
one of the two datasets the PS names.

---

## Evaluation design

Three properties make the benchmark worth reading:

1. **Never split randomly.** Consecutive windows are highly autocorrelated; a
   random split lets the model see window *t* in training and *t+1* in test.
   Two non-random splits are supported, and they answer different questions —
   both are reported rather than whichever flatters the model.

   **Temporal** (`--split temporal`, the default) — train on the first 70% of
   every capture, validate on the next 15%, test on the last 15%, with a guard
   band so no sequence straddles a boundary. This is the deployment shape: a
   system installed on a network learns that network and forecasts its future.

   **Family holdout** (`--split family`) — asks whether the model transfers to
   malware it has never seen.

   | Split | Scenarios | Families |
   |---|---|---|
   | Train | 1, 4, 7, 10 | Neris, Rbot, Sogou |
   | Validation | 12 | NSIS.ay |
   | Test | 5, 8 | Virut, Murlo |

   Family holdout is the harder question and the model does poorly on it, which
   is unsurprising at this data scale: CTU-13 gives roughly one infected host
   per scenario, so training sees about four distinct compromised machines.
   Four examples is not enough to learn a malware-independent notion of
   compromise, and we report that rather than quietly dropping the split.

2. **Thresholds are chosen on validation and frozen** before the test split is
   touched.

3. **The baselines are given every advantage.** Identical features, identical
   scaler, identical forward-looking label. `stacked` additionally sees the same
   8-window history the world model does — so any remaining gap is attributable
   to learned dynamics rather than to a larger input. For stage forecasting the
   comparison is a **persistence baseline** ("assume the current stage holds"),
   which on a dataset where hosts mostly stay put is genuinely hard to beat;
   beating it is the only real evidence that transition dynamics were learned.

Results are written to `artifacts/reports/benchmark.{json,md}` and rendered in
the dashboard's Benchmark tab. Inference is deterministic
(`observe(..., sample=False)`) and rollouts are seeded, so re-running the
benchmark reproduces the report byte for byte — verified by running it twice.

### Results — temporal split

Trained on the first 70% of scenarios 1, 4, 5, 7, 8, 10, 12; tested on the
final 15% of each.

| Model | Precision | Recall | F1 | FPR | ROC-AUC | AP |
|---|---|---|---|---|---|---|
| **World model (RSSM)** | **0.968** | **1.000** | **0.984** | **0.000** | 1.000 | 1.000 |
| Logistic regression (8-window stack) | 0.628 | 0.912 | 0.744 | 0.004 | 0.997 | 0.858 |
| Logistic regression (single window) | 0.409 | 0.842 | 0.550 | 0.009 | 0.994 | 0.730 |

**Read the binary numbers carefully — twice over.**

*First*, because an infected host is malicious in every window it appears,
`infiltration_next` is near-constant per host. A strong score means the model
identified *which host is compromised* — a real detection result with a large
margin over both baselines — but a perfect score at +10 windows is **not**
evidence of forecasting skill, because the target barely changes across the
horizon. For context, the best single feature (`frac_syn_only`) reaches AP 0.21
on validation, so the model is not riding one giveaway column.

*Second, and more limiting:* every positive window in this test split belongs to
**three host-slots, all of them `147.32.84.165`** (in scenarios 1, 4 and 8).
That is not a sampling choice — it is what falls in the held-out final 15% of
each capture. Measured directly:

| Host | Malicious windows | Model risk |
|---|---|---|
| scenario 1, `147.32.84.165` | 284 | **1.000** |
| scenario 10, `147.32.84.165` | 20 | **0.000** |
| scenario 10, `147.32.84.191` … `.209` (9 more) | ~20 each | **0.000** |

The same IP address scores 1.000 in one capture and 0.000 in another, so this is
**not address memorisation** — it is a dependence on *sustained* activity. The
model needs a long run of malicious windows to accumulate confidence; a
twenty-minute burst produces nothing.

So the honest headline is: **F1 0.984 for detecting sustained compromise.**
Short-burst compromise is currently missed, and scenario 10's ten
lightly-infected hosts are the worked example. Fixing it likely means training
with explicit short-burst positives rather than letting long runs dominate the
loss.

| MITRE stage prediction | Accuracy | Macro-F1 | Macro-F1 (classes present) |
|---|---|---|---|
| **World model (RSSM)** | 0.998 | **0.455** | **0.683** |
| Logistic regression (8-window stack) | 0.975 | 0.353 | 0.530 |

**Stage forecasting is the honest test**, and the world model beats the
like-for-like persistence baseline at 9 of 10 horizons — at +4 to +6 windows it
matches the *oracle* persistence baseline that is handed the true current stage.
Quality decays with horizon as it should: macro-F1 0.61 at +2 windows, 0.42 at
+10.

Rollouts are stochastic and the test split contains few stage transitions, so
single-horizon differences are noise; read the trend across the column.

---

## Explainability

Every prediction carries three complementary explanations, because a single one
is easy to mislead yourself with:

- **Feature attribution** — integrated gradients from a baseline of "an average
  host" (the zero vector in scaled space, which after standardisation is the
  training mean). Plain gradient × input was the first implementation and it
  broke on exactly the cases that matter: once the model is confident, the local
  gradient collapses to ~1e-3 and every feature looks equally irrelevant.
  Integrating along the path fixes that and satisfies completeness, so the
  reported shares are comparable. `src/explain.py` also provides sampled
  Shapley values as an independent check.
- **Temporal attention** — the causal attention weights the prediction heads
  *actually consumed*, not a post-hoc approximation. Step *i* is masked from
  every step after it, and the smoke test asserts it.
- **Predicted state delta** — the decoder's imagined future observation minus
  the current one, in real units. This is the one defenders act on: not "risk
  is 0.81" but "distinct destination ports expected to go from 12 to 240".

The dashboard also reports the split of attribution mass between flow-level and
packet-level features, so you can see when the packet level is carrying the
decision.

### Model surprise, and why it reads backwards

The world model's prior gives a label-free novelty signal: decode
`p(z_t | h_t)` and compare with what actually arrived. On CTU-13 it does **not**
detect attacks — it anti-detects them:

| Signal | ROC-AUC | AP |
|---|---|---|
| Supervised head | 1.000 | 1.000 |
| Model surprise | 0.375 | 0.006 |
| Random | 0.500 | 0.008 |

Mean surprise is 0.494 on benign windows against 0.349 on malicious ones.
Botnet traffic is *more* predictable than human traffic, because beaconing and
spam are machine-generated and regular while a university network's real users
are erratic. That is still a usable signal read in the right direction — low
surprise on a host the risk head flags is corroborating evidence of automation —
so the dashboard shows it as a novelty channel with that reading spelled out,
and never folds it into the risk score.

---

## Dashboard

`server/app.py` + a single self-contained `index.html`. No CDN, no external
font, no telemetry, charts hand-drawn on canvas — it runs with the network
cable unplugged, which the PS requires and which is also the only sane way to
demo in a venue with unreliable wifi.

- Hosts ranked by forecast risk (triage view)
- Observed risk flowing into an imagined future with a 10th–90th percentile band
- MITRE kill chain with current and predicted stage
- Feature attribution, temporal attention, predicted state changes
- Benchmark tab
- **Upload** a `.pcap`/`.pcapng` or a `.binetflow`/`.csv` and get the same
  analysis. For a PCAP, flows are reconstructed from raw packets first
  (`flows_from_pcap`) so both feature levels are available — the job Argus or
  nfdump normally does upstream.

---

## Repository layout

```
src/
  config.py            all hyperparameters and paths, serialised into checkpoints
  mitre.py             stage vocabulary, label mapping table, behavioural rules
  dataset.py           sequence construction, scaling, imbalance-aware sampling
  train.py             training loop, family-disjoint splits
  evaluate.py          benchmark against LR and persistence baselines
  explain.py           attribution, attention, state deltas, SHAP
  inference.py         forecast engine used by the API and CLI
  features/
    flow.py            .binetflow → flows, TCP flags from Argus state strings
    packet.py          PCAP → packet features; PCAP → reconstructed flows
    windows.py         (host, window) state cells and forward-looking targets
  model/
    world_model.py     RSSM, heads, causal attention, losses
    baseline.py        logistic regression and persistence baselines, metrics
server/
  app.py               FastAPI
  static/index.html    offline dashboard
tests/
  smoke_model.py       shapes, gradients, causal mask, imagination independence
```

## Reproducibility

Seeds are fixed (`TrainConfig.seed`). Every checkpoint stores its full
`RunConfig`, the feature column order, the fitted scaler, and which scenarios
were used for each split — so a checkpoint fully describes how to reproduce and
how to load it.

## Dataset

CTU-13 (Stratosphere IPS, CTU University) — CC BY 2.0.
García, S. et al., *An empirical comparison of botnet detection methods*,
Computers & Security, 2014.
