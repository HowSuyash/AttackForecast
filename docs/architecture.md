# Architecture — AI Network Attack Forecasting

**PS 26153 · NTRO · World-model based predictive cyber defence · Team: Git with It**

---

## 1. Problem framing

Flow classifiers answer "is this flow malicious". The PS asks a different
question: *given how this network has been behaving, where is it heading?*
That requires a model of state transitions, `P(S_t+1 | S_t)`, that can be run
forward without observations. Everything below follows from that requirement.

## 2. Pipeline

```
CTU-13 .binetflow ──┐
                    ├──▶ flow records ──┐
PCAP ──[Scapy]──────┘   (Argus State →  │
        │                TCP flag bits)  │
        │                                ├──▶ (host, 60s window) state cells
        └──[Scapy]──▶ packet features ───┘     39 flow + 23 packet features
                      TTL / TCP window /       + MITRE stage + forecast targets
                      frag / retrans /
                      IAT / scan score
```

**State definition.** One state `S_t` is everything a single internal host did
in one 60-second window. Host-level rather than network-level because
"will the network be attacked" is not actionable, while "is *this* host on a
trajectory to exfiltration" is — and it multiplies training sequences by the
host count.

**Two feature levels, joined on an absolute window grid** (`epoch // width`).
A PCAP and a flow export of the same capture begin at different timestamps, so
a per-file relative grid silently misaligns them.

**Stage labels** come from CTU-13's own flow annotations (`-CC16-`, `-SPAM`,
`-Binary-Download`, `-Attempt`, `-DNS`) mapped onto ATT&CK's five stages by a
single inspectable table; documented behavioural rules fill the gaps, which in
practice means lateral movement. A cell takes the *dominant* stage among its
malicious flows, not the furthest-along one — otherwise a spam bot's first
spam flow pins every later window to Exfiltration and progression disappears.

## 3. World model

```
obs x_t ──[encoder]──▶ e_t
                        │
   h_t = GRU(h_t-1, z_t-1)        deterministic state, carries context
                        │
   posterior q(z_t | h_t, e_t)    while traffic is visible
   prior     p(z_t | h_t)         when it is not — i.e. the future
                        │
              S_t = [h_t ; z_t]
                 ╱      │      ╲
          decoder    heads    causal temporal attention
```

Recurrent state-space model, ~138k parameters, CPU-only.

**Why this is a world model, testably.** Training fits the prior to the
posterior via a KL term with a free-nats floor. Once they agree, the prior
alone is a simulator: sample `z`, feed it back through the GRU, and the model
produces network states it never observed. The prediction heads sit on the
latent state, not the observation, so they apply unchanged to imagined states.
`tests/smoke_model.py` asserts the property directly — an imagination-only loss
must produce **zero gradient in the encoder**. If the rollout were peeking at
observations, that test fails.

**Objective.** Reconstruction (forces the latent to encode traffic) + KL (fits
the prior, which is what makes imagination valid) + supervised infiltration and
stage heads + an **imagination loss** that supervises the heads on rolled-out
states, so multi-step forecasting is trained rather than hoped for.

**Forecast.** K independent rollouts from the current latent; the mean is the
forecast and the 10th–90th percentile spread is the uncertainty band that
widens as evidence runs out.

## 4. Explainability

Three channels, because one is easy to fool yourself with:

| Channel | Answers | Method |
|---|---|---|
| Feature attribution | which measurements drove the score | integrated gradients from an "average host" baseline; plain gradient × input collapsed to ~1e-3 on confident predictions, which is exactly when an explanation is needed |
| Temporal attention | which earlier windows mattered | the causal attention weights the heads actually consumed, masked so step *i* cannot see *i+1* |
| Predicted state delta | what the model expects to change | decoder output on the imagined state, in real units |

The dashboard also splits attribution mass between flow-level and packet-level
features, showing when the packet level is carrying the decision.

## 5. Evaluation design

Two different questions, reported separately:

- **Temporal split** (primary) — train on the first 70% of every capture,
  forecast its future, with a guard band so no sequence straddles a boundary.
  This is the deployment shape: a system installed on a network learns that
  network.
- **Family holdout** — train on Neris/Rbot/Menti/Sogou, test on Virut and
  Murlo. Asks whether the model transfers to unseen malware. On seven scenarios
  this failed outright; with all thirteen it reaches F1 0.874 and ROC-AUC 0.982.
  Stage forecasting still does not transfer across families.

Baselines get identical features, scaler and labels. The stacked logistic
regression additionally sees the same 8-window history the world model does, so
any gap is attributable to learned dynamics rather than a larger input. Stage
forecasting is compared against **persistence** ("assume nothing changes") in
two variants: one given the ground-truth current stage (an oracle, not
deployable) and one repeating the model's own inferred stage (like-for-like).

## 6. Findings that shaped the build

**CTU-13 has no pre-infection baseline.** Across all thirteen scenarios, infected hosts are malicious in *every* window they appear — 4,391 malicious cells and not one benign window belonging to a compromised machine, in 258,229 windows. So "will this host be attacked" is close to degenerate here, and kill-chain progression is the forecastable signal instead.

**A PCAP can leak the label.** CTU-13's conveniently sized scenario-1 capture holds only the infected host's traffic, so joined onto the state cells `has_packet_features` became a perfect label proxy: 0.9995 on training windows, 0.003 on every later window of the same host. The model had learned the metadata, not the behaviour. Packet features are now opt-in and enabled only when coverage is label-independent; removing the shortcut took detection F1 from 0.23 to 0.98 — the leak was making the model *worse*.

**The two channels fail in opposite regimes.** The prior-error "surprise" signal is *anti*-correlated with compromise (ROC-AUC 0.210) — sustained bot traffic is more predictable than human traffic. But the supervised head needs that sustained run to build confidence, so short bursts are invisible to it and surprising to the prior. Triage flags on either channel: 28 of 30 infected hosts caught at 4.9% false alarms, ten of them by the anomaly channel alone.

## 7. Decision support surface

FastAPI + a single self-contained HTML page: no CDN, no external font, no
telemetry, charts drawn on canvas. Runs with the network cable unplugged.

| View | What it answers | How it is computed |
|---|---|---|
| **Triage list** | which host first | every host scored in one batched pass — 149 hosts in 0.5 s |
| **Forecast + replay** | is this host heading somewhere bad | `observe` once for all latent states, then one batched `imagine` from every timestep — 145 replay frames in ~2 s |
| **Kill-chain strip** | what has this host been doing all capture | one block per window, coloured by inferred stage, dataset labels ticked underneath |
| **Topology** | where does it sit in the network | separate `(src, dst)` edge table; node colour is the same risk score |
| **Explanations** | why | integrated gradients, causal attention, decoded state delta |
| **Upload** | does it work on my traffic | PCAP → flows reconstructed → both feature levels → same forecast |

Two engineering notes worth defending:

**Replay is batched, not looped.** A frame per minute could have been a request
per minute; instead `observe` yields the latent state at every timestep in one
pass and all rollouts run as a single batch. The difference is 2 seconds against
several minutes, and it is what makes playback usable in front of an audience.

**The topology view is deliberately truncated.** The bot in scenario 1 contacted
1,850 external peers; drawing them all produces an unreadable hairball and an
O(n²) layout that stalls the browser. Nodes are selected by priority — flagged
hosts, then the busiest malicious peers, then volume — and the untruncated
counts are reported as figures instead, which state the fan-out more clearly
than the picture could.
