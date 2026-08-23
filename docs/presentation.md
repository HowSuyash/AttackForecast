# Technical Presentation — 5 slides

PS 26153 · AI Network Attack Forecasting · NTRO

Slide content plus speaker notes. Numbers marked `[from benchmark]` should be
copied from `artifacts/reports/benchmark.md` after the final run so the deck
never disagrees with the repository.

---

## Slide 1 — The gap

**Title:** Classification tells you what happened. Defence needs what happens next.

- A flow classifier maps one flow → benign/malicious, discarding the temporal
  and causal structure of an infiltration.
- An intrusion is a *process*: ports probed in sequence, SYNs before ACK floods,
  reconnaissance timing before lateral movement begins.
- **World model:** learn `P(S_t+1 | S_t)` — the distribution over future network
  states — then roll it forward K steps and see whether the trajectory converges
  on compromise.

> **Speaker note:** open on the distinction, not the architecture. The single
> sentence that matters: *we do not classify traffic, we simulate the network
> forward and read the risk off the simulation.*

---

## Slide 2 — System

**Title:** Two feature levels → latent state → imagined future

Diagram (left to right):

```
.binetflow ─┐                          ┌── decoder ── predicted traffic
            ├─▶ 39 flow features ──┐   │
PCAP ───────┘                      ├──▶ encoder ─▶ GRU ─▶ [h;z] ─┼── infiltration head
   └──▶ 23 packet features ────────┘        prior/posterior       │
        TTL var · TCP window · frag         (the simulator)       └── MITRE stage head
        retrans · IAT · scan score                                └── causal attention
```

- **Flow level:** fan-out, TCP flag rates recovered from Argus state strings,
  entropy, beaconing regularity.
- **Packet level:** TTL variance, TCP window, fragmentation, retransmissions,
  per-packet timing, sequential-scan score. Joined on an absolute window grid.
- **~138k parameters, CPU-only, fully offline.**

> **Speaker note:** if asked "how is this different from an LSTM classifier" —
> the heads read the *latent state*, not the observation, so they still work on
> states the model imagined. That is the whole mechanism.

---

## Slide 3 — Forecast and explanation

**Title:** A prediction a defender can act on

Screenshot: the dashboard forecast panel — observed risk flowing into the
dashed forecast with its 10th–90th band, the MITRE kill chain with current and
predicted stage, and the attribution panel.

Three explanation channels, all shown per prediction:

| Channel | Answers |
|---|---|
| Integrated-gradients attribution | which traffic measurements drove the score |
| Causal temporal attention | which earlier windows the heads actually used |
| Decoded state delta | *"distinct destination ports: 12 → 240"* |

- Kill chain mapped from CTU-13's own flow annotations (`CC16`, `SPAM`,
  `Binary-Download`) onto ATT&CK's five stages via one inspectable table.
- Model surprise (prior prediction error) shown alongside as an unsupervised
  novelty channel that needs no labels.

> **Speaker note:** the state delta is the line that lands with practitioners.
> Not "risk 0.81" but "the model expects port fan-out to grow 20x in the next
> six minutes".

---

## Slide 4 — Results

**Title:** Benchmarked honestly against baselines that were given every advantage

**Temporal split** — learn each capture's past, forecast its future:

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| **World model (RSSM)** | **0.968** | **1.000** | **0.984** | **0.000** |
| Logistic regression (8-window stack) | 0.628 | 0.912 | 0.744 | 0.004 |
| Logistic regression (single window) | 0.409 | 0.842 | 0.550 | 0.009 |

MITRE stage macro-F1: **0.455** vs 0.353 for the stacked baseline.
Stage forecasting beats the like-for-like persistence baseline at **9 of 10
horizons**, and matches the *oracle* persistence baseline at +4 to +6 windows.

Baselines received identical features, scaler and labels; the stacked logistic
regression additionally saw the same 8-window history. Inference is
deterministic and rollouts are seeded — running the benchmark twice reproduces
the report byte for byte.

**Two findings we report rather than hide:**

1. **CTU-13 has no pre-infection baseline** — infected hosts are malicious in
   every window they appear (856 malicious cells, zero benign). Binary
   "will it be attacked" is near-degenerate here; kill-chain progression
   (138 real transitions) is the forecastable signal.
2. **A PCAP leaked the label.** The convenient scenario-1 capture contains only
   botnet traffic, so `has_packet_features` became a perfect label proxy —
   0.9995 on training windows, 0.003 on every later window of the same host,
   with the cliff exactly on the split boundary. The shortcut crowded out the
   real behavioural features; removing it took detection F1 from 0.23 to 0.98.
   The leak was making the model *worse*.

> **Speaker note:** lead with finding 2 if the panel is technical. Catching a
> leak in your own pipeline is a stronger signal of rigour than any metric.

---

## Slide 5 — Deployment and roadmap

**Title:** Runs offline today, on the network you are defending

- FastAPI + single self-contained HTML page. No CDN, no external font, no
  telemetry — runs with the cable unplugged, as the PS requires.
- Upload a `.pcap` or `.binetflow`: flows are reconstructed from raw packets,
  both feature levels computed, forecast and explanation returned.
- Triage view ranks every host in a capture in **under a second** after the
  first sweep.

**Next, in order of value:**

1. A capture with a genuine pre-infection baseline (CIC-IDS2017's
   morning/afternoon structure, LANL auth logs) to train true pre-compromise
   forecasting.
2. Graph-structured state — host-to-host edges via a GNN — so lateral movement
   is modelled as topology change rather than inferred per host.
3. Online adaptation: keep updating the prior on the live network so the model
   tracks drift instead of aging out.

> **Speaker note:** close on point 1. It names the exact dataset property the
> problem needs and shows we understand why our current numbers look the way
> they do.
