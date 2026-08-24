### Infiltration detection - temporal split (train on each capture's past, test on its future)

| Model | Precision | Recall | F1 | FPR | ROC-AUC | AP |
|---|---|---|---|---|---|---|
| World model (RSSM) | 0.959 | 1.000 | 0.979 | 0.002 | 1.000 | 0.995 |
| Logistic regression (single window) | 0.948 | 0.979 | 0.963 | 0.002 | 0.999 | 0.986 |
| Logistic regression (8-window stack) | 0.956 | 0.999 | 0.977 | 0.002 | 1.000 | 0.998 |

### What the test split actually contains

| Host carrying positives | Positive windows |
|---|---|
| `3:147.32.84.165` | 2160 |
| `13:147.32.84.165` | 528 |
| `1:147.32.84.165` | 144 |
| `9:147.32.84.206` | 128 |
| `9:147.32.84.205` | 127 |
| `9:147.32.84.207` | 127 |
| `9:147.32.84.208` | 127 |
| `9:147.32.84.209` | 127 |
| `9:147.32.84.165` | 112 |
| `9:147.32.84.191` | 112 |
| `9:147.32.84.192` | 112 |
| `9:147.32.84.193` | 112 |
| `9:147.32.84.204` | 112 |
| `2:147.32.84.165` | 79 |
| `4:147.32.84.165` | 64 |
| `8:147.32.84.165` | 32 |
| `6:147.32.84.165` | 31 |

> **Scope of the detection numbers.** Every positive window in this split belongs to the 17 host(s) above. Measured separately, the model scores risk 1.000 for a host with 284 sustained malicious windows and 0.000 for hosts with roughly 20 - including the same IP address in a different capture, so this is not address memorisation but a dependence on sustained activity. The figures below therefore characterise **detection of sustained compromise**; short bursts of around twenty minutes are currently missed.


> **Reading the binary numbers.** On CTU-13 an infected host is malicious in *every* window it appears, so `infiltration_next` is near-constant per host. Scoring well on it means the model identified which host is compromised - a detection result, and a real one - but a perfect score at +10 windows is not evidence of forecasting skill, because the target barely changes over the horizon. The stage columns below are the honest forecasting test.


### MITRE stage prediction

| Model | Accuracy | Macro-F1 | Macro-F1 (classes present) |
|---|---|---|---|
| World model (RSSM) | 0.998 | 0.537 | 0.806 |
| Logistic regression (8-window stack) | 0.981 | 0.453 | 0.680 |


### Forecast quality by horizon

| Steps ahead | Seconds | Binary F1 | ROC-AUC | Stage macro-F1 | Persistence (inferred) | Persistence (oracle) |
|---|---|---|---|---|---|---|
| +1 | 60 | 0.989 | 1.000 | 0.478 | 0.478 | 0.649 |
| +2 | 120 | 0.989 | 1.000 | 0.583 | 0.473 | 0.644 |
| +3 | 180 | 0.991 | 1.000 | 0.647 | 0.478 | 0.640 |
| +4 | 240 | 0.991 | 1.000 | 0.642 | 0.474 | 0.636 |
| +5 | 300 | 0.991 | 1.000 | 0.626 | 0.460 | 0.613 |
| +6 | 360 | 0.991 | 1.000 | 0.624 | 0.455 | 0.616 |
| +7 | 420 | 0.991 | 1.000 | 0.565 | 0.460 | 0.566 |
| +8 | 480 | 0.991 | 1.000 | 0.552 | 0.456 | 0.562 |
| +9 | 540 | 0.991 | 1.000 | 0.547 | 0.442 | 0.557 |
| +10 | 600 | 0.979 | 1.000 | 0.524 | 0.436 | 0.551 |

_Persistence (oracle) is given the ground-truth stage at the cut-off and is therefore not deployable; persistence (inferred) repeats the model's own filtered estimate and is the like-for-like comparison._

> **Stage forecasting verdict.** The rolled-out forecast beats the like-for-like persistence baseline at 9 of 10 horizons, so imagination is adding skill over assuming the current stage holds. It still trails the oracle variant, which is handed the true current stage. Caveat worth stating: rollouts are stochastic and the test split contains few stage transitions, so this comparison moves by a few points between runs even with a fixed seed. Treat single-horizon differences as noise and read the trend across the column.
