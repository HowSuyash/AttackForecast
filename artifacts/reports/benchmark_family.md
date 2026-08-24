### Infiltration detection - held-out malware families

| Model | Precision | Recall | F1 | FPR | ROC-AUC | AP |
|---|---|---|---|---|---|---|
| World model (RSSM) | 0.903 | 0.847 | 0.874 | 0.002 | 0.982 | 0.917 |
| Logistic regression (single window) | 0.865 | 0.941 | 0.901 | 0.003 | 0.963 | 0.928 |
| Logistic regression (8-window stack) | 0.513 | 0.959 | 0.669 | 0.019 | 0.973 | 0.913 |

### What the test split actually contains

| Host carrying positives | Positive windows |
|---|---|
| `13:147.32.84.165` | 3856 |
| `8:147.32.84.165` | 799 |
| `5:147.32.84.165` | 32 |

> **Scope of the detection numbers.** Every positive window in this split belongs to the 3 host(s) above. Measured separately, the model scores risk 1.000 for a host with 284 sustained malicious windows and 0.000 for hosts with roughly 20 - including the same IP address in a different capture, so this is not address memorisation but a dependence on sustained activity. The figures below therefore characterise **detection of sustained compromise**; short bursts of around twenty minutes are currently missed.


> **Reading the binary numbers.** On CTU-13 an infected host is malicious in *every* window it appears, so `infiltration_next` is near-constant per host. Scoring well on it means the model identified which host is compromised - a detection result, and a real one - but a perfect score at +10 windows is not evidence of forecasting skill, because the target barely changes over the horizon. The stage columns below are the honest forecasting test.


### MITRE stage prediction

| Model | Accuracy | Macro-F1 | Macro-F1 (classes present) |
|---|---|---|---|
| World model (RSSM) | 0.989 | 0.406 | 0.487 |
| Logistic regression (8-window stack) | 0.982 | 0.370 | 0.443 |


### Forecast quality by horizon

| Steps ahead | Seconds | Binary F1 | ROC-AUC | Stage macro-F1 | Persistence (inferred) | Persistence (oracle) |
|---|---|---|---|---|---|---|
| +1 | 60 | 0.908 | 0.983 | 0.401 | 0.415 | 0.786 |
| +2 | 120 | 0.914 | 0.984 | 0.390 | 0.409 | 0.768 |
| +3 | 180 | 0.909 | 0.985 | 0.392 | 0.412 | 0.703 |
| +4 | 240 | 0.911 | 0.988 | 0.387 | 0.411 | 0.693 |
| +5 | 300 | 0.905 | 0.989 | 0.382 | 0.409 | 0.653 |
| +6 | 360 | 0.907 | 0.989 | 0.368 | 0.404 | 0.665 |
| +7 | 420 | 0.905 | 0.990 | 0.367 | 0.408 | 0.643 |
| +8 | 480 | 0.901 | 0.990 | 0.365 | 0.407 | 0.668 |
| +9 | 540 | 0.897 | 0.990 | 0.359 | 0.405 | 0.650 |
| +10 | 600 | 0.893 | 0.989 | 0.349 | 0.398 | 0.655 |

_Persistence (oracle) is given the ground-truth stage at the cut-off and is therefore not deployable; persistence (inferred) repeats the model's own filtered estimate and is the like-for-like comparison._

> **Stage forecasting verdict.** The rolled-out forecast beats the like-for-like persistence baseline at only 0 of 10 horizons, so imagination is not yet adding skill over assuming the current stage holds. This is the number to improve, and the honest place to point a reviewer. Caveat worth stating: rollouts are stochastic and the test split contains few stage transitions, so this comparison moves by a few points between runs even with a fixed seed. Treat single-horizon differences as noise and read the trend across the column.
