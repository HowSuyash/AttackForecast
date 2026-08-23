### Infiltration detection - temporal split (train on each capture's past, test on its future)

| Model | Precision | Recall | F1 | FPR | ROC-AUC | AP |
|---|---|---|---|---|---|---|
| World model (RSSM) | 0.968 | 1.000 | 0.984 | 0.000 | 1.000 | 1.000 |
| Logistic regression (single window) | 0.409 | 0.842 | 0.550 | 0.009 | 0.994 | 0.730 |
| Logistic regression (8-window stack) | 0.628 | 0.912 | 0.744 | 0.004 | 0.997 | 0.858 |

> **Reading the binary numbers.** On CTU-13 an infected host is malicious in *every* window it appears, so `infiltration_next` is near-constant per host. Scoring well on it means the model identified which host is compromised - a detection result, and a real one - but a perfect score at +10 windows is not evidence of forecasting skill, because the target barely changes over the horizon. The stage columns below are the honest forecasting test.


### MITRE stage prediction

| Model | Accuracy | Macro-F1 | Macro-F1 (classes present) |
|---|---|---|---|
| World model (RSSM) | 0.998 | 0.455 | 0.683 |
| Logistic regression (8-window stack) | 0.975 | 0.353 | 0.530 |


### Forecast quality by horizon

| Steps ahead | Seconds | Binary F1 | ROC-AUC | Stage macro-F1 | Persistence (inferred) | Persistence (oracle) |
|---|---|---|---|---|---|---|
| +1 | 60 | 1.000 | 1.000 | 0.440 | 0.440 | 0.638 |
| +2 | 120 | 1.000 | 1.000 | 0.606 | 0.440 | 0.638 |
| +3 | 180 | 1.000 | 1.000 | 0.606 | 0.440 | 0.638 |
| +4 | 240 | 1.000 | 1.000 | 0.638 | 0.440 | 0.638 |
| +5 | 300 | 1.000 | 1.000 | 0.612 | 0.415 | 0.612 |
| +6 | 360 | 1.000 | 1.000 | 0.612 | 0.415 | 0.612 |
| +7 | 420 | 1.000 | 1.000 | 0.522 | 0.404 | 0.545 |
| +8 | 480 | 1.000 | 1.000 | 0.499 | 0.404 | 0.545 |
| +9 | 540 | 1.000 | 1.000 | 0.422 | 0.383 | 0.522 |
| +10 | 600 | 1.000 | 1.000 | 0.422 | 0.383 | 0.522 |

_Persistence (oracle) is given the ground-truth stage at the cut-off and is therefore not deployable; persistence (inferred) repeats the model's own filtered estimate and is the like-for-like comparison._

> **Stage forecasting verdict.** The rolled-out forecast beats the like-for-like persistence baseline at 9 of 10 horizons, so imagination is adding skill over assuming the current stage holds. It still trails the oracle variant, which is handed the true current stage. Caveat worth stating: rollouts are stochastic and the test split contains few stage transitions, so this comparison moves by a few points between runs even with a fixed seed. Treat single-horizon differences as noise and read the trend across the column.
