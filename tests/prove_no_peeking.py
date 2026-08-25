"""Show that the forecast is a forecast, not a lookahead.

Run: python -m tests.prove_no_peeking

The project's central claim is that the model rolls forward without seeing
traffic. `tests/smoke_model.py` already asserts it, but an assertion that
passes proves nothing on its own - a test that cannot fail is decoration.

So this runs the check twice. Once the way the model actually forecasts, with
the rollout starting from a detached state; once deliberately wired so the
rollout still reaches back to the encoder. If the first is zero and the second
is not, the check has teeth and the claim is standing on it.

Written to be run in front of someone.
"""

import torch

from src.config import ModelConfig
from src.model.world_model import WorldModel

OBS_DIM = 62          # 39 flow + 23 packet features
BATCH, STEPS, HORIZON = 4, 24, 10


def encoder_gradient(model, h, z) -> float:
    """Total gradient reaching the encoder from an imagination-only loss."""
    model.zero_grad(set_to_none=True)
    dream = model.imagine(h, z, steps=HORIZON)
    dream["infiltration_logit"].sum().backward(retain_graph=True)
    grad = model.encoder[0].weight.grad
    return 0.0 if grad is None else grad.abs().sum().item()


def main() -> None:
    torch.manual_seed(0)
    model = WorldModel(ModelConfig(obs_dim=OBS_DIM))
    obs = torch.randn(BATCH, STEPS, OBS_DIM)
    out = model.observe(obs)

    print(f"\nModel: {model.count_parameters():,} parameters, "
          f"{OBS_DIM} features, {HORIZON}-step rollout")
    print("Backpropagating an imagination-only loss and measuring what "
          "reaches the encoder.\n")

    honest = encoder_gradient(model, out["h"][:, -1].detach(),
                              out["z"][:, -1].detach())
    print(f"  1. Rollout from a detached state  (how we forecast)")
    print(f"     encoder gradient = {honest:.6f}")
    print(f"     -> the encoder took no part. Nothing was observed.\n")

    peeking = encoder_gradient(model, out["h"][:, -1], out["z"][:, -1])
    print(f"  2. Rollout still wired to the observations  (the bug)")
    print(f"     encoder gradient = {peeking:.6f}")
    print(f"     -> the encoder is in the loop. This would be a lookahead.\n")

    assert honest == 0.0, "the forecast is reaching the encoder"
    assert peeking > 0.0, "the check cannot fail, so it proves nothing"
    print("Both hold: the claim is falsifiable, and it is not falsified.")
    print("smoke_model.py asserts case 1 on every run.\n")


if __name__ == "__main__":
    main()
