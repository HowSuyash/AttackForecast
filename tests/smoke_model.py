"""Shape and gradient smoke test for the world model.

Run: python -m tests.smoke_model
Catches the errors that are expensive to find during a real training run:
wrong tensor shapes, a broken causal mask, NaN losses, dead gradients.
"""

import torch

from src.config import ModelConfig, TrainConfig
from src.model.world_model import WorldModel


def main() -> None:
    obs_dim = 62
    model = WorldModel(ModelConfig(obs_dim=obs_dim))
    print(f"parameters: {model.count_parameters():,}")

    b, t, horizon = 8, 32, 10
    obs = torch.randn(b, t, obs_dim)
    infiltration = torch.randint(0, 2, (b, t))
    stage = torch.randint(0, 6, (b, t))

    out = model.observe(obs)
    assert out["states"].shape == (b, t, model.cfg.hidden_dim + model.cfg.latent_dim)
    assert out["recon"].shape == (b, t, obs_dim)
    assert out["infiltration_logit"].shape == (b, t)
    assert out["stage_logits"].shape == (b, t, 6)
    assert out["attention"].shape == (b, t, t)
    print("observe: shapes OK")

    dream = model.imagine(out["h"][:, -1], out["z"][:, -1], steps=horizon,
                          history=out["states"])
    assert dream["states"].shape[1] == horizon
    assert dream["infiltration_prob"].shape == (b, horizon)
    assert dream["pred_obs"].shape == (b, horizon, obs_dim)
    print("imagine: shapes OK")

    # Imagination must not touch the encoder - that is what makes it a forecast
    # rather than a lookahead. Verified by checking the encoder gets no gradient
    # from an imagination-only loss.
    model.zero_grad(set_to_none=True)
    fresh = model.imagine(out["h"][:, -1].detach(), out["z"][:, -1].detach(),
                          steps=horizon)
    fresh["infiltration_logit"].sum().backward(retain_graph=True)
    enc_grad = model.encoder[0].weight.grad
    assert enc_grad is None or enc_grad.abs().sum().item() == 0.0, (
        "encoder received gradient during imagination - the rollout is peeking "
        "at observations"
    )
    print("imagine: no encoder dependency OK")

    model.zero_grad(set_to_none=True)
    loss, metrics = model.compute_losses(obs, infiltration, stage, TrainConfig())
    assert torch.isfinite(loss), f"non-finite loss: {loss}"
    loss.backward()

    grad_norm = sum(
        p.grad.norm().item() ** 2 for p in model.parameters() if p.grad is not None
    ) ** 0.5
    assert grad_norm > 0, "no gradient reached the parameters"
    print("losses:", {k: round(v, 4) for k, v in metrics.items()})
    print(f"grad norm: {grad_norm:.3f}")

    # Causal mask: step i must place zero weight on every step after i.
    attn = out["attention"][0].detach()
    for i in (0, 5, t - 2):
        future = attn[i, i + 1:].abs().sum().item()
        assert future < 1e-6, f"step {i} attends to the future (mass {future})"
    print("attention: causal mask OK")

    print("\nall smoke checks passed")


if __name__ == "__main__":
    main()
