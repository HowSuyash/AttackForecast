"""Recurrent state-space world model for network attack forecasting.

The distinction the PS draws - a world model versus a classifier - comes down
to one thing: a classifier learns P(label | observation), a world model learns
P(S_t+1 | S_t) and can therefore be run *without* observations. That capability
is what this architecture is built around.

    obs x_t --[encoder]--> e_t
                            |
    h_t = GRU(h_t-1, z_t-1) |          deterministic path, carries context
                            v
    posterior  q(z_t | h_t, e_t)       used while we can still see traffic
    prior      p(z_t | h_t)            used when we cannot - i.e. the future
                            |
                   [h_t ; z_t] = S_t
                       /      |      \\
              decoder      heads    causal temporal attention

Training fits the prior to the posterior (the KL term). Once they agree, the
prior alone is a learned simulator: sample z from it, feed it back through the
GRU, and the model produces a trajectory of future network states it has never
observed. `imagine()` does exactly that, and it is what the K-step infiltration
forecast is read off.

The heads sit on the latent state, not on the raw observation, so they apply
unchanged to imagined states. That is the whole trick: forecasting attacker
progression is just running the same heads over dreamed states.
"""

from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F

from ..config import ModelConfig

# Numerical floor on predicted standard deviations. Without it the KL term can
# drive sigma to zero and produce NaNs a few hundred steps into training.
MIN_STD = 0.1


def _mlp(sizes: list[int], dropout: float = 0.0, out_activation: bool = False) -> nn.Sequential:
    layers: list[nn.Module] = []
    for i in range(len(sizes) - 1):
        layers.append(nn.Linear(sizes[i], sizes[i + 1]))
        is_last = i == len(sizes) - 2
        if not is_last or out_activation:
            layers.append(nn.LayerNorm(sizes[i + 1]))
            layers.append(nn.SiLU())
            if dropout > 0:
                layers.append(nn.Dropout(dropout))
    return nn.Sequential(*layers)


@dataclass
class StateDistribution:
    """A diagonal Gaussian over the stochastic latent."""

    mean: torch.Tensor
    std: torch.Tensor

    def rsample(self) -> torch.Tensor:
        return self.mean + self.std * torch.randn_like(self.std)

    def kl_to(self, other: "StateDistribution") -> torch.Tensor:
        """Analytic KL(self || other), summed over the latent dimension."""
        var_ratio = (self.std / other.std).pow(2)
        t1 = ((self.mean - other.mean) / other.std).pow(2)
        return 0.5 * (var_ratio + t1 - 1.0 - var_ratio.log()).sum(-1)


class CausalTemporalAttention(nn.Module):
    """Attention over past states, masked so no step can see the future.

    This is not decoration. The prediction heads read the attention context,
    so the weights this module produces are a genuine account of which earlier
    windows the model used - which is what the PS asks for under explainability.
    """

    def __init__(self, dim: int, n_heads: int, dropout: float):
        super().__init__()
        self.attn = nn.MultiheadAttention(
            embed_dim=dim, num_heads=n_heads, dropout=dropout, batch_first=True
        )
        self.norm = nn.LayerNorm(dim)

    def forward(self, states: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            states: (B, T, D) sequence of latent states.

        Returns:
            context: (B, T, D) attention-pooled history for each step.
            weights: (B, T, T) attention weights, averaged over heads.
        """
        t = states.size(1)
        # True = "not allowed to attend". Upper triangle above the diagonal is
        # the future; each step may attend to itself and everything before it.
        mask = torch.triu(
            torch.ones(t, t, dtype=torch.bool, device=states.device), diagonal=1
        )
        x = self.norm(states)
        context, weights = self.attn(x, x, x, attn_mask=mask, need_weights=True,
                                     average_attn_weights=True)
        return context, weights


class WorldModel(nn.Module):
    """The full RSSM plus decision heads."""

    def __init__(self, cfg: ModelConfig):
        super().__init__()
        self.cfg = cfg
        h, z, e = cfg.hidden_dim, cfg.latent_dim, cfg.embed_dim

        self.encoder = _mlp([cfg.obs_dim, e, e], cfg.dropout, out_activation=True)

        # Deterministic transition. Input is the previous stochastic latent;
        # the GRU state is the deterministic part of S.
        self.cell = nn.GRUCell(z, h)

        # p(z_t | h_t) - the learned simulator used for imagination.
        self.prior_net = _mlp([h, cfg.head_hidden, 2 * z], cfg.dropout)
        # q(z_t | h_t, e_t) - the filter used while observations are available.
        self.posterior_net = _mlp([h + e, cfg.head_hidden, 2 * z], cfg.dropout)

        self.decoder = _mlp([h + z, e, cfg.obs_dim], cfg.dropout)

        state_dim = h + z
        self.attention = CausalTemporalAttention(
            state_dim, cfg.attention_heads, cfg.dropout
        )

        # Heads read state + attention context, so they see both the immediate
        # situation and the history the attention selected.
        head_in = state_dim * 2
        self.infiltration_head = _mlp([head_in, cfg.head_hidden, 1], cfg.dropout)
        self.stage_head = _mlp([head_in, cfg.head_hidden, cfg.n_stages], cfg.dropout)

    # -- distribution helpers -------------------------------------------

    def _split(self, params: torch.Tensor) -> StateDistribution:
        mean, raw_std = params.chunk(2, dim=-1)
        std = F.softplus(raw_std) + MIN_STD
        return StateDistribution(mean, std)

    def prior(self, h: torch.Tensor) -> StateDistribution:
        return self._split(self.prior_net(h))

    def posterior(self, h: torch.Tensor, embed: torch.Tensor) -> StateDistribution:
        return self._split(self.posterior_net(torch.cat([h, embed], dim=-1)))

    def initial_state(self, batch: int, device) -> tuple[torch.Tensor, torch.Tensor]:
        h = torch.zeros(batch, self.cfg.hidden_dim, device=device)
        z = torch.zeros(batch, self.cfg.latent_dim, device=device)
        return h, z

    # -- filtering ------------------------------------------------------

    def observe(self, obs: torch.Tensor, sample: bool = True) -> dict:
        """Run the model forward over an observed sequence.

        Args:
            obs: (B, T, obs_dim) observed network states.
            sample: draw the latent from the posterior (training) or take its
                mean (inference). Sampling during inference makes every call
                non-deterministic - the same host scored twice gives different
                answers, and a benchmark cannot be reproduced even with a fixed
                seed. The mean is the right estimator once we are no longer
                propagating gradients through the KL term.

        Returns:
            dict with per-step latent states, both distributions, the
            reconstruction, head logits and attention weights.
        """
        b, t, _ = obs.shape
        device = obs.device
        embed = self.encoder(obs)

        h, z = self.initial_state(b, device)
        hs, zs, prior_means, prior_stds, post_means, post_stds = [], [], [], [], [], []

        for i in range(t):
            h = self.cell(z, h)
            pr = self.prior(h)
            po = self.posterior(h, embed[:, i])
            z = po.rsample() if sample else po.mean

            hs.append(h)
            zs.append(z)
            prior_means.append(pr.mean)
            prior_stds.append(pr.std)
            post_means.append(po.mean)
            post_stds.append(po.std)

        h_seq = torch.stack(hs, dim=1)
        z_seq = torch.stack(zs, dim=1)
        states = torch.cat([h_seq, z_seq], dim=-1)

        context, attn_weights = self.attention(states)
        head_in = torch.cat([states, context], dim=-1)

        return {
            "states": states,
            "h": h_seq,
            "z": z_seq,
            "recon": self.decoder(states),
            "infiltration_logit": self.infiltration_head(head_in).squeeze(-1),
            "stage_logits": self.stage_head(head_in),
            "attention": attn_weights,
            "prior": StateDistribution(
                torch.stack(prior_means, 1), torch.stack(prior_stds, 1)
            ),
            "posterior": StateDistribution(
                torch.stack(post_means, 1), torch.stack(post_stds, 1)
            ),
        }

    # -- imagination ----------------------------------------------------

    def imagine(
        self,
        h: torch.Tensor,
        z: torch.Tensor,
        steps: int,
        history: torch.Tensor | None = None,
        sample: bool = True,
    ) -> dict:
        """Roll the model forward with no observations at all.

        This is the forecast. Each step draws z from the *prior*, which is the
        only distribution available when there is no traffic to condition on,
        feeds it back through the GRU, and reads the heads off the imagined
        state. Nothing here touches the encoder.

        Args:
            h: (B, hidden_dim) deterministic state to continue from.
            z: (B, latent_dim) stochastic latent to continue from.
            steps: how many windows to imagine.
            history: optional (B, T, state_dim) observed states, so attention
                can look back at real evidence rather than only dreamed states.
            sample: draw from the prior when True, take the mean when False.
                Sampling is what makes repeated rollouts give a distribution.

        Returns:
            dict of (B, steps, ...) imagined states, predicted observations,
            infiltration probabilities and stage logits.
        """
        imagined_states = []
        for _ in range(steps):
            h = self.cell(z, h)
            pr = self.prior(h)
            z = pr.rsample() if sample else pr.mean
            imagined_states.append(torch.cat([h, z], dim=-1))

        imagined = torch.stack(imagined_states, dim=1)

        # Attention runs over real history followed by the imagined tail, so a
        # forecast stays anchored to the evidence that led into it.
        if history is not None and history.numel():
            full = torch.cat([history, imagined], dim=1)
            context, _ = self.attention(full)
            context = context[:, -steps:]
        else:
            context, _ = self.attention(imagined)

        head_in = torch.cat([imagined, context], dim=-1)
        logits = self.infiltration_head(head_in).squeeze(-1)

        return {
            "states": imagined,
            "h": h,
            "z": z,
            "pred_obs": self.decoder(imagined),
            "infiltration_logit": logits,
            "infiltration_prob": torch.sigmoid(logits),
            "stage_logits": self.stage_head(head_in),
        }

    # -- losses ---------------------------------------------------------

    def compute_losses(
        self,
        obs: torch.Tensor,
        infiltration: torch.Tensor,
        stage: torch.Tensor,
        cfg,
        pos_weight: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, dict]:
        """Full training objective.

        Four terms, and each earns its place:
          reconstruction - forces the latent to actually encode traffic state
          KL             - fits the prior to the posterior, which is what makes
                           imagination valid
          heads          - supervised infiltration and stage prediction
          imagination    - the same heads supervised on *rolled-out* states, so
                           multi-step forecasts are trained rather than hoped for
        """
        out = self.observe(obs)

        recon_loss = F.mse_loss(out["recon"], obs)

        kl = out["posterior"].kl_to(out["prior"])
        # Free nats: ignore KL below a floor so the posterior keeps some
        # freedom early on instead of collapsing onto the prior. The floor is a
        # total over the latent dimension, not a per-dimension allowance.
        kl_loss = torch.clamp(kl, min=cfg.free_nats).mean()

        inf_loss = F.binary_cross_entropy_with_logits(
            out["infiltration_logit"], infiltration.float(), pos_weight=pos_weight
        )
        stage_loss = F.cross_entropy(
            out["stage_logits"].reshape(-1, self.cfg.n_stages), stage.reshape(-1)
        )

        # -- imagination loss --------------------------------------------
        # Branch off partway through the sequence and imagine the remainder,
        # then score those imagined steps against what actually happened.
        imag_loss = torch.zeros((), device=obs.device)
        k = cfg.imagination_steps
        t = obs.size(1)
        if k > 0 and t > k + 1:
            split = t - k
            h_at = out["h"][:, split - 1]
            z_at = out["z"][:, split - 1]
            dream = self.imagine(
                h_at, z_at, steps=k, history=out["states"][:, :split], sample=True
            )
            imag_loss = F.binary_cross_entropy_with_logits(
                dream["infiltration_logit"], infiltration[:, split:].float(),
                pos_weight=pos_weight,
            ) + F.cross_entropy(
                dream["stage_logits"].reshape(-1, self.cfg.n_stages),
                stage[:, split:].reshape(-1),
            )

        total = (
            cfg.w_reconstruction * recon_loss
            + cfg.w_kl * kl_loss
            + cfg.w_infiltration * inf_loss
            + cfg.w_stage * stage_loss
            + cfg.w_imagination * imag_loss
        )

        metrics = {
            "loss": float(total.detach()),
            "recon": float(recon_loss.detach()),
            "kl": float(kl_loss.detach()),
            "infiltration": float(inf_loss.detach()),
            "stage": float(stage_loss.detach()),
            "imagination": float(imag_loss.detach()),
        }
        return total, metrics

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)
