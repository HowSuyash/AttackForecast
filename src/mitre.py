"""MITRE ATT&CK stage vocabulary and the rules that derive stage labels.

CTU-13 does not ship ATT&CK annotations, but its flow labels are far richer
than the usual Background/Normal/Botnet summary suggests. The capture authors
annotated the actual behaviour of each malicious flow, and that vocabulary is
consistent across every malware family in the dataset:

    flow=From-Botnet-V42-TCP-CC16-HTTP-Not-Encrypted     <- C2 channel, numbered
    flow=From-Botnet-V45-TCP-CC106-IRC-Not-Encrypted     <- C2 over IRC
    flow=From-Botnet-V42-TCP-Attempt-SPAM                <- spam delivery
    flow=From-Botnet-V46-TCP-Not-Encrypted-SMTP-Private-Proxy
    flow=From-Botnet-V49-TCP-Established-HTTP-Binary-Download
    flow=From-Botnet-V42-UDP-DNS / -TCP-Attempt / -ICMP

So stage supervision comes from two sources, in this order of authority:

  1. `stage_from_label` - the dataset's own annotation. A flow the capture
     authors marked CC16 is a command-and-control flow; we are reading their
     ground truth, not guessing.
  2. `derive_stage` - behavioural rules, used only where the labels are silent.
     In practice that is lateral movement, which CTU-13's spam-oriented
     botnets barely exercise, and any input arriving without labels at all
     (the dashboard's PCAP upload path).

Worth stating plainly in the demo: the mapping from CTU-13's vocabulary onto
ATT&CK's five stages is our interpretation, and it is defined in one table
below so a reviewer can read and challenge every line of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .config import C2_PORTS, INTERNAL_PREFIXES, LATERAL_PORTS

# --------------------------------------------------------------------------
# Stage vocabulary
# --------------------------------------------------------------------------

BENIGN = 0
RECONNAISSANCE = 1
INITIAL_ACCESS = 2
LATERAL_MOVEMENT = 3
COMMAND_AND_CONTROL = 4
EXFILTRATION = 5

STAGE_NAMES = (
    "Benign",
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Command & Control",
    "Exfiltration",
)

N_STAGES = len(STAGE_NAMES)

# Kill-chain ordering used by the dashboard to decide whether a forecast
# represents *progression* (advancing to a later stage) or merely persistence.
STAGE_ORDER = {
    BENIGN: -1,
    RECONNAISSANCE: 0,
    INITIAL_ACCESS: 1,
    LATERAL_MOVEMENT: 2,
    COMMAND_AND_CONTROL: 3,
    EXFILTRATION: 4,
}


@dataclass(frozen=True)
class TechniqueRef:
    """A MITRE ATT&CK tactic/technique pair shown alongside a predicted stage."""

    tactic_id: str
    tactic: str
    technique_id: str
    technique: str


# One representative technique per stage. Kept deliberately small: the point is
# to give a defender a recognisable handle, not to enumerate ATT&CK.
STAGE_TECHNIQUES: dict[int, TechniqueRef] = {
    BENIGN: TechniqueRef("-", "No adversary activity", "-", "-"),
    RECONNAISSANCE: TechniqueRef(
        "TA0043", "Reconnaissance", "T1046", "Network Service Discovery"
    ),
    INITIAL_ACCESS: TechniqueRef(
        "TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application"
    ),
    LATERAL_MOVEMENT: TechniqueRef(
        "TA0008", "Lateral Movement", "T1021", "Remote Services"
    ),
    COMMAND_AND_CONTROL: TechniqueRef(
        "TA0011", "Command and Control", "T1071", "Application Layer Protocol"
    ),
    EXFILTRATION: TechniqueRef(
        "TA0010", "Exfiltration", "T1041", "Exfiltration Over C2 Channel"
    ),
}


def is_internal(addr: str) -> bool:
    """True when an address sits inside the monitored enterprise range."""
    return any(addr.startswith(p) for p in INTERNAL_PREFIXES)


# --------------------------------------------------------------------------
# Stage from the dataset's own flow annotation
# --------------------------------------------------------------------------

# Ordered (pattern, stage) table. The first match wins, so the order encodes
# precedence and the reasoning for each entry is given inline.
#
# Precedence notes worth defending out loud:
#   - CC before HTTP: a "CC16-HTTP-Not-Encrypted" label is a C2 channel that
#     happens to use HTTP, not ordinary web traffic.
#   - SPAM before Attempt: "TCP-Attempt-SPAM" is a spam delivery that failed to
#     connect. The intent is data leaving the host, so it reads as exfiltration
#     rather than as probing.
#   - Binary-Download is payload delivery, which is the closest thing CTU-13
#     contains to initial access on the wire.
_LABEL_STAGE_RULES: tuple[tuple[str, int], ...] = (
    # Explicit command-and-control channels, numbered by the capture authors.
    (r"-cc\d+", COMMAND_AND_CONTROL),
    (r"irc", COMMAND_AND_CONTROL),
    # A bespoke encryption scheme on a botnet flow is a covert channel.
    (r"custom-encryption", COMMAND_AND_CONTROL),

    # Data leaving the host: spam campaigns and mail relaying.
    (r"spam", EXFILTRATION),
    (r"smtp", EXFILTRATION),

    # Payload retrieval.
    (r"binary-download", INITIAL_ACCESS),

    # Click fraud and bot tasking over the application layer. Grouped with C2
    # under T1071 because the host is acting on instructions it fetched.
    (r"http-ad", COMMAND_AND_CONTROL),
    (r"web-established", COMMAND_AND_CONTROL),

    # Unanswered probes and discovery traffic.
    (r"attempt", RECONNAISSANCE),
    (r"dns", RECONNAISSANCE),
    (r"icmp", RECONNAISSANCE),

    # Generic established botnet traffic with no further annotation.
    (r"established", INITIAL_ACCESS),
)

# Compiled once; `stage_from_label` runs over millions of rows.
_LABEL_STAGE_COMPILED = tuple(
    (re.compile(pattern), stage) for pattern, stage in _LABEL_STAGE_RULES
)


def stage_from_label(label: str) -> int | None:
    """Map a CTU-13 flow label onto an ATT&CK stage.

    Args:
        label: the raw `Label` field, e.g. `flow=From-Botnet-V42-TCP-CC16-...`.

    Returns:
        A stage constant, or None when the label carries no behavioural
        annotation and the caller should fall back to `derive_stage`.
    """
    if not label:
        return None
    text = label.lower()
    if "botnet" not in text:
        return None
    for pattern, stage in _LABEL_STAGE_COMPILED:
        if pattern.search(text):
            return stage
    return None


def label_stage_patterns() -> list[dict]:
    """The mapping table, for the architecture document and the dashboard."""
    return [
        {"pattern": p, "stage": STAGE_NAMES[s], "stage_id": s}
        for p, s in _LABEL_STAGE_RULES
    ]


# --------------------------------------------------------------------------
# Stage derivation
# --------------------------------------------------------------------------


def derive_stage(
    *,
    n_flows: int,
    n_unique_dst_ips: int,
    n_unique_dst_ports: int,
    mean_duration: float,
    src_bytes: float,
    total_bytes: float,
    frac_internal_dst: float,
    frac_lateral_ports: float,
    frac_c2_ports: float,
    frac_syn_only: float,
    beacon_regularity: float,
) -> int:
    """Map one host-window of *malicious* flow behaviour onto a kill-chain stage.

    The ordering of the checks matters: scanning is the most visually distinct
    behaviour so it is tested first, exfiltration is tested before C2 because a
    large outbound transfer over a C2 channel should read as exfiltration.

    Args:
        n_flows: flows originated by the host in this window.
        n_unique_dst_ips: distinct destinations contacted.
        n_unique_dst_ports: distinct destination ports contacted.
        mean_duration: mean flow duration in seconds.
        src_bytes: bytes sent by the host.
        total_bytes: bytes in both directions.
        frac_internal_dst: share of flows aimed inside the enterprise range.
        frac_lateral_ports: share of flows on admin/remote-access ports.
        frac_c2_ports: share of flows on ports commonly used for C2.
        frac_syn_only: share of flows that never completed a handshake.
        beacon_regularity: 0..1, how evenly spaced the flows are in time.

    Returns:
        One of the stage constants defined in this module.
    """
    fan_out = max(n_unique_dst_ips, n_unique_dst_ports)
    egress_ratio = src_bytes / total_bytes if total_bytes > 0 else 0.0

    # --- Reconnaissance -------------------------------------------------
    # Wide fan-out of short, mostly unanswered connections. This is the
    # signature the PS calls out explicitly (sequential/randomised port access).
    if fan_out >= 15 and mean_duration < 2.0 and (frac_syn_only > 0.5 or n_flows >= 25):
        return RECONNAISSANCE

    # --- Exfiltration ---------------------------------------------------
    # Heavily outbound transfer leaving the enterprise range. Checked before C2
    # because exfil frequently rides the established C2 channel.
    if (
        egress_ratio > 0.75
        and src_bytes > 50_000
        and frac_internal_dst < 0.5
        and n_unique_dst_ips <= 5
    ):
        return EXFILTRATION

    # --- Lateral movement -----------------------------------------------
    # Internal-to-internal traffic on remote administration ports.
    if frac_internal_dst > 0.6 and frac_lateral_ports > 0.3:
        return LATERAL_MOVEMENT

    # --- Command and control --------------------------------------------
    # Repeated, regularly spaced, low-volume contact with a small set of peers.
    if (
        beacon_regularity > 0.6
        and n_unique_dst_ips <= 3
        and n_flows >= 4
        and total_bytes < 200_000
    ) or (frac_c2_ports > 0.5 and n_unique_dst_ips <= 3 and beacon_regularity > 0.4):
        return COMMAND_AND_CONTROL

    # --- Initial access -------------------------------------------------
    # Malicious but none of the above: a small number of substantive
    # connections, which is what exploitation of a specific target looks like.
    return INITIAL_ACCESS


def stage_name(stage: int) -> str:
    return STAGE_NAMES[stage]


def is_progression(from_stage: int, to_stage: int) -> bool:
    """True when `to_stage` sits later in the kill chain than `from_stage`."""
    return STAGE_ORDER.get(to_stage, -1) > STAGE_ORDER.get(from_stage, -1)


def describe(stage: int) -> dict:
    """Serialisable stage description for the API layer."""
    ref = STAGE_TECHNIQUES[stage]
    return {
        "id": stage,
        "name": STAGE_NAMES[stage],
        "tactic_id": ref.tactic_id,
        "tactic": ref.tactic,
        "technique_id": ref.technique_id,
        "technique": ref.technique,
        "order": STAGE_ORDER[stage],
    }


def all_stages() -> Sequence[dict]:
    return [describe(s) for s in range(N_STAGES)]
