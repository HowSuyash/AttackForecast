"""Flow-level feature extraction from CTU-13 `.binetflow` records.

The bidirectional NetFlow format shipped with CTU-13 carries everything the PS
asks for at flow level: address/port pairs, protocol, byte and packet counts,
duration, and - encoded in the `State` column - the TCP flag bitmask.

`State` is the field worth understanding. Argus writes it as `SRC_DST` where
each side is a string of flag letters seen on that direction of the
conversation, e.g. `S_` is a SYN that was never answered (a scan probe),
`SA_SA` is a completed handshake, `FSPA_FSPA` is a full conversation that
closed cleanly. Recovering per-direction flags from it is what lets us build
the SYN-before-ACK-flood style features the PS calls out.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# Column layout of a CTU-13 .binetflow file.
BINETFLOW_COLUMNS = [
    "StartTime", "Dur", "Proto", "SrcAddr", "Sport", "Dir", "DstAddr",
    "Dport", "State", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes", "Label",
]

# Argus flag letters -> the column we expose them as.
FLAG_LETTERS = {
    "S": "syn",
    "A": "ack",
    "F": "fin",
    "R": "rst",
    "P": "psh",
    "U": "urg",
    "C": "cwr",
    "E": "ece",
}

LABEL_BACKGROUND = 0
LABEL_NORMAL = 1
LABEL_BOTNET = 2


def _parse_port(value) -> int:
    """Ports appear as decimal, hex (`0x0303`), or blank for non-port protocols."""
    if value is None:
        return -1
    s = str(value).strip()
    if not s or s.lower() in ("nan", "none"):
        return -1
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except (ValueError, TypeError):
        return -1


def _classify_label(label: str) -> int:
    """CTU-13 labels are free text; only three classes actually matter."""
    l = label.lower()
    if "botnet" in l:
        return LABEL_BOTNET
    if "normal" in l:
        return LABEL_NORMAL
    return LABEL_BACKGROUND


def _stage_hints(labels: pd.Series) -> np.ndarray:
    """Per-flow ATT&CK stage read from the dataset's own annotation.

    A capture has millions of flows but only a couple of hundred distinct label
    strings, so the regex table runs over the unique values and the result is
    mapped back. That turns a multi-million-row regex sweep into a dictionary
    lookup.

    Returns:
        int8 array, -1 where the label carries no behavioural annotation.
    """
    from ..mitre import stage_from_label

    text = labels.fillna("")
    unique = text.unique()
    lookup = {u: (stage_from_label(u) if stage_from_label(u) is not None else -1)
              for u in unique}
    log.info("stage hints derived from %d distinct labels", len(unique))
    return text.map(lookup).to_numpy(dtype=np.int8)


def _expand_state_flags(state: pd.Series) -> pd.DataFrame:
    """Split the Argus `State` column into per-direction TCP flag indicators.

    Returns one column per (direction, flag) pair plus `handshake_complete`
    and `syn_only`, the two derived signals the stage rules depend on.
    """
    s = state.fillna("").astype(str).str.upper()
    # Everything before the first underscore is the source side.
    src_part = s.str.split("_").str[0].fillna("")
    dst_part = s.str.split("_").str[1].fillna("")

    out = {}
    for letter, name in FLAG_LETTERS.items():
        out[f"src_{name}"] = src_part.str.contains(letter, regex=False).astype(np.int8)
        out[f"dst_{name}"] = dst_part.str.contains(letter, regex=False).astype(np.int8)

    frame = pd.DataFrame(out, index=state.index)

    # A handshake is complete when we saw SYN out and SYN+ACK back.
    frame["handshake_complete"] = (
        (frame["src_syn"] == 1) & (frame["dst_syn"] == 1) & (frame["dst_ack"] == 1)
    ).astype(np.int8)

    # A probe that got nothing back - the core port-scan signal.
    frame["syn_only"] = (
        (frame["src_syn"] == 1) & (dst_part.str.len() == 0)
    ).astype(np.int8)

    # Connection refused / torn down by the peer.
    frame["reset"] = ((frame["src_rst"] == 1) | (frame["dst_rst"] == 1)).astype(np.int8)
    return frame


def load_binetflow(path: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load one CTU-13 scenario into a normalised flow table.

    Args:
        path: path to a `.binetflow` file.
        max_rows: optional cap, useful for smoke tests on the full 2.8M-flow
            scenarios.

    Returns:
        DataFrame sorted by timestamp with normalised dtypes and the expanded
        TCP flag columns.
    """
    path = Path(path)
    log.info("reading %s", path.name)

    df = pd.read_csv(
        path,
        nrows=max_rows,
        dtype={"Sport": "string", "Dport": "string", "State": "string",
               "Proto": "string", "Dir": "string", "Label": "string"},
        low_memory=False,
    )

    missing = set(BINETFLOW_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"{path.name}: unexpected layout, missing {sorted(missing)}")

    out = pd.DataFrame(index=df.index)

    # Two traps here, both silent if you get them wrong.
    #
    # 1. pandas >= 3.0 infers datetime64[us] for this format, not [ns]. Casting
    #    straight to int64 would yield microseconds, so dividing by 1e9 shrinks
    #    every timestamp 1000x - a 94-minute capture collapses into 6 seconds
    #    and every flow lands in one window. `as_unit("ns")` pins the resolution.
    # 2. NaT casts to int64 as -9223372036854775808 rather than NaN, so a single
    #    malformed row would survive dropna() and drag the window grid with it.
    #    Masking on notna() before the cast turns those into real NaNs.
    parsed = pd.to_datetime(
        df["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce"
    )
    n_bad = int(parsed.isna().sum())
    if n_bad:
        log.warning("%s: %d unparseable timestamps dropped", path.name, n_bad)
    out["ts"] = parsed.dt.as_unit("ns").astype("int64").where(parsed.notna()) / 1e9
    out["duration"] = pd.to_numeric(df["Dur"], errors="coerce").fillna(0.0)
    out["proto"] = df["Proto"].fillna("unknown").str.lower()
    out["src"] = df["SrcAddr"].astype(str)
    out["dst"] = df["DstAddr"].astype(str)
    out["sport"] = df["Sport"].map(_parse_port).astype(np.int32)
    out["dport"] = df["Dport"].map(_parse_port).astype(np.int32)
    out["tot_pkts"] = pd.to_numeric(df["TotPkts"], errors="coerce").fillna(0).astype(np.int64)
    out["tot_bytes"] = pd.to_numeric(df["TotBytes"], errors="coerce").fillna(0).astype(np.int64)
    out["src_bytes"] = pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0).astype(np.int64)
    out["bidirectional"] = df["Dir"].fillna("").str.contains("<").astype(np.int8)
    out["label_class"] = df["Label"].fillna("").map(_classify_label).astype(np.int8)
    out["stage_hint"] = _stage_hints(df["Label"])

    out = pd.concat([out, _expand_state_flags(df["State"])], axis=1)

    # Bytes returned to the source; needed for the egress ratio in stage rules.
    out["dst_bytes"] = (out["tot_bytes"] - out["src_bytes"]).clip(lower=0)

    out = out.dropna(subset=["ts"]).sort_values("ts", kind="stable").reset_index(drop=True)
    log.info(
        "%s: %d flows, %.1f%% botnet, span %.1f min",
        path.name,
        len(out),
        100.0 * (out["label_class"] == LABEL_BOTNET).mean(),
        (out["ts"].max() - out["ts"].min()) / 60.0,
    )
    return out


def summarise(df: pd.DataFrame) -> dict:
    """Small summary used by the ingest report and the dashboard upload path."""
    counts = df["label_class"].value_counts().to_dict()
    return {
        "n_flows": int(len(df)),
        "n_hosts": int(df["src"].nunique()),
        "duration_minutes": float((df["ts"].max() - df["ts"].min()) / 60.0),
        "background": int(counts.get(LABEL_BACKGROUND, 0)),
        "normal": int(counts.get(LABEL_NORMAL, 0)),
        "botnet": int(counts.get(LABEL_BOTNET, 0)),
    }
