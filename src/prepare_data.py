"""Turn raw CTU-13 captures into model-ready state cells.

Run as:
    python -m src.prepare_data                 # all discovered scenarios
    python -m src.prepare_data --scenarios 1 4 # a subset
    python -m src.prepare_data --max-rows 5e5  # quick smoke run

Each scenario becomes one parquet of (host, window) state cells with flow-level
features, packet-level features where a matching PCAP is available, the
malicious label, the derived MITRE stage, and the forward-looking targets.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from pathlib import Path

import pandas as pd

from .config import LOOKAHEAD_WINDOWS, MIN_FLOWS_PER_CELL, PROCESSED_DIR, RAW_DIR, WINDOW_SECONDS
from .features.flow import load_binetflow, summarise
from .features.packet import extract_packet_features
from .features.windows import (
    add_forecast_targets,
    attach_packet_features,
    build_edges,
    build_state_cells,
)

log = logging.getLogger(__name__)

# PCAPs that line up with a scenario, keyed by scenario number. CTU-13 ships
# per-scenario captures; we only fetch the ones small enough to be practical.
SCENARIO_PCAPS = {
    1: "neris-botnet.pcap",
}


def discover_scenarios(raw_dir: Path = RAW_DIR) -> dict[int, Path]:
    """Locate every extracted `.binetflow`, keyed by CTU-13 scenario number.

    The archive lays out as CTU-13-Dataset/<n>/<capture>.binetflow, so the
    scenario number is the parent directory name.
    """
    found: dict[int, Path] = {}
    for path in sorted(raw_dir.rglob("*.binetflow")):
        parent = path.parent.name
        if re.fullmatch(r"\d+", parent):
            found[int(parent)] = path
        else:
            log.warning("skipping %s: parent %r is not a scenario number", path, parent)
    return dict(sorted(found.items()))


def process_scenario(
    scenario: int,
    flow_path: Path,
    pcap_path: Path | None = None,
    max_rows: int | None = None,
    window_seconds: float = WINDOW_SECONDS,
    min_flows: int = MIN_FLOWS_PER_CELL,
    lookahead: int = LOOKAHEAD_WINDOWS,
) -> tuple[pd.DataFrame, dict]:
    """Full pipeline for one scenario: flows -> cells -> targets."""
    t0 = time.time()
    flows = load_binetflow(flow_path, max_rows=max_rows)
    flow_summary = summarise(flows)

    cells = build_state_cells(
        flows, window_seconds=window_seconds, min_flows=min_flows
    )

    packet_cells = None
    if pcap_path is not None and pcap_path.exists():
        log.info("extracting packet features from %s", pcap_path.name)
        packet_cells = extract_packet_features(pcap_path, window_seconds=window_seconds)
    cells = attach_packet_features(cells, packet_cells)

    cells = add_forecast_targets(cells, lookahead=lookahead)
    cells["scenario"] = scenario

    # Topology for the dashboard's graph view. Saved alongside rather than
    # merged in: it is keyed on (src, dst) pairs, not (host, window) cells.
    edges = build_edges(flows, window_seconds=window_seconds)
    edges["scenario"] = scenario

    stats = {
        "scenario": scenario,
        "flow_file": flow_path.name,
        "pcap_file": pcap_path.name if pcap_path and pcap_path.exists() else None,
        "elapsed_seconds": round(time.time() - t0, 1),
        "n_cells": int(len(cells)),
        "n_hosts": int(cells["src"].nunique()),
        "malicious_cell_rate": float(cells["is_malicious"].mean()),
        "infiltration_next_rate": float(cells["infiltration_next"].mean()),
        "packet_coverage": float(cells["has_packet_features"].mean()),
        "n_edges": int(len(edges)),
        "stage_counts": {
            int(k): int(v) for k, v in cells["stage"].value_counts().items()
        },
        **{f"flow_{k}": v for k, v in flow_summary.items()},
    }
    log.info("scenario %d done in %.1fs: %s", scenario, stats["elapsed_seconds"],
             {k: stats[k] for k in ("n_cells", "n_hosts", "malicious_cell_rate")})
    return cells, edges, stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=int, nargs="*", default=None,
                        help="scenario numbers to process (default: all found)")
    parser.add_argument("--max-rows", type=float, default=None,
                        help="cap flows read per scenario, for smoke tests")
    parser.add_argument("--window-seconds", type=float, default=WINDOW_SECONDS)
    parser.add_argument("--min-flows", type=int, default=MIN_FLOWS_PER_CELL)
    parser.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    parser.add_argument("--out-dir", type=Path, default=PROCESSED_DIR)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    available = discover_scenarios(args.raw_dir)
    if not available:
        raise SystemExit(
            f"No .binetflow files under {args.raw_dir}. "
            "Extract CTU-13-Dataset.tar.bz2 first."
        )

    wanted = args.scenarios or sorted(available)
    missing = [s for s in wanted if s not in available]
    if missing:
        log.warning("requested but not found: %s", missing)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    max_rows = int(args.max_rows) if args.max_rows else None
    all_stats = []

    for scenario in wanted:
        if scenario not in available:
            continue
        pcap_name = SCENARIO_PCAPS.get(scenario)
        pcap_path = args.raw_dir / pcap_name if pcap_name else None

        cells, edges, stats = process_scenario(
            scenario, available[scenario], pcap_path,
            max_rows=max_rows,
            window_seconds=args.window_seconds,
            min_flows=args.min_flows,
        )
        out = args.out_dir / f"scenario_{scenario:02d}.parquet"
        cells.to_parquet(out, index=False)
        edges.to_parquet(args.out_dir / f"scenario_{scenario:02d}_edges.parquet",
                         index=False)
        stats["output"] = str(out)
        all_stats.append(stats)
        log.info("wrote %s (%d cells)", out.name, len(cells))

    report = args.out_dir / "ingest_report.json"
    report.write_text(json.dumps(all_stats, indent=2), encoding="utf-8")
    log.info("ingest report -> %s", report)


if __name__ == "__main__":
    main()
