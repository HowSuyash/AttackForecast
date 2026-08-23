"""FastAPI backend for the attack forecasting dashboard.

Runs fully offline. No CDN, no external API, no telemetry - the PS requires it
and a defensive tool that phones home would be a poor demonstration anyway.

    python -m uvicorn server.app:app --reload --port 8000

The upload endpoint accepts either input the PS names:
  - a PCAP/PCAPNG, from which flows are reconstructed and both feature levels
    are computed;
  - a CTU-13 .binetflow / CSV of flow records, which gives the flow level and
    leaves the packet level zeroed with an explicit availability flag.
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
from functools import lru_cache
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.config import CHECKPOINT_DIR, INTERNAL_PREFIXES, PROCESSED_DIR, REPORT_DIR
from src.features.flow import load_binetflow, summarise
from src.features.packet import extract_packet_features, flows_from_pcap
from src.features.windows import (
    add_forecast_targets,
    attach_packet_features,
    build_state_cells,
)
from src.inference import ForecastEngine, rank_hosts
from src.mitre import all_stages, label_stage_patterns

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

# Guard rails on upload size. A 50 MB capture is already a couple of hundred
# thousand packets, which is more than enough for a demonstration and keeps the
# request inside a few seconds.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_PACKETS = 400_000
MAX_FLOW_ROWS = 2_000_000

app = FastAPI(title="Network Attack Forecasting", version="1.0")

_engine: ForecastEngine | None = None


def get_engine() -> ForecastEngine:
    """Load the checkpoint on first use so the server starts without one."""
    global _engine
    if _engine is None:
        try:
            _engine = ForecastEngine(CHECKPOINT_DIR / "world_model.pt")
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"{exc} Train the model, then reload this page.",
            ) from exc
    return _engine


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------


@app.get("/api/meta")
def meta() -> dict:
    """Everything the dashboard needs to render before any analysis runs."""
    try:
        engine = get_engine()
        model_info = engine.metadata
        ready = True
    except HTTPException:
        model_info, ready = {}, False

    return {
        "model_ready": ready,
        "model": model_info,
        "stages": all_stages(),
        "label_stage_patterns": label_stage_patterns(),
        "scenarios": available_scenarios(),
        "benchmark_available": (REPORT_DIR / "benchmark.json").exists(),
    }


# Anchored so it matches scenario_07.parquet but not scenario_07_edges.parquet.
# A plain `scenario_*.parquet` glob matches both, and since both stems split to
# the same number every capture appeared twice in the dropdown.
_SCENARIO_FILE = re.compile(r"^scenario_(\d+)$")


def available_scenarios() -> list[dict]:
    from src.config import CTU13_FAMILIES

    out = []
    for path in sorted(PROCESSED_DIR.glob("scenario_*.parquet")):
        m = _SCENARIO_FILE.match(path.stem)
        if not m:
            continue
        n = int(m.group(1))
        out.append({
            "id": n,
            "family": CTU13_FAMILIES.get(n, "unknown"),
            "file": path.name,
        })
    return out


@app.get("/api/benchmark")
def benchmark() -> JSONResponse:
    path = REPORT_DIR / "benchmark.json"
    if not path.exists():
        raise HTTPException(404, "No benchmark yet. Run `python -m src.evaluate`.")
    return JSONResponse(content=__import__("json").loads(path.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------
# Prepared scenarios
# --------------------------------------------------------------------------


@lru_cache(maxsize=4)
def _load_scenario_cached(scenario: int) -> pd.DataFrame:
    """Parquet read, memoised.

    A scenario is tens of thousands of rows and every dashboard interaction
    touches one, so re-reading per request dominated the response time.
    Prepared data is immutable once written, which makes caching safe; restart
    the server after re-running `prepare_data`.
    """
    path = PROCESSED_DIR / f"scenario_{scenario:02d}.parquet"
    if not path.exists():
        raise FileNotFoundError(scenario)
    return pd.read_parquet(path)


# Ranked host lists are pure functions of (scenario, checkpoint) and cost a
# full sweep to compute, so they are memoised too.
@lru_cache(maxsize=4)
def _rank_scenario_cached(scenario: int) -> tuple:
    return tuple(rank_hosts(_load_scenario_cached(scenario), get_engine()))


def _load_scenario(scenario: int) -> pd.DataFrame:
    try:
        return _load_scenario_cached(scenario)
    except FileNotFoundError:
        raise HTTPException(404, f"Scenario {scenario} has not been prepared.")


@app.get("/api/hosts")
def hosts(scenario: int = Query(...), limit: int = Query(40)) -> dict:
    """Triage view: every host in a scenario ranked by forecast risk."""
    get_engine()  # surfaces a clear 503 before the expensive sweep
    _load_scenario(scenario)  # and a clear 404
    ranked = list(_rank_scenario_cached(scenario))
    return {
        "scenario": scenario,
        "n_hosts": len(ranked),
        "hosts": ranked[:limit],
    }


@app.get("/api/replay")
def replay(
    scenario: int = Query(...),
    host: str = Query(...),
    horizon: int = Query(10, ge=1, le=20),
    window_limit: int = Query(160, ge=32, le=600),
) -> dict:
    """Frame-by-frame forecasts so the dashboard can play a capture back."""
    engine = get_engine()
    cells = _load_scenario(scenario)
    sub = cells[cells["src"] == host].sort_values("window")
    if sub.empty:
        raise HTTPException(404, f"Host {host} not found in scenario {scenario}.")
    try:
        return engine.replay(sub.tail(window_limit), horizon=horizon)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@lru_cache(maxsize=4)
def _load_edges_cached(scenario: int) -> pd.DataFrame:
    path = PROCESSED_DIR / f"scenario_{scenario:02d}_edges.parquet"
    if not path.exists():
        raise FileNotFoundError(scenario)
    return pd.read_parquet(path)


@app.get("/api/graph")
def graph(scenario: int = Query(...), max_nodes: int = Query(90, ge=10, le=400)) -> dict:
    """Host-to-host topology, with each internal node carrying its risk score.

    Trimmed to the busiest `max_nodes` hosts. A full capture has hundreds of
    peers and a force-directed layout of all of them is unreadable; the point of
    this view is to show the compromised host sitting inside its neighbourhood,
    which needs the neighbourhood to be legible.
    """
    get_engine()
    try:
        edges = _load_edges_cached(scenario)
    except FileNotFoundError:
        raise HTTPException(
            404,
            f"No topology for scenario {scenario}. Re-run `python -m src.prepare_data`.",
        )

    ranked = {r["host"]: r for r in _rank_scenario_cached(scenario)}

    volume: dict[str, float] = {}
    for row in edges.itertuples():
        volume[row.src] = volume.get(row.src, 0.0) + float(row.n_flows)
        volume[row.dst] = volume.get(row.dst, 0.0) + float(row.n_flows)

    # Selection order matters, and an earlier version got it backwards: it
    # admitted every monitored host first, which on a 147-host capture used the
    # whole budget before a single external peer was considered. Since a
    # botnet's malicious traffic goes *outward* - to spam relays and C2 - every
    # malicious edge was then dropped for having an endpoint outside the set,
    # and the graph rendered with nothing to see.
    #
    # So: the endpoints that carry the story come first, and volume only fills
    # whatever budget is left.
    malicious_edges = edges[edges["is_malicious"] == 1]
    malicious_peers = sorted(
        set(malicious_edges["dst"]) | set(malicious_edges["src"]),
        key=lambda h: -volume.get(h, 0.0),
    )

    keep: set[str] = set()

    # Budgeted, in priority order, and the budget is enforced at every stage.
    # Taking *all* malicious endpoints looked right until a spam bot turned out
    # to have contacted 1,849 external relays, which produced a 1,874-node
    # hairball that the O(n^2) layout could not render.
    at_risk = sorted(
        (h for h in ranked if h in volume),
        key=lambda h: -ranked[h]["observed_peak_risk"],
    )
    keep.update(at_risk[:25])
    keep.update(malicious_peers[: max(0, max_nodes - len(keep) - 15)])
    for host in sorted(volume, key=lambda h: -volume[h]):
        if len(keep) >= max_nodes:
            break
        keep.add(host)

    sub = edges[edges["src"].isin(keep) & edges["dst"].isin(keep)]

    nodes = []
    for host in sorted(keep):
        info = ranked.get(host)
        nodes.append({
            "id": host,
            "internal": any(host.startswith(p) for p in INTERNAL_PREFIXES),
            "flows": float(volume.get(host, 0.0)),
            "risk": float(info["observed_peak_risk"]) if info else None,
            "stage": info["current_stage"] if info else None,
            "monitored": info is not None,
        })

    return {
        "scenario": scenario,
        # Totals before trimming. "Contacted 1,849 external hosts" is a stronger
        # statement than anything the drawn subgraph can show, so it is reported
        # rather than silently discarded with the nodes.
        "totals": {
            "hosts": int(len(volume)),
            "pairs": int(len(edges)),
            "malicious_pairs": int(len(malicious_edges)),
            "malicious_peers": int(len(malicious_peers)),
            "drawn": len(nodes),
        },
        "nodes": nodes,
        "edges": [
            {
                "source": r.src,
                "target": r.dst,
                "flows": int(r.n_flows),
                "malicious": int(r.is_malicious),
            }
            for r in sub.itertuples()
        ],
    }


@app.get("/api/analyse")
def analyse(
    scenario: int = Query(...),
    host: str = Query(...),
    horizon: int = Query(10, ge=1, le=30),
    window_limit: int = Query(120, ge=8, le=1000),
) -> dict:
    """Full forecast plus explanations for one host."""
    engine = get_engine()
    cells = _load_scenario(scenario)
    sub = cells[cells["src"] == host].sort_values("window")
    if sub.empty:
        raise HTTPException(404, f"Host {host} not found in scenario {scenario}.")

    # Analyse the most recent slice; the whole capture would make the timeline
    # unreadable and adds nothing to the forecast.
    sub = sub.tail(window_limit)
    result = engine.analyse(sub, horizon=horizon)
    result["scenario"] = scenario
    return result


# --------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------


def _cells_from_upload(path: Path, suffix: str) -> tuple[pd.DataFrame, dict]:
    """Run the ingest pipeline appropriate to the uploaded file type."""
    if suffix in (".pcap", ".pcapng", ".cap"):
        flows = flows_from_pcap(path, max_packets=MAX_PACKETS)
        packet_cells = extract_packet_features(path, max_packets=MAX_PACKETS)
        source = "pcap"
    elif suffix in (".binetflow", ".csv", ".txt"):
        flows = load_binetflow(path, max_rows=MAX_FLOW_ROWS)
        packet_cells = None
        source = "flow-csv"
    else:
        raise HTTPException(
            400,
            f"Unsupported file type {suffix!r}. "
            "Upload a .pcap/.pcapng capture or a .binetflow/.csv flow export.",
        )

    # Uploaded captures come from arbitrary networks, so the internal-range
    # filter that makes sense for CTU-13 would silently drop everything.
    cells = build_state_cells(flows, internal_only=False)
    cells = attach_packet_features(cells, packet_cells)
    cells = add_forecast_targets(cells)

    info = {
        "source": source,
        "n_flows": int(len(flows)),
        "n_cells": int(len(cells)),
        "n_hosts": int(cells["src"].nunique()),
        "packet_features": bool(packet_cells is not None and not packet_cells.empty),
    }
    if source == "flow-csv":
        info.update(summarise(flows))
    return cells, info


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), horizon: int = Query(10)) -> dict:
    """Ingest a capture or flow export and forecast its highest-risk hosts."""
    engine = get_engine()
    suffix = Path(file.filename or "").suffix.lower()

    tmp_dir = Path(tempfile.mkdtemp(prefix="netforecast_"))
    tmp_path = tmp_dir / (file.filename or "upload.bin")
    try:
        size = 0
        with tmp_path.open("wb") as fh:
            # Stream in chunks so a large upload never sits in memory whole.
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        413, f"File exceeds the {MAX_UPLOAD_BYTES // 1024 // 1024} MB limit."
                    )
                fh.write(chunk)

        try:
            cells, info = _cells_from_upload(tmp_path, suffix)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

        # Validate against the columns *this checkpoint* was trained on, not the
        # current global default. The two diverge whenever the packet-feature
        # flag is toggled, and an older checkpoint must keep working.
        missing = [c for c in engine.feature_columns if c not in cells.columns]
        if missing:
            raise HTTPException(500, f"Feature extraction incomplete: {missing[:5]}")

        ranked = rank_hosts(cells, engine, min_windows=8)
        if not ranked:
            raise HTTPException(
                422,
                "No host produced at least 8 consecutive one-minute windows. "
                "The capture is likely too short to forecast from.",
            )

        top = ranked[0]["host"]
        focus_cells = cells[cells["src"] == top].sort_values("window").tail(120)
        detail = engine.analyse(focus_cells, horizon=horizon)

        # Replay frames travel with the response rather than behind a second
        # endpoint. /api/replay is addressed by (scenario, host) and reads from
        # disk; an upload has neither, so without this the Play button stays
        # dead on exactly the capture a visitor brought themselves. The frames
        # are one batched pass, so this costs about two seconds.
        replay_frames = None
        try:
            replay_frames = engine.replay(focus_cells, horizon=horizon)
        except ValueError as exc:
            # Too few consecutive windows to roll forward from - the analysis
            # above is still valid, so report it rather than failing the upload.
            log.info("replay unavailable for %s: %s", top, exc)

        return {
            "filename": file.filename,
            "ingest": info,
            "hosts": ranked[:20],
            "focus": detail,
            "replay": replay_frames,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# Static dashboard
# --------------------------------------------------------------------------


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
