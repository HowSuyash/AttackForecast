"""Packet-level feature extraction from PCAP files.

The PS is explicit that flow-level features alone are not enough: aggregate
counters show you a SYN flood, but only per-packet timing and header state
expose a slow reconnaissance scan built to stay under flow thresholds. This
module supplies the second level - TTL dispersion, TCP window behaviour, IP
fragmentation, payload size distribution, retransmissions and port-access
ordering - aggregated onto the same (host, window) grid the flow features use,
so the two levels concatenate cleanly.

Implementation note: we read the capture with Scapy's RawPcapReader and unpack
the Ethernet/IP/TCP headers with struct rather than letting Scapy build a full
object graph per packet. Scapy's high-level parser costs roughly 40x more per
packet, which is the difference between a dashboard upload returning in a few
seconds and timing out. The header offsets are standard and the parsing is
exercised by tests/test_packet.py.
"""

from __future__ import annotations

import logging
import math
import struct
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from ..config import WINDOW_SECONDS

log = logging.getLogger(__name__)

ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
PROTO_TCP = 6
PROTO_UDP = 17

# Datalink types we know how to strip a header from.
DLT_EN10MB = 1       # Ethernet
DLT_RAW = 101        # raw IP
DLT_LINUX_SLL = 113  # Linux cooked capture


def _l2_offset(linktype: int, buf: bytes) -> int | None:
    """Return the byte offset of the IPv4 header, or None if not IPv4."""
    if linktype == DLT_EN10MB:
        if len(buf) < 14:
            return None
        etype = struct.unpack("!H", buf[12:14])[0]
        off = 14
        # Hop over a single VLAN tag if present.
        if etype == ETH_P_8021Q:
            if len(buf) < 18:
                return None
            etype = struct.unpack("!H", buf[16:18])[0]
            off = 18
        return off if etype == ETH_P_IP else None
    if linktype == DLT_LINUX_SLL:
        if len(buf) < 16:
            return None
        etype = struct.unpack("!H", buf[14:16])[0]
        return 16 if etype == ETH_P_IP else None
    if linktype == DLT_RAW:
        return 0
    return None


def _ip_str(raw: bytes) -> str:
    return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"


def iter_packets(path: str | Path, max_packets: int | None = None):
    """Stream decoded packet records from a PCAP/PCAPNG file.

    Yields dicts with the header fields the feature aggregator needs. Packets
    that are not IPv4, or are truncated, are skipped silently - real captures
    always contain some.
    """
    from scapy.utils import RawPcapReader  # lazy import keeps CLI startup fast

    n = 0
    with RawPcapReader(str(path)) as reader:
        linktype = getattr(reader, "linktype", DLT_EN10MB)
        for buf, meta in reader:
            if max_packets is not None and n >= max_packets:
                break
            off = _l2_offset(linktype, buf)
            if off is None or len(buf) < off + 20:
                continue

            ip = buf[off:]
            ver_ihl = ip[0]
            if (ver_ihl >> 4) != 4:
                continue
            ihl = (ver_ihl & 0x0F) * 4
            if ihl < 20 or len(ip) < ihl:
                continue

            total_len = struct.unpack("!H", ip[2:4])[0]
            flags_frag = struct.unpack("!H", ip[6:8])[0]
            ttl = ip[8]
            proto = ip[9]
            src = _ip_str(ip[12:16])
            dst = _ip_str(ip[16:20])

            more_fragments = (flags_frag >> 13) & 0x1
            dont_fragment = (flags_frag >> 14) & 0x1
            frag_offset = flags_frag & 0x1FFF

            ts = float(meta.sec) + float(meta.usec) / 1e6

            rec = {
                "ts": ts, "src": src, "dst": dst, "proto": proto, "ttl": ttl,
                "ip_len": total_len,
                "frag": int(more_fragments or frag_offset > 0),
                "dont_frag": int(dont_fragment),
                "sport": -1, "dport": -1, "tcp_window": -1, "seq": -1,
                "flags": 0, "payload_len": max(0, total_len - ihl),
            }

            l4 = ip[ihl:]
            if proto == PROTO_TCP and len(l4) >= 20:
                sport, dport, seq = struct.unpack("!HHI", l4[0:8])
                data_off = (l4[12] >> 4) * 4
                rec["sport"] = sport
                rec["dport"] = dport
                rec["seq"] = seq
                rec["flags"] = l4[13]
                rec["tcp_window"] = struct.unpack("!H", l4[14:16])[0]
                rec["payload_len"] = max(0, total_len - ihl - data_off)
            elif proto == PROTO_UDP and len(l4) >= 8:
                sport, dport = struct.unpack("!HH", l4[0:4])
                rec["sport"] = sport
                rec["dport"] = dport
                rec["payload_len"] = max(0, total_len - ihl - 8)

            n += 1
            yield rec


def _entropy(counts) -> float:
    """Shannon entropy in bits of a collection of counts."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def _sequential_scan_score(ports: list[int]) -> float:
    """Fraction of consecutive port accesses that step by a small increment.

    A sequential scanner walks 1024, 1025, 1026...; a randomised scanner does
    not. Both differ from normal traffic, which revisits a handful of ports.
    Returns a value in 0..1.
    """
    if len(ports) < 4:
        return 0.0
    steps = np.diff(np.asarray(ports, dtype=np.int64))
    small_forward = np.sum((steps > 0) & (steps <= 3))
    return float(small_forward) / float(len(steps))


def extract_packet_features(
    path: str | Path,
    window_seconds: float = WINDOW_SECONDS,
    max_packets: int | None = None,
) -> pd.DataFrame:
    """Aggregate a PCAP into per-(host, window) packet-level features.

    The returned frame is keyed by `src` and `window` so it can be joined onto
    the flow-level cells produced by features.windows.
    """
    ttl: dict = defaultdict(list)
    win: dict = defaultdict(list)
    payload: dict = defaultdict(list)
    times: dict = defaultdict(list)
    ports: dict = defaultdict(list)
    dst_counts: dict = defaultdict(lambda: defaultdict(int))
    port_counts: dict = defaultdict(lambda: defaultdict(int))
    n_pkts: dict = defaultdict(int)
    n_frag: dict = defaultdict(int)
    n_retrans: dict = defaultdict(int)
    n_syn: dict = defaultdict(int)
    n_rst: dict = defaultdict(int)
    seen_seq: dict = defaultdict(set)

    for rec in iter_packets(path, max_packets=max_packets):
        # Window indices are absolute (epoch // width), not relative to the
        # first packet. A PCAP and a flow file covering the same capture start
        # at different timestamps, so only an absolute grid lets the two
        # feature levels be joined on (host, window).
        w = int(rec["ts"] // window_seconds)
        key = (rec["src"], w)

        n_pkts[key] += 1
        ttl[key].append(rec["ttl"])
        payload[key].append(rec["payload_len"])
        times[key].append(rec["ts"])
        n_frag[key] += rec["frag"]
        dst_counts[key][rec["dst"]] += 1

        if rec["dport"] >= 0:
            ports[key].append(rec["dport"])
            port_counts[key][rec["dport"]] += 1

        if rec["proto"] == PROTO_TCP:
            if rec["tcp_window"] >= 0:
                win[key].append(rec["tcp_window"])
            flags = rec["flags"]
            if flags & 0x02:
                n_syn[key] += 1
            if flags & 0x04:
                n_rst[key] += 1
            # A repeated sequence number on the same conversation is a
            # retransmission - a strong congestion / scan-timeout signal.
            if rec["payload_len"] > 0:
                sig = (rec["dst"], rec["sport"], rec["dport"], rec["seq"])
                if sig in seen_seq[key]:
                    n_retrans[key] += 1
                else:
                    seen_seq[key].add(sig)

    if not n_pkts:
        return pd.DataFrame(columns=["src", "window"] + PACKET_FEATURE_COLUMNS)

    rows = []
    for key, count in n_pkts.items():
        host, w = key
        t = np.asarray(sorted(times[key]))
        iat = np.diff(t) if len(t) > 1 else np.zeros(1)
        ttl_arr = np.asarray(ttl[key], dtype=np.float64)
        win_arr = np.asarray(win[key], dtype=np.float64) if win[key] else np.zeros(1)
        pay_arr = np.asarray(payload[key], dtype=np.float64)

        rows.append({
            "src": host,
            "window": w,
            "pkt_count": float(count),
            # TTL dispersion: a host talking to one destination has a stable
            # TTL; spoofed or multi-path traffic does not.
            "pkt_ttl_mean": float(ttl_arr.mean()),
            "pkt_ttl_std": float(ttl_arr.std()),
            "pkt_ttl_nunique": float(len(np.unique(ttl_arr))),
            "pkt_win_mean": float(win_arr.mean()),
            "pkt_win_std": float(win_arr.std()),
            "pkt_win_zero_frac": float(np.mean(win_arr == 0)),
            "pkt_frag_frac": float(n_frag[key] / count),
            "pkt_payload_mean": float(pay_arr.mean()),
            "pkt_payload_std": float(pay_arr.std()),
            "pkt_payload_p90": float(np.percentile(pay_arr, 90)),
            "pkt_payload_zero_frac": float(np.mean(pay_arr == 0)),
            "pkt_retrans_frac": float(n_retrans[key] / count),
            "pkt_syn_frac": float(n_syn[key] / count),
            "pkt_rst_frac": float(n_rst[key] / count),
            "pkt_iat_mean": float(iat.mean()),
            "pkt_iat_std": float(iat.std()),
            # Coefficient of variation of inter-arrival time. Near zero means
            # metronomic traffic, the classic beaconing signature.
            "pkt_iat_cv": float(iat.std() / iat.mean()) if iat.mean() > 1e-9 else 0.0,
            "pkt_port_entropy": _entropy(port_counts[key].values()),
            "pkt_dst_entropy": _entropy(dst_counts[key].values()),
            "pkt_seq_scan_score": _sequential_scan_score(ports[key]),
            "pkt_nunique_dport": float(len(port_counts[key])),
            "pkt_nunique_dst": float(len(dst_counts[key])),
        })

    out = pd.DataFrame(rows).sort_values(["src", "window"]).reset_index(drop=True)
    log.info("packet features: %d cells from %s", len(out), Path(path).name)
    return out


def flows_from_pcap(
    path: str | Path,
    idle_timeout: float = 120.0,
    max_packets: int | None = None,
) -> pd.DataFrame:
    """Reconstruct bidirectional flow records from raw packets.

    This is what makes the dashboard's PCAP upload path work end to end. The
    model needs both feature levels, but a capture file on its own only yields
    packet-level features - so we rebuild the NetFlow layer here, which is
    exactly the job Argus or nfdump does before CTU-13's .binetflow files exist.

    Flows are keyed on the canonical (address, port) pair so both directions of
    a conversation land in one record, and split when the conversation goes
    quiet for `idle_timeout` seconds.

    Args:
        path: PCAP or PCAPNG file.
        idle_timeout: gap after which a new flow record starts.
        max_packets: cap for very large captures.

    Returns:
        A frame with the same schema `load_binetflow` produces, so every
        downstream stage is shared between the two input paths. `label_class`
        is 0 and `stage_hint` is -1 throughout: an uploaded capture has no
        ground truth, which is the point - the model supplies the verdict.
    """
    from .flow import LABEL_BACKGROUND

    active: dict = {}
    completed: list[dict] = []

    def close(key, rec):
        src, dst, sport, dport = rec["a_addr"], rec["b_addr"], rec["a_port"], rec["b_port"]
        completed.append({
            "ts": rec["start"],
            "duration": max(0.0, rec["last"] - rec["start"]),
            "proto": rec["proto"],
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "tot_pkts": rec["pkts"],
            "tot_bytes": rec["bytes"],
            "src_bytes": rec["a_bytes"],
            "dst_bytes": rec["bytes"] - rec["a_bytes"],
            "bidirectional": 1 if rec["b_pkts"] > 0 else 0,
            "label_class": LABEL_BACKGROUND,
            "stage_hint": np.int8(-1),
            "src_syn": rec["a_flags"]["syn"], "src_ack": rec["a_flags"]["ack"],
            "src_fin": rec["a_flags"]["fin"], "src_rst": rec["a_flags"]["rst"],
            "src_psh": rec["a_flags"]["psh"], "src_urg": rec["a_flags"]["urg"],
            "src_cwr": 0, "src_ece": 0,
            "dst_syn": rec["b_flags"]["syn"], "dst_ack": rec["b_flags"]["ack"],
            "dst_fin": rec["b_flags"]["fin"], "dst_rst": rec["b_flags"]["rst"],
            "dst_psh": rec["b_flags"]["psh"], "dst_urg": rec["b_flags"]["urg"],
            "dst_cwr": 0, "dst_ece": 0,
            "handshake_complete": int(
                rec["a_flags"]["syn"] and rec["b_flags"]["syn"] and rec["b_flags"]["ack"]
            ),
            "syn_only": int(rec["a_flags"]["syn"] and rec["b_pkts"] == 0),
            "reset": int(rec["a_flags"]["rst"] or rec["b_flags"]["rst"]),
        })

    proto_names = {PROTO_TCP: "tcp", PROTO_UDP: "udp", 1: "icmp"}

    for rec in iter_packets(path, max_packets=max_packets):
        a, b = rec["src"], rec["dst"]
        ap, bp = rec["sport"], rec["dport"]
        # Canonical ordering so both directions share one key.
        forward = (a, ap) <= (b, bp)
        key = ((a, ap), (b, bp), rec["proto"]) if forward else ((b, bp), (a, ap), rec["proto"])

        cur = active.get(key)
        if cur is not None and rec["ts"] - cur["last"] > idle_timeout:
            close(key, cur)
            cur = None

        if cur is None:
            # The side that sent the first packet is the flow's source, which
            # is what makes src_bytes mean "bytes the initiator sent".
            cur = {
                "start": rec["ts"], "last": rec["ts"],
                "a_addr": a, "b_addr": b, "a_port": ap, "b_port": bp,
                "proto": proto_names.get(rec["proto"], str(rec["proto"])),
                "pkts": 0, "bytes": 0, "a_bytes": 0, "a_pkts": 0, "b_pkts": 0,
                "a_flags": {k: 0 for k in ("syn", "ack", "fin", "rst", "psh", "urg")},
                "b_flags": {k: 0 for k in ("syn", "ack", "fin", "rst", "psh", "urg")},
            }
            active[key] = cur

        is_a_side = (rec["src"] == cur["a_addr"] and rec["sport"] == cur["a_port"])
        cur["last"] = rec["ts"]
        cur["pkts"] += 1
        cur["bytes"] += rec["ip_len"]
        if is_a_side:
            cur["a_bytes"] += rec["ip_len"]
            cur["a_pkts"] += 1
            flags = cur["a_flags"]
        else:
            cur["b_pkts"] += 1
            flags = cur["b_flags"]

        f = rec["flags"]
        if f & 0x02: flags["syn"] = 1
        if f & 0x10: flags["ack"] = 1
        if f & 0x01: flags["fin"] = 1
        if f & 0x04: flags["rst"] = 1
        if f & 0x08: flags["psh"] = 1
        if f & 0x20: flags["urg"] = 1

    for key, rec in active.items():
        close(key, rec)

    if not completed:
        raise ValueError(f"No IPv4 flows reconstructed from {Path(path).name}")

    df = pd.DataFrame(completed).sort_values("ts", kind="stable").reset_index(drop=True)
    for col in ("src_syn", "src_ack", "src_fin", "src_rst", "src_psh", "src_urg",
                "dst_syn", "dst_ack", "dst_fin", "dst_rst", "dst_psh", "dst_urg",
                "handshake_complete", "syn_only", "reset", "bidirectional",
                "label_class", "stage_hint"):
        df[col] = df[col].astype(np.int8)

    log.info("reconstructed %d flows from %s", len(df), Path(path).name)
    return df


# Columns contributed by this module, in the fixed order the model relies on.
PACKET_FEATURE_COLUMNS = [
    "pkt_count", "pkt_ttl_mean", "pkt_ttl_std", "pkt_ttl_nunique",
    "pkt_win_mean", "pkt_win_std", "pkt_win_zero_frac", "pkt_frag_frac",
    "pkt_payload_mean", "pkt_payload_std", "pkt_payload_p90",
    "pkt_payload_zero_frac", "pkt_retrans_frac", "pkt_syn_frac",
    "pkt_rst_frac", "pkt_iat_mean", "pkt_iat_std", "pkt_iat_cv",
    "pkt_port_entropy", "pkt_dst_entropy", "pkt_seq_scan_score",
    "pkt_nunique_dport", "pkt_nunique_dst",
]
