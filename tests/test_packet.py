"""Tests for the PCAP parsing path.

The struct offsets in `features/packet.py` are the part of this project most
likely to be silently wrong: a bad offset does not raise, it just yields
plausible-looking garbage. These tests build packets byte by byte with known
field values and assert the parser recovers them.

Run: python -m tests.test_packet
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import numpy as np

from src.features.packet import (
    _entropy,
    _l2_offset,
    _sequential_scan_score,
    extract_packet_features,
    flows_from_pcap,
    iter_packets,
)

DLT_EN10MB = 1


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
          frag_flags: int = 0) -> bytes:
    """Minimal IPv4 header with a 20-byte (no options) length."""
    total = 20 + len(payload)
    return (
        struct.pack(
            "!BBHHHBBH",
            0x45,            # version 4, IHL 5 words
            0,               # DSCP/ECN
            total,
            0x1234,          # identification
            frag_flags,
            ttl,
            proto,
            0,               # checksum, not validated by the parser
        )
        + bytes(int(o) for o in src.split("."))
        + bytes(int(o) for o in dst.split("."))
        + payload
    )


def _tcp(sport: int, dport: int, seq: int, flags: int, window: int,
         payload: bytes = b"") -> bytes:
    return (
        struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, window, 0, 0)
        + payload
    )


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _eth(payload: bytes) -> bytes:
    return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0800) + payload


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    """Write a classic little-endian pcap so Scapy's RawPcapReader can read it."""
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_EN10MB))
        for ts, buf in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(buf), len(buf)))
            fh.write(buf)


def test_l2_offset() -> None:
    assert _l2_offset(DLT_EN10MB, _eth(b"\x45" + b"\x00" * 30)) == 14
    # A VLAN tag pushes the IPv4 header out by four bytes.
    vlan = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x8100) + b"\x00\x64" \
        + struct.pack("!H", 0x0800) + b"\x45" + b"\x00" * 30
    assert _l2_offset(DLT_EN10MB, vlan) == 18
    # ARP is not IPv4 and must be skipped, not misparsed.
    arp = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0806) + b"\x00" * 30
    assert _l2_offset(DLT_EN10MB, arp) is None
    print("l2 offset: OK")


def test_header_fields_round_trip(tmp: Path) -> None:
    """Every header field the model depends on must survive the parse."""
    syn, ack, psh = 0x02, 0x10, 0x08
    pkts = [
        (1000.0, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6,
                            _tcp(1234, 80, 555, syn, 8192), ttl=128))),
        (1000.5, _eth(_ipv4("10.0.0.2", "10.0.0.1", 6,
                            _tcp(80, 1234, 999, syn | ack, 64240), ttl=55))),
        (1001.0, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6,
                            _tcp(1234, 80, 556, psh | ack, 8192, b"x" * 40),
                            ttl=128))),
        (1001.5, _eth(_ipv4("10.0.0.1", "8.8.8.8", 17, _udp(5353, 53, b"q" * 20),
                            ttl=128))),
    ]
    path = tmp / "fields.pcap"
    _write_pcap(path, pkts)

    got = list(iter_packets(path))
    assert len(got) == 4, f"expected 4 packets, parsed {len(got)}"

    p0 = got[0]
    assert p0["src"] == "10.0.0.1" and p0["dst"] == "10.0.0.2"
    assert p0["sport"] == 1234 and p0["dport"] == 80
    assert p0["ttl"] == 128, p0["ttl"]
    assert p0["tcp_window"] == 8192, p0["tcp_window"]
    assert p0["flags"] & 0x02, "SYN flag lost"
    assert p0["payload_len"] == 0
    assert abs(p0["ts"] - 1000.0) < 1e-6

    assert got[1]["ttl"] == 55 and got[1]["tcp_window"] == 64240
    assert got[2]["payload_len"] == 40, got[2]["payload_len"]

    udp = got[3]
    assert udp["proto"] == 17 and udp["dport"] == 53
    assert udp["payload_len"] == 20, udp["payload_len"]
    print("header fields: OK")


def test_fragmentation_flag(tmp: Path) -> None:
    """More-fragments and a non-zero offset must both register as fragmented."""
    pkts = [
        (10.0, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1, 2, 0, 0x10, 100),
                          frag_flags=0x2000))),          # MF set
        (10.1, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1, 2, 0, 0x10, 100),
                          frag_flags=0x0025))),          # offset 37
        (10.2, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1, 2, 0, 0x10, 100),
                          frag_flags=0x4000))),          # DF only, not fragmented
    ]
    path = tmp / "frag.pcap"
    _write_pcap(path, pkts)
    got = list(iter_packets(path))
    assert [p["frag"] for p in got] == [1, 1, 0], [p["frag"] for p in got]
    assert got[2]["dont_frag"] == 1
    print("fragmentation: OK")


def test_retransmission_and_aggregation(tmp: Path) -> None:
    """A repeated sequence number on one conversation counts once as a retransmit."""
    psh_ack = 0x18
    body = _tcp(4444, 80, 7000, psh_ack, 512, b"z" * 10)
    pkts = [
        (500.0, _eth(_ipv4("10.0.0.5", "10.0.0.9", 6, body))),
        (500.2, _eth(_ipv4("10.0.0.5", "10.0.0.9", 6, body))),   # retransmission
        (500.4, _eth(_ipv4("10.0.0.5", "10.0.0.9", 6,
                           _tcp(4444, 80, 7011, psh_ack, 512, b"z" * 10)))),
    ]
    path = tmp / "retrans.pcap"
    _write_pcap(path, pkts)

    cells = extract_packet_features(path, window_seconds=60.0)
    row = cells[cells["src"] == "10.0.0.5"].iloc[0]
    assert row["pkt_count"] == 3
    assert abs(row["pkt_retrans_frac"] - 1 / 3) < 1e-6, row["pkt_retrans_frac"]
    assert row["pkt_ttl_mean"] == 64
    assert row["pkt_nunique_dst"] == 1
    print("retransmission + aggregation: OK")


def test_flow_reconstruction(tmp: Path) -> None:
    """Both directions of a conversation must collapse into one flow record."""
    syn, synack, ack = 0x02, 0x12, 0x10
    pkts = [
        (900.0, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(5000, 80, 1, syn, 8192)))),
        (900.1, _eth(_ipv4("10.0.0.2", "10.0.0.1", 6, _tcp(80, 5000, 1, synack, 6000)))),
        (900.2, _eth(_ipv4("10.0.0.1", "10.0.0.2", 6,
                           _tcp(5000, 80, 2, ack, 8192, b"a" * 100)))),
        # Unanswered probe to a different port: the port-scan signal.
        (900.3, _eth(_ipv4("10.0.0.1", "10.0.0.3", 6, _tcp(5001, 81, 1, syn, 8192)))),
    ]
    path = tmp / "flows.pcap"
    _write_pcap(path, pkts)

    flows = flows_from_pcap(path)
    assert len(flows) == 2, f"expected 2 flows, got {len(flows)}\n{flows}"

    conv = flows[flows["dport"] == 80].iloc[0]
    assert conv["tot_pkts"] == 3, conv["tot_pkts"]
    assert conv["bidirectional"] == 1
    assert conv["handshake_complete"] == 1, "SYN/SYN-ACK handshake not detected"
    assert conv["syn_only"] == 0
    assert conv["src"] == "10.0.0.1" and conv["dst"] == "10.0.0.2"

    probe = flows[flows["dport"] == 81].iloc[0]
    assert probe["syn_only"] == 1, "unanswered SYN not flagged"
    assert probe["bidirectional"] == 0
    print("flow reconstruction: OK")


def test_pure_helpers() -> None:
    assert _entropy([1, 1, 1, 1]) == 2.0            # four equally likely values
    assert _entropy([5]) == 0.0                      # no uncertainty
    assert _entropy([]) == 0.0

    # A sequential scanner steps by one; random access does not.
    assert _sequential_scan_score([100, 101, 102, 103, 104]) == 1.0
    assert _sequential_scan_score([9, 4000, 22, 51000]) == 0.0
    assert _sequential_scan_score([80]) == 0.0       # too short to judge
    print("pure helpers: OK")


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        test_l2_offset()
        test_header_fields_round_trip(tmp)
        test_fragmentation_flag(tmp)
        test_retransmission_and_aggregation(tmp)
        test_flow_reconstruction(tmp)
        test_pure_helpers()
    print("\nall packet tests passed")


if __name__ == "__main__":
    main()
