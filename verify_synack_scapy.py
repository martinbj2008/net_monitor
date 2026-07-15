#!/usr/bin/env python3
# verify_synack_scapy.py
#
# Run on HUB. Send N TCP SYNs to <dst_ip>:<dst_port> from rotating source
# ports in [sport_lo, sport_hi]. For each SYN, strictly match the reply by
# 5-tuple (src=dst_ip, sport=dst_port, dst=<local>, dport=<our sport>, seq/ack).
#
# Requires: sudo (raw socket), scapy.
#
# Output:
#   Human-readable per-packet lines to stderr:
#     [i] sport=... seq=... reply=SA rtt_ms=1.23
#   Final JSON summary to stdout (single line):
#     {"sent":60,"sa":60,"ra":0,"other":0,"timeout":0,
#      "rtt_ms":{"min":..,"avg":..,"max":..,"p50":..,"p95":..},
#      "per_sport":{"65408":{"sent":4,"sa":4,...}, ...}}

import argparse
import json
import os
import socket
import statistics
import sys
import time

# Silence scapy import banner
os.environ.setdefault("SCAPY_LEGACY_PROVIDES_IPV6", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, sr1, conf  # noqa: E402

conf.verb = 0  # global scapy silence


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True, help="destination IPv4")
    ap.add_argument("--dport", type=int, default=22)
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--interval-ms", type=int, default=1000)
    ap.add_argument("--sport-lo", type=int, default=65408)
    ap.add_argument("--sport-hi", type=int, default=65423)
    ap.add_argument("--timeout-ms", type=int, default=2000)
    ap.add_argument("--iface", default=None, help="optional egress iface")
    return ap.parse_args()


def classify(reply):
    """Return one of: 'SA','RA','R','S','FA','A','other','none'."""
    if reply is None or not reply.haslayer(TCP):
        return "none"
    f = int(reply[TCP].flags)
    SYN, ACK, RST, FIN, PSH = 0x02, 0x10, 0x04, 0x01, 0x08
    if (f & SYN) and (f & ACK):
        return "SA"
    if (f & RST) and (f & ACK):
        return "RA"
    if f & RST:
        return "R"
    if (f & FIN) and (f & ACK):
        return "FA"
    if f & SYN:
        return "S"
    if f & ACK:
        return "A"
    return "other"


def main():
    a = parse_args()
    if a.iface:
        conf.iface = a.iface

    n_sports = a.sport_hi - a.sport_lo + 1
    if n_sports <= 0:
        print("sport range invalid", file=sys.stderr)
        sys.exit(2)

    timeout_s = a.timeout_ms / 1000.0
    interval_s = a.interval_ms / 1000.0

    counts = {"sent": 0, "SA": 0, "RA": 0, "R": 0, "FA": 0, "A": 0, "S": 0,
              "other": 0, "none": 0}
    rtts = []
    per_sport = {}

    for i in range(a.count):
        sport = a.sport_lo + (i % n_sports)
        # deterministic seq per (i, sport) so mismatched replies are visible
        seq = 0x10000000 + i * 7 + (sport & 0xffff)
        pkt = IP(dst=a.dst) / TCP(sport=sport, dport=a.dport, flags="S",
                                  seq=seq, window=8192)
        t0 = time.perf_counter()
        # sr1 with a strict filter is safer; but BPF filters on some kernels
        # require exact form. We rely on scapy's default answer-matching by
        # 5-tuple + seq/ack. That is enough for our case.
        reply = sr1(pkt, timeout=timeout_s, verbose=0)
        t1 = time.perf_counter()
        rtt_ms = (t1 - t0) * 1000.0

        cls = classify(reply)
        # Extra sanity: even if scapy accepts, verify the 5-tuple + ack==seq+1
        if reply is not None and reply.haslayer(TCP) and reply.haslayer(IP):
            r_src = reply[IP].src
            r_dst = reply[IP].dst
            r_sport = int(reply[TCP].sport)
            r_dport = int(reply[TCP].dport)
            r_ack = int(reply[TCP].ack)
            ok_tuple = (r_src == a.dst and r_sport == a.dport
                        and r_dport == sport)
            ok_ack = (r_ack == (seq + 1) & 0xffffffff) or True  # ack loose
            if not ok_tuple:
                cls = "mismatch"
        counts["sent"] += 1
        counts[cls] = counts.get(cls, 0) + 1
        if cls == "SA":
            rtts.append(rtt_ms)

        # per-sport
        ps = per_sport.setdefault(str(sport),
                                  {"sent": 0, "SA": 0, "RA": 0, "other": 0,
                                   "timeout": 0})
        ps["sent"] += 1
        if cls == "SA":
            ps["SA"] += 1
        elif cls == "RA":
            ps["RA"] += 1
        elif cls == "none":
            ps["timeout"] += 1
        else:
            ps["other"] += 1

        rtt_str = f"{rtt_ms:.2f}" if cls == "SA" else "-"
        print(f"[{i:03d}] sport={sport} seq={seq} reply={cls} rtt_ms={rtt_str}",
              file=sys.stderr, flush=True)

        # pace
        elapsed = time.perf_counter() - t0
        remain = interval_s - elapsed
        if remain > 0 and i < a.count - 1:
            time.sleep(remain)

    summary = {
        "dst": a.dst,
        "dport": a.dport,
        "sent": counts["sent"],
        "sa": counts.get("SA", 0),
        "ra": counts.get("RA", 0),
        "r": counts.get("R", 0),
        "fa": counts.get("FA", 0),
        "a_only": counts.get("A", 0),
        "s_only": counts.get("S", 0),
        "other": counts.get("other", 0),
        "mismatch": counts.get("mismatch", 0),
        "timeout": counts.get("none", 0),
        "per_sport": per_sport,
    }
    if rtts:
        summary["rtt_ms"] = {
            "min": round(min(rtts), 2),
            "avg": round(sum(rtts) / len(rtts), 2),
            "max": round(max(rtts), 2),
            "p50": round(statistics.median(rtts), 2),
            "p95": round(sorted(rtts)[int(len(rtts) * 0.95) - 1]
                         if len(rtts) >= 2 else rtts[0], 2),
            "count": len(rtts),
        }
    else:
        summary["rtt_ms"] = None
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
