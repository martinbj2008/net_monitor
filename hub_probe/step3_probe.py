#!/usr/bin/env python3
# hub_probe/step3_probe.py — Step 3 verification probe.
#
# Purpose:
#   1. Send N TCP SYN packets from hub to <target>:<dport>, using a source port
#      rotated across [65408..65423] (the sysctl-reserved range).
#   2. In parallel, sniff hub's own OUTBOUND RST packets destined to <target>.
#      If hub's kernel TCP stack sees the peer's SYN-ACK, it will emit a RST
#      (because we never opened a real socket). If XDP is attached and doing
#      its job, the SA is dropped before the stack sees it and NO RST is sent.
#   3. Also sniff INBOUND SYN-ACK from <target>, purely as ground truth that
#      the peer really replied. tcpdump/AF_PACKET taps are earlier than XDP
#      on ingress, so we can see SAs even when XDP later drops them.
#
# Two round protocol (run manually):
#
#   Round 1 — control, NO XDP attached:
#       sudo python3 step3_probe.py --target 43.132.210.4 --count 5
#     Expect: rx_synack=5, tx_rst=5   (kernel replies RST to unexpected SA)
#
#   Round 2 — with XDP attached (in another terminal run test_loader.py):
#     Terminal A: sudo python3 test_loader.py --iface eth0 --count 0
#     Terminal B: sudo python3 step3_probe.py --target 43.132.210.4 --count 5
#     Expect on this side: rx_synack=5, tx_rst=0
#     Expect on Terminal A: 5 ringbuf events with flags=SYN|ACK
#
# Notes:
#   - Send is done via scapy sr1 (no timing loop, just fire-and-move-on).
#   - We do NOT rely on the SYN-ACK reaching us via sr1 return value; sr1
#     matches on kernel-level socket state which is exactly what XDP breaks.
#     Instead we use AsyncSniffer, which taps AF_PACKET and sees SAs even
#     when XDP later drops them.
#   - We deliberately use raw scapy send()/sr1() with Ether/IP/TCP crafted
#     manually so that the src port lands in the reserved range (kernel
#     wouldn't grab it if we used a regular socket).

import argparse
import ipaddress
import os
import socket
import sys
import time

# scapy is noisy; silence its warnings before importing
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, send, AsyncSniffer, conf as scapy_conf

SPORT_LO = 65408
SPORT_HI = 65423   # inclusive, 16 ports

def local_ip_for(target: str) -> str:
    """Ask the kernel which src IP it would pick for this dest."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 1))   # no packet actually sent
        return s.getsockname()[0]
    finally:
        s.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="leaf public IPv4")
    ap.add_argument("--dport",  type=int, default=22)
    ap.add_argument("--count",  type=int, default=5)
    ap.add_argument("--iface",  default="eth0")
    ap.add_argument("--gap-ms", type=int, default=200,
                    help="delay between SYN sends")
    ap.add_argument("--settle-s", type=float, default=2.0,
                    help="how long to keep sniffer running after last send")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root (raw socket + AF_PACKET sniff)", file=sys.stderr)
        sys.exit(1)

    try:
        ipaddress.IPv4Address(args.target)
    except ValueError:
        print(f"bad target IPv4: {args.target}", file=sys.stderr); sys.exit(2)

    src_ip = local_ip_for(args.target)
    print(f"[info] target={args.target}:{args.dport}  src_ip={src_ip}  "
          f"iface={args.iface}  count={args.count}")
    print(f"[info] sport rotation: [{SPORT_LO}..{SPORT_HI}]")

    # BPF filter for the sniffer: only traffic on this pair, in either direction,
    # restricted to the dport (leaf side is 22) or reserved sport range on hub.
    # Simpler: just "host <target>" — we'll classify per-packet in the callback.
    bpf = f"tcp and host {args.target}"

    counts = {"rx_synack": 0, "tx_rst": 0, "tx_syn": 0, "other": 0}
    samples = []   # keep first few packets of each kind for eyeballing

    def on_pkt(p):
        if IP not in p or TCP not in p:
            return
        ip = p[IP]; tcp = p[TCP]
        # classify
        if ip.src == src_ip and ip.dst == args.target:
            # outbound
            if tcp.flags & 0x04:   # RST
                counts["tx_rst"] += 1
                if len(samples) < 20:
                    samples.append(f"  TX RST  {ip.src}:{tcp.sport} -> "
                                   f"{ip.dst}:{tcp.dport} seq={tcp.seq}")
            elif (tcp.flags & 0x02) and not (tcp.flags & 0x10):
                counts["tx_syn"] += 1
            else:
                counts["other"] += 1
        elif ip.src == args.target and ip.dst == src_ip:
            # inbound
            if (tcp.flags & 0x12) == 0x12:   # SYN|ACK
                counts["rx_synack"] += 1
                if len(samples) < 20:
                    samples.append(f"  RX  SA  {ip.src}:{tcp.sport} -> "
                                   f"{ip.dst}:{tcp.dport} "
                                   f"seq={tcp.seq} ack={tcp.ack}")
            else:
                counts["other"] += 1

    sniffer = AsyncSniffer(iface=args.iface, filter=bpf, prn=on_pkt, store=False)
    sniffer.start()
    time.sleep(0.3)   # let the sniffer install its filter

    print("[info] sending SYNs ...")
    for i in range(args.count):
        sport = SPORT_LO + (i % (SPORT_HI - SPORT_LO + 1))
        # deterministic seq so we can eyeball
        seq = 0x10000000 + i
        pkt = IP(src=src_ip, dst=args.target) / \
              TCP(sport=sport, dport=args.dport, flags="S", seq=seq,
                  window=64240, options=[("MSS", 1460)])
        # verbose=0 keeps scapy quiet
        send(pkt, iface=args.iface, verbose=0)
        print(f"  [{i+1:02d}] TX SYN  sport={sport} dport={args.dport} "
              f"seq={seq:#010x}")
        time.sleep(args.gap_ms / 1000.0)

    print(f"[info] all sent, waiting {args.settle_s}s for late replies ...")
    time.sleep(args.settle_s)
    sniffer.stop()

    print()
    print("=" * 60)
    print(f"result: tx_syn={counts['tx_syn']} tx_rst={counts['tx_rst']} "
          f"rx_synack={counts['rx_synack']} other={counts['other']}")
    print("=" * 60)
    for s in samples:
        print(s)

    # verdict
    if counts["rx_synack"] == 0:
        print()
        print("[VERDICT] no SYN-ACK observed — peer unreachable or dport closed.")
        sys.exit(3)

    if counts["tx_rst"] == 0:
        print()
        print("[VERDICT] XDP IS WORKING: peer replied SA but hub sent 0 RST.")
    else:
        print()
        print(f"[VERDICT] XDP NOT active (or not filtering): "
              f"hub sent {counts['tx_rst']} RST(s).")

if __name__ == "__main__":
    main()
