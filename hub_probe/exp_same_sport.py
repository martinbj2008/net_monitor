#!/usr/bin/env python3
# hub_probe/exp_same_sport.py — one-shot experiment.
#
# Goal: with hub's XDP dropper attached (so hub kernel keeps its mouth shut
# and never RSTs the incoming SYN-ACKs), send N SYNs to the leaf using the
# *same* sport but strictly increasing seq (delta 5000). Observe:
#   - how many SYN-ACKs the leaf's sshd stack sends back
#   - each SA's tcp.seq (leaf ISN, freshly picked or reused?)
#   - each SA's tcp.ack (hub_isn+1, tells us which of our SYNs it acked)
#
# Capture uses AF_PACKET (no external tcpdump needed) and runs in a thread
# started before the SYNs go out.
#
# Usage on hub (must run under `sudo` with XDP dropper already attached
# on eth0 via test_loader or step4_run; otherwise the kernel will RST):
#   sudo python3 exp_same_sport.py --dst 43.132.210.4
#
# Optional:
#   --sport 65430          fixed sport (default 65430; must be in 65408..65423
#                          if you also want XDP to see them, but the leaf's
#                          replies are captured via AF_PACKET so any sport
#                          works — 65430 is outside the XDP filter which
#                          means the kernel *may* RST if XDP doesn't cover
#                          it. Keep in [65408..65423] for a clean test.)
#   --count 3
#   --delta 5000
#   --gap-ms 200
#   --listen-s 8           how long to keep capturing after last SYN

import argparse
import os
import socket
import struct
import sys
import threading
import time

os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, send as scapy_send  # noqa: E402

ETH_P_IP = 0x0800

def local_ip_for(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 1)); return s.getsockname()[0]
    finally: s.close()

def parse_ipv4_tcp(pkt: bytes):
    """Return dict or None. Assumes Ethernet II frame."""
    if len(pkt) < 14 + 20: return None
    if struct.unpack("!H", pkt[12:14])[0] != ETH_P_IP: return None
    ip = pkt[14:]
    ver_ihl = ip[0]
    if (ver_ihl >> 4) != 4: return None
    ihl = (ver_ihl & 0x0f) * 4
    if ip[9] != 6: return None  # not tcp
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20: return None
    sport, dport, seq, ack = struct.unpack("!HHII", tcp[:12])
    flags = tcp[13]
    return {
        "src": src, "dst": dst,
        "sport": sport, "dport": dport,
        "seq": seq, "ack": ack, "flags": flags,
    }

def flag_str(f):
    names = [("F",0x01),("S",0x02),("R",0x04),("P",0x08),
             ("A",0x10),("U",0x20),("E",0x40),("C",0x80)]
    return "".join(n for n,b in names if f & b)

class Sniffer(threading.Thread):
    def __init__(self, iface, my_ip, leaf_ip, my_sport, stop_evt):
        super().__init__(daemon=True)
        self.iface = iface
        self.my_ip = my_ip
        self.leaf_ip = leaf_ip
        self.my_sport = my_sport
        self.stop_evt = stop_evt
        self.hits = []
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(ETH_P_IP))
        self.sock.bind((iface, ETH_P_IP))
        self.sock.settimeout(0.3)

    def run(self):
        while not self.stop_evt.is_set():
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            info = parse_ipv4_tcp(data)
            if not info: continue
            # inbound SA from leaf sshd -> our hub sport
            if info["src"] != self.leaf_ip: continue
            if info["dst"] != self.my_ip: continue
            if info["sport"] != 22: continue
            if info["dport"] != self.my_sport: continue
            if (info["flags"] & 0x12) != 0x12:  # want SYN|ACK
                # still print other packets we get on this 4-tuple for context
                info["_t"] = time.monotonic()
                self.hits.append(info)
                continue
            info["_t"] = time.monotonic()
            self.hits.append(info)
        try: self.sock.close()
        except: pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dport", type=int, default=22)
    ap.add_argument("--sport", type=int, default=65430)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--delta", type=int, default=5000)
    ap.add_argument("--gap-ms", type=int, default=200)
    ap.add_argument("--listen-s", type=float, default=8.0)
    ap.add_argument("--seq-base", type=lambda x: int(x, 0),
                    default=0x20000000)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr); sys.exit(1)

    my_ip = local_ip_for(args.dst)
    print(f"[info] hub={my_ip} leaf={args.dst}:{args.dport} "
          f"sport={args.sport} count={args.count} delta={args.delta} "
          f"gap={args.gap_ms}ms")
    print("[warn] make sure the XDP dropper is attached on "
          f"{args.iface} first, otherwise the kernel will RST the SAs")

    stop = threading.Event()
    sn = Sniffer(args.iface, my_ip, args.dst, args.sport, stop)
    sn.start()

    sent = []
    t0_wall = time.time()
    for i in range(args.count):
        seq_i = (args.seq_base + i * args.delta) & 0xffffffff
        pkt = IP(src=my_ip, dst=args.dst) / \
              TCP(sport=args.sport, dport=args.dport, flags="S",
                  seq=seq_i, window=64240,
                  options=[("MSS", 1460)])
        t_send = time.monotonic()
        scapy_send(pkt, iface=args.iface, verbose=0)
        sent.append((i, seq_i, t_send))
        print(f"[tx {i}] seq={seq_i} (=0x{seq_i:08x}) "
              f"ack_expected_by_hub={(seq_i+1)&0xffffffff:#010x}")
        if i < args.count - 1:
            time.sleep(args.gap_ms / 1000.0)

    print(f"[info] all {args.count} SYNs sent, listening {args.listen_s}s ...")
    time.sleep(args.listen_s)
    stop.set(); sn.join(timeout=2.0)

    print()
    print(f"=========== captured {len(sn.hits)} inbound packets from "
          f"{args.dst}:22 -> hub:{args.sport} ===========")
    if not sn.hits:
        print("(none — kernel may have RST'd, or leaf sshd dropped, or "
              "packets were filtered upstream)")
        return

    # de-dup print by (seq, ack, flags) but preserve order
    for h in sn.hits:
        rel = h["_t"] - sent[0][2]
        # which of our SYNs does this ack answer?
        which = "?"
        for i, s, _ in sent:
            if h["ack"] == (s + 1) & 0xffffffff:
                which = f"SYN#{i}(seq={s:#010x})"; break
        print(f"  t+{rel*1000:7.1f}ms flags={flag_str(h['flags']):<5} "
              f"seq(leaf_isn)={h['seq']:#010x} "
              f"ack(hub_isn+1)={h['ack']:#010x} -> acks {which}")

    # summary
    sas = [h for h in sn.hits if (h["flags"] & 0x12) == 0x12]
    unique_ack = sorted({h["ack"] for h in sas})
    unique_seq = sorted({h["seq"] for h in sas})
    print()
    print(f"[sum] total_SA={len(sas)} "
          f"unique_ack={len(unique_ack)} unique_leaf_isn={len(unique_seq)}")
    print(f"[sum] unique_ack list: {[hex(a) for a in unique_ack]}")
    print(f"[sum] unique_leaf_isn list: {[hex(s) for s in unique_seq]}")

if __name__ == "__main__":
    main()
