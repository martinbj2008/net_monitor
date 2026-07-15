#!/usr/bin/env python3
# hub_probe/exp_same_sport.py — sender-only experiment driver.
#
# What this does on the HUB:
#   1. (optional but recommended) attach the probe_xdp dropper so the hub
#      kernel drops every inbound TCP whose dport is in [65408..65423]
#      before its own stack sees it — this way hub never RSTs, never sends
#      challenge-ACKs, never disturbs the leaf's half-open bookkeeping.
#   2. Send N raw SYNs to the leaf's sshd from the SAME sport, with
#      strictly increasing seq (delta configurable). All SYNs share the
#      exact same 4-tuple, only tcp.seq differs.
#   3. Sleep --wait-s, then detach XDP and exit.
#
# There is NO capture inside this script. To see what the leaf actually
# replied, run tcpdump on the leaf (or on hub egress) in another shell:
#   # on the leaf, before starting this script:
#   sudo tcpdump -i any -n -w /tmp/exp.pcap \
#        "host <hub_ip> and (tcp port 22 or tcp portrange 65408-65423)"
#
# Usage on hub:
#   sudo python3 exp_same_sport.py --dst 43.132.210.4 \
#       --attach-xdp --sport 65420 --count 3 --delta 5000 --gap-ms 200

import argparse
import ctypes as ct
import os
import socket
import sys
import time
from pathlib import Path

os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, send as scapy_send  # noqa: E402

XDP_FLAGS_SKB_MODE = 1 << 1

def load_libbpf():
    for n in ("libbpf.so.1", "libbpf.so.0", "libbpf.so"):
        try: return ct.CDLL(n, use_errno=True)
        except OSError: pass
    raise RuntimeError("libbpf not found")

class XdpAttach:
    """Minimal: open bpf object, attach probe_xdp on iface (generic mode),
    detach on __exit__."""
    def __init__(self, iface, obj_path):
        self.iface = iface
        self.obj_path = str(obj_path)
        self.lb = load_libbpf()
        lb = self.lb
        lb.bpf_object__open_file.restype  = ct.c_void_p
        lb.bpf_object__open_file.argtypes = [ct.c_char_p, ct.c_void_p]
        lb.bpf_object__load.restype       = ct.c_int
        lb.bpf_object__load.argtypes      = [ct.c_void_p]
        lb.bpf_object__close.argtypes     = [ct.c_void_p]
        lb.bpf_object__find_program_by_name.restype  = ct.c_void_p
        lb.bpf_object__find_program_by_name.argtypes = [ct.c_void_p, ct.c_char_p]
        lb.bpf_program__fd.restype  = ct.c_int
        lb.bpf_program__fd.argtypes = [ct.c_void_p]
        lb.bpf_xdp_attach.restype   = ct.c_int
        lb.bpf_xdp_attach.argtypes  = [ct.c_int, ct.c_int, ct.c_uint32, ct.c_void_p]
        lb.bpf_xdp_detach.restype   = ct.c_int
        lb.bpf_xdp_detach.argtypes  = [ct.c_int, ct.c_uint32, ct.c_void_p]
        self.obj = None
        self.ifindex = socket.if_nametoindex(iface)
        self.flags = XDP_FLAGS_SKB_MODE

    def __enter__(self):
        lb = self.lb
        self.obj = lb.bpf_object__open_file(self.obj_path.encode(), None)
        if not self.obj: raise RuntimeError("bpf_object__open_file failed")
        if lb.bpf_object__load(self.obj) != 0:
            raise RuntimeError(f"bpf_object__load: {os.strerror(ct.get_errno())}")
        prog = lb.bpf_object__find_program_by_name(self.obj, b"probe_xdp")
        if not prog: raise RuntimeError("prog probe_xdp not found")
        prog_fd = lb.bpf_program__fd(prog)
        if lb.bpf_xdp_attach(self.ifindex, prog_fd, self.flags, None) != 0:
            raise RuntimeError(f"bpf_xdp_attach: {os.strerror(ct.get_errno())}")
        print(f"[xdp] attached on {self.iface} (generic mode)")
        return self

    def __exit__(self, *a):
        try:
            self.lb.bpf_xdp_detach(self.ifindex, self.flags, None)
            print("[xdp] detached")
        except Exception as e:
            print(f"[xdp] detach err: {e}")
        if self.obj:
            self.lb.bpf_object__close(self.obj); self.obj = None

def local_ip_for(dst):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 1)); return s.getsockname()[0]
    finally: s.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dport", type=int, default=22)
    ap.add_argument("--sport", type=int, default=65420,
                    help="fixed hub sport for ALL N SYNs. Should be in "
                         "[65408..65423] so the XDP dropper covers the "
                         "replies (kernel stays quiet).")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--delta", type=int, default=5000,
                    help="add this to tcp.seq for each subsequent SYN")
    ap.add_argument("--gap-ms", type=int, default=200,
                    help="sleep between successive SYNs")
    ap.add_argument("--wait-s", type=float, default=6.0,
                    help="sleep this long after the last SYN before "
                         "detaching XDP and exiting, so late retransmits "
                         "still get dropped by XDP and captured by "
                         "tcpdump on the leaf side")
    ap.add_argument("--seq-base", type=lambda x: int(x, 0),
                    default=0x20000000)
    ap.add_argument("--attach-xdp", action="store_true")
    ap.add_argument("--obj",
                    default=str(Path(__file__).resolve().parent.parent
                                / "bpf" / "probe_xdp.bpf.o"),
                    help="path to probe_xdp.bpf.o (used with --attach-xdp)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr); sys.exit(1)
    if args.attach_xdp and not (65408 <= args.sport <= 65423):
        print(f"[warn] sport {args.sport} is outside XDP window "
              "[65408..65423] — replies will NOT be dropped by XDP and "
              "the hub kernel will emit RST. Consider a sport in-window.",
              file=sys.stderr)

    my_ip = local_ip_for(args.dst)
    print(f"[info] hub={my_ip} leaf={args.dst}:{args.dport} "
          f"sport={args.sport} count={args.count} delta={args.delta} "
          f"gap={args.gap_ms}ms wait={args.wait_s}s")
    print("[hint] on the LEAF, run in parallel:")
    print(f"       sudo tcpdump -i any -nn -tttt -S "
          f"'host <hub_public_ip> and (tcp port {args.dport} "
          f"or tcp portrange 65408-65423)'")

    def send_all():
        for i in range(args.count):
            seq_i = (args.seq_base + i * args.delta) & 0xffffffff
            pkt = IP(src=my_ip, dst=args.dst) / \
                  TCP(sport=args.sport, dport=args.dport, flags="S",
                      seq=seq_i, window=64240,
                      options=[("MSS", 1460)])
            scapy_send(pkt, iface=args.iface, verbose=0)
            print(f"[tx {i}] seq={seq_i:#010x} ({seq_i}) "
                  f"ack_expected={(seq_i+1)&0xffffffff:#010x}")
            if i < args.count - 1:
                time.sleep(args.gap_ms / 1000.0)
        print(f"[info] all {args.count} SYNs sent, waiting {args.wait_s}s "
              "before exit (XDP stays attached to keep hub kernel quiet) ...")
        time.sleep(args.wait_s)

    if args.attach_xdp:
        with XdpAttach(args.iface, args.obj):
            send_all()
    else:
        send_all()

if __name__ == "__main__":
    main()
