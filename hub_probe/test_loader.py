#!/usr/bin/env python3
# hub_probe/test_loader.py — Step 2 smoke test for probe_xdp.bpf.o
#
# What it does:
#   1. dlopen libbpf.so
#   2. bpf_object__open_file("../bpf/probe_xdp.bpf.o")
#   3. bpf_object__load    -> creates the ringbuf map + verifies program
#   4. bpf_program__attach_xdp(prog_fd, ifindex) -> attach to eth0
#   5. ring_buffer__poll for --count events (default 10), print each
#   6. detach + close on Ctrl-C or when we reach --count
#
# Run on hub:
#   cd ~/git/net_monitor/bpf && make      # produces probe_xdp.bpf.o
#   cd ~/git/net_monitor/hub_probe && sudo python3 test_loader.py --iface eth0
#
# Design note: we call libbpf directly via ctypes to avoid depending on
# python3-bcc (which forces us to install clang + kernel-headers separately
# for every kernel upgrade). libbpf.so.1 is already installed on the hub.

import argparse
import ctypes as ct
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path

# ---------- event decoding (must match bpf/probe_xdp.h) ----------
# struct probe_event {  __u64 ts_ns;
#                       __u32 saddr;   __u32 daddr;
#                       __u16 sport;   __u16 dport;
#                       __u32 seq;     __u32 ack_seq;
#                       __u8  tcp_flags; __u8 _pad[3]; };
EVENT_FMT  = "<QIIHHIIB3x"          # little-endian host struct layout
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 32, f"probe_event size mismatch: {EVENT_SIZE}"

FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
              (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]

def flags_str(f: int) -> str:
    return "|".join(name for bit, name in FLAG_NAMES if f & bit) or "-"

def ip_str(be32: int) -> str:
    # be32 is a host-order integer holding a network-byte-order IPv4.
    return socket.inet_ntoa(struct.pack("<I", be32))

# ---------- libbpf ctypes binding (only the calls we need) ----------
LIBBPF_CANDIDATES = [
    "libbpf.so.1", "libbpf.so.0", "libbpf.so",
    "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
]

def load_libbpf():
    last_err = None
    for name in LIBBPF_CANDIDATES:
        try:
            return ct.CDLL(name, use_errno=True)
        except OSError as e:
            last_err = e
    raise RuntimeError(f"cannot dlopen libbpf: {last_err}")

lb = load_libbpf()

# --- bpf_object ---
lb.bpf_object__open_file.restype  = ct.c_void_p
lb.bpf_object__open_file.argtypes = [ct.c_char_p, ct.c_void_p]

lb.bpf_object__load.restype  = ct.c_int
lb.bpf_object__load.argtypes = [ct.c_void_p]

lb.bpf_object__close.restype  = None
lb.bpf_object__close.argtypes = [ct.c_void_p]

lb.bpf_object__find_program_by_name.restype  = ct.c_void_p
lb.bpf_object__find_program_by_name.argtypes = [ct.c_void_p, ct.c_char_p]

lb.bpf_object__find_map_by_name.restype  = ct.c_void_p
lb.bpf_object__find_map_by_name.argtypes = [ct.c_void_p, ct.c_char_p]

# --- program / map fds ---
lb.bpf_program__fd.restype  = ct.c_int
lb.bpf_program__fd.argtypes = [ct.c_void_p]

lb.bpf_map__fd.restype  = ct.c_int
lb.bpf_map__fd.argtypes = [ct.c_void_p]

# --- attach xdp ---
# Use bpf_xdp_attach / bpf_xdp_detach (libbpf >= 0.7). Fallback signatures:
try:
    lb.bpf_xdp_attach.restype  = ct.c_int
    lb.bpf_xdp_attach.argtypes = [ct.c_int, ct.c_int, ct.c_uint32, ct.c_void_p]
    lb.bpf_xdp_detach.restype  = ct.c_int
    lb.bpf_xdp_detach.argtypes = [ct.c_int, ct.c_uint32, ct.c_void_p]
    HAVE_XDP_ATTACH = True
except AttributeError:
    HAVE_XDP_ATTACH = False

# --- ringbuf ---
RINGBUF_CB = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_size_t)
lb.ring_buffer__new.restype  = ct.c_void_p
lb.ring_buffer__new.argtypes = [ct.c_int, RINGBUF_CB, ct.c_void_p, ct.c_void_p]

lb.ring_buffer__poll.restype  = ct.c_int
lb.ring_buffer__poll.argtypes = [ct.c_void_p, ct.c_int]

lb.ring_buffer__free.restype  = None
lb.ring_buffer__free.argtypes = [ct.c_void_p]

# XDP attach flags (from linux/if_link.h)
XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0
XDP_FLAGS_SKB_MODE          = 1 << 1   # generic
XDP_FLAGS_DRV_MODE          = 1 << 2   # native
XDP_FLAGS_HW_MODE           = 1 << 3

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--obj",
                    default=str(Path(__file__).resolve().parent.parent
                                / "bpf" / "probe_xdp.bpf.o"))
    ap.add_argument("--count", type=int, default=10,
                    help="stop after N events (0 = run until Ctrl-C)")
    ap.add_argument("--mode", choices=["native", "generic", "auto"],
                    default="auto")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root (needs CAP_NET_ADMIN + CAP_BPF)", file=sys.stderr)
        sys.exit(1)

    obj_path = Path(args.obj)
    if not obj_path.exists():
        print(f"object not found: {obj_path} — run `make` in bpf/ first",
              file=sys.stderr)
        sys.exit(1)

    ifindex = socket.if_nametoindex(args.iface)
    print(f"[info] iface={args.iface} ifindex={ifindex} obj={obj_path}")

    # 1. open + load
    obj = lb.bpf_object__open_file(str(obj_path).encode(), None)
    if not obj:
        print("bpf_object__open_file failed", file=sys.stderr); sys.exit(1)

    if lb.bpf_object__load(obj) != 0:
        err = ct.get_errno()
        print(f"bpf_object__load failed: errno={err} ({os.strerror(err)})",
              file=sys.stderr)
        lb.bpf_object__close(obj); sys.exit(1)
    print("[info] object loaded")

    prog = lb.bpf_object__find_program_by_name(obj, b"probe_xdp")
    if not prog:
        print("program 'probe_xdp' not found", file=sys.stderr)
        lb.bpf_object__close(obj); sys.exit(1)
    prog_fd = lb.bpf_program__fd(prog)

    m = lb.bpf_object__find_map_by_name(obj, b"events")
    if not m:
        print("map 'events' not found", file=sys.stderr)
        lb.bpf_object__close(obj); sys.exit(1)
    map_fd = lb.bpf_map__fd(m)

    # 2. attach xdp
    if not HAVE_XDP_ATTACH:
        print("libbpf too old: no bpf_xdp_attach()", file=sys.stderr)
        lb.bpf_object__close(obj); sys.exit(1)

    if args.mode == "native":
        flags = XDP_FLAGS_DRV_MODE
    elif args.mode == "generic":
        flags = XDP_FLAGS_SKB_MODE
    else:
        flags = 0  # let kernel choose (usually native if driver supports it)

    if lb.bpf_xdp_attach(ifindex, prog_fd, flags, None) != 0:
        err = ct.get_errno()
        print(f"bpf_xdp_attach failed: errno={err} ({os.strerror(err)})",
              file=sys.stderr)
        lb.bpf_object__close(obj); sys.exit(1)
    print(f"[info] xdp attached (mode={args.mode}, flags=0x{flags:x})")

    # 3. ringbuf poll
    counter = {"n": 0}
    limit   = args.count

    def on_event(ctx, data_ptr, size):
        if size < EVENT_SIZE:
            return 0
        raw = ct.string_at(data_ptr, EVENT_SIZE)
        (ts, sa, da, sp, dp, seq, ack, fl) = struct.unpack(EVENT_FMT, raw)
        counter["n"] += 1
        print(f"[{counter['n']:04d}] "
              f"ts={ts/1e9:.6f} "
              f"{ip_str(sa)}:{socket.ntohs(sp)} -> "
              f"{ip_str(da)}:{socket.ntohs(dp)} "
              f"flags={flags_str(fl)} "
              f"seq={socket.ntohl(seq) & 0xffffffff} "
              f"ack={socket.ntohl(ack) & 0xffffffff}")
        return 0

    cb = RINGBUF_CB(on_event)
    rb = lb.ring_buffer__new(map_fd, cb, None, None)
    if not rb:
        err = ct.get_errno()
        print(f"ring_buffer__new failed: errno={err}", file=sys.stderr)
        lb.bpf_xdp_detach(ifindex, flags, None)
        lb.bpf_object__close(obj); sys.exit(1)

    stop = {"flag": False}
    def _sig(_signum, _frame):
        stop["flag"] = True
    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"[info] polling ringbuf (limit={limit or 'unlimited'}) — Ctrl-C to stop")
    try:
        while not stop["flag"]:
            n = lb.ring_buffer__poll(rb, 200)  # 200 ms
            if n < 0:
                err = ct.get_errno()
                if err == 4:   # EINTR
                    continue
                print(f"ring_buffer__poll err errno={err}", file=sys.stderr)
                break
            if limit and counter["n"] >= limit:
                print(f"[info] reached --count={limit}, stopping")
                break
    finally:
        print("[info] detaching xdp ...")
        lb.ring_buffer__free(rb)
        lb.bpf_xdp_detach(ifindex, flags, None)
        lb.bpf_object__close(obj)
        print(f"[info] done, saw {counter['n']} events")

if __name__ == "__main__":
    main()
