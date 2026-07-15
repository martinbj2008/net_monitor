#!/usr/bin/env python3
# hub_probe/probe_daemon.py — Step 4: end-to-end probe daemon.
#
# Combines the roles of Step 2 (XDP loader + ringbuf reader) and Step 3
# (SYN sender + verification sniffer) into one long-running process, and
# adds:
#   * per-probe RTT calculation via TCP seq/ack_seq matching
#   * CSV output in the schema of docker/postgres/initdb/01_schema.sql
#   * per-target timeout accounting (so loss% is measurable)
#
# --- Match strategy ---
# Every SYN we send carries a deterministic seq = SEQ_BASE + counter, and the
# leaf's SYN-ACK will carry ack_seq = seq + 1. dport (hub-side ephemeral) is
# recycled through [65408..65423], so seq is the only reliable per-probe key.
# We maintain a pending_map keyed by ack_seq -> (send_ts_ns_monotonic,
# send_ts_wall, sport, dst_ip, dst_name, probe_seq).
#
# --- CSV columns (aligned with probe_sample) ---
#   ts_iso, src, dst, dst_addr, proto, ip_ver, seq, rtt_ms, ok, batch_ts_iso
#
# --- Usage on hub ---
#   sudo python3 probe_daemon.py \
#     --iface eth0 \
#     --target hongkong=43.132.210.4 \
#     --target virginia=170.106.106.161 \
#     --src-name bangkok \
#     --interval-ms 1000 --duration-s 60 \
#     --csv /var/log/vps_probe/rtt.csv
#
# Multiple --target args allowed. Each interval fires one SYN per target in
# round-robin. XDP is attached at startup, detached on exit (ctrl-c/SIGTERM).

import argparse
import csv
import ctypes as ct
import datetime as dt
import ipaddress
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# scapy noise
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, send as scapy_send  # noqa: E402

# ---------- constants shared with BPF ----------
EVENT_FMT  = "<QIIHHIIB3x"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 32

SPORT_LO   = 65408
SPORT_HI   = 65423   # inclusive
SPORT_SPAN = SPORT_HI - SPORT_LO + 1

SEQ_BASE   = 0x10000000

# ---------- libbpf ctypes bindings ----------
LIBBPF_CANDIDATES = [
    "libbpf.so.1", "libbpf.so.0", "libbpf.so",
    "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
]

def load_libbpf():
    last = None
    for n in LIBBPF_CANDIDATES:
        try:
            return ct.CDLL(n, use_errno=True)
        except OSError as e:
            last = e
    raise RuntimeError(f"cannot dlopen libbpf: {last}")

lb = load_libbpf()

lb.bpf_object__open_file.restype  = ct.c_void_p
lb.bpf_object__open_file.argtypes = [ct.c_char_p, ct.c_void_p]
lb.bpf_object__load.restype       = ct.c_int
lb.bpf_object__load.argtypes      = [ct.c_void_p]
lb.bpf_object__close.restype      = None
lb.bpf_object__close.argtypes     = [ct.c_void_p]
lb.bpf_object__find_program_by_name.restype  = ct.c_void_p
lb.bpf_object__find_program_by_name.argtypes = [ct.c_void_p, ct.c_char_p]
lb.bpf_object__find_map_by_name.restype  = ct.c_void_p
lb.bpf_object__find_map_by_name.argtypes = [ct.c_void_p, ct.c_char_p]
lb.bpf_program__fd.restype  = ct.c_int
lb.bpf_program__fd.argtypes = [ct.c_void_p]
lb.bpf_map__fd.restype  = ct.c_int
lb.bpf_map__fd.argtypes = [ct.c_void_p]

lb.bpf_xdp_attach.restype  = ct.c_int
lb.bpf_xdp_attach.argtypes = [ct.c_int, ct.c_int, ct.c_uint32, ct.c_void_p]
lb.bpf_xdp_detach.restype  = ct.c_int
lb.bpf_xdp_detach.argtypes = [ct.c_int, ct.c_uint32, ct.c_void_p]

RINGBUF_CB = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_size_t)
lb.ring_buffer__new.restype  = ct.c_void_p
lb.ring_buffer__new.argtypes = [ct.c_int, RINGBUF_CB, ct.c_void_p, ct.c_void_p]
lb.ring_buffer__poll.restype  = ct.c_int
lb.ring_buffer__poll.argtypes = [ct.c_void_p, ct.c_int]
lb.ring_buffer__free.restype  = None
lb.ring_buffer__free.argtypes = [ct.c_void_p]

XDP_FLAGS_SKB_MODE = 1 << 1
XDP_FLAGS_DRV_MODE = 1 << 2

# ---------- helpers ----------
def parse_target(spec: str):
    """`name=ip` -> (name, ip). Both required."""
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"target must be name=ipv4, got: {spec}")
    name, ip = spec.split("=", 1)
    name = name.strip(); ip = ip.strip()
    if not name or not ip:
        raise argparse.ArgumentTypeError(f"empty name or ip in: {spec}")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad ipv4: {ip}")
    return (name, ip)

def local_ip_for(target_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()

def iso_utc(ts_wall: float) -> str:
    return dt.datetime.fromtimestamp(ts_wall, dt.timezone.utc)\
             .isoformat(timespec="microseconds")

# ---------- main daemon ----------
class ProbeDaemon:
    def __init__(self, args):
        self.args = args
        self.stop_flag = False

        self.src_name = args.src_name or socket.gethostname()
        # pick src IP once from the first target — hub only has one uplink
        first_ip = args.target[0][1]
        self.src_ip = local_ip_for(first_ip)

        self.batch_ts_wall = time.time()
        self.batch_ts_iso  = iso_utc(self.batch_ts_wall)

        # pending: ack_seq_expected -> row dict
        self.pending_lock = threading.Lock()
        self.pending = {}

        # counters
        self.n_sent = 0
        self.n_matched = 0
        self.n_timeout = 0
        self.n_unknown_sa = 0    # SA came in but no pending entry

        # CSV
        csv_path = Path(args.csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not csv_path.exists() or csv_path.stat().st_size == 0
        self.csv_fh = open(csv_path, "a", buffering=1, newline="")
        self.csv_w  = csv.writer(self.csv_fh)
        if new_file:
            self.csv_w.writerow([
                "ts_iso", "src", "dst", "dst_addr",
                "proto", "ip_ver", "seq", "rtt_ms", "ok",
                "batch_ts_iso",
            ])

        # BPF state
        self.obj = None
        self.rb  = None
        self.xdp_flags = 0
        self.ifindex = socket.if_nametoindex(args.iface)

    # ---- BPF ----
    def bpf_setup(self):
        obj_path = Path(self.args.obj)
        if not obj_path.exists():
            raise RuntimeError(f"obj not found: {obj_path}")

        self.obj = lb.bpf_object__open_file(str(obj_path).encode(), None)
        if not self.obj:
            raise RuntimeError("bpf_object__open_file failed")
        if lb.bpf_object__load(self.obj) != 0:
            err = ct.get_errno()
            raise RuntimeError(f"bpf_object__load: {os.strerror(err)}")

        prog = lb.bpf_object__find_program_by_name(self.obj, b"probe_xdp")
        if not prog: raise RuntimeError("prog probe_xdp not found")
        prog_fd = lb.bpf_program__fd(prog)

        m = lb.bpf_object__find_map_by_name(self.obj, b"events")
        if not m: raise RuntimeError("map events not found")
        map_fd = lb.bpf_map__fd(m)

        if self.args.mode == "native":
            self.xdp_flags = XDP_FLAGS_DRV_MODE
        elif self.args.mode == "generic":
            self.xdp_flags = XDP_FLAGS_SKB_MODE
        else:
            self.xdp_flags = 0

        if lb.bpf_xdp_attach(self.ifindex, prog_fd,
                             self.xdp_flags, None) != 0:
            err = ct.get_errno()
            raise RuntimeError(f"bpf_xdp_attach: {os.strerror(err)}")
        print(f"[bpf] xdp attached iface={self.args.iface} "
              f"mode={self.args.mode} flags=0x{self.xdp_flags:x}")

        # keep the callback alive for the whole run
        self._cb_ref = RINGBUF_CB(self._on_event)
        self.rb = lb.ring_buffer__new(map_fd, self._cb_ref, None, None)
        if not self.rb:
            err = ct.get_errno()
            raise RuntimeError(f"ring_buffer__new: {os.strerror(err)}")

    def bpf_teardown(self):
        try:
            if self.rb:
                lb.ring_buffer__free(self.rb); self.rb = None
        finally:
            try:
                lb.bpf_xdp_detach(self.ifindex, self.xdp_flags, None)
            except Exception:
                pass
            if self.obj:
                lb.bpf_object__close(self.obj); self.obj = None
        print("[bpf] xdp detached")

    # ---- ringbuf callback ----
    def _on_event(self, ctx, data_ptr, size):
        if size < EVENT_SIZE:
            return 0
        raw = ct.string_at(data_ptr, EVENT_SIZE)
        ts_ns_mono, sa_be, da_be, sp_be, dp_be, seq_be, ack_be, fl \
            = struct.unpack(EVENT_FMT, raw)

        ack_host = socket.ntohl(ack_be) & 0xffffffff
        recv_mono = time.monotonic_ns()

        with self.pending_lock:
            row = self.pending.pop(ack_host, None)

        if row is None:
            # SA arrived we didn't send for — could be stray or after timeout
            self.n_unknown_sa += 1
            return 0

        rtt_ns = recv_mono - row["send_mono_ns"]
        rtt_ms = round(rtt_ns / 1e6, 3)
        self.n_matched += 1

        # verify src ip matches (defensive)
        sa_ip = socket.inet_ntoa(struct.pack("<I", sa_be))
        if sa_ip != row["dst_addr"]:
            # unlikely; keep going but note it
            print(f"[warn] SA src {sa_ip} != expected {row['dst_addr']} "
                  f"for ack={ack_host:#x}")

        self.csv_w.writerow([
            iso_utc(row["send_wall"]),
            self.src_name, row["dst"], row["dst_addr"],
            "tcp_synack", 4, row["probe_seq"], int(round(rtt_ms)), True,
            self.batch_ts_iso,
        ])
        if self.args.verbose:
            print(f"[rtt] {row['dst']:<12} sport={row['sport']} "
                  f"seq={row['probe_seq']} rtt={rtt_ms:.2f}ms")
        return 0

    # ---- sender ----
    def _send_one(self, dst_name: str, dst_ip: str):
        probe_seq = self.n_sent          # monotonically increasing per daemon run
        self.n_sent += 1

        sport = SPORT_LO + (probe_seq % SPORT_SPAN)
        tcp_seq = (SEQ_BASE + probe_seq) & 0xffffffff
        ack_expected = (tcp_seq + 1) & 0xffffffff

        pkt = IP(src=self.src_ip, dst=dst_ip) / \
              TCP(sport=sport, dport=self.args.dport, flags="S",
                  seq=tcp_seq, window=64240,
                  options=[("MSS", 1460)])

        send_wall = time.time()
        send_mono = time.monotonic_ns()

        with self.pending_lock:
            self.pending[ack_expected] = {
                "send_mono_ns": send_mono,
                "send_wall":    send_wall,
                "sport":        sport,
                "dst":          dst_name,
                "dst_addr":     dst_ip,
                "probe_seq":    probe_seq,
                "deadline_ns":  send_mono + self.args.timeout_ms * 1_000_000,
            }

        scapy_send(pkt, iface=self.args.iface, verbose=0)
        if self.args.verbose:
            print(f"[tx]  {dst_name:<12} sport={sport} "
                  f"seq={probe_seq} tcp_seq={tcp_seq:#010x}")

    def _sender_loop(self):
        interval = self.args.interval_ms / 1000.0
        end = time.monotonic() + self.args.duration_s if self.args.duration_s > 0 else None
        i = 0
        while not self.stop_flag:
            if end and time.monotonic() >= end:
                print("[info] --duration-s reached, stopping sender")
                self.stop_flag = True
                break
            dst_name, dst_ip = self.args.target[i % len(self.args.target)]
            try:
                self._send_one(dst_name, dst_ip)
            except Exception as e:
                print(f"[send err] {dst_name} {dst_ip}: {e}")
            i += 1
            # sleep in small ticks so ctrl-c is responsive
            slept = 0.0
            while slept < interval and not self.stop_flag:
                dt_s = min(0.1, interval - slept)
                time.sleep(dt_s)
                slept += dt_s

    def _sweep_timeouts(self):
        """Drain expired pending entries -> CSV as ok=false rows."""
        now = time.monotonic_ns()
        expired = []
        with self.pending_lock:
            for k, v in list(self.pending.items()):
                if now >= v["deadline_ns"]:
                    expired.append(v)
                    del self.pending[k]
        for row in expired:
            self.n_timeout += 1
            self.csv_w.writerow([
                iso_utc(row["send_wall"]),
                self.src_name, row["dst"], row["dst_addr"],
                "tcp_synack", 4, row["probe_seq"], None, False,
                self.batch_ts_iso,
            ])
            if self.args.verbose:
                print(f"[to]  {row['dst']:<12} sport={row['sport']} "
                      f"seq={row['probe_seq']} TIMEOUT")

    # ---- main poll loop ----
    def run(self):
        self.bpf_setup()

        # sender in a thread; poll in main
        t = threading.Thread(target=self._sender_loop, name="sender",
                             daemon=True)
        t.start()

        # signals
        def _sig(_signum, _frame):
            self.stop_flag = True
        signal.signal(signal.SIGINT,  _sig)
        signal.signal(signal.SIGTERM, _sig)

        print(f"[info] daemon started. src={self.src_name}({self.src_ip}) "
              f"targets={[t[0] for t in self.args.target]} "
              f"interval={self.args.interval_ms}ms "
              f"timeout={self.args.timeout_ms}ms")
        print(f"[info] csv -> {self.args.csv}")

        last_stat = time.monotonic()
        last_sweep = time.monotonic()
        try:
            while not self.stop_flag:
                n = lb.ring_buffer__poll(self.rb, 200)
                if n < 0:
                    err = ct.get_errno()
                    if err == 4:  # EINTR
                        continue
                    print(f"[poll err] errno={err}", file=sys.stderr)
                    break
                now = time.monotonic()
                if now - last_sweep >= 0.5:
                    self._sweep_timeouts()
                    last_sweep = now
                if now - last_stat >= 5.0:
                    print(f"[stat] sent={self.n_sent} matched={self.n_matched} "
                          f"timeout={self.n_timeout} "
                          f"unknown_sa={self.n_unknown_sa} "
                          f"pending={len(self.pending)}")
                    last_stat = now
        finally:
            # give sender a moment to finish + drain remaining pending as timeouts
            self.stop_flag = True
            t.join(timeout=2.0)
            # final sweep — count anything still pending as loss
            with self.pending_lock:
                remaining = list(self.pending.values())
                self.pending.clear()
            for row in remaining:
                self.n_timeout += 1
                self.csv_w.writerow([
                    iso_utc(row["send_wall"]),
                    self.src_name, row["dst"], row["dst_addr"],
                    "tcp_synack", 4, row["probe_seq"], None, False,
                    self.batch_ts_iso,
                ])
            self.csv_fh.flush(); self.csv_fh.close()
            self.bpf_teardown()
            print(f"[done] sent={self.n_sent} matched={self.n_matched} "
                  f"timeout={self.n_timeout} unknown_sa={self.n_unknown_sa}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--obj",
                    default=str(Path(__file__).resolve().parent.parent
                                / "bpf" / "probe_xdp.bpf.o"))
    ap.add_argument("--mode", choices=["native", "generic", "auto"],
                    default="generic")
    ap.add_argument("--target", action="append", type=parse_target,
                    required=True,
                    help="one or more name=ipv4 targets, e.g. hongkong=1.2.3.4")
    ap.add_argument("--dport", type=int, default=22)
    ap.add_argument("--src-name", default=None,
                    help="src label written to CSV (default: hostname)")
    ap.add_argument("--interval-ms", type=int, default=1000,
                    help="delay between successive SYNs across all targets")
    ap.add_argument("--timeout-ms", type=int, default=3000,
                    help="mark probe as loss if no SA within this window")
    ap.add_argument("--duration-s", type=int, default=0,
                    help="stop after N seconds (0 = run until ctrl-c)")
    ap.add_argument("--csv", default="/var/log/vps_probe/rtt.csv")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root (XDP + raw send)", file=sys.stderr)
        sys.exit(1)

    ProbeDaemon(args).run()


if __name__ == "__main__":
    main()
