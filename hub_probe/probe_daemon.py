#!/usr/bin/env python3
# hub_probe/probe_daemon.py — Step 4: end-to-end probe daemon.
#
# Combines the roles of Step 2 (XDP loader + ringbuf reader) and Step 3
# (SYN sender + verification sniffer) into one long-running process, and
# adds:
#   * per-probe RTT via 4-tuple + ack_seq matching
#   * in-memory buffered inserts into Postgres probe_sample (or stdout for debug)
#   * per-target timeout accounting (so loss% is measurable)
#   * SA-retransmission accounting (so leaf's re-tx SAs aren't miscounted)
#
# --- Match strategy ---
# Every SYN we send from hub uses a FIXED sport (default 65535, configurable
# via --sport) toward leaf:22. seq starts at a random 32-bit value picked at
# process startup and increments by SEQ_STEP (5000) per probe, wrapping
# naturally in the 32-bit space; not persisted across restarts.
#
# Because sport is fixed, the 4-tuple on the wire is identical every probe;
# the only thing distinguishing probes is seq. The pending map is therefore
# still keyed by the full identifier of a specific SYN's expected reply:
#     (dst_ip, dport, sport, ack_expected)   with ack_expected = seq + 1
# so different probes still get different keys.
#
# When XDP fires, we take (SA.saddr, SA.sport, SA.dport, SA.ack_seq) and look
# it up. First match records RTT. Later hits on the same key are counted as
# leaf-side SA retransmissions (leaf keeps re-sending SA every ~1-32s until
# our half-open TCB is either ACKed or expires).
#
# NOTE: reusing one sport at 1Hz will keep leaf's half-open TCB warm; each
# subsequent SYN with a jumped seq lands out-of-window on that TCB and elicits
# challenge-ACK / RST-ACK rather than a fresh SYN-ACK. XDP swallows those on
# hub side, and userspace matches on ack_seq regardless of flag combo, so
# they're still valid RTT samples.
#
# --- Sink ---
# Default: batched INSERT into Postgres. Buffer flushes when either
# --batch-size rows accumulate OR --batch-interval-s elapses. --sink stdout
# just prints rows without touching a DB — used during dev/debug.
#
# --- Usage on hub ---
#   sudo python3 probe_daemon.py \
#     --iface eth0 \
#     --target hongkong=43.132.210.4 \
#     --src-name bangkok \
#     --interval-ms 1000 --duration-s 60 \
#     --sink pg \
#     --pg-dsn 'postgresql://probe:PASS@127.0.0.1:25432/probe'

import argparse
import ctypes as ct
import datetime as dt
import ipaddress
import os
import secrets
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

# The XDP filter drops any inbound TCP whose dport equals PROBE_PORT. We use
# a single reserved port so the filter is trivially exact and there's no
# "dead window" of unused reserved ports.
PROBE_PORT = 65535

# Fixed sport used by every SYN. Must equal PROBE_PORT so that XDP on
# hub-side catches (and drops) the replies before the local TCP stack gets
# a chance to emit its own RST toward leaf.
DEFAULT_SPORT = PROBE_PORT

# seq step per probe. Big enough that any reasonable in-flight TCP window on
# a half-open state at leaf can't accidentally cover two consecutive probes'
# seq numbers, small enough that 32-bit wrap doesn't matter in practice.
SEQ_STEP = 5000

# how long we keep a matched entry around so leaf SA retransmissions can be
# recognized as "retrans" instead of "orphan"
MATCHED_TTL_S = 40.0   # covers Linux default SA retransmit window (~31s)

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

# ---------- sinks ----------
INSERT_SQL = """
INSERT INTO probe_sample
  (ts, src, dst, dst_addr, proto, ip_ver, seq, rtt_ms, ok, batch_ts)
VALUES %s
ON CONFLICT (ts, src, dst, proto, ip_ver) DO NOTHING
"""

class StdoutSink:
    def __init__(self):
        self.total = 0
    def flush(self, rows):
        for r in rows:
            print(f"[row] {r}")
        self.total += len(rows)
    def close(self): pass

class PgSink:
    def __init__(self, dsn: str):
        import psycopg2               # lazy import so --sink stdout works w/o
        import psycopg2.extras        # psycopg2 installed
        self._psycopg2 = psycopg2
        self._extras   = psycopg2.extras
        self.dsn = dsn
        self.conn = None
        self.total = 0
        self._connect()

    def _connect(self):
        self.conn = self._psycopg2.connect(self.dsn)
        self.conn.autocommit = False

    def flush(self, rows):
        if not rows: return
        # retry once on connection loss
        for attempt in range(2):
            try:
                with self.conn:
                    with self.conn.cursor() as cur:
                        self._extras.execute_values(
                            cur, INSERT_SQL, rows, page_size=500)
                self.total += len(rows)
                return
            except self._psycopg2.OperationalError as e:
                print(f"[pg] operational error (attempt {attempt+1}): {e}",
                      file=sys.stderr)
                try: self.conn.close()
                except Exception: pass
                time.sleep(1.0)
                self._connect()
        print(f"[pg] FAILED to flush {len(rows)} rows after retry — "
              f"dropping to avoid unbounded memory", file=sys.stderr)

    def close(self):
        try:
            if self.conn: self.conn.close()
        except Exception: pass

# ---------- main daemon ----------
class ProbeDaemon:
    def __init__(self, args):
        self.args = args
        self.stop_flag = False

        # --src-name is required (enforced by argparse). We deliberately do NOT
        # fall back to socket.gethostname(): the box hostname (e.g.
        # 'VM-0-15-ubuntu') is meaningless as a business label and silently
        # ends up in probe_sample.src, polluting downstream dashboards.
        # Deployment MUST decide the name (see run_forever.sh SRC_NAME).
        self.src_name = args.src_name
        # pick src IP once from the first target — hub only has one uplink
        first_ip = args.target[0][1]
        self.src_ip = local_ip_for(first_ip)

        self.batch_ts_wall = time.time()
        self.batch_ts_iso  = iso_utc(self.batch_ts_wall)

        # seq state: random 32-bit start per process, +SEQ_STEP each probe,
        # natural 32-bit wrap, no persistence across restarts.
        self._seq_cursor = secrets.randbits(32)
        print(f"[init] seq start=0x{self._seq_cursor:08x} step={SEQ_STEP} "
              f"sport={args.sport}")

        # pending: key(4-tuple) -> row-in-flight; matched=True means SA seen
        # (kept for MATCHED_TTL_S so retransmitted SAs get counted correctly).
        self.pending_lock = threading.Lock()
        self.pending = {}

        # buffered rows waiting to be flushed to sink
        self.buffer_lock = threading.Lock()
        self.buffer = []
        self.last_flush = time.monotonic()

        # counters
        self.n_sent = 0
        self.n_matched = 0
        self.n_timeout = 0
        self.n_sa_retrans = 0   # SA arrived, tuple known + already matched
        self.n_sa_orphan  = 0   # SA arrived, tuple not in pending map at all

        # sink
        if args.sink == "pg":
            if not args.pg_dsn:
                raise RuntimeError("--sink pg requires --pg-dsn or "
                                   "$PROBE_PG_DSN")
            self.sink = PgSink(args.pg_dsn)
        elif args.sink == "stdout":
            self.sink = StdoutSink()
        else:
            raise RuntimeError(f"unknown sink: {args.sink}")

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

        # SA fields on the wire are (leaf_ip, leaf_sport=22, hub_ip, hub_dport,
        # seq=leaf_isn, ack_seq=hub_isn+1). We keyed pending by the SYN we
        # sent: (dst_ip=leaf_ip, dport=leaf_port=22, sport=hub_port,
        #        ack_expected=hub_isn+1). So the lookup key is:
        sa_src_ip   = socket.inet_ntoa(struct.pack("<I", sa_be))
        sa_src_port = socket.ntohs(sp_be)
        sa_dst_port = socket.ntohs(dp_be)
        ack_host    = socket.ntohl(ack_be) & 0xffffffff
        key = (sa_src_ip, sa_src_port, sa_dst_port, ack_host)

        recv_mono = time.monotonic_ns()

        with self.pending_lock:
            row = self.pending.get(key)
            if row is None:
                self.n_sa_orphan += 1
                return 0
            if row.get("matched"):
                # leaf re-sent the SA; ignore, but count
                self.n_sa_retrans += 1
                return 0
            row["matched"]     = True
            row["match_mono"]  = recv_mono

        rtt_ns = recv_mono - row["send_mono_ns"]
        rtt_ms = rtt_ns / 1e6
        self.n_matched += 1

        self._enqueue_row(
            ts_iso  = iso_utc(row["send_wall"]),
            dst     = row["dst"],
            dst_ip  = row["dst_addr"],
            probe_seq = row["probe_seq"],
            rtt_ms  = int(round(rtt_ms)),
            ok      = True,
        )

        if self.args.verbose:
            print(f"[rtt] {row['dst']:<12} sport={row['sport']} "
                  f"seq={row['probe_seq']} rtt={rtt_ms:.2f}ms")
        return 0

    # ---- buffer / flush ----
    def _enqueue_row(self, *, ts_iso, dst, dst_ip, probe_seq, rtt_ms, ok):
        row = (ts_iso, self.src_name, dst, dst_ip,
               "tcp_synack", 4, probe_seq, rtt_ms, ok,
               self.batch_ts_iso)
        need_flush = False
        with self.buffer_lock:
            self.buffer.append(row)
            if len(self.buffer) >= self.args.batch_size:
                need_flush = True
        if need_flush:
            self._flush("batch-size")

    def _flush(self, reason: str):
        with self.buffer_lock:
            if not self.buffer:
                self.last_flush = time.monotonic()
                return
            rows = self.buffer
            self.buffer = []
            self.last_flush = time.monotonic()
        t0 = time.monotonic()
        try:
            self.sink.flush(rows)
        except Exception as e:
            print(f"[flush err] {e}", file=sys.stderr)
        dt_ms = (time.monotonic() - t0) * 1000
        print(f"[flush] reason={reason} rows={len(rows)} took={dt_ms:.1f}ms "
              f"sink_total={self.sink.total}")

    # ---- sender ----
    def _send_one(self, dst_name: str, dst_ip: str):
        probe_seq = self.n_sent
        self.n_sent += 1

        # Fixed sport, seq walks by SEQ_STEP per probe with natural 32-bit wrap.
        sport = self.args.sport
        tcp_seq = self._seq_cursor
        self._seq_cursor = (self._seq_cursor + SEQ_STEP) & 0xffffffff
        ack_expected = (tcp_seq + 1) & 0xffffffff

        pkt = IP(src=self.src_ip, dst=dst_ip) / \
              TCP(sport=sport, dport=self.args.dport, flags="S",
                  seq=tcp_seq, window=64240,
                  options=[("MSS", 1460)])

        send_wall = time.time()
        send_mono = time.monotonic_ns()

        key = (dst_ip, self.args.dport, sport, ack_expected)
        with self.pending_lock:
            # if same key still present (e.g. sport reused before old TTL),
            # overwrite — the old one already had its outcome recorded.
            self.pending[key] = {
                "send_mono_ns": send_mono,
                "send_wall":    send_wall,
                "sport":        sport,
                "dst":          dst_name,
                "dst_addr":     dst_ip,
                "probe_seq":    probe_seq,
                "deadline_ns":  send_mono + self.args.timeout_ms * 1_000_000,
                "matched":      False,
                "match_mono":   0,
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
            slept = 0.0
            while slept < interval and not self.stop_flag:
                dt_s = min(0.1, interval - slept)
                time.sleep(dt_s)
                slept += dt_s

    def _sweep_pending(self):
        """(a) mark unmatched entries past deadline as timeout, enqueue loss row
           (b) evict matched entries older than MATCHED_TTL_S."""
        now_ns  = time.monotonic_ns()
        ttl_ns  = int(MATCHED_TTL_S * 1e9)
        expired_timeouts = []
        with self.pending_lock:
            for k in list(self.pending.keys()):
                v = self.pending[k]
                if v["matched"]:
                    if now_ns - v["match_mono"] >= ttl_ns:
                        del self.pending[k]
                else:
                    if now_ns >= v["deadline_ns"]:
                        expired_timeouts.append(v)
                        del self.pending[k]
        for v in expired_timeouts:
            self.n_timeout += 1
            self._enqueue_row(
                ts_iso    = iso_utc(v["send_wall"]),
                dst       = v["dst"],
                dst_ip    = v["dst_addr"],
                probe_seq = v["probe_seq"],
                rtt_ms    = None,
                ok        = False,
            )
            if self.args.verbose:
                print(f"[to]  {v['dst']:<12} sport={v['sport']} "
                      f"seq={v['probe_seq']} TIMEOUT")

    # ---- main poll loop ----
    def run(self):
        self.bpf_setup()

        t = threading.Thread(target=self._sender_loop, name="sender",
                             daemon=True)
        t.start()

        def _sig(_signum, _frame):
            self.stop_flag = True
        signal.signal(signal.SIGINT,  _sig)
        signal.signal(signal.SIGTERM, _sig)

        print(f"[info] daemon started. src={self.src_name}({self.src_ip}) "
              f"targets={[x[0] for x in self.args.target]} "
              f"interval={self.args.interval_ms}ms "
              f"timeout={self.args.timeout_ms}ms "
              f"sink={self.args.sink} "
              f"batch_size={self.args.batch_size} "
              f"batch_interval={self.args.batch_interval_s}s")

        last_stat  = time.monotonic()
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
                    self._sweep_pending()
                    last_sweep = now
                if now - self.last_flush >= self.args.batch_interval_s:
                    self._flush("batch-interval")
                if now - last_stat >= 5.0:
                    with self.buffer_lock:
                        buf_n = len(self.buffer)
                    with self.pending_lock:
                        pend_n = len(self.pending)
                    print(f"[stat] sent={self.n_sent} matched={self.n_matched} "
                          f"timeout={self.n_timeout} "
                          f"sa_retrans={self.n_sa_retrans} "
                          f"sa_orphan={self.n_sa_orphan} "
                          f"pending={pend_n} buffer={buf_n} "
                          f"flushed={self.sink.total}")
                    last_stat = now
        finally:
            self.stop_flag = True
            t.join(timeout=2.0)
            # final sweep — count remaining unmatched as timeout
            with self.pending_lock:
                remaining = [v for v in self.pending.values()
                             if not v["matched"]]
                self.pending.clear()
            for v in remaining:
                self.n_timeout += 1
                self._enqueue_row(
                    ts_iso    = iso_utc(v["send_wall"]),
                    dst       = v["dst"],
                    dst_ip    = v["dst_addr"],
                    probe_seq = v["probe_seq"],
                    rtt_ms    = None,
                    ok        = False,
                )
            self._flush("shutdown")
            self.sink.close()
            self.bpf_teardown()
            print(f"[done] sent={self.n_sent} matched={self.n_matched} "
                  f"timeout={self.n_timeout} "
                  f"sa_retrans={self.n_sa_retrans} "
                  f"sa_orphan={self.n_sa_orphan} "
                  f"flushed_total={self.sink.total}")


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
    ap.add_argument("--sport", type=int, default=DEFAULT_SPORT,
                    help=f"fixed source port for every SYN; must equal "
                         f"PROBE_PORT ({PROBE_PORT}) so XDP catches replies. "
                         f"default {DEFAULT_SPORT}")
    ap.add_argument("--src-name", required=True,
                    help="business label for this probe host, written to "
                         "probe_sample.src (e.g. 'bangkok'). REQUIRED: we "
                         "refuse to fall back to socket.gethostname() because "
                         "the OS hostname is not a business identity.")
    ap.add_argument("--interval-ms", type=int, default=1000,
                    help="delay between successive SYNs across all targets")
    ap.add_argument("--timeout-ms", type=int, default=3000,
                    help="mark probe as loss if no SA within this window")
    ap.add_argument("--duration-s", type=int, default=0,
                    help="stop after N seconds (0 = run until ctrl-c)")

    ap.add_argument("--sink", choices=["pg", "stdout"], default="pg")
    ap.add_argument("--pg-dsn",
                    default=os.environ.get("PROBE_PG_DSN", ""),
                    help="Postgres DSN; also read from $PROBE_PG_DSN")
    ap.add_argument("--batch-size", type=int, default=1000,
                    help="flush when buffer reaches this many rows")
    ap.add_argument("--batch-interval-s", type=int, default=300,
                    help="flush at least every N seconds even if buffer small")

    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root (XDP + raw send)", file=sys.stderr)
        sys.exit(1)

    if not (args.sport == PROBE_PORT):
        print(f"--sport={args.sport} does not match XDP PROBE_PORT "
              f"({PROBE_PORT}); XDP will NOT catch replies and leaf will "
              f"see hub-kernel RSTs. refuse to start.",
              file=sys.stderr)
        sys.exit(2)

    ProbeDaemon(args).run()


if __name__ == "__main__":
    main()
