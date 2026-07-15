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
#     --target hongkong=43.132.210.4,2402:xxxx::1 \
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
import select
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
from scapy.all import IP, IPv6, TCP, send as scapy_send  # noqa: E402

# ---------- constants shared with BPF ----------
# v2 (2026-07): unified v4/v6 layout, 56 bytes. Must match struct probe_event
# in bpf/probe_xdp.h exactly.
#   <  little-endian, no padding
#   Q  u64 ts_ns
#   B  u8  ip_ver     (4 or 6)
#   B  u8  tcp_flags
#   2x _pad0[2]
#   H  u16 sport      (network byte order)
#   H  u16 dport      (network byte order)
#   I  u32 seq        (network byte order)
#   I  u32 ack_seq    (network byte order)
#  16s saddr[16]      (network byte order; v4 uses first 4, rest 0)
#  16s daddr[16]      (same)
EVENT_FMT  = "<QBB2xHHII16s16s"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 56, f"EVENT_SIZE={EVENT_SIZE}, expected 56"


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
    """`name=ip[,ip]` -> (name, ipv4_or_None, ipv6_or_None).

    Accepted forms:
        hongkong=1.2.3.4
        hongkong=2402:xxxx::1
        hongkong=1.2.3.4,2402:xxxx::1
        hongkong=2402:xxxx::1,1.2.3.4       (order-agnostic)
    At least one address must be present. IPv6 addresses containing '::' or
    hex groups are auto-detected via ipaddress.ip_address.
    """
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"target must be name=ip[,ip], got: {spec}")
    name, addrs = spec.split("=", 1)
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError(f"empty name in: {spec}")
    v4 = None
    v6 = None
    for part in addrs.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            ip = ipaddress.ip_address(p)
        except ValueError:
            raise argparse.ArgumentTypeError(f"bad ip in {spec}: {p}")
        if isinstance(ip, ipaddress.IPv4Address):
            if v4 is not None:
                raise argparse.ArgumentTypeError(
                    f"two IPv4 addrs in {spec}")
            v4 = str(ip)
        else:
            if v6 is not None:
                raise argparse.ArgumentTypeError(
                    f"two IPv6 addrs in {spec}")
            v6 = str(ip)
    if v4 is None and v6 is None:
        raise argparse.ArgumentTypeError(f"no addr in: {spec}")
    return (name, v4, v6)

def local_ip_for(target_ip: str, family: int) -> str:
    """Discover the local egress IP for reaching target_ip.
    family = socket.AF_INET or socket.AF_INET6."""
    s = socket.socket(family, socket.SOCK_DGRAM)
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

        # Expand targets into a flat list of (name, family, dst_ip, proto)
        # pairs. Sender loop round-robins through this list, so a target
        # that has both v4 and v6 gets both probed on independent rows in
        # PG, and for each family we also emit an ICMP echo probe alongside
        # the TCP SYN probe. proto is one of:
        #   'tcp_synack'  - hub sends SYN, XDP catches SA on ringbuf
        #   'icmp'        - raw ICMP echo request (v4 wire) or ICMPv6 echo
        #                   request (v6 wire); the ip_ver column already
        #                   distinguishes the two, so we keep proto='icmp'
        #                   for both families rather than encoding the wire
        #                   version twice.
        self.pairs = []           # list[(name, family:int, dst_ip:str, proto:str)]
        first_v4 = None
        first_v6 = None
        for (name, v4, v6) in args.target:
            if v4:
                self.pairs.append((name, socket.AF_INET,  v4, "tcp_synack"))
                self.pairs.append((name, socket.AF_INET,  v4, "icmp"))
                if first_v4 is None: first_v4 = v4
            if v6:
                self.pairs.append((name, socket.AF_INET6, v6, "tcp_synack"))
                self.pairs.append((name, socket.AF_INET6, v6, "icmp"))
                if first_v6 is None: first_v6 = v6
        if not self.pairs:
            raise RuntimeError("no probe pairs after target expansion")

        # Discover local egress addresses. We look each family up ONCE at
        # startup — the hub has a single uplink of each kind (eth0 + wg).
        self.src_ip_v4 = local_ip_for(first_v4, socket.AF_INET) \
                         if first_v4 else None
        self.src_ip_v6 = local_ip_for(first_v6, socket.AF_INET6) \
                         if first_v6 else None

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
        self.n_icmp_orphan = 0  # ICMP echo reply without matching in-flight

        # ICMP echo identifier: 16-bit, tied to process PID (traditional
        # ping(8) convention). Fixed for the process lifetime; probes are
        # distinguished by the 16-bit sequence number.
        self.icmp_id = os.getpid() & 0xffff
        self._icmp_seq_v4 = 0   # walks 0..65535, wraps naturally
        self._icmp_seq_v6 = 0

        # raw sockets for ICMP send+recv. Populated in icmp_setup().
        self.icmp4_sock = None
        self.icmp6_sock = None
        self._icmp_rx_thread = None

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
        (ts_ns_mono, ip_ver, fl, sp_be, dp_be, seq_be, ack_be,
         sa_bytes, da_bytes) = struct.unpack(EVENT_FMT, raw)

        # Decode source address per ip_ver. v4 uses first 4 bytes of the 16B
        # slot; v6 uses all 16. saddr on the wire is the leaf's IP. XDP only
        # ever hands us TCP replies (it filters by dport=PROBE_PORT), so proto
        # is always tcp_synack here.
        if ip_ver == 4:
            sa_src_ip = socket.inet_ntop(socket.AF_INET, sa_bytes[:4])
        elif ip_ver == 6:
            sa_src_ip = socket.inet_ntop(socket.AF_INET6, sa_bytes)
        else:
            # unknown ip_ver — ignore
            return 0
        proto = "tcp_synack"

        # SA fields on the wire are (leaf_ip, leaf_sport=22, hub_ip, hub_dport,
        # seq=leaf_isn, ack_seq=hub_isn+1). We keyed pending by the SYN we
        # sent: (proto, ip_ver, dst_ip=leaf_ip, dport=leaf_port=22,
        #        sport=hub_port, ack_expected=hub_isn+1). Note ip_ver comes
        # straight from the BPF event, so v4 and v6 keys are disjoint.
        sa_src_port = socket.ntohs(sp_be)
        sa_dst_port = socket.ntohs(dp_be)
        ack_host    = socket.ntohl(ack_be) & 0xffffffff
        key = (proto, int(ip_ver), sa_src_ip, sa_src_port, sa_dst_port,
               ack_host)

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
            proto   = "tcp_synack",
            ip_ver  = int(ip_ver),
            probe_seq = row["probe_seq"],
            rtt_ms  = int(round(rtt_ms)),
            ok      = True,
        )

        if self.args.verbose:
            print(f"[rtt] tcp v{int(ip_ver)} {row['dst']:<12} sport={row['sport']} "
                  f"seq={row['probe_seq']} rtt={rtt_ms:.2f}ms")
        return 0

    # ---- buffer / flush ----
    def _enqueue_row(self, *, ts_iso, dst, dst_ip, proto, ip_ver, probe_seq,
                     rtt_ms, ok):
        row = (ts_iso, self.src_name, dst, dst_ip,
               proto, int(ip_ver), probe_seq, rtt_ms, ok,
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

    # ---- sender: TCP SYN branch ----
    def _send_one_tcp(self, dst_name: str, family: int, dst_ip: str):
        probe_seq = self.n_sent
        self.n_sent += 1

        # Fixed sport, seq walks by SEQ_STEP per probe with natural 32-bit wrap.
        sport = self.args.sport
        tcp_seq = self._seq_cursor
        self._seq_cursor = (self._seq_cursor + SEQ_STEP) & 0xffffffff
        ack_expected = (tcp_seq + 1) & 0xffffffff

        if family == socket.AF_INET:
            ip_ver = 4
            src_ip = self.src_ip_v4
            l3 = IP(src=src_ip, dst=dst_ip)
        elif family == socket.AF_INET6:
            ip_ver = 6
            src_ip = self.src_ip_v6
            l3 = IPv6(src=src_ip, dst=dst_ip)
        else:
            raise RuntimeError(f"unsupported family: {family}")

        pkt = l3 / TCP(sport=sport, dport=self.args.dport, flags="S",
                       seq=tcp_seq, window=64240,
                       options=[("MSS", 1460)])

        send_wall = time.time()
        send_mono = time.monotonic_ns()

        # Key MUST match what _on_event builds when a reply arrives.
        # (proto, ip_ver) prefix keeps v4/v6/icmp key spaces disjoint.
        key = ("tcp_synack", ip_ver, dst_ip, self.args.dport, sport,
               ack_expected)
        with self.pending_lock:
            # if same key still present (e.g. sport reused before old TTL),
            # overwrite — the old one already had its outcome recorded.
            self.pending[key] = {
                "proto":        "tcp_synack",
                "send_mono_ns": send_mono,
                "send_wall":    send_wall,
                "sport":        sport,
                "dst":          dst_name,
                "dst_addr":     dst_ip,
                "ip_ver":       ip_ver,
                "probe_seq":    probe_seq,
                "deadline_ns":  send_mono + self.args.timeout_ms * 1_000_000,
                "matched":      False,
                "match_mono":   0,
            }

        scapy_send(pkt, iface=self.args.iface, verbose=0)
        if self.args.verbose:
            print(f"[tx]  tcp v{ip_ver} {dst_name:<12} sport={sport} "
                  f"seq={probe_seq} tcp_seq={tcp_seq:#010x}")

    # ---- sender: ICMP echo branch ----
    @staticmethod
    def _icmp_checksum(data: bytes) -> int:
        """Standard Internet 16-bit one's-complement sum (RFC 1071).
        Used for ICMPv4. For ICMPv6 the kernel fills in the checksum
        automatically on raw sockets, so we send 0 there."""
        if len(data) & 1:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i+1]
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return (~s) & 0xffff

    def _send_one_icmp(self, dst_name: str, family: int, dst_ip: str):
        """Send one ICMP (v4) or ICMPv6 echo request via raw socket.

        Reply is caught by the icmp rx thread (_icmp_rx_loop) which decodes
        the echo identifier + sequence to match against self.pending.
        """
        probe_seq = self.n_sent
        self.n_sent += 1

        if family == socket.AF_INET:
            ip_ver = 4
            proto  = "icmp"
            sock   = self.icmp4_sock
            icmp_type = 8            # ICMP echo request
            seq = self._icmp_seq_v4
            self._icmp_seq_v4 = (self._icmp_seq_v4 + 1) & 0xffff
        elif family == socket.AF_INET6:
            ip_ver = 6
            # proto stays 'icmp' regardless of wire family; ip_ver=6
            # already tells downstream (PG rows / grafana filters) that
            # this is ICMPv6 on the wire.
            proto  = "icmp"
            sock   = self.icmp6_sock
            icmp_type = 128          # ICMPv6 echo request
            seq = self._icmp_seq_v6
            self._icmp_seq_v6 = (self._icmp_seq_v6 + 1) & 0xffff
        else:
            raise RuntimeError(f"unsupported family: {family}")

        # 8B ICMP header + 8B payload (send_mono_ns as timestamp is not
        # strictly needed since we look it up in self.pending, but a bit of
        # payload makes the packet look like a normal ping to any middle
        # box). Keep it small; MTU is not a concern at 16 bytes.
        payload = b"vpsprobe"
        header = struct.pack("!BBHHH", icmp_type, 0, 0, self.icmp_id, seq)
        if family == socket.AF_INET:
            csum = self._icmp_checksum(header + payload)
            header = struct.pack("!BBHHH", icmp_type, 0, csum,
                                 self.icmp_id, seq)
        # else: kernel fills icmpv6 checksum (IPV6_CHECKSUM=2 default on
        # SOCK_RAW+IPPROTO_ICMPV6).
        pkt = header + payload

        send_wall = time.time()
        send_mono = time.monotonic_ns()

        # Key: (proto, ip_ver, dst_ip, icmp_id, seq). ICMP has no ports;
        # (id, seq) uniquely identifies an in-flight echo.
        key = (proto, ip_ver, dst_ip, self.icmp_id, seq)
        with self.pending_lock:
            self.pending[key] = {
                "proto":        proto,
                "send_mono_ns": send_mono,
                "send_wall":    send_wall,
                "sport":        self.icmp_id,   # for log symmetry with tcp
                "dst":          dst_name,
                "dst_addr":     dst_ip,
                "ip_ver":       ip_ver,
                "probe_seq":    probe_seq,
                "deadline_ns":  send_mono + self.args.timeout_ms * 1_000_000,
                "matched":      False,
                "match_mono":   0,
            }

        try:
            if family == socket.AF_INET:
                sock.sendto(pkt, (dst_ip, 0))
            else:
                sock.sendto(pkt, (dst_ip, 0, 0, 0))
        except OSError as e:
            # e.g. EPERM / ENETUNREACH — mark this probe as failed immediately
            # so it doesn't linger until timeout, and don't leak the pending
            # entry.
            with self.pending_lock:
                self.pending.pop(key, None)
            self._enqueue_row(
                ts_iso    = iso_utc(send_wall),
                dst       = dst_name,
                dst_ip    = dst_ip,
                proto     = proto,
                ip_ver    = ip_ver,
                probe_seq = probe_seq,
                rtt_ms    = None,
                ok        = False,
            )
            if self.args.verbose:
                print(f"[tx err] {proto} v{ip_ver} {dst_name} {dst_ip}: {e}")
            return

        if self.args.verbose:
            print(f"[tx]  {proto:<7} v{ip_ver} {dst_name:<12} id={self.icmp_id} "
                  f"seq={seq} probe_seq={probe_seq}")

    def _sender_loop(self):
        interval = self.args.interval_ms / 1000.0
        end = time.monotonic() + self.args.duration_s if self.args.duration_s > 0 else None
        i = 0
        while not self.stop_flag:
            if end and time.monotonic() >= end:
                print("[info] --duration-s reached, stopping sender")
                self.stop_flag = True
                break
            dst_name, family, dst_ip, proto = self.pairs[i % len(self.pairs)]
            try:
                if proto == "tcp_synack":
                    self._send_one_tcp(dst_name, family, dst_ip)
                else:
                    self._send_one_icmp(dst_name, family, dst_ip)
            except Exception as e:
                print(f"[send err] {proto} {dst_name} {dst_ip}: {e}")
            i += 1
            slept = 0.0
            while slept < interval and not self.stop_flag:
                dt_s = min(0.1, interval - slept)
                time.sleep(dt_s)
                slept += dt_s

    # ---- ICMP rx: independent thread, blocks on select() over v4+v6 raw ----
    def icmp_setup(self):
        """Open v4/v6 ICMP raw sockets if the target list needs them.
        Only opens the families that actually have probes queued.

        Both v4 and v6 icmp probes carry proto='icmp' in the pending map
        and in PG (ip_ver distinguishes them); we tell the two families
        apart here by looking at the (family, proto) pair from the
        expanded target list."""
        need_v4 = any(f == socket.AF_INET  and p == "icmp"
                      for (_, f, _, p) in self.pairs)
        need_v6 = any(f == socket.AF_INET6 and p == "icmp"
                      for (_, f, _, p) in self.pairs)
        if need_v4:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_ICMP)
            s.setblocking(False)
            self.icmp4_sock = s
        if need_v6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                              socket.IPPROTO_ICMPV6)
            s.setblocking(False)
            self.icmp6_sock = s
        print(f"[icmp] raw sockets: v4={'yes' if self.icmp4_sock else 'no'} "
              f"v6={'yes' if self.icmp6_sock else 'no'} id={self.icmp_id}")

    def icmp_teardown(self):
        for s in (self.icmp4_sock, self.icmp6_sock):
            try:
                if s: s.close()
            except Exception:
                pass
        self.icmp4_sock = None
        self.icmp6_sock = None

    def _handle_icmp_reply(self, family: int, buf: bytes, src_ip: str):
        """Parse one ICMP/ICMPv6 datagram and, if it's an echo reply that
        matches an in-flight probe, record RTT.

        On AF_INET raw sockets, the kernel hands us the full IP header + ICMP
        payload. On AF_INET6 raw sockets, the kernel strips the IPv6 header
        and we get the ICMPv6 packet directly. That asymmetry is a Linux
        quirk we accommodate here.
        """
        recv_mono = time.monotonic_ns()
        if family == socket.AF_INET:
            if len(buf) < 20:
                return
            ihl = (buf[0] & 0x0f) * 4
            if len(buf) < ihl + 8:
                return
            icmp = buf[ihl:]
            icmp_type = icmp[0]
            if icmp_type != 0:       # 0 = echo reply
                return
            ident, seq = struct.unpack("!HH", icmp[4:8])
            proto = "icmp"
            ip_ver = 4
        else:
            if len(buf) < 8:
                return
            icmp_type = buf[0]
            if icmp_type != 129:     # 129 = ICMPv6 echo reply
                return
            ident, seq = struct.unpack("!HH", buf[4:8])
            # See icmp_setup docstring: v6 icmp probes are also stored as
            # proto='icmp'; ip_ver=6 is what disambiguates them from v4.
            proto = "icmp"
            ip_ver = 6

        if ident != self.icmp_id:
            # Reply for a different process/instance; ignore.
            return

        key = (proto, ip_ver, src_ip, self.icmp_id, seq)
        with self.pending_lock:
            row = self.pending.get(key)
            if row is None:
                self.n_icmp_orphan += 1
                return
            if row.get("matched"):
                # Duplicate reply for the same (id, seq) — rare but possible
                # if a middle box duplicates the packet. Count as retrans-ish
                # under sa_retrans bucket to keep stat surface small.
                self.n_sa_retrans += 1
                return
            row["matched"]    = True
            row["match_mono"] = recv_mono

        rtt_ns = recv_mono - row["send_mono_ns"]
        rtt_ms = rtt_ns / 1e6
        self.n_matched += 1
        self._enqueue_row(
            ts_iso    = iso_utc(row["send_wall"]),
            dst       = row["dst"],
            dst_ip    = row["dst_addr"],
            proto     = proto,
            ip_ver    = ip_ver,
            probe_seq = row["probe_seq"],
            rtt_ms    = int(round(rtt_ms)),
            ok        = True,
        )
        if self.args.verbose:
            print(f"[rtt] {proto:<7} v{ip_ver} {row['dst']:<12} "
                  f"id={self.icmp_id} seq={seq} rtt={rtt_ms:.2f}ms")

    def _icmp_rx_loop(self):
        socks = []
        if self.icmp4_sock is not None: socks.append(self.icmp4_sock)
        if self.icmp6_sock is not None: socks.append(self.icmp6_sock)
        if not socks:
            return
        while not self.stop_flag:
            try:
                r, _, _ = select.select(socks, [], [], 0.3)
            except (OSError, ValueError):
                # socket closed during shutdown
                break
            for s in r:
                try:
                    data, addr = s.recvfrom(2048)
                except BlockingIOError:
                    continue
                except OSError:
                    continue
                family = s.family
                src_ip = addr[0] if addr else ""
                try:
                    self._handle_icmp_reply(family, data, src_ip)
                except Exception as e:
                    print(f"[icmp rx err] {e}", file=sys.stderr)

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
                proto     = v["proto"],
                ip_ver    = v["ip_ver"],
                probe_seq = v["probe_seq"],
                rtt_ms    = None,
                ok        = False,
            )
            if self.args.verbose:
                print(f"[to]  {v['proto']:<7} v{v['ip_ver']} {v['dst']:<12} "
                      f"sport={v['sport']} seq={v['probe_seq']} TIMEOUT")

    # ---- main poll loop ----
    def run(self):
        self.bpf_setup()
        self.icmp_setup()

        t = threading.Thread(target=self._sender_loop, name="sender",
                             daemon=True)
        t.start()

        rx_t = None
        if self.icmp4_sock is not None or self.icmp6_sock is not None:
            rx_t = threading.Thread(target=self._icmp_rx_loop,
                                    name="icmp_rx", daemon=True)
            rx_t.start()
            self._icmp_rx_thread = rx_t

        def _sig(_signum, _frame):
            self.stop_flag = True
        signal.signal(signal.SIGINT,  _sig)
        signal.signal(signal.SIGTERM, _sig)

        pair_summary = ",".join(
            f"{n}/v{4 if f == socket.AF_INET else 6}/{p}"
            for (n, f, _ip, p) in self.pairs
        )
        print(f"[info] daemon started. src={self.src_name} "
              f"v4={self.src_ip_v4} v6={self.src_ip_v6} "
              f"pairs=[{pair_summary}] "
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
                          f"icmp_orphan={self.n_icmp_orphan} "
                          f"pending={pend_n} buffer={buf_n} "
                          f"flushed={self.sink.total}")
                    last_stat = now
        finally:
            self.stop_flag = True
            t.join(timeout=2.0)
            if rx_t is not None:
                rx_t.join(timeout=2.0)
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
                    proto     = v["proto"],
                    ip_ver    = v["ip_ver"],
                    probe_seq = v["probe_seq"],
                    rtt_ms    = None,
                    ok        = False,
                )
            self._flush("shutdown")
            self.sink.close()
            self.icmp_teardown()
            self.bpf_teardown()
            print(f"[done] sent={self.n_sent} matched={self.n_matched} "
                  f"timeout={self.n_timeout} "
                  f"sa_retrans={self.n_sa_retrans} "
                  f"sa_orphan={self.n_sa_orphan} "
                  f"icmp_orphan={self.n_icmp_orphan} "
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
                    help="one or more name=ip[,ip] targets. Each may specify "
                         "an IPv4, an IPv6, or both (comma-separated). "
                         "Example: hongkong=1.2.3.4,2402:xxxx::1")
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
    ap.add_argument("--batch-interval-s", type=int, default=60,
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
