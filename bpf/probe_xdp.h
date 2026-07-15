/* probe_xdp.h — shared event layout for BPF <-> userspace ringbuf.
 *
 * IMPORTANT: any change here must be mirrored in Python's struct.unpack
 * format string in hub_probe/probe_daemon.py (EVENT_FMT / EVENT_SIZE).
 *
 * v2 (2026-07): unified v4/v6 layout. saddr/daddr are always 16 bytes:
 *   - IPv4: first 4 bytes hold the address in NETWORK byte order, remaining
 *           12 bytes are zero.
 *   - IPv6: all 16 bytes hold the address in NETWORK byte order.
 * The ip_ver field (4 or 6) tells userspace how to interpret them.
 *
 * All multi-byte integer fields are in NETWORK byte order for the network
 * identifiers (saddr/daddr/sport/dport/seq/ack_seq), because BPF reads them
 * directly from packet headers without byte-swapping. Userspace is responsible
 * for ntohl / ntohs when displaying.
 *
 * ts_ns is host byte order (bpf_ktime_get_ns, monotonic since boot).
 *
 * Field offsets (must stay natural-aligned so no implicit C padding creeps in):
 *   0   u64 ts_ns
 *   8   u8  ip_ver
 *   9   u8  tcp_flags
 *   10  u8  _pad0[2]
 *   12  u16 sport
 *   14  u16 dport
 *   16  u32 seq
 *   20  u32 ack_seq
 *   24  u8  saddr[16]
 *   40  u8  daddr[16]
 *   56  end
 * Total = 56 bytes, 8B aligned.
 */
#ifndef PROBE_XDP_H
#define PROBE_XDP_H

struct probe_event {
    __u64 ts_ns;         /* bpf_ktime_get_ns() — monotonic, host byte order   */
    __u8  ip_ver;        /* 4 or 6                                            */
    __u8  tcp_flags;     /* raw TCP flag byte (URG|ACK|PSH|RST|SYN|FIN bits)  */
    __u8  _pad0[2];      /* explicit padding to align sport/dport             */
    __u16 sport;         /* source TCP port (network byte order) — leaf side  */
    __u16 dport;         /* dest   TCP port (network byte order) — hub  side  */
    __u32 seq;           /* TCP seq     (network byte order)                  */
    __u32 ack_seq;       /* TCP ack_seq (network byte order)                  */
    __u8  saddr[16];     /* v4: first 4B valid, rest 0. v6: all 16B.  NBO.    */
    __u8  daddr[16];     /* same convention as saddr                          */
};

#endif /* PROBE_XDP_H */
