/* probe_xdp.h — shared event layout for BPF <-> userspace ringbuf.
 *
 * IMPORTANT: any change here must be mirrored in Python's struct.unpack
 * format string in hub_probe/test_loader.py (currently "<QIIHHIIB3x", 32B).
 *
 * All multi-byte integer fields are in NETWORK byte order for the network
 * identifiers (saddr/daddr/sport/dport/seq/ack_seq), because BPF reads them
 * directly from packet headers without byte-swapping. Userspace is responsible
 * for ntohl / ntohs when displaying.
 *
 * ts_ns is host byte order (bpf_ktime_get_ns, monotonic since boot).
 */
#ifndef PROBE_XDP_H
#define PROBE_XDP_H

struct probe_event {
    __u64 ts_ns;      /* bpf_ktime_get_ns() — monotonic, host byte order   */
    __u32 saddr;      /* source IPv4 (network byte order) — leaf IP        */
    __u32 daddr;      /* dest   IPv4 (network byte order) — hub  IP        */
    __u16 sport;      /* source TCP port (network byte order) — leaf side  */
    __u16 dport;      /* dest   TCP port (network byte order) — hub  side  */
    __u32 seq;        /* TCP seq     (network byte order)                  */
    __u32 ack_seq;    /* TCP ack_seq (network byte order)                  */
    __u8  tcp_flags;  /* raw TCP flag byte (URG|ACK|PSH|RST|SYN|FIN bits)  */
    __u8  _pad[3];    /* explicit padding — struct is exactly 32 bytes     */
};

#endif /* PROBE_XDP_H */
