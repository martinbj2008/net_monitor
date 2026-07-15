/* probe_xdp.bpf.c — Step 3: filter + drop every inbound TCP packet whose
 *                   dport falls into the hub's reserved probe window.
 *
 * Role in the probe pipeline:
 *   hub sends SYN from a single reserved src port (65535) toward leaf:22
 *   leaf's TCP stack replies with something (SYN|ACK on happy path, but also
 *   possibly RST|ACK / RST / retransmitted SA / etc. depending on the leaf's
 *   half-open state, e.g. when we send several SYNs from the same sport with
 *   jumping seq numbers). We do NOT try to be clever about the flag byte in
 *   the kernel: userspace matches on ack_seq == our_syn_seq+1 anyway, so any
 *   reply landing on the right dport with the right ack is by definition our
 *   probe's echo. Filtering on flags here would only lose signal in the
 *   edge cases we specifically want to measure.
 *
 * Match criteria (ALL must hold):
 *   - IPv4 + TCP
 *   - dport (host order) == 65535  (hub-side sysctl-reserved probe port)
 *
 * On match:
 *   - Emit a probe_event on the ringbuf with the raw TCP flag byte, seq,
 *     ack_seq, and 4-tuple. Userspace does the ack_seq bookkeeping.
 *   - Return XDP_DROP so hub's own TCP stack never sees the reply and never
 *     emits anything (RST, challenge-ACK, etc.) back to the leaf. That keeps
 *     the leaf's half-open bookkeeping undisturbed and lets us safely probe
 *     with the same sport across multiple SYNs.
 *
 * Port 65535 is ours exclusively (sysctl ip_local_reserved_ports plus
 * firewalled outbound), so any TCP hitting it is a probe reply.
 */
#include "vmlinux.h"          /* CO-RE kernel types via BTF                */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "probe_xdp.h"

/* vmlinux.h contains only struct/typedef, not uapi #defines. Provide the
 * few constants we need explicitly so we don't drag in <linux/*.h>. */
#ifndef ETH_P_IP
#define ETH_P_IP        0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6
#endif
#ifndef XDP_PASS
#define XDP_PASS        2
#endif
#ifndef XDP_DROP
#define XDP_DROP        1
#endif

char LICENSE[] SEC("license") = "GPL";

/* 256 KB ringbuf — at ~8 pps * 24 B = 200 B/s this holds ~20 min of events.
 * Must be a power of two and a multiple of the page size. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("xdp")
int probe_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* IPv4 options: skip via ihl */
    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip))
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl_bytes;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* --- Step 3 filter: single dport only. Flag combos are all captured. --- */

    /* dport: hub-side probe port reserved via ip_local_reserved_ports.
     * tcp->dest is network byte order; compare in host order for readability. */
    __u16 dport_h = bpf_ntohs(tcp->dest);
    if (dport_h != 65535)
        return XDP_PASS;

    /* Assemble the flag byte for reporting. We deliberately do NOT gate on
     * (SYN|ACK) vs (RST|ACK) etc. here — userspace matches on ack_seq and
     * the 4-tuple, so any TCP reply landing in this dport window with the
     * right ack is our probe's echo, regardless of flag combo. */
    __u8 flags = 0;
    if (tcp->fin) flags |= 0x01;
    if (tcp->syn) flags |= 0x02;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;
    if (tcp->ack) flags |= 0x10;
    if (tcp->urg) flags |= 0x20;

    /* Reserve on ringbuf. If full, drop the event (not the packet). */
    struct probe_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return XDP_PASS;

    ev->ts_ns     = bpf_ktime_get_ns();
    ev->saddr     = ip->saddr;         /* keep network byte order */
    ev->daddr     = ip->daddr;
    ev->sport     = tcp->source;
    ev->dport     = tcp->dest;
    ev->seq       = tcp->seq;
    ev->ack_seq   = tcp->ack_seq;
    ev->tcp_flags = flags;

    ev->_pad[0] = 0;
    ev->_pad[1] = 0;
    ev->_pad[2] = 0;

    bpf_ringbuf_submit(ev, 0);

    /* Swallow the reply so hub's TCP stack never sees it — the kernel must
     * not emit anything (RST, challenge-ACK, ...) back to the leaf. This is
     * what lets us safely probe the same sport multiple times without
     * corrupting the leaf's half-open queue. */
    return XDP_DROP;
}
