/* probe_xdp.bpf.c — Step 3: filter + drop probe SYN-ACKs.
 *
 * Role in the probe pipeline:
 *   hub sends SYN from an ephemeral src port in [65408..65423] toward leaf:22
 *   leaf's TCP stack replies with SYN|ACK (leaf:22 -> hub:65408..65423)
 *   this XDP prog intercepts that inbound SYN|ACK, emits a probe_event, and
 *   returns XDP_DROP so hub's own TCP stack never sees the SA and therefore
 *   never sends a RST back — leaf's half-open queue drains normally on its
 *   own timeout, ssh stays untouched.
 *
 * Match criteria (ALL must hold):
 *   - IPv4 + TCP
 *   - dport (host order) in [65408, 65423]  (hub-side ephemeral, sysctl-reserved)
 *   - flags & (SYN|ACK|RST) == (SYN|ACK)    (proper SA, not RST, not just ACK)
 *
 * Anything else -> XDP_PASS. In particular:
 *   - RST packets (even inside the port window) pass through, so if the peer
 *     ever sends RST we still see it via normal tools (tcpdump/netstat) for
 *     diagnosis; XDP is not silently eating diagnostic signal.
 *   - ssh, metadata, DNS, and every other flow is untouched.
 *
 * saddr allowlist for the 3 leaf IPs is intentionally NOT enforced here.
 * The 16 reserved ports are ours exclusively, so any SA landing on them
 * must be a response to our probe.
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

    /* --- Step 3 filter: only probe SYN-ACKs get intercepted. --- */

    /* dport window: hub-side ephemeral ports reserved via ip_local_reserved_ports.
     * tcp->dest is network byte order; compare in host order for readability. */
    __u16 dport_h = bpf_ntohs(tcp->dest);
    if (dport_h < 65408 || dport_h > 65423)
        return XDP_PASS;

    /* Assemble the 6-bit flag byte once; reuse below when writing the event. */
    __u8 flags = 0;
    if (tcp->fin) flags |= 0x01;
    if (tcp->syn) flags |= 0x02;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;
    if (tcp->ack) flags |= 0x10;
    if (tcp->urg) flags |= 0x20;

    /* Must be exactly SYN|ACK (with RST clear). Other combos (pure ACK, RST,
     * FIN, etc.) fall through so they remain visible to tcpdump for diag. */
    if ((flags & (0x02 | 0x10 | 0x04)) != (0x02 | 0x10))
        return XDP_PASS;

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

    /* Swallow the SA so hub's TCP stack never sees it and never generates a
     * RST back to leaf. That is the whole point of this program. */
    return XDP_DROP;
}
