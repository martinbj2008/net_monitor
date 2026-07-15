/* probe_xdp.bpf.c — hub-side XDP: catch TCP replies on the reserved probe
 *                   port and drop them so the local TCP stack never emits
 *                   anything back to the leaf.
 *
 * v2 (2026-07): event layout unified for v4/v6 (see probe_xdp.h). Both the
 * IPv4 and IPv6 branches now write the 56B probe_event: ip_ver=4/6,
 * saddr/daddr memcpy'd into fixed 16-byte address slots (v4 uses first 4B).
 *
 * Match criteria for a probe reply (ALL must hold):
 *   - IPv4 or IPv6, next header = TCP
 *   - dport (host order) == 65535  (hub-side sysctl-reserved probe port)
 *
 * On match:
 *   - Emit a probe_event on the ringbuf. Userspace matches by ack_seq.
 *   - Return XDP_DROP so hub's TCP stack never sees the reply.
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
#ifndef ETH_P_IPV6
#define ETH_P_IPV6      0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP     6
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS   0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING  43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS  60
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE     59
#endif
#ifndef XDP_PASS
#define XDP_PASS        2
#endif
#ifndef XDP_DROP
#define XDP_DROP        1
#endif

#define PROBE_PORT      65535

/* Max IPv6 extension headers to walk before giving up. Real traffic almost
 * never chains more than 2; 8 is a safety ceiling that also keeps the BPF
 * verifier happy with a bounded loop. */
#define MAX_V6_EXTHDRS  8

char LICENSE[] SEC("license") = "GPL";

/* 256 KB ringbuf — at ~8 pps * 56 B = 450 B/s this holds ~10 min of events.
 * Must be a power of two and a multiple of the page size. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Assemble the TCP flag byte from bitfield members. Kept as a static helper
 * so both v4 and v6 branches share it. */
static __always_inline __u8 tcp_flag_byte(const struct tcphdr *tcp)
{
    __u8 f = 0;
    if (tcp->fin) f |= 0x01;
    if (tcp->syn) f |= 0x02;
    if (tcp->rst) f |= 0x04;
    if (tcp->psh) f |= 0x08;
    if (tcp->ack) f |= 0x10;
    if (tcp->urg) f |= 0x20;
    return f;
}

/* Returns 1 if nexthdr is an IPv6 extension header we know how to skip. */
static __always_inline int is_v6_exthdr(__u8 nh)
{
    return nh == IPPROTO_HOPOPTS  ||
           nh == IPPROTO_ROUTING  ||
           nh == IPPROTO_FRAGMENT ||
           nh == IPPROTO_DSTOPTS;
}

SEC("xdp")
int probe_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;

    /* ============================================================ IPv4 */
    if (h_proto == bpf_htons(ETH_P_IP)) {
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

        if (bpf_ntohs(tcp->dest) != PROBE_PORT)
            return XDP_PASS;

        struct probe_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (!ev)
            return XDP_PASS;

        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ts_ns     = bpf_ktime_get_ns();
        ev->ip_ver    = 4;
        ev->tcp_flags = tcp_flag_byte(tcp);
        ev->sport     = tcp->source;      /* keep NBO */
        ev->dport     = tcp->dest;
        ev->seq       = tcp->seq;
        ev->ack_seq   = tcp->ack_seq;
        __builtin_memcpy(ev->saddr, &ip->saddr, 4);
        __builtin_memcpy(ev->daddr, &ip->daddr, 4);

        bpf_ringbuf_submit(ev, 0);
        return XDP_DROP;
    }

    /* ============================================================ IPv6 */
    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        /* Walk any extension headers. IPv6 ext-hdr layout is:
         *   struct { u8 nexthdr; u8 hdrlen; u8 opts[6 + hdrlen*8]; }
         * except Fragment which is always 8 bytes. We only need to advance
         * `cursor` to the next header until we hit TCP (or bail). */
        __u8   nh  = ip6->nexthdr;
        void  *cur = (void *)(ip6 + 1);

        #pragma unroll
        for (int i = 0; i < MAX_V6_EXTHDRS; i++) {
            if (nh == IPPROTO_TCP)
                break;
            if (!is_v6_exthdr(nh))
                return XDP_PASS;

            /* Fragment header is a fixed 8 bytes and we don't try to
             * reassemble — a fragmented TCP SYN-ACK on the probe port is
             * something we'd rather ignore than half-parse. */
            if (nh == IPPROTO_FRAGMENT)
                return XDP_PASS;

            /* Generic ext hdr: read nexthdr(1B) + hdrlen(1B). Length in 8B
             * units, not counting the first 8 bytes. */
            struct { __u8 nexthdr; __u8 hdrlen; } *xh = cur;
            if ((void *)(xh + 1) > data_end)
                return XDP_PASS;
            __u32 sz = (xh->hdrlen + 1) * 8;
            /* Bound sz so verifier can prove pointer arithmetic stays sane. */
            if (sz > 256)
                return XDP_PASS;

            void *next = cur + sz;
            if (next > data_end)
                return XDP_PASS;
            nh  = xh->nexthdr;
            cur = next;
        }
        if (nh != IPPROTO_TCP)
            return XDP_PASS;

        struct tcphdr *tcp = cur;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (bpf_ntohs(tcp->dest) != PROBE_PORT)
            return XDP_PASS;

        struct probe_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (!ev)
            return XDP_PASS;

        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ts_ns     = bpf_ktime_get_ns();
        ev->ip_ver    = 6;
        ev->tcp_flags = tcp_flag_byte(tcp);
        ev->sport     = tcp->source;      /* keep NBO */
        ev->dport     = tcp->dest;
        ev->seq       = tcp->seq;
        ev->ack_seq   = tcp->ack_seq;
        __builtin_memcpy(ev->saddr, &ip6->saddr, 16);
        __builtin_memcpy(ev->daddr, &ip6->daddr, 16);

        bpf_ringbuf_submit(ev, 0);
        return XDP_DROP;
    }

    /* Non-IP: let it pass. */
    return XDP_PASS;
}
