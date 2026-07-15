/* probe_xdp.bpf.c — Step 2 skeleton.
 *
 * Purpose in Step 2 (this file):
 *   - Verify the full toolchain end-to-end: compile -> load -> attach ->
 *     ringbuf event -> userspace decode -> detach.
 *   - Report EVERY inbound TCP packet as a probe_event to a ringbuf and
 *     return XDP_PASS. No filtering. No drop. This is DELIBERATE:
 *       * we must never risk dropping ssh in the scaffold stage;
 *       * seeing our own ssh packets show up is proof the pipeline works.
 *
 * In Step 3 we will add:
 *   - filter: only SYN|ACK responses to our probe port range 65408-65423
 *   - action: XDP_DROP those SYN|ACKs so the kernel never sends RST back
 *   - saddr allowlist for the 3 leaf IPs (deferred; not needed now)
 */
#include "vmlinux.h"          /* CO-RE kernel types via BTF                */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "probe_xdp.h"

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

    /* Rebuild the classic 6-bit flag byte from the bitfields in tcphdr.
     * vmlinux.h exposes fin/syn/rst/psh/ack/urg as 1-bit fields. */
    __u8 flags = 0;
    if (tcp->fin) flags |= 0x01;
    if (tcp->syn) flags |= 0x02;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;
    if (tcp->ack) flags |= 0x10;
    if (tcp->urg) flags |= 0x20;
    ev->tcp_flags = flags;

    ev->_pad[0] = 0;
    ev->_pad[1] = 0;
    ev->_pad[2] = 0;

    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}
