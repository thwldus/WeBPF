#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "snoop_events.h"

#define bpf_ntohs(x) __builtin_bswap16(x)

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct snoop_event *e;

    u16 sport, dport;
    u32 saddr, daddr;

    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    dport = bpf_ntohs(dport);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->common.pid = bpf_get_current_pid_tgid() >> 32;
    e->common.ppid = 0;  
    e->common.uid = bpf_get_current_uid_gid();
    e->common.timestamp_ns = bpf_ktime_get_ns();
    e->common.type = EVENT_TCP;
    bpf_get_current_comm(&e->common.comm, sizeof(e->common.comm));

    e->data.tcp.saddr = saddr;
    e->data.tcp.daddr = daddr;
    e->data.tcp.sport = sport;
    e->data.tcp.dport = dport;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

