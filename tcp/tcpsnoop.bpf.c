#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tcpsnoop.h"

// 값을 네트워크 바이트 순서(big-endian)로 변환하기 위해 
// 16비트 정수를 바이트 스왑하는 매크로 정의
#define bpf_ntohs(x) __builtin_bswap16(x)

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk;
    struct event *e;
    u16 sport, dport;
    u32 saddr, daddr;

    sk = (struct sock *)PT_REGS_PARM1(ctx); // 첫 번째 인자 (struct sock *)

    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->sport = sport;
    e->dport = dport;
    e->saddr = saddr;
    e->daddr = daddr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

