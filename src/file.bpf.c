#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "snoop_events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    struct snoop_event *e;
    const char *filename = (const char *)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->common.pid = bpf_get_current_pid_tgid() >> 32;
    e->common.ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->common.uid = bpf_get_current_uid_gid();
    e->common.timestamp_ns = bpf_ktime_get_ns();
    e->common.type = EVENT_OPEN;

    bpf_get_current_comm(&e->common.comm, sizeof(e->common.comm));
    bpf_probe_read_user_str(e->data.open.filename, sizeof(e->data.open.filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

