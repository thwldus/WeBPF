// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer map 정의
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = uid;
    e->retval = 0;
    e->is_exit = false;
    e->timestamp_ns = bpf_ktime_get_ns();

    const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(e->comm, sizeof(e->comm), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

