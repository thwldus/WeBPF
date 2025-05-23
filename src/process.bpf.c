// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "snoop_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 공통 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} events SEC(".maps");

// EXECVE 추적
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct snoop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->common.pid = pid;
    e->common.ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->common.uid = uid;
    e->common.timestamp_ns = bpf_ktime_get_ns();
    e->common.type = EVENT_EXEC;

    const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(e->common.comm, sizeof(e->common.comm), filename);

    e->data.exec.retval = 0;
    e->data.exec.is_exit = false;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// EXIT 추적
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (pid != tid)
        return 0;

    struct snoop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 start_time = BPF_CORE_READ(task, start_time);

    e->common.pid = pid;
    e->common.ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->common.uid = bpf_get_current_uid_gid();
    e->common.timestamp_ns = bpf_ktime_get_ns();
    e->common.type = EVENT_EXIT;

    bpf_get_current_comm(&e->common.comm, sizeof(e->common.comm));

    e->data.bootstrap.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    e->data.bootstrap.duration_ns = bpf_ktime_get_ns() - start_time;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// FORK 추적
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 current_pid = id >> 32;

    if (current_pid != ctx->parent_pid)
        return 0;

    struct snoop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->common.pid = ctx->child_pid;
    e->common.ppid = ctx->parent_pid;
    e->common.uid = bpf_get_current_uid_gid();
    e->common.timestamp_ns = bpf_ktime_get_ns();
    e->common.type = EVENT_FORK;

    bpf_get_current_comm(&e->common.comm, sizeof(e->common.comm));

    e->data.bootstrap.exit_code = 0;
    e->data.bootstrap.duration_ns = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

