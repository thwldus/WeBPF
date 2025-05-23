// SPDX-License-Identifier: BSD-2-Clause
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "snoop_events.h"

static volatile bool exiting = false;

static void sig_handler(int signo) {
    exiting = true;
}

static void format_timestamp(__u64 event_ts_ns, char *buf, size_t buf_size) {
    struct timespec real_ts, mono_ts;

    clock_gettime(CLOCK_REALTIME, &real_ts);
    clock_gettime(CLOCK_MONOTONIC, &mono_ts);

    uint64_t real_time_ns = (uint64_t)real_ts.tv_sec * 1000000000ULL + real_ts.tv_nsec;
    uint64_t mono_time_ns = (uint64_t)mono_ts.tv_sec * 1000000000ULL + mono_ts.tv_nsec;
    uint64_t boot_time_ns = real_time_ns - mono_time_ns;

    uint64_t abs_time_ns = boot_time_ns + event_ts_ns;
    time_t sec = abs_time_ns / 1000000000ULL;

    struct tm *tm_info = localtime(&sec);
    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct snoop_event *e = data;

    char timebuf[64];
    format_timestamp(e->common.timestamp_ns, timebuf, sizeof(timebuf));

    switch (e->common.type) {
        case EVENT_EXEC:
            printf("{\"type\": \"exec\", \"timestamp\": \"%s\", \"pid\": %d, \"ppid\": %d, \"uid\": %d, \"comm\": \"%s\"}\n",
                   timebuf, e->common.pid, e->common.ppid, e->common.uid, e->common.comm);
            break;
        case EVENT_EXIT:
            printf("{\"type\": \"exit\", \"timestamp\": \"%s\", \"pid\": %d, \"ppid\": %d, \"exit_code\": %u, \"duration_ns\": %llu, \"comm\": \"%s\"}\n",
                   timebuf, e->common.pid, e->common.ppid, e->data.bootstrap.exit_code, e->data.bootstrap.duration_ns, e->common.comm);
            break;
        case EVENT_FORK:
            printf("{\"type\": \"fork\", \"timestamp\": \"%s\", \"pid\": %d, \"ppid\": %d, \"comm\": \"%s\"}\n",
                   timebuf, e->common.pid, e->common.ppid, e->common.comm);
            break;
        default:
            printf("{\"type\": \"unknown\", \"timestamp\": \"%s\", \"pid\": %d}\n", timebuf, e->common.pid);
            break;
    }

    return 0;
}

__attribute__((__unused__))
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;
    int map_fd, err;

    signal(SIGINT, sig_handler);

    obj = bpf_object__open_file("process.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Attach exec
    prog = bpf_object__find_program_by_name(obj, "trace_exec");
    if (!prog || !(link1 = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve"))) {
        fprintf(stderr, "Failed to attach execve tracepoint\n");
        return 1;
    }

    // Attach exit
    prog = bpf_object__find_program_by_name(obj, "handle_exit");
    if (!prog || !(link2 = bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit"))) {
        fprintf(stderr, "Failed to attach exit tracepoint\n");
        return 1;
    }

    // Attach fork
    prog = bpf_object__find_program_by_name(obj, "handle_fork");
    if (!prog || !(link3 = bpf_program__attach_tracepoint(prog, "sched", "sched_process_fork"))) {
        fprintf(stderr, "Failed to attach fork tracepoint\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ringbuf map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Waiting for process exec/fork/exit events... Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Ring buffer polling error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link1);
    bpf_link__destroy(link2);
    bpf_link__destroy(link3);
    bpf_object__close(obj);

    return 0;
}

