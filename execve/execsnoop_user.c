#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <bpf/libbpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"

volatile sig_atomic_t exiting = 0;

void handle_sigint(int sig) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    if (!e->is_exit) {
        printf("{\"type\":\"exec\", \"pid\":%d, \"ppid\":%d, \"uid\":%d, \"comm\":\"%s\"}\n",
               e->pid, e->ppid, e->uid, e->comm);
        fflush(stdout);  // 스트리밍 환경에서는 즉시 출력
    }
    return 0;
}

int main() {
    struct execsnoop_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    skel = execsnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = execsnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        execsnoop_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        execsnoop_bpf__destroy(skel);
        return 1;
    }

    printf("Listening for execve events... Press Ctrl+C to exit.\n");

    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    execsnoop_bpf__destroy(skel);
    return 0;
}

