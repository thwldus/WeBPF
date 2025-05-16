#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "opensnoop.skel.h"
#include "opensnoop.h"

static volatile sig_atomic_t stop;

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("{\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"filename\":\"%s\"}\n",
           e->pid, e->uid, e->comm, e->filename);
    return 0;
}

void sig_int(int signo) {
    stop = 1;
}

int main() {
    struct opensnoop_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_int);

    skel = opensnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = opensnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Tracing openat()... Ctrl+C to exit.\n");
    while (!stop) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    ring_buffer__free(rb);
    opensnoop_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

