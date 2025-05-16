#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include "tcpsnoop.skel.h"
#include "tcpsnoop.h"

static void get_exe_path(int pid, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, buf, size - 1);
    if (len > 0) {
        buf[len] = '\0';
    } else {
        strncpy(buf, "unknown", size);
    }
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    char exe_path[256];
    get_exe_path(e->pid, exe_path, sizeof(exe_path));

    printf("{\"pid\":%d,\"comm\":\"%s\",\"exe\":\"%s\",\"saddr\":\"%u.%u.%u.%u\",\"daddr\":\"%u.%u.%u.%u\",\"sport\":%d,\"dport\":%d}\n",
        e->pid, e->comm, exe_path,
        (e->saddr >> 0) & 0xff, (e->saddr >> 8) & 0xff,
        (e->saddr >> 16) & 0xff, (e->saddr >> 24) & 0xff,
        (e->daddr >> 0) & 0xff, (e->daddr >> 8) & 0xff,
        (e->daddr >> 16) & 0xff, (e->daddr >> 24) & 0xff,
        e->sport, e->dport);
    return 0;
}

int main() {
    struct tcpsnoop_bpf *skel;
    struct ring_buffer *rb;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = tcpsnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    if (tcpsnoop_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for TCP connections... Press Ctrl+C to exit.\n");
    while (1) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Ring buffer polling failed\n");
            break;
        }
    }

    ring_buffer__free(rb);
    tcpsnoop_bpf__destroy(skel);
    return 0;
}

