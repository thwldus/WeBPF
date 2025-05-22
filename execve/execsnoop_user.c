#include <time.h>
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
        struct timespec real_ts, mono_ts;
        clock_gettime(CLOCK_REALTIME, &real_ts);		// 현재 시간
        clock_gettime(CLOCK_MONOTONIC, &mono_ts);		// 부팅 후 경과 시간

        uint64_t real_time_ns = (uint64_t)real_ts.tv_sec * 1000000000ULL + real_ts.tv_nsec;
        uint64_t mono_time_ns = (uint64_t)mono_ts.tv_sec * 1000000000ULL + mono_ts.tv_nsec;
        uint64_t boot_time_ns = real_time_ns - mono_time_ns; 	// 컴퓨터가 켜진 시간 계산(= 현재 - 경과 시간)

        uint64_t abs_time_ns = boot_time_ns + e->timestamp_ns;	// BPF 이벤트 시간(= 부팅 시각 + 이벤트  시간)

        time_t sec = abs_time_ns / 1000000000ULL;
        struct tm *tm_info = localtime(&sec);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

        printf("{\"type\":\"exec\", \"timestamp\":\"%s\", \"pid\":%d, \"ppid\":%d, \"uid\":%d, \"comm\":\"%s\"}\n",
               timebuf, e->pid, e->ppid, e->uid, e->comm);
        fflush(stdout);  
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

