#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>  
#include "exitsnoop.h"

static volatile bool exiting = false;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("{\"type\": \"exit\", \"pid\": %d, \"ppid\": %d, \"exit_code\": %u, \"duration_ns\": %llu, \"comm\": \"%s\"}\n",
           e->pid, e->ppid, e->exit_code, e->duration_ns, e->comm);
    return 0;
}

// 사용하지 않는 함수는 제거하거나 아래처럼 처리
__attribute__((__unused__))
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void sig_int(int signo) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;  
    int map_fd, err;

    signal(SIGINT, sig_int);

    obj = bpf_object__open_file("exitsnoop.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_exit");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    link = bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit");
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ringbuf map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Waiting for process exit events... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);  // 리소스 해제
    bpf_object__close(obj);
    return 0;
}

