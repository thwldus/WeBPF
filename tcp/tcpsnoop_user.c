#include <stdio.h>
#include <bpf/libbpf.h>
#include "tcpsnoop.skel.h"
#include "tcpsnoop.h"

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;

    printf("{\"pid\":%d,\"comm\":\"%s\",\"saddr\":\"%u.%u.%u.%u\",\"daddr\":\"%u.%u.%u.%u\",\"sport\":%d,\"dport\":%d}\n",
        e->pid, e->comm,
        (e->saddr >>  0) & 0xff, (e->saddr >>  8) & 0xff,
        (e->saddr >> 16) & 0xff, (e->saddr >> 24) & 0xff,
        (e->daddr >>  0) & 0xff, (e->daddr >>  8) & 0xff,
        (e->daddr >> 16) & 0xff, (e->daddr >> 24) & 0xff,
        e->sport, e->dport);
    return 0;
}

int main() {
    struct tcpsnoop_bpf *skel;
    struct ring_buffer *rb;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = tcpsnoop_bpf__open_and_load();
    tcpsnoop_bpf__attach(skel);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    
    printf("Listening for tcp connection events... Press Ctrl+C to exit.\n");
    
    while (1) ring_buffer__poll(rb, 100);

    tcpsnoop_bpf__destroy(skel);
    return 0;
}

