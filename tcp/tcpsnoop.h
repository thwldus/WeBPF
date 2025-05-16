#ifndef __TCPSNOOP_H__
#define __TCPSNOOP_H__

struct event {
    __u32 pid;
    char comm[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

#endif

