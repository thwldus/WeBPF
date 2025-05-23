#ifndef __SNOOP_EVENTS_H__
#define __SNOOP_EVENTS_H__

#define TASK_COMM_LEN 16
#define PATH_MAX 256

// 모든 이벤트 타입 식별자
enum event_type {
    EVENT_EXEC = 0,
    EVENT_OPEN = 1,
    EVENT_EXIT = 2,
    EVENT_FORK = 3,
    EVENT_TCP = 4,
};

// 공통 필드
struct common_event {
    int pid;
    int ppid;
    int uid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
    enum event_type type;
};

// 각 이벤트별 데이터
struct exec_data {
    int retval;
    bool is_exit;
};

struct open_data {
    char filename[PATH_MAX];
};

struct bootstrap_data {
    unsigned exit_code;
    unsigned long long duration_ns;
};

struct tcp_data {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// 통합 이벤트
struct snoop_event {
    struct common_event common;

    union {
        struct exec_data exec;
        struct open_data open;
        struct bootstrap_data bootstrap;
        struct tcp_data tcp;
    } data;
};

#endif /* __SNOOP_EVENTS_H__ */

