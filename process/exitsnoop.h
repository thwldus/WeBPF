#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

enum event_type {
    EVENT_EXIT = 0,
    EVENT_FORK = 1,
};

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
    int type;  // EVENT_EXIT 또는 EVENT_FORK
};


#endif /* __BOOTSTRAP_H */
