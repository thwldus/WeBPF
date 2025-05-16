#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN 16
#define PATH_MAX 256

struct event {
    int pid;
    int uid;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
};

#endif /* __OPENSNOOP_H */

