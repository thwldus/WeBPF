# 컴파일러 설정
BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I..

CC = gcc
USER_CFLAGS = -g -O2 -I. -I../libbpf/include -I../libbpf/src
USER_LDFLAGS = ../libbpf/src/libbpf.a -lelf -lz

# 파일 설정
BPF_PROG = exitsnoop.bpf.o
USER_PROG = exitsnoop
USER_SRCS = exitsnoop_user.c
USER_OBJS = $(USER_SRCS:.c=.o)

.PHONY: all clean

all: $(USER_PROG)

$(BPF_PROG): exitsnoop.bpf.c exitsnoop.h ../vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -I../libbpf/include -c $< -o $@

$(USER_OBJS): exitsnoop.h

$(USER_PROG): $(USER_OBJS) $(BPF_PROG)
	$(CC) $(USER_CFLAGS) $(USER_OBJS) -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(BPF_PROG) $(USER_PROG) $(USER_OBJS)

