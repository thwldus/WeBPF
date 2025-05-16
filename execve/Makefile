# 컴파일러 설정
BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -target bpf -D__TARGET_ARCH_x86 -I..

CC=gcc
USER_CFLAGS=-g -O2 -I. -I../libbpf/include -I/usr/include
USER_LDFLAGS=../libbpf/src/libbpf.a -lelf -lz

# 파일 설정
BPF_PROG=execsnoop.bpf.o
SKEL_HEADER=execsnoop.skel.h
USER_PROG=execsnoop_user
USER_SRCS=execsnoop_user.c
USER_OBJS=$(USER_SRCS:.c=.o)

.PHONY: all clean

# 전체 빌드
all: $(USER_PROG)

# BPF 오브젝트
$(BPF_PROG): execsnoop.bpf.c execsnoop.h ../vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# skeleton 헤더 자동 생성
$(SKEL_HEADER): $(BPF_PROG)
	bpftool gen skeleton $< > $@

# execsnoop_user.o는 skel 헤더에 의존
$(USER_OBJS): $(SKEL_HEADER)

# 유저 프로그램
$(USER_PROG): $(USER_OBJS)
	$(CC) $(USER_CFLAGS) $(USER_OBJS) -o $@ $(USER_LDFLAGS)

# 정리
clean:
	rm -f $(BPF_PROG) $(USER_PROG) $(USER_OBJS) $(SKEL_HEADER)

