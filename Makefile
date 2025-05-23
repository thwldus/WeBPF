# 컴파일러 설정
BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64 \
             -I. -Isrc -Ilibbpf/include

CC = gcc
USER_CFLAGS = -g -O2 -Wall -I. -Isrc -Ilibbpf/include
USER_LDFLAGS = libbpf/src/libbpf.a -lelf -lz

# 파일 경로 설정
BPF_SRC = src/process.bpf.c src/vile.bpf.c
USER_SRC = src/snoop_user.c
BPF_HDR = src/snoop_events.h

BPF_OBJ = process.bpf.o file.bpf.o
USER_OBJ = snoop_user
BPFTOOL ?= bpftool

.PHONY: all clean

all: $(USER_OBJ)

# BPF 오브젝트 빌드
%.bpf.o: src/%.bpf.c $(BPF_HDR) $(VMLINUX)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# 사용자 프로그램 빌드
$(USER_OBJ): $(USER_SRC) $(BPF_OBJ) $(BPF_HDR)
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

# 정리
clean:
	rm -f $(BPF_OBJ) $(USER_OBJ) 

