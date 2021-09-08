# Requires: linux-tools-{common,generic} https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/bpftool llvm
INCLUDES := -I/usr/include/x86_64-linux-gnu/ -I.
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = minimal

minimal:
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c minimal.bpf.c -o minimal.bpf.o
	llvm-strip -g minimal.bpf.o
	../bpftool gen skeleton minimal.bpf.o > minimal.skel.h

	gcc $(CFLAGS) $(INCLUDES) minimal.c -lelf -lz -Lbpf -lbpf -o minimal