# Requires: linux-tools-{common,generic} https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/bpftool llvm
INCLUDES := -I/usr/include/x86_64-linux-gnu/ -I. # -I/usr/src/linux-headers-5.4.0-81/include -I/usr/src/linux-headers-5.4.0-81/arch/x86/include/
CFLAGS := -g -Wall -DCONFIG_X86_64
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

profile:
	clang -g -O2 -target bpf -D__x86_64__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c profile.bpf.c -o profile.bpf.o
	llvm-strip -g profile.bpf.o
	../bpftool gen skeleton profile.bpf.o > profile.skel.h

	gcc $(CFLAGS) $(INCLUDES) profile.c -lelf -lz -Lbpf -lbpf -o profile