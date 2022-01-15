# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2021 Gabriele N. Tornetta
OUTPUT := build
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/sbin/bpftool
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -Wall
OPTS := 
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

APPS = \
	profile \
	copy_from_user_remote

$(OUTPUT):
	mkdir -p $@

$(APPS): %: %.c $(OUTPUT)/%.skel.h | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPTS) $(filter %.c,$^) -lelf -lz -lbpf -o $(OUTPUT)/$@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $^ > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(OUTPUT)/vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: all clean
all: $(APPS)
clean:
	test -d $(OUTPUT) && rm -rf $(OUTPUT)

.DELETE_ON_ERROR:
