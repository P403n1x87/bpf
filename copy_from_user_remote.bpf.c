// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;
int count = 0;
int secret = 0;
pid_t target_pid = 0;
void *user_ptr = NULL;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid)
        return 0;

    count++;

    return 0;
}

SEC("fentry.s/__x64_sys_write")
int BPF_PROG(test_sys_write, int fd, const void *buf, size_t count)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid)
        return 0;

    long bytes;

    bytes = bpf_copy_from_user_remote(&secret, sizeof(secret), user_ptr, target_pid);
    bpf_printk("bpf_copy_from_user_remote: copied %d bytes", bytes);

    return 0;
}
