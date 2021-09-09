// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Gabriele N. Tornetta

#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN 16

typedef __u32 u32;
typedef __u64 u64;

#ifdef PERF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH PERF_MAX_STACK_DEPTH
#else
#define BPF_MAX_STACK_DEPTH 127
#endif

struct bpf_stacktrace
{
    u64 ip[BPF_MAX_STACK_DEPTH];
};

struct key_t
{
    u32 pid;
    u64 kernel_ip;
    u64 kernel_ret_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */