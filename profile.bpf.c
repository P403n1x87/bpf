// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Gabriele N. Tornetta

// This is a BPF CO-RE port of the BCC tool with the same name:
// https://github.com/iovisor/bcc/blob/e83019bdf6c400b589e69c7d18092e38088f89a8/tools/profile.py

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "profile.h"

char LICENSE[] SEC("license") = "GPL";

#define IDLE_FILTER 0 // pid == 0
#define THREAD_FILTER (tgid == target_pid)
#define STACK_STORAGE_SIZE 14 // 16384

pid_t target_pid = 0;
bool kernel = 0;

#define PAGE_OFFSET 0xC0000000 // ARCH dependent?

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, u64);
} counts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, (1UL << STACK_STORAGE_SIZE));
    __type(key, u32);
    __type(value, struct bpf_stacktrace);
} stackmap SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (IDLE_FILTER)
        return 0;
    if (!(THREAD_FILTER))
        return 0;

    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    key.kernel_stack_id = kernel ? bpf_get_stackid(ctx, &stackmap, 0) : -1;

    if (key.kernel_stack_id >= 0)
    {
        // populate extras to fix the kernel stack
        u64 ip = PT_REGS_IP(&ctx->regs);
        u64 page_offset;
        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif
        if (ip > page_offset)
        {
            key.kernel_ip = ip;
        }
    }

    // Update the counts
    u64 count = 1;
    u64 *countp = bpf_map_lookup_elem(&counts, &key);
    if (!countp)
    {
        countp = &count;
    }
    else
    {
        (*countp)++;
    }
    bpf_map_update_elem(&counts, &key, countp, BPF_ANY);
    return 0;
}