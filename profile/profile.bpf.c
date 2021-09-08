#include <linux/ptrace.h>
#include <linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <sys/types.h>
#include "profile.h"

#define IDLE_FILTER 1
#define THREAD_FILTER (tgid == target_pid)
#define STACK_STORAGE_SIZE 14 // 16384

pid_t target_pid = 0;

#define PAGE_OFFSET 0xC0000000 // ARCH dependent!

#define PT_REGS_IP(ctx) ((ctx)->rip) // ARCH dependent!

#ifdef PERF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH PERF_MAX_STACK_DEPTH
#else
#define BPF_MAX_STACK_DEPTH 127
#endif

static int (*bcc_get_stackid_)(void *ctx, void *map, u64 flags) =
    (void *)BPF_FUNC_get_stackid;
static inline __attribute__((always_inline)) int bcc_get_stackid(uintptr_t map, void *ctx, u64 flags)
{
    return bcc_get_stackid_(ctx, (void *)map, flags);
}

struct bpf_stacktrace
{
    u64 ip[BPF_MAX_STACK_DEPTH];
};

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
    __type(key, int);
    __type(value, struct bpf_stacktrace);
} stack_traces SEC(".maps");

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

    // create map key
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.name, sizeof(key.name));
    // get stacks
    key.user_stack_id = bcc_get_stackid((uintptr_t)&stack_traces, &ctx->regs, BPF_F_USER_STACK);
    key.kernel_stack_id = bcc_get_stackid((uintptr_t)&stack_traces, &ctx->regs, 0);
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