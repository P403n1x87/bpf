#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include "profile.skel.h"
#include "profile.h"

#define MAX_CPU_NR 128

// ----------------------------------------------------------------------------
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

// ----------------------------------------------------------------------------
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

// ----------------------------------------------------------------------------
static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
                                      struct bpf_link *links[])
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .freq = 1,
        .sample_period = freq,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };
    int i, fd, nr_cpus;

    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0)
    {
        printf("failed to get # of possible cpus: '%s'!\n",
               strerror(-nr_cpus));
        return -1;
    }
    if (nr_cpus > MAX_CPU_NR)
    {
        fprintf(stderr, "the number of cpu cores is too big, please "
                        "increase MAX_CPU_NR's value and recompile");
        return -1;
    }

    for (i = 0; i < nr_cpus; i++)
    {
        fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        if (fd < 0)
        {
            /* Ignore CPU that is offline */
            if (errno == ENODEV)
                continue;
            fprintf(stderr, "failed to init perf sampling: %s\n",
                    strerror(errno));
            return -1;
        }
        links[i] = bpf_program__attach_perf_event(prog, fd);
        if (libbpf_get_error(links[i]))
        {
            fprintf(stderr, "failed to attach perf event on cpu: "
                            "%d\n",
                    i);
            links[i] = NULL;
            close(fd);
            return -1;
        }
    }

    return nr_cpus;
}

// ----------------------------------------------------------------------------
static volatile bool exiting;

static void sig_handler(int sig)
{
    exiting = true;
}

// ----------------------------------------------------------------------------
int print_kernel_stack(struct profile_bpf *skel)
{
    struct bpf_map *st_map = skel->maps.stack_traces;
    struct bpf_map *c_map = skel->maps.counts;
    int err;
    int st_fd = bpf_map__fd(st_map);
    int c_fd = bpf_map__fd(c_map);

    __u32 lookup_key = -2, next_key;
    struct bpf_stacktrace *st;
    struct key_t c_key, next_c_key;

    while (!bpf_map_get_next_key(c_fd, &lookup_key, &next_key))
    {
    }

    // while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
    // {
    //     err = bpf_map_lookup_elem(fd, &next_key, &st);
    //     if (err < 0)
    //     {
    //         fprintf(stderr, "failed to lookup stacktrace: %d\n", err);
    //         return -1;
    //     }

    //     // printf(st->)

    //     lookup_key = next_key;
    // }

    return 0;
}

// ----------------------------------------------------------------------------
int main(int argc, char **argv)
{
    struct profile_bpf *skel;
    int err;
    struct bpf_link *links[MAX_CPU_NR] = {};

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = profile_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* ensure BPF program only handles write() syscalls from our process */
    skel->bss->target_pid = getpid(); // Self-profile;

    /* Load & verify BPF programs */
    err = profile_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    int nr_cpus = open_and_attach_perf_event(99, skel->progs.do_sample, links);
    if (err)
        goto cleanup;

    printf("Sampling stack traces for 3 seconds ...\n");

    signal(SIGINT, sig_handler);

    sleep(3); // Sample for 3 seconds

    print_kernel_stack(skel);

cleanup:
    for (int i = 0; i < nr_cpus; i++)
        bpf_link__destroy(links[i]);
    profile_bpf__destroy(skel);

    return err != 0;
}