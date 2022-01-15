// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Gabriele N. Tornetta

#include <argp.h>
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

#include "logging.h"
#include "profile.skel.h"
#include "profile.h"

#define MAX_CPU_NR 128

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
            fprintf(stderr, "CPU %d is offline\n", i);
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
int print_stack(struct profile_bpf *skel, pid_t pid)
{
    struct bpf_map *st_map = skel->maps.stackmap;
    struct bpf_map *c_map = skel->maps.counts;
    int st_fd = bpf_map__fd(st_map);
    int c_fd = bpf_map__fd(c_map);

    struct bpf_stacktrace st;
    struct key_t c_key, next_c_key;

    while (!bpf_map_get_next_key(c_fd, &c_key, &next_c_key))
    {
        c_key = next_c_key;
        u64 count;
        if (bpf_map_lookup_elem(c_fd, &c_key, &count))
        {
            printf("Failed to retrieve stack count\n");
            return 1;
        }

        if (c_key.kernel_stack_id >= 0)
        {
            if (bpf_map_lookup_elem(st_fd, &c_key.kernel_stack_id, &st))
            {
                printf("Failed to lookup kernel stack %d\n", c_key.kernel_stack_id);
                return 1;
            }
            for (int i = 0; i < PERF_MAX_STACK_DEPTH && st.ip[i]; printf("k%p;", (void *)st.ip[i++]))
                ;
        }

        if (c_key.user_stack_id >= 0)
        {
            if (bpf_map_lookup_elem(st_fd, &c_key.user_stack_id, &st))
            {
                printf("Failed to lookup kernel stack\n");
                return 1;
            }
            for (int i = 0; i < PERF_MAX_STACK_DEPTH && st.ip[i]; printf("u%p;", (void *)st.ip[i++]))
                ;
        }

        printf("P%d %lld\n", pid, count);
    }

    return 0;
}

// ----------------------------------------------------------------------------
static int
print_maps(pid_t pid)
{
    char file_name[32];
    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 0;

    sprintf(file_name, "/proc/%d/maps", pid);
    fp = fopen(file_name, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Cannot read maps file %s: %s", file_name, strerror(errno));
        return 1;
    }

    while (getline(&line, &len, fp) != -1)
    {
        ssize_t lower, upper;
        char pathname[1024];

        if (sscanf(line, "%lx-%lx %*s %*x %*x:%*x %*x %s\n",
                   &lower, &upper, // Map bounds
                   pathname        // Binary path
                   ) == 3 &&
            pathname[0] != '[')
        {
            printf("# map: %lx-%lx %s\n", lower, upper, pathname);
        }
    }

    if (line != NULL)
        free(line);
    fclose(fp);

    return 0;
}

// ----------------------------------------------------------------------------
static struct pargs
{
    pid_t pid;
    bool kernel;
    int depth;
    int size;
    int freq;
    bool cpu;
    int exposure;
} pargs = {
    .pid = 0,
    .kernel = false,
    .size = 1024,
    .depth = 127,
    .freq = 99,
    .cpu = false,
    .exposure = 3,
};

const char *argp_program_version = "profile 0.1.0";
const char *argp_program_bug_address = "https://github.com/p403n1x87/bpf/issues";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "The PID of the process to profile (mandatory)"}, // FIX: Mandatory option?!?
    {"kernel", 'k', NULL, 0, "Include kernel stacks"},
    {"depth", 'd', "DEPTH", 0, "Maximum stack depth (defaults to 127)"},
    {"size", 's', "SIZE", 0, "Maximum number of unique stacks (defaults to 1024)"},
    {"freq", 'f', "FREQ", 0, "Sampling frequency (defaults to 99 Hz)"},
    {"cpu", 'c', NULL, 0, "Sample on-CPU stacks only"},
    {"exposure", 'x', "EXP", 0, "Sampling duration (defaults to 3 seconds)"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    errno = 0;

    switch (key)
    {
    case 'p':
        pargs.pid = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid PID: %s\n", arg);
            argp_usage(state);
        }
        break;

    case 'k':
        pargs.kernel = true;
        break;

    case 'c':
        pargs.cpu = true;
        break;

    case 'f':
        pargs.freq = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid frequency: %s\n", arg);
            argp_usage(state);
        }
        break;

    case 'd':
        pargs.depth = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid max stack depth: %s\n", arg);
            argp_usage(state);
        }
        break;

    case 's':
        pargs.size = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid stack storage size: %s\n", arg);
            argp_usage(state);
        }
        break;

    case 'x':
        pargs.exposure = strtol(arg, NULL, 10);
        if (errno)
        {
            fprintf(stderr, "invalid exposure: %s\n", arg);
            argp_usage(state);
        }
        break;

    case ARGP_KEY_ARG:
        fprintf(stderr, "Unexpected positional argument: %s\n", arg);
        argp_usage(state);

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
};

// ----------------------------------------------------------------------------
int main(int argc, char **argv)
{
    struct profile_bpf *skel;
    int err;
    struct bpf_link *links[MAX_CPU_NR] = {};
    int nr_cpus = -1;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    if (pargs.pid == 0)
    {
        fprintf(stderr, "A PID must be provided.\n");
        return 1;
    }

    libbpf_enable_debug_logging();

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = profile_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->bss->target_pid = pargs.pid;
    skel->bss->kernel = pargs.kernel;

    /* Load & verify BPF programs */
    err = profile_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    fprintf(stderr, "Sampling @ %d Hz for %d seconds ...\n", pargs.freq, pargs.exposure);

    nr_cpus = open_and_attach_perf_event(pargs.freq, skel->progs.do_sample, links);
    if (nr_cpus == -1)
        goto cleanup;

    signal(SIGINT, sig_handler);

    // Print memory maps so that we can resolve address to source:function:lineno
    print_maps(pargs.pid);

    // Let the kernel sample the stacks
    sleep(pargs.exposure);

    // Retrieve and print the stacks
    print_stack(skel, pargs.pid);

cleanup:
    for (int i = 0; i < nr_cpus; i++)
        bpf_link__destroy(links[i]);
    profile_bpf__destroy(skel);

    return err;
}