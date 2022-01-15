// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <bpf/libbpf.h>

#include "logging.h"
#include "copy_from_user_remote.skel.h"

struct _pargs
{
    pid_t pid;
    void *user_ptr;
};
static struct _pargs args;

extern ssize_t process_vm_readv(pid_t pid,
                                const struct iovec *local_iov,
                                unsigned long liovcnt,
                                const struct iovec *remote_iov,
                                unsigned long riovcnt,
                                unsigned long flags);

static ssize_t process_vm_read(pid_t pid, void *dst, ssize_t size,
                               const void *user_ptr, unsigned long flags)
{
    struct iovec lvec = {.iov_base = dst, .iov_len = size};
    struct iovec rvec = {.iov_base = (void *)user_ptr, .iov_len = size};

    return process_vm_readv(pid, &lvec, 1, &rvec, 1, flags);
}

static int get_secret()
{
    int secret = 0;

    int ret = process_vm_read(args.pid, &secret, sizeof(secret), args.user_ptr, 0);

    if (ret < 0)
        return ret;

    return secret;
}

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

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: copy_from_user_remote <PID> <ADDR>\n");
        return -1;
    }

    args.pid = atoi(argv[1]);
    args.user_ptr = (void *)strtoull(argv[2], NULL, 0);

    struct copy_from_user_remote_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = copy_from_user_remote_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* ensure BPF program only handles write() syscalls from our process */
    skel->bss->my_pid = getpid();
    skel->bss->target_pid = args.pid;
    skel->bss->user_ptr = args.user_ptr;
    skel->bss->secret = -1;

    /* Load & verify BPF programs */
    err = copy_from_user_remote_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = copy_from_user_remote_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    int expected = get_secret();

    while (skel->bss->count < 3)
    {
        /* trigger our BPF program */
        fprintf(stderr, "count: %d\tsecret: %d (expected: %d)\r", skel->bss->count, skel->bss->secret, expected);
        sleep(1);
    }
    printf("\n%s\n", skel->bss->secret == expected ? "🎉" : "💥");

cleanup:
    copy_from_user_remote_bpf__destroy(skel);
    return -err;
}