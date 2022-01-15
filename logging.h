// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021-2022 Gabriele N. Tornetta


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
#ifdef DEBUG
    return vfprintf(stderr, format, args);
#else
    return 0;
#endif
}


/* Set up libbpf errors and debug info callback */
#define libbpf_enable_debug_logging() {libbpf_set_print(libbpf_print_fn);}
