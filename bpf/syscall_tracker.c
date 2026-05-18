// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned char       __u8;
typedef unsigned int        __u32;
typedef long long           __s64;
typedef unsigned long long  __u64;

struct sys_enter_ctx {
    __u64 _pad;
    __s64 id;
    __u64 args[6];
};

#define __NR_prctl          157
#define PR_SET_NO_NEW_PRIVS  38

/*
 * Set of cgroup v2 IDs that are currently being profiled.
 * Userspace adds entries on container start and removes them on stop.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, __u8);
} tracked_cgids SEC(".maps");

/*
 * Composite key: one entry per (container, syscall) pair.
 * Padding is zeroed by the struct initializer so hash keys are stable.
 */
struct cgid_syscall_key {
    __u64 cgid;
    __u32 nr;
    __u32 _pad;
};

/*
 * Per-CPU hash so each CPU writes to its own slot with no atomic ops.
 * Userspace ORs all per-CPU values at collection time.
 * max_entries = 128 containers × 512 syscalls.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct cgid_syscall_key);
    __type(value, __u8);
} syscall_seen SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_ctx *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();

    __u8 *tracked = bpf_map_lookup_elem(&tracked_cgids, &cgid);
    if (!tracked || !*tracked)
        return 0;

    __s64 nr = ctx->id;
    if (nr < 0 || nr >= 512)
        return 0;

    if (nr == __NR_prctl && ctx->args[0] == PR_SET_NO_NEW_PRIVS)
        return 0;

    struct cgid_syscall_key key = { .cgid = cgid, .nr = (__u32)nr };
    __u8 one = 1;
    bpf_map_update_elem(&syscall_seen, &key, &one, BPF_ANY);
    return 0;
}

char __license[] SEC("license") = "GPL";
