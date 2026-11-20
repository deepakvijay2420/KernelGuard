#include "vmlinux.h"

#define EPERM 1
#define MAX_PATH 256
#define ACTION_ALLOW 1
#define ACTION_DENY  2
#define ACTION_REVIEW 3

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Agent root PID -> policy profile ID. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} agent_roots SEC(".maps");

/*
 * Policy key is (profile_id, FNV-1a-64(executable path)).
 * Values: 1=ALLOW, 2=DENY, 3=REVIEW.
 */
struct policy_key {
    __u32 profile_id;
    __u32 pad;
    __u64 path_hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct policy_key);
    __type(value, __u8);
} execution_policy SEC(".maps");

static __always_inline __u32 find_agent_profile(struct task_struct *task)
{
    __u32 tgid;
    __u32 *profile_id;

    for (int i = 0; i < 8; i++) {
        if (!task)
            return 0;

        tgid = BPF_CORE_READ(task, tgid);
        profile_id = bpf_map_lookup_elem(&agent_roots, &tgid);
        if (profile_id && *profile_id != 0)
            return *profile_id;

        task = BPF_CORE_READ(task, real_parent);
    }
    return 0;
}

static __always_inline __u64 hash_path(const char *path)
{
    __u64 hash = 14695981039346656037ULL;

    /* MAX_PATH bounds this loop and matches the controller's hash. */
    for (int i = 0; i < MAX_PATH; i++) {
        __u8 c = (__u8)path[i];
        if (c == 0)
            break;
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(kernelguard_zta_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename)
        return 0;

    char path[MAX_PATH] = {};
    long copied = bpf_probe_read_kernel_str(path, sizeof(path), filename);
    if (copied <= 0 || copied >= MAX_PATH)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 profile_id = find_agent_profile(task);
    if (profile_id == 0)
        return 0;

    struct policy_key key = {
        .profile_id = profile_id,
        .pad = 0,
        .path_hash = hash_path(path),
    };

    __u8 *action = bpf_map_lookup_elem(&execution_policy, &key);
    if (!action)
        return 0; /* Unlisted paths are REVIEW/monitor-only, not denied. */

    if (*action == ACTION_DENY) {
        bpf_printk("KernelGuard ZTA DENY profile=%u", profile_id);
        return -EPERM;
    }

    /* ALLOW and REVIEW are non-blocking decisions in this hook. */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
