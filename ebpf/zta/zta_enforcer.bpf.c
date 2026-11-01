#include "vmlinux.h"

#define EPERM 1
#define MAX_PATH 64

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
 * ============================================================
 * Registered Agent Roots
 * ============================================================
 *
 * key   = Agent root PID
 * value = 1
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
}
agent_roots SEC(".maps");


/*
 * ============================================================
 * Blocked Zero Trust Rules
 * ============================================================
 *
 * 1 = /usr/bin/sudo
 * 2 = /bin/bash
 * 3 = /bin/sh
 * 4 = /usr/bin/passwd
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
}
blocked_rules SEC(".maps");


/*
 * ============================================================
 * Find registered Agent root
 * ============================================================
 *
 * Walk up to 8 parent processes.
 */
static __always_inline __u32 find_agent_root(
    struct task_struct *task)
{
    __u32 tgid;
    __u8 *registered;

    for (int i = 0; i < 8; i++)
    {
        if (!task)
            return 0;

        tgid = BPF_CORE_READ(task, tgid);

        registered = bpf_map_lookup_elem(
            &agent_roots,
            &tgid
        );

        if (registered && *registered == 1)
            return tgid;

        task = BPF_CORE_READ(
            task,
            real_parent
        );
    }

    return 0;
}


/*
 * ============================================================
 * Identify executable
 * ============================================================
 *
 * We intentionally avoid memcmp/strcmp because those can
 * become unresolved extern functions in the BPF object.
 *
 * Instead we compare the fixed path characters directly.
 */
static __always_inline __u32 get_rule_id(
    char *path)
{
    /*
     * /usr/bin/sudo
     */
    if (path[0]  == '/' &&
        path[1]  == 'u' &&
        path[2]  == 's' &&
        path[3]  == 'r' &&
        path[4]  == '/' &&
        path[5]  == 'b' &&
        path[6]  == 'i' &&
        path[7]  == 'n' &&
        path[8]  == '/' &&
        path[9]  == 's' &&
        path[10] == 'u' &&
        path[11] == 'd' &&
        path[12] == 'o')
    {
        return 1;
    }


    /*
     * /bin/bash
     */
    if (path[0] == '/' &&
        path[1] == 'b' &&
        path[2] == 'i' &&
        path[3] == 'n' &&
        path[4] == '/' &&
        path[5] == 'b' &&
        path[6] == 'a' &&
        path[7] == 's' &&
        path[8] == 'h')
    {
        return 2;
    }


    /*
     * /bin/sh
     */
    if (path[0] == '/' &&
        path[1] == 'b' &&
        path[2] == 'i' &&
        path[3] == 'n' &&
        path[4] == '/' &&
        path[5] == 's' &&
        path[6] == 'h')
    {
        return 3;
    }


    /*
     * /usr/bin/passwd
     */
    if (path[0]  == '/' &&
        path[1]  == 'u' &&
        path[2]  == 's' &&
        path[3]  == 'r' &&
        path[4]  == '/' &&
        path[5]  == 'b' &&
        path[6]  == 'i' &&
        path[7]  == 'n' &&
        path[8]  == '/' &&
        path[9]  == 'p' &&
        path[10] == 'a' &&
        path[11] == 's' &&
        path[12] == 's' &&
        path[13] == 'w' &&
        path[14] == 'd')
    {
        return 4;
    }

    return 0;
}


/*
 * ============================================================
 * BPF-LSM EXECUTION HOOK
 * ============================================================
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(
    kernelguard_zta_exec,
    struct linux_binprm *bprm,
    int ret)
{
    /*
     * Preserve an earlier LSM decision.
     */
    if (ret != 0)
        return ret;


    /*
     * Get executable filename.
     */
    const char *filename =
        BPF_CORE_READ(
            bprm,
            filename
        );

    if (!filename)
        return 0;


    /*
     * Copy executable path into BPF buffer.
     */
    char path[MAX_PATH] = {};

    long copied =
        bpf_probe_read_kernel_str(
            path,
            sizeof(path),
            filename
        );

    if (copied <= 0)
        return 0;


    /*
     * Get current process.
     */
    struct task_struct *task =
        (struct task_struct *)
        bpf_get_current_task();


    /*
     * Determine whether the process belongs
     * to a registered Agent process tree.
     */
    __u32 agent_pid =
        find_agent_root(task);


    /*
     * Not an Agent.
     *
     * Do not apply Agent-specific policy.
     */
    if (agent_pid == 0)
        return 0;


    /*
     * Identify executable rule.
     */
    __u32 rule_id =
        get_rule_id(path);


    /*
     * Executable is not blocked.
     */
    if (rule_id == 0)
        return 0;


    /*
     * Check administrator-controlled
     * blocked rule map.
     */
    __u8 *deny =
        bpf_map_lookup_elem(
            &blocked_rules,
            &rule_id
        );


    /*
     * Rule is not enabled.
     */
    if (!deny || *deny != 1)
        return 0;


    /*
     * ========================================================
     * ZERO TRUST ENFORCEMENT
     * ========================================================
     *
     * Known Agent identity
     * +
     * explicitly blocked executable
     * =
     * DENY
     */
    bpf_printk(
        "KernelGuard ZTA DENY"
    );


    /*
     * EPERM = Operation not permitted.
     */
    return -EPERM;
}


char LICENSE[] SEC("license") = "GPL";
