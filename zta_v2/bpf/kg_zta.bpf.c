#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "kg_common.h"

/*
 * KernelGuard v2
 * Initial execution-event monitoring.
 *
 * Audit only: this program does not block operations.
 */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} kg_events SEC(".maps");

/*
 * KernelGuard v2 Zero Trust Policy Map
 * Key: agent cgroup ID + executable filename
 * Value: ALLOW / DENY / REVIEW
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct kg_policy_key);
    __type(value, struct kg_policy_value);
} kg_policy_map SEC(".maps");



static __always_inline void
kg_submit_exec_event(struct linux_binprm *bprm)
{
    struct kg_event *event;

    event = bpf_ringbuf_reserve(
        &kg_events,
        sizeof(*event),
        0
    );

    if (!event)
        return;

    __builtin_memset(event, 0, sizeof(*event));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->event_type = KG_EVENT_EXEC;
    event->tgid = pid_tgid >> 32;
    event->uid = (__u32)uid_gid;

    event->cgroup_id = bpf_get_current_cgroup_id();
    event->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(
        event->comm,
        sizeof(event->comm)
    );

    if (bprm) {
        bpf_probe_read_kernel_str(
            event->filename,
            sizeof(event->filename),
            bprm->filename
        );
    }

    bpf_ringbuf_submit(event, 0);
}


SEC("lsm/bprm_check_security")
int BPF_PROG(
    kg_v2_exec_probe,
    struct linux_binprm *bprm,
    int ret
)
{
    /* Preserve an earlier LSM denial. */
    if (ret != 0)
        return ret;

    /* Continue recording every execution attempt. */
    kg_submit_exec_event(bprm);

    /*
     * KernelGuard v2 Zero Trust enforcement.
     * Only exact cgroup + executable matches are evaluated.
     * Unknown entries remain allowed and are audited.
     */
    if (bprm) {
        struct kg_policy_key key = {};
        struct kg_policy_value *policy;

        key.cgroup_id = bpf_get_current_cgroup_id();

        long read_result = bpf_probe_read_kernel_str(
            key.filename,
            sizeof(key.filename),
            bprm->filename
        );

        if (read_result > 0) {
            policy = bpf_map_lookup_elem(
                &kg_policy_map,
                &key
            );

            if (policy &&
                policy->decision == KG_POLICY_DENY) {
                return -13; /* -EPERM */
            }
        }
    }

    /* ALLOW, REVIEW and unknown entries continue. */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
