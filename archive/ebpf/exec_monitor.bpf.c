#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Event sent from kernel to userspace */
struct exec_event {
    __u32 pid;
    __u32 uid;
    char comm[64];
    char filename[256];
};

/* Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* LSM Hook - Detect process execution */
SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm)
{
    struct exec_event *event;
    const char *filename;

    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event)
        return 0;

    /* Get Process ID */
    event->pid = bpf_get_current_pid_tgid() >> 32;

    /* Get User ID */
    event->uid = bpf_get_current_uid_gid() & 0xffffffff;

    /* Get process command name */
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* Get actual executable filename */
    filename = BPF_CORE_READ(bprm, filename);

    if (filename) {
        bpf_probe_read_kernel_str(
            event->filename,
            sizeof(event->filename),
            filename
        );
    } else {
        event->filename[0] = '\0';
    }

    /* Send event to userspace */
    bpf_ringbuf_submit(event, 0);

    return 0;
}
