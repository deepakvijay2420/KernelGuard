/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KernelGuard structures shared by
 *   - bpf/kg_zta.bpf.c   (kernel side, includes vmlinux.h first)
 *   - tools/kg_events.c  (user space, includes <linux/types.h> first)
 *   - kgctl.py           (mirrors the byte layouts with struct.pack)
 *
 * IMPORTANT: if you change a struct here, change the matching pack_*()
 * function in kgctl.py and the layout test in tests/test_kgctl.py.
 * All structs are laid out WITHOUT implicit padding on purpose, because
 * they are used as BPF hash-map keys (padding bytes would break lookups).
 */
#ifndef KG_COMMON_H
#define KG_COMMON_H

#define KG_NAME_LEN 32

/* Which LSM hook produced an event */
enum kg_hook {
	KG_HOOK_EXEC     = 1, /* bprm_check_security  */
	KG_HOOK_FILE     = 2, /* file_open            */
	KG_HOOK_CONNECT  = 3, /* socket_connect       */
	KG_HOOK_SENDMSG  = 4, /* socket_sendmsg (UDP sendto without connect) */
	KG_HOOK_BPF      = 5, /* bpf() syscall        */
	KG_HOOK_PTRACE   = 6, /* ptrace_access_check  */
};

/* What KernelGuard decided */
enum kg_verdict {
	KG_ALLOW      = 0,
	KG_DENY       = 1, /* enforced: kernel returned -EPERM            */
	KG_AUDIT_DENY = 2, /* audit mode: WOULD have been denied, allowed */
	KG_TAINT      = 3, /* sensitive file read, agent marked as tainted */
};

/* Per-agent enforcement mode */
enum kg_mode {
	KG_MODE_AUDIT   = 0,
	KG_MODE_ENFORCE = 1,
};

/* Action attached to a sensitive file name */
enum kg_sens_action {
	KG_SENS_TAINT = 1, /* allow the open, but taint the agent */
	KG_SENS_DENY  = 2, /* refuse the open                       */
};

#define KG_TAINT_SENSITIVE_READ 0x1u

/* key: cgroup id (u64)  ->  value: this */
struct kg_agent_cfg {
	__u32 agent_id;           /* 1..63, matches the policy file          */
	__u32 mode;               /* enum kg_mode                            */
	__u32 egress_default_deny;/* 1 = unlisted destinations are refused   */
	__u32 flags;              /* reserved                                */
};                                /* 16 bytes */

/* exec_allow key: identifies an executable by inode, NOT by path string */
struct kg_inode_key {
	__u64 ino;
	__u32 dev;                /* kernel dev_t: (major << 20) | minor     */
	__u32 agent_id;
};                                /* 16 bytes */

/* egress_allow key.  addr is in NETWORK byte order, port in HOST order.
 * port == 0 means "any port on this address". */
struct kg_egress_key {
	__u32 agent_id;
	__u32 addr;
	__u16 port;
	__u16 pad;                /* always 0 (explicit, so no hidden hole)  */
};                                /* 12 bytes */

/* sensitive_names key: NUL padded file name (final path component) */
struct kg_name_key {
	char name[KG_NAME_LEN];
};                                /* 32 bytes */

/* agent_state value: runtime state per cgroup (taint) */
struct kg_state {
	__u32 flags;              /* KG_TAINT_*                              */
	__u32 pad;
	__u64 first_taint_ns;
};                                /* 16 bytes */

/* ring-buffer record */
struct kg_event {
	__u64 ts_ns;
	__u64 cgroup_id;
	__u64 ino;
	__u32 pid;
	__u32 agent_id;
	__u32 hook;               /* enum kg_hook    */
	__u32 verdict;            /* enum kg_verdict */
	__u32 dev;
	__u32 addr;               /* network byte order, 0 if not network    */
	__u16 port;               /* host byte order                          */
	__u16 family;
	char  comm[16];
	char  name[KG_NAME_LEN];  /* exec path / file name, NUL terminated    */
};

#endif /* KG_COMMON_H */
