// SPDX-License-Identifier: GPL-2.0
/*
 * KernelGuard kernel enforcement program (BPF-LSM)
 *
 * The unified enforcement implementation uses:
 *
 *  1. IDENTITY   : cgroup v2 id instead of "PID + 8-level parent walk".
 *                  Children inherit the cgroup, so double-fork / reparenting
 *                  to init no longer escapes.  PID reuse is irrelevant.
 *  2. EXEC       : DENY BY DEFAULT.  An agent may only exec files whose
 *                  (device, inode) is in exec_allow.  String path tricks
 *                  (symlink, ../, //, copy to /tmp, memfd) do not match.
 *  3. FILES      : file_open hook.  Sensitive file names (.env, id_rsa,
 *                  shadow, ...) are either denied or "taint" the agent.
 *  4. NETWORK    : socket_connect + socket_sendmsg.  Egress allow-list
 *                  by IPv4:port.  A TAINTED agent loses all non-listed
 *                  egress (read secret -> cannot phone home).
 *  5. SELF-PROTECT: agents cannot call bpf() or ptrace().
 *  6. AUDIT MODE : per-agent audit|enforce, so a policy can be measured
 *                  for false positives before it is turned on.
 *
 * The program never trusts anything the agent can choose (path strings,
 * comm, pid).  It trusts only the cgroup the controller put it in and the
 * kernel's own inode numbers.
 *
 * Build: see zta_v2/Makefile.  Needs CONFIG_BPF_LSM=y and "bpf" in lsm=.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "kg_common.h"

#ifndef EPERM
#define EPERM 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* Maps (pinned by the loader, filled by kgctl.py)                    */
/* ------------------------------------------------------------------ */

/* cgroup id -> agent config.  Presence of the key == "this is an agent". */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct kg_agent_cfg);
} agent_cgroups SEC(".maps");

/* (agent_id, dev, ino) -> 1 : executables this agent may run */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct kg_inode_key);
	__type(value, __u8);
} exec_allow SEC(".maps");

/* file name -> enum kg_sens_action (global, not per agent) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct kg_name_key);
	__type(value, __u8);
} sensitive_names SEC(".maps");

/* (agent_id, ipv4, port) -> 1 : allowed egress destinations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct kg_egress_key);
	__type(value, __u8);
} egress_allow SEC(".maps");

/* cgroup id -> runtime state (taint) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct kg_state);
} agent_state SEC(".maps");

/* counters[hook * 8 + verdict], useful for the evaluation chapter */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static __always_inline struct kg_agent_cfg *current_agent(__u64 *cgid)
{
	__u64 id = bpf_get_current_cgroup_id();

	*cgid = id;
	return bpf_map_lookup_elem(&agent_cgroups, &id);
}

static __always_inline void bump(__u32 hook, __u32 verdict)
{
	__u32 idx = hook * 8 + verdict;
	__u64 *v;

	if (idx >= 64)
		return;
	v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += 1;
}

static __always_inline void emit(struct kg_agent_cfg *cfg, __u64 cgid,
				 __u32 hook, __u32 verdict, __u64 ino,
				 __u32 dev, __u32 addr, __u16 port,
				 __u16 family, const char *name)
{
	struct kg_event *e;

	bump(hook, verdict);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	/* zero everything: the ring buffer is not cleared and we must not
	 * leak stale kernel memory to user space through padding. */
	__builtin_memset(e, 0, sizeof(*e));

	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = cgid;
	e->ino = ino;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->agent_id = cfg->agent_id;
	e->hook = hook;
	e->verdict = verdict;
	e->dev = dev;
	e->addr = addr;
	e->port = port;
	e->family = family;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	if (name)
		bpf_probe_read_kernel_str(e->name, sizeof(e->name), name);

	bpf_ringbuf_submit(e, 0);
}

/*
 * Record a policy violation.  Returns what the LSM hook must return:
 *   enforce mode -> -EPERM
 *   audit mode   -> 0 (but the event says AUDIT_DENY)
 */
static __always_inline int violation(struct kg_agent_cfg *cfg, __u64 cgid,
				     __u32 hook, __u64 ino, __u32 dev,
				     __u32 addr, __u16 port, __u16 family,
				     const char *name)
{
	__u32 verdict = cfg->mode == KG_MODE_ENFORCE ? KG_DENY : KG_AUDIT_DENY;

	emit(cfg, cgid, hook, verdict, ino, dev, addr, port, family, name);
	return verdict == KG_DENY ? -EPERM : 0;
}

static __always_inline void taint(__u64 cgid)
{
	struct kg_state *s = bpf_map_lookup_elem(&agent_state, &cgid);
	struct kg_state n = {};

	if (s) {
		s->flags |= KG_TAINT_SENSITIVE_READ;
		return;
	}
	n.flags = KG_TAINT_SENSITIVE_READ;
	n.first_taint_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&agent_state, &cgid, &n, BPF_ANY);
}

static __always_inline int is_tainted(__u64 cgid)
{
	struct kg_state *s = bpf_map_lookup_elem(&agent_state, &cgid);

	return s && (s->flags & KG_TAINT_SENSITIVE_READ);
}

/* ------------------------------------------------------------------ */
/* 1. EXEC: deny by default, identify binaries by inode               */
/* ------------------------------------------------------------------ */
SEC("lsm/bprm_check_security")
int BPF_PROG(kg_exec, struct linux_binprm *bprm, int ret)
{
	struct kg_agent_cfg *cfg;
	struct kg_inode_key k = {};
	struct file *f;
	__u64 cgid;

	if (ret)
		return ret; /* keep an earlier LSM's refusal */

	cfg = current_agent(&cgid);
	if (!cfg)
		return 0; /* not an agent: KernelGuard does not interfere */

	f = BPF_CORE_READ(bprm, file);
	k.ino = BPF_CORE_READ(f, f_inode, i_ino);
	k.dev = BPF_CORE_READ(f, f_inode, i_sb, s_dev);
	k.agent_id = cfg->agent_id;

	if (bpf_map_lookup_elem(&exec_allow, &k))
		return 0;

	return violation(cfg, cgid, KG_HOOK_EXEC, k.ino, k.dev, 0, 0, 0,
			 BPF_CORE_READ(bprm, filename));
}

/* ------------------------------------------------------------------ */
/* 2. FILES: sensitive names -> deny or taint                         */
/* ------------------------------------------------------------------ */
SEC("lsm/file_open")
int BPF_PROG(kg_file_open, struct file *file, int ret)
{
	struct kg_agent_cfg *cfg;
	struct kg_name_key nk = {};
	const unsigned char *np;
	__u8 *action;
	__u64 cgid;

	if (ret)
		return ret;

	cfg = current_agent(&cgid);
	if (!cfg)
		return 0;

	/* final path component of the *resolved* file: opening it through a
	 * symlink with an innocent name still shows the real name here. */
	np = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (!np)
		return 0;
	bpf_probe_read_kernel_str(nk.name, sizeof(nk.name), np);

	action = bpf_map_lookup_elem(&sensitive_names, &nk);
	if (!action)
		return 0;

	if (*action == KG_SENS_TAINT) {
		taint(cgid);
		emit(cfg, cgid, KG_HOOK_FILE, KG_TAINT,
		     BPF_CORE_READ(file, f_inode, i_ino),
		     BPF_CORE_READ(file, f_inode, i_sb, s_dev), 0, 0, 0,
		     (const char *)np);
		return 0;
	}

	return violation(cfg, cgid, KG_HOOK_FILE,
			 BPF_CORE_READ(file, f_inode, i_ino),
			 BPF_CORE_READ(file, f_inode, i_sb, s_dev), 0, 0, 0,
			 (const char *)np);
}

/* ------------------------------------------------------------------ */
/* 3. NETWORK                                                         */
/* ------------------------------------------------------------------ */

/* sockaddr_ptr is a KERNEL pointer (already copied from user space). */
static __always_inline int check_dest(struct kg_agent_cfg *cfg, __u64 cgid,
				      __u32 hook, const void *sockaddr_ptr)
{
	struct kg_egress_key key = {};
	struct sockaddr_in sin = {};
	__u16 family = 0;
	int restricted;

	if (bpf_probe_read_kernel(&family, sizeof(family), sockaddr_ptr))
		return violation(cfg, cgid, hook, 0, 0, 0, 0, 0, NULL);

	/* AF_UNIX / AF_NETLINK etc.: not an egress path, leave alone.
	 * (AF_UNIX can still reach local daemons, see ROADMAP "limits") */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	restricted = cfg->egress_default_deny || is_tainted(cgid);

	if (family == AF_INET) {
		if (bpf_probe_read_kernel(&sin, sizeof(sin), sockaddr_ptr))
			return violation(cfg, cgid, hook, 0, 0, 0, 0, family,
					 NULL);

		key.agent_id = cfg->agent_id;
		key.addr = sin.sin_addr.s_addr;      /* network order */
		key.port = bpf_ntohs(sin.sin_port);  /* host order    */

		if (bpf_map_lookup_elem(&egress_allow, &key))
			return 0;
		key.port = 0; /* wildcard-port rule for this address */
		if (bpf_map_lookup_elem(&egress_allow, &key))
			return 0;

		if (!restricted)
			return 0;
		return violation(cfg, cgid, hook, 0, 0, sin.sin_addr.s_addr,
				 bpf_ntohs(sin.sin_port), family, NULL);
	}

	/* IPv6: no allow-list yet (ROADMAP phase 3).  Treat as unlisted. */
	if (!restricted)
		return 0;
	return violation(cfg, cgid, hook, 0, 0, 0, 0, family, NULL);
}

SEC("lsm/socket_connect")
int BPF_PROG(kg_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct kg_agent_cfg *cfg;
	__u64 cgid;

	if (ret)
		return ret;
	cfg = current_agent(&cgid);
	if (!cfg)
		return 0;
	return check_dest(cfg, cgid, KG_HOOK_CONNECT, address);
}

/* UDP sendto()/sendmsg() with an explicit destination bypasses connect(). */
SEC("lsm/socket_sendmsg")
int BPF_PROG(kg_sendmsg, struct socket *sock, struct msghdr *msg, int size,
	     int ret)
{
	struct kg_agent_cfg *cfg;
	void *name;
	__u64 cgid;

	if (ret)
		return ret;
	cfg = current_agent(&cgid);
	if (!cfg)
		return 0;

	name = BPF_CORE_READ(msg, msg_name);
	if (!name)
		return 0; /* connected socket: destination vetted at connect() */
	return check_dest(cfg, cgid, KG_HOOK_SENDMSG, name);
}

/* ------------------------------------------------------------------ */
/* 4. SELF-PROTECTION                                                 */
/* ------------------------------------------------------------------ */
SEC("lsm/bpf")
int BPF_PROG(kg_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	struct kg_agent_cfg *cfg;
	__u64 cgid;

	if (ret)
		return ret;
	cfg = current_agent(&cgid);
	if (!cfg)
		return 0;
	return violation(cfg, cgid, KG_HOOK_BPF, 0, 0, 0, 0, 0, NULL);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(kg_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
	struct kg_agent_cfg *cfg;
	__u64 cgid;

	if (ret)
		return ret;
	cfg = current_agent(&cgid);
	if (!cfg)
		return 0;
	return violation(cfg, cgid, KG_HOOK_PTRACE, 0, 0, 0, 0, 0, NULL);
}
