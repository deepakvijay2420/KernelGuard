// SPDX-License-Identifier: GPL-2.0
/*
 * kg_events - print KernelGuard ZTA v2 decisions as JSON lines.
 *
 *   build/kg_events [/sys/fs/bpf/kg_zta/maps/events]
 *
 * One JSON object per line, easy to feed into Python / pandas / jq, and
 * directly usable as the labelled "ground truth" for the evaluation chapter:
 *   {"ts_ns":..., "agent":1, "hook":"exec", "verdict":"deny", "pid":123, ...}
 */
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kg_common.h"

static volatile sig_atomic_t stop;

static void on_sig(int s)
{
	(void)s;
	stop = 1;
}

static const char *hook_name(__u32 h)
{
	switch (h) {
	case KG_HOOK_EXEC:    return "exec";
	case KG_HOOK_FILE:    return "file_open";
	case KG_HOOK_CONNECT: return "connect";
	case KG_HOOK_SENDMSG: return "sendmsg";
	case KG_HOOK_BPF:     return "bpf";
	case KG_HOOK_PTRACE:  return "ptrace";
	}
	return "unknown";
}

static const char *verdict_name(__u32 v)
{
	switch (v) {
	case KG_ALLOW:      return "allow";
	case KG_DENY:       return "deny";
	case KG_AUDIT_DENY: return "audit_deny";
	case KG_TAINT:      return "taint";
	}
	return "unknown";
}

/* print a C string as a JSON string (escape quotes, backslashes, controls) */
static void json_str(const char *s, size_t max)
{
	putchar('"');
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static int on_event(void *ctx, void *data, size_t len)
{
	const struct kg_event *e = data;
	char ip[INET_ADDRSTRLEN] = "";

	(void)ctx;
	if (len < sizeof(*e))
		return 0;

	if (e->addr) {
		struct in_addr a = { .s_addr = e->addr };

		inet_ntop(AF_INET, &a, ip, sizeof(ip));
	}

	printf("{\"ts_ns\":%llu,\"cgroup_id\":%llu,\"agent\":%u,\"hook\":\"%s\","
	       "\"verdict\":\"%s\",\"pid\":%u,\"comm\":",
	       (unsigned long long)e->ts_ns, (unsigned long long)e->cgroup_id,
	       e->agent_id, hook_name(e->hook), verdict_name(e->verdict), e->pid);
	json_str(e->comm, sizeof(e->comm));
	printf(",\"name\":");
	json_str(e->name, sizeof(e->name));
	printf(",\"ino\":%llu,\"dev\":%u,\"dst\":\"%s\",\"port\":%u,\"family\":%u}\n",
	       (unsigned long long)e->ino, e->dev, ip, e->port, e->family);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/sys/fs/bpf/kg_zta/maps/events";
	struct ring_buffer *rb;
	int fd, err = 0;

	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "kg_events: cannot open %s: %s (is KernelGuard loaded? run as root)\n",
			path, strerror(errno));
		return 1;
	}
	rb = ring_buffer__new(fd, on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "kg_events: ring_buffer__new failed\n");
		return 1;
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	while (!stop) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "kg_events: poll error %d\n", err);
			break;
		}
	}
	ring_buffer__free(rb);
	return err < 0 ? 1 : 0;
}
