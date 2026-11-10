#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../bpf/kg_common.h"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static const char *event_name(unsigned int type)
{
    switch (type) {
    case KG_EVENT_EXEC: return "EXEC";
    case KG_EVENT_FILE_OPEN: return "FILE_OPEN";
    case KG_EVENT_SOCKET_CONNECT: return "SOCKET_CONNECT";
    case KG_EVENT_SOCKET_SENDMSG: return "SOCKET_SENDMSG";
    case KG_EVENT_BPF: return "BPF";
    case KG_EVENT_PTRACE: return "PTRACE";
    default: return "UNKNOWN";
    }
}

static int load_policy_map(int map_fd)
{
    FILE *fp = fopen("policy/policy.bin", "rb");
    if (!fp) {
        perror("Opening policy/policy.bin");
        return -errno;
    }

    uint32_t count = 0;

    if (fread(&count, sizeof(count), 1, fp) != 1) {
        fprintf(stderr, "[ERROR] Invalid policy file header\n");
        fclose(fp);
        return -EINVAL;
    }

    if (count > 1024) {
        fprintf(stderr, "[ERROR] Too many policy entries: %u\n", count);
        fclose(fp);
        return -E2BIG;
    }

    for (uint32_t i = 0; i < count; i++) {
        struct kg_policy_key key = {};
        struct kg_policy_value value = {};

        if (fread(&key, sizeof(key), 1, fp) != 1 ||
            fread(&value, sizeof(value), 1, fp) != 1) {
            fprintf(stderr, "[ERROR] Invalid policy entry %u\n", i);
            fclose(fp);
            return -EINVAL;
        }

        if (value.decision != KG_POLICY_ALLOW &&
            value.decision != KG_POLICY_DENY) {
            fprintf(stderr, "[ERROR] Invalid decision in entry %u\n", i);
            fclose(fp);
            return -EINVAL;
        }

        int err = bpf_map_update_elem(
            map_fd, &key, &value, BPF_ANY
        );

        if (err) {
            err = -errno;
            perror("Updating BPF policy map");
            fclose(fp);
            return err;
        }
    }

    if (fgetc(fp) != EOF) {
        fprintf(stderr, "[ERROR] Unexpected trailing policy data\n");
        fclose(fp);
        return -EINVAL;
    }

    fclose(fp);

    printf("[KernelGuard v2] Loaded %u policy entries.\n", count);
    return 0;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;

    if (size < sizeof(struct kg_event)) {
        fprintf(stderr, "[ERROR] Invalid event size: %zu\n", size);
        return 0;
    }

    const struct kg_event *event = data;

    printf(
        "{\"event\":\"%s\","
        "\"tgid\":%u,"
        "\"uid\":%u,"
        "\"cgroup_id\":%llu,"
        "\"timestamp_ns\":%llu,"
        "\"comm\":\"%.15s\","
        "\"filename\":\"%.127s\"}\n",
        event_name(event->event_type),
        event->tgid,
        event->uid,
        event->cgroup_id,
        event->timestamp_ns,
        event->comm,
        event->filename
    );

    fflush(stdout);
    return 0;
}

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *policy_map;
    struct bpf_map *events_map;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;

    int err = 0;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[KernelGuard v2] Opening BPF object...\n");

    obj = bpf_object__open_file("build/kg_zta.bpf.o", NULL);

    err = libbpf_get_error(obj);
    if (err) {
        obj = NULL;
        fprintf(stderr, "[ERROR] Opening BPF object: %d\n", err);
        return 1;
    }

    printf("[KernelGuard v2] Loading BPF object...\n");

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[ERROR] BPF load failed: %d\n", err);
        goto cleanup;
    }

    policy_map = bpf_object__find_map_by_name(obj, "kg_policy_map");
    events_map = bpf_object__find_map_by_name(obj, "kg_events");

    if (!policy_map || !events_map) {
        fprintf(stderr, "[ERROR] Required BPF map not found\n");
        err = -ENOENT;
        goto cleanup;
    }

    printf("[KernelGuard v2] Loading policy before hook attachment...\n");

    err = load_policy_map(bpf_map__fd(policy_map));
    if (err)
        goto cleanup;

    prog = bpf_object__find_program_by_name(obj, "kg_v2_exec_probe");

    if (!prog) {
        fprintf(stderr, "[ERROR] BPF program not found\n");
        err = -ENOENT;
        goto cleanup;
    }

    printf("[KernelGuard v2] Attaching execution hook...\n");

    link = bpf_program__attach(prog);

    err = libbpf_get_error(link);
    if (err) {
        link = NULL;
        fprintf(stderr, "[ERROR] BPF attach failed: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(events_map),
        handle_event,
        NULL,
        NULL
    );

    err = libbpf_get_error(rb);
    if (err) {
        rb = NULL;
        fprintf(stderr, "[ERROR] Ring buffer creation failed: %d\n", err);
        goto cleanup;
    }

    printf("[KernelGuard v2] Monitoring execution events.\n");
    printf("[KernelGuard v2] Press Ctrl+C to stop.\n");

    while (running) {
        err = ring_buffer__poll(rb, 1000);

        if (err == -EINTR) {
            err = 0;
            continue;
        }

        if (err < 0) {
            fprintf(stderr, "[ERROR] Ring buffer poll: %d\n", err);
            break;
        }

        err = 0;
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);

    if (link)
        bpf_link__destroy(link);

    if (obj)
        bpf_object__close(obj);

    printf("[KernelGuard v2] Reader stopped.\n");
    return err < 0 ? 1 : 0;
}
