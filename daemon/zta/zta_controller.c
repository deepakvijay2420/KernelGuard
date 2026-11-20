#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <yaml.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../../ebpf/zta/zta_enforcer.skel.h"

#define DEFAULT_POLICY_PATH "policies/policy.yaml"
#define MAX_POLICY_RULES 256
#define MAX_POLICY_PATH 256
#define ACTION_ALLOW 1
#define ACTION_DENY  2
#define ACTION_REVIEW 3

struct policy_key {
    uint32_t profile_id;
    uint32_t pad;
    uint64_t path_hash;
};

struct policy_entry {
    struct policy_key key;
    uint8_t action;
};

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_requested = 0;

static void handle_signal(int sig)
{
    if (sig == SIGHUP)
        reload_requested = 1;
    else
        running = 0;
}

static uint32_t profile_hash(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 16777619u;
    }
    return h ? h : 1u;
}

static uint64_t path_hash(const char *s)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; s[i] && i < MAX_POLICY_PATH; i++) {
        h ^= (uint8_t)s[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static yaml_node_t *map_value(yaml_document_t *doc,
                              yaml_node_t *mapping,
                              const char *wanted)
{
    if (!mapping || mapping->type != YAML_MAPPING_NODE)
        return NULL;

    for (yaml_node_pair_t *p = mapping->data.mapping.pairs.start;
         p < mapping->data.mapping.pairs.top; p++) {
        yaml_node_t *key = yaml_document_get_node(doc, p->key);
        if (key && key->type == YAML_SCALAR_NODE &&
            key->data.scalar.length == strlen(wanted) &&
            memcmp(key->data.scalar.value, wanted, strlen(wanted)) == 0)
            return yaml_document_get_node(doc, p->value);
    }
    return NULL;
}

static int append_sequence(yaml_document_t *doc,
                           yaml_node_t *sequence,
                           uint32_t profile_id,
                           uint8_t action,
                           struct policy_entry *entries,
                           size_t *count)
{
    if (!sequence || sequence->type != YAML_SEQUENCE_NODE)
        return -1;

    for (yaml_node_item_t *item = sequence->data.sequence.items.start;
         item < sequence->data.sequence.items.top; item++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        if (!node || node->type != YAML_SCALAR_NODE)
            return -1;

        size_t len = node->data.scalar.length;
        char path[MAX_POLICY_PATH];
        if (len == 0 || len >= sizeof(path) ||
            node->data.scalar.value[0] != '/') {
            fprintf(stderr, "[POLICY] Invalid executable path in YAML\n");
            return -1;
        }
        memcpy(path, node->data.scalar.value, len);
        path[len] = '\0';

        if (*count >= MAX_POLICY_RULES) {
            fprintf(stderr, "[POLICY] More than %d rules are not supported\n",
                    MAX_POLICY_RULES);
            return -1;
        }

        entries[*count].key.profile_id = profile_id;
        entries[*count].key.pad = 0;
        entries[*count].key.path_hash = path_hash(path);
        entries[*count].action = action;
        (*count)++;
    }
    return 0;
}

static int load_policy_file(const char *filename,
                            const char *profile,
                            struct policy_entry *entries,
                            size_t *count,
                            uint32_t *profile_id)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[POLICY] Cannot open %s: %s\n",
                filename, strerror(errno));
        return -1;
    }

    yaml_parser_t parser;
    yaml_document_t doc;
    if (!yaml_parser_initialize(&parser)) {
        fclose(fp);
        fprintf(stderr, "[POLICY] YAML parser initialization failed\n");
        return -1;
    }

    yaml_parser_set_input_file(&parser, fp);
    if (!yaml_parser_load(&parser, &doc)) {
        fprintf(stderr, "[POLICY] YAML parse error: %s\n",
                parser.problem ? parser.problem : "unknown error");
        yaml_parser_delete(&parser);
        fclose(fp);
        return -1;
    }
    yaml_parser_delete(&parser);
    fclose(fp);

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    yaml_node_t *agents = map_value(&doc, root, "agents");
    yaml_node_t *agent = map_value(&doc, agents, profile);
    yaml_node_t *execution = map_value(&doc, agent, "execution");
    yaml_node_t *allow = map_value(&doc, execution, "allow");
    yaml_node_t *deny = map_value(&doc, execution, "deny");

    if (!agent || !execution || !allow || !deny) {
        fprintf(stderr,
                "[POLICY] Profile '%s' must define execution.allow and execution.deny\n",
                profile);
        yaml_document_delete(&doc);
        return -1;
    }

    *count = 0;
    *profile_id = profile_hash(profile);

    int rc = append_sequence(&doc, allow, *profile_id, ACTION_ALLOW,
                             entries, count);
    if (rc == 0)
        rc = append_sequence(&doc, deny, *profile_id, ACTION_DENY,
                             entries, count);

    yaml_document_delete(&doc);
    if (rc != 0)
        return -1;

    printf("[POLICY] Loaded profile '%s' (ID=%u), %zu executable rules\n",
           profile, *profile_id, *count);
    return 0;
}

static int clear_policy_map(int map_fd)
{
    struct policy_key keys[MAX_POLICY_RULES];
    struct policy_key previous, next;
    size_t count = 0;
    int have_previous = 0;

    while (bpf_map_get_next_key(map_fd,
                                have_previous ? &previous : NULL,
                                &next) == 0) {
        if (count >= MAX_POLICY_RULES) {
            fprintf(stderr, "[POLICY] Map contains more than %d entries\n",
                    MAX_POLICY_RULES);
            return -1;
        }
        keys[count++] = next;
        previous = next;
        have_previous = 1;
    }

    for (size_t i = 0; i < count; i++) {
        if (bpf_map_delete_elem(map_fd, &keys[i]) != 0 && errno != ENOENT) {
            fprintf(stderr, "[POLICY] Failed to clear old rule: %s\n",
                    strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int apply_policy(int map_fd, const char *policy_path,
                        const char *profile, uint32_t *profile_id_out)
{
    struct policy_entry entries[MAX_POLICY_RULES];
    size_t count = 0;
    uint32_t profile_id = 0;

    /* Parse and validate completely before touching the active map. */
    if (load_policy_file(policy_path, profile, entries, &count,
                         &profile_id) != 0)
        return -1;

    if (clear_policy_map(map_fd) != 0)
        return -1;

    for (size_t i = 0; i < count; i++) {
        if (bpf_map_update_elem(map_fd, &entries[i].key,
                                &entries[i].action, BPF_ANY) != 0) {
            fprintf(stderr, "[POLICY] Failed to install rule %zu: %s\n",
                    i + 1, strerror(errno));
            return -1;
        }
    }

    *profile_id_out = profile_id;
    printf("[POLICY] Successfully applied %zu rules to the kernel map\n",
           count);
    return 0;
}

static int agent_exists(uint32_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u", pid);
    return access(path, F_OK) == 0;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "Usage: sudo %s <AGENT_PID> <AGENT_PROFILE> [POLICY_FILE]\n"
                "Example: sudo %s 7217 research_agent policies/policy.yaml\n",
                argv[0], argv[0]);
        return 1;
    }

    char *end = NULL;
    unsigned long parsed_pid = strtoul(argv[1], &end, 10);
    if (!argv[1][0] || !end || *end || parsed_pid == 0 ||
        parsed_pid > UINT32_MAX) {
        fprintf(stderr, "[ERROR] Invalid Agent PID\n");
        return 1;
    }

    uint32_t agent_pid = (uint32_t)parsed_pid;
    const char *profile = argv[2];
    const char *policy_path = argc == 4 ? argv[3] : DEFAULT_POLICY_PATH;

    if (!agent_exists(agent_pid)) {
        fprintf(stderr, "[ERROR] Agent PID %u does not exist\n", agent_pid);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct policy_entry validation[MAX_POLICY_RULES];
    size_t validation_count = 0;
    uint32_t profile_id = 0;
    if (load_policy_file(policy_path, profile, validation,
                         &validation_count, &profile_id) != 0)
        return 1;

    struct zta_enforcer_bpf *skel = zta_enforcer_bpf__open();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open BPF skeleton\n");
        return 1;
    }

    int err = zta_enforcer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load BPF program: %d\n", err);
        zta_enforcer_bpf__destroy(skel);
        return 1;
    }

    err = zta_enforcer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to attach BPF-LSM: %d\n", err);
        zta_enforcer_bpf__destroy(skel);
        return 1;
    }

    int agent_map_fd = bpf_map__fd(skel->maps.agent_roots);
    int policy_map_fd = bpf_map__fd(skel->maps.execution_policy);
    if (agent_map_fd < 0 || policy_map_fd < 0) {
        fprintf(stderr, "[ERROR] Failed to obtain BPF map FDs\n");
        zta_enforcer_bpf__destroy(skel);
        return 1;
    }

    if (apply_policy(policy_map_fd, policy_path, profile, &profile_id) != 0) {
        zta_enforcer_bpf__destroy(skel);
        return 1;
    }

    if (bpf_map_update_elem(agent_map_fd, &agent_pid,
                            &profile_id, BPF_ANY) != 0) {
        fprintf(stderr, "[ERROR] Agent registration failed: %s\n",
                strerror(errno));
        zta_enforcer_bpf__destroy(skel);
        return 1;
    }

    printf("\n[+] BPF-LSM attached\n");
    printf("[+] Agent PID %u registered with profile '%s' (ID=%u)\n",
           agent_pid, profile, profile_id);
    printf("[+] DENY rules are enforced in the kernel\n");
    printf("[+] ALLOW and unlisted REVIEW decisions are non-blocking\n");
    printf("[+] Send SIGHUP to reload the YAML policy; Ctrl+C to stop\n");

    while (running) {
        if (reload_requested) {
            reload_requested = 0;
            printf("[*] Reloading policy from %s...\n", policy_path);
            uint32_t new_profile_id = profile_id;
            if (apply_policy(policy_map_fd, policy_path, profile,
                             &new_profile_id) == 0 &&
                new_profile_id == profile_id) {
                printf("[+] Policy reload successful\n");
            } else {
                fprintf(stderr,
                        "[-] Policy reload failed; existing agent profile remains registered\n");
            }
        }
        sleep(1);
    }

    bpf_map_delete_elem(agent_map_fd, &agent_pid);
    zta_enforcer_bpf__destroy(skel);
    printf("[+] Agent registration removed; BPF-LSM detached\n");
    return 0;
}
