#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <yaml.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_RULES 50
#define MAX_PATH_LEN 256

/* ==========================================
 * EVENT STRUCTURE FROM eBPF
 * ========================================== */
struct exec_event {
    uint32_t pid;
    uint32_t uid;
    char comm[64];
    char filename[256];
};

/* ==========================================
 * POLICY STRUCTURE
 * ========================================== */
struct policy {
    char high_risk_paths[MAX_RULES][MAX_PATH_LEN];
    int high_count;

    char medium_risk_commands[MAX_RULES][MAX_PATH_LEN];
    int medium_count;

    char low_risk_commands[MAX_RULES][MAX_PATH_LEN];
    int low_count;
};

static struct policy g_policy;
static volatile sig_atomic_t exiting = 0;


/* ==========================================
 * SIGNAL HANDLER
 * ========================================== */
static void sig_handler(int sig)
{
    exiting = 1;
}


/* ==========================================
 * ADD POLICY RULE
 * ========================================== */
static void add_rule(char rules[][MAX_PATH_LEN],
                     int *count,
                     const char *value)
{
    if (*count >= MAX_RULES)
        return;

    strncpy(rules[*count], value, MAX_PATH_LEN - 1);
    rules[*count][MAX_PATH_LEN - 1] = '\0';

    (*count)++;
}


/* ==========================================
 * LOAD YAML POLICY
 * ========================================== */
static int load_policy(const char *filename)
{
    FILE *fh;
    yaml_parser_t parser;
    yaml_event_t event;

    char current_section[64] = "";

    fh = fopen(filename, "r");

    if (!fh) {
        perror("Failed to open policy file");
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(fh);
        return -1;
    }

    yaml_parser_set_input_file(&parser, fh);

    while (1) {

        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "YAML parsing error\n");
            yaml_parser_delete(&parser);
            fclose(fh);
            return -1;
        }

        if (event.type == YAML_SCALAR_EVENT) {

            const char *value =
                (const char *)event.data.scalar.value;

            /*
             * Detect section names
             */
            if (strcmp(value, "high_risk_paths") == 0) {

                strcpy(current_section, "high");

            } else if (strcmp(value, "medium_risk_commands") == 0) {

                strcpy(current_section, "medium");

            } else if (strcmp(value, "low_risk_commands") == 0) {

                strcpy(current_section, "low");

            } else {

                /*
                 * Add rules to appropriate section
                 */
                if (strcmp(current_section, "high") == 0) {

                    add_rule(
                        g_policy.high_risk_paths,
                        &g_policy.high_count,
                        value
                    );

                } else if (strcmp(current_section, "medium") == 0) {

                    add_rule(
                        g_policy.medium_risk_commands,
                        &g_policy.medium_count,
                        value
                    );

                } else if (strcmp(current_section, "low") == 0) {

                    add_rule(
                        g_policy.low_risk_commands,
                        &g_policy.low_count,
                        value
                    );
                }
            }
        }

        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(fh);

    printf("[+] Policy loaded successfully\n");
    printf("    HIGH rules   : %d\n", g_policy.high_count);
    printf("    MEDIUM rules : %d\n", g_policy.medium_count);
    printf("    LOW rules    : %d\n", g_policy.low_count);

    return 0;
}


/* ==========================================
 * CHECK EXACT COMMAND
 * ========================================== */
static int matches_command(const char *path,
                           char rules[][MAX_PATH_LEN],
                           int count)
{
    for (int i = 0; i < count; i++) {

        if (strcmp(path, rules[i]) == 0)
            return 1;
    }

    return 0;
}


/* ==========================================
 * CHECK PATH PREFIX
 * ========================================== */
static int matches_path_prefix(const char *path,
                               char rules[][MAX_PATH_LEN],
                               int count)
{
    for (int i = 0; i < count; i++) {

        size_t len = strlen(rules[i]);

        if (strncmp(path, rules[i], len) == 0)
            return 1;
    }

    return 0;
}


/* ==========================================
 * DYNAMIC POLICY ENGINE
 * ========================================== */
static void evaluate_policy(struct exec_event *event,
                            const char **risk,
                            const char **reason,
                            const char **status,
                            const char **action)
{
    /* HIGH RISK */
    if (matches_path_prefix(
            event->filename,
            g_policy.high_risk_paths,
            g_policy.high_count)) {

        *risk = "HIGH";
        *reason = "Execution from high-risk path";
        *status = "Potentially suspicious activity detected";
        *action = "ALERT";
    }

    /* MEDIUM RISK */
    else if (matches_command(
                 event->filename,
                 g_policy.medium_risk_commands,
                 g_policy.medium_count)) {

        *risk = "MEDIUM";
        *reason = "Sensitive command detected";
        *status = "Sensitive activity detected";
        *action = "WARNING";
    }

    /* LOW RISK */
    else if (matches_command(
                 event->filename,
                 g_policy.low_risk_commands,
                 g_policy.low_count)) {

        *risk = "LOW";
        *reason = "Known standard system command";
        *status = "Normal activity";
        *action = "ALLOW";
    }

    /* UNKNOWN */
    else {

        *risk = "REVIEW";
        *reason = "Executable not found in current policy";
        *status = "Unknown activity - Review required";
        *action = "MONITOR";
    }
}


/* ==========================================
 * SECURITY LOGGER
 * ========================================== */
static void log_security_event(struct exec_event *event,
                               const char *risk,
                               const char *reason,
                               const char *status,
                               const char *action)
{
    FILE *log_file;
    time_t now;
    struct tm *time_info;
    char timestamp[64];

    log_file = fopen(
        "/home/deepak/kernelguard/logs/security_events.log",
        "a"
    );

    if (!log_file) {
        perror("Failed to open security log");
        return;
    }

    time(&now);
    time_info = localtime(&now);

    strftime(timestamp, sizeof(timestamp),
             "%Y-%m-%d %H:%M:%S", time_info);

    fprintf(log_file,
            "[%s]\n"
            "PID     : %u\n"
            "UID     : %u\n"
            "PROCESS : %s\n"
            "PATH    : %s\n"
            "RISK    : %s\n"
            "REASON  : %s\n"
            "STATUS  : %s\n"
            "ACTION  : %s\n"
            "----------------------------------------\n",
            timestamp,
            event->pid,
            event->uid,
            event->comm,
            event->filename,
            risk,
            reason,
            status,
            action);

    fclose(log_file);
}


/* ==========================================
 * RESPONSE ENGINE
 * ========================================== */
static void execute_response(struct exec_event *event,
                             const char *risk,
                             const char *action)
{
    if (strcmp(risk, "HIGH") == 0) {

        printf("\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("     KERNELGUARD SECURITY ALERT\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("HIGH RISK PROCESS DETECTED!\n");
        printf("PROCESS : %s\n", event->comm);
        printf("PATH    : %s\n", event->filename);
        printf("ACTION  : %s GENERATED\n", action);
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }

    else if (strcmp(risk, "MEDIUM") == 0) {

        printf("\n[!] SECURITY WARNING: Sensitive activity detected\n");
        printf("    ACTION: %s\n", action);
    }
}


/* ==========================================
 * RING BUFFER EVENT HANDLER
 * ========================================== */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct exec_event *event = data;

    const char *risk;
    const char *reason;
    const char *status;
    const char *action;

    evaluate_policy(
        event,
        &risk,
        &reason,
        &status,
        &action
    );

    execute_response(event, risk, action);

    log_security_event(
        event,
        risk,
        reason,
        status,
        action
    );

    printf("\n");
    printf("========================================\n");
    printf("       KERNELGUARD SECURITY EVENT\n");
    printf("========================================\n");

    printf("PID      : %u\n", event->pid);
    printf("UID      : %u\n", event->uid);
    printf("PROCESS  : %s\n", event->comm);
    printf("PATH     : %s\n", event->filename);

    printf("----------------------------------------\n");

    printf("RISK     : %s\n", risk);
    printf("REASON   : %s\n", reason);
    printf("STATUS   : %s\n", status);
    printf("ACTION   : %s\n", action);

    printf("========================================\n");

    return 0;
}


/* ==========================================
 * MAIN
 * ========================================== */
int main(void)
{
    const char *map_path =
        "/sys/fs/bpf/kernelguard_events";

    const char *policy_path =
        "/home/deepak/kernelguard/policy.yaml";

    int map_fd;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("========================================\n");
    printf("     KernelGuard Security Monitor\n");
    printf("========================================\n");

    /* Load dynamic policy */
    if (load_policy(policy_path) != 0) {
        fprintf(stderr,
                "Failed to load security policy\n");
        return 1;
    }

    /* Connect to eBPF Ring Buffer */
    map_fd = bpf_obj_get(map_path);

    if (map_fd < 0) {

        fprintf(stderr,
                "Failed to open KernelGuard ring buffer: %s\n",
                strerror(errno));

        return 1;
    }

    printf("[+] Ring buffer connected successfully\n");
    printf("[+] Dynamic policy engine loaded\n");
    printf("[+] Response engine loaded\n");
    printf("[+] Security event logging enabled\n");
    printf("[+] Waiting for process execution events...\n");

    rb = ring_buffer__new(
        map_fd,
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {

        fprintf(stderr,
                "Failed to create ring buffer\n");

        close(map_fd);
        return 1;
    }

    while (!exiting) {

        err = ring_buffer__poll(rb, 100);

        if (err < 0 && err != -EINTR) {

            fprintf(stderr,
                    "Ring buffer polling error: %d\n",
                    err);

            break;
        }
    }

    printf("\nKernelGuard monitor stopped.\n");

    ring_buffer__free(rb);
    close(map_fd);

    return 0;
}
