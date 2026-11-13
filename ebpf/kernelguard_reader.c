#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EVENT_MAP "/sys/fs/bpf/kernelguard_events"

/* Install root: set KG_HOME in the environment (default: $HOME/kernelguard). */
static const char *kg_home(void)
{
    const char *h = getenv("KG_HOME");
    if (h && *h)
        return h;
    static char buf[512];
    const char *home = getenv("HOME");
    snprintf(buf, sizeof(buf), "%s/kernelguard", home ? home : ".");
    return buf;
}

static const char *kg_path(const char *rel)
{
    static char out[2][1024];
    static int i;
    i ^= 1;
    snprintf(out[i], sizeof(out[i]), "%s/%s", kg_home(), rel);
    return out[i];
}

#define POLICY_ENGINE kg_path("daemon/dynamic_policy_engine.py")
#define LOG_FILE      kg_path("logs/kernelguard_live.log")


/* ============================================================
 * Event structure
 * Must match exec_monitor.bpf.c
 * ============================================================ */

struct exec_event {
    unsigned int pid;
    unsigned int uid;

    char comm[64];
    char filename[256];
};


/* ============================================================
 * Check whether an event should be ignored
 *
 * These processes are generated internally by the policy engine
 * and other helper operations.
 * ============================================================ */

static int should_ignore_event(struct exec_event *event)
{
    const char *ignored_paths[] = {

        /* Shell used internally by popen() */
        "/bin/sh",
        "/usr/bin/sh",

        /* Common shell helpers */
        "/usr/bin/lesspipe",
        "/usr/bin/basename",
        "/usr/bin/dirname",
        "/usr/bin/dircolors",

        /* Python policy engine */
        "/usr/bin/python3",
        "/bin/python3",

        NULL
    };

    for (int i = 0; ignored_paths[i] != NULL; i++) {

        if (strcmp(event->filename, ignored_paths[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


/* ============================================================
 * Run dynamic Python policy engine
 * ============================================================ */

static int check_policy(
    const char *path,
    char *risk,
    size_t risk_size,
    char *reason,
    size_t reason_size,
    char *action,
    size_t action_size
)
{
    char command[1024];
    char output[1024];

    /*
     * The executable path comes from the kernel.
     *
     * Escape single quotes before passing the path
     * to the shell.
     */

    char safe_path[600];
    size_t j = 0;

    for (size_t i = 0;
         path[i] != '\0' && j < sizeof(safe_path) - 5;
         i++) {

        if (path[i] == '\'') {

            safe_path[j++] = '\'';
            safe_path[j++] = '\\';
            safe_path[j++] = '\'';
            safe_path[j++] = '\'';

        } else {

            safe_path[j++] = path[i];
        }
    }

    safe_path[j] = '\0';


    /*
     * Run Python policy engine.
     */

    snprintf(
        command,
        sizeof(command),
        "python3 '%s' '%s'",
        POLICY_ENGINE,
        safe_path
    );


    FILE *fp = popen(command, "r");

    if (!fp) {

        snprintf(
            risk,
            risk_size,
            "REVIEW"
        );

        snprintf(
            reason,
            reason_size,
            "Policy engine unavailable"
        );

        snprintf(
            action,
            action_size,
            "REVIEW"
        );

        return -1;
    }


    /* Clear output buffers */

    risk[0] = '\0';
    reason[0] = '\0';
    action[0] = '\0';


    /* Read Python policy output */

    while (fgets(output, sizeof(output), fp)) {

        if (strncmp(output, "RISK=", 5) == 0) {

            snprintf(
                risk,
                risk_size,
                "%s",
                output + 5
            );

            risk[strcspn(risk, "\n")] = '\0';
        }

        else if (strncmp(output, "REASON=", 7) == 0) {

            snprintf(
                reason,
                reason_size,
                "%s",
                output + 7
            );

            reason[strcspn(reason, "\n")] = '\0';
        }

        else if (strncmp(output, "ACTION=", 7) == 0) {

            snprintf(
                action,
                action_size,
                "%s",
                output + 7
            );

            action[strcspn(action, "\n")] = '\0';
        }
    }


    pclose(fp);


    /* ========================================================
     * Fallback values
     * ======================================================== */

    if (risk[0] == '\0') {

        snprintf(
            risk,
            risk_size,
            "REVIEW"
        );
    }

    if (reason[0] == '\0') {

        snprintf(
            reason,
            reason_size,
            "No policy decision"
        );
    }

    if (action[0] == '\0') {

        snprintf(
            action,
            action_size,
            "REVIEW"
        );
    }


    return 0;
}


/* ============================================================
 * Write event to log file
 *
 * All events, including REVIEW events, are retained in the log.
 * ============================================================ */

static void write_log(
    struct exec_event *event,
    const char *risk,
    const char *reason,
    const char *action
)
{
    FILE *log = fopen(LOG_FILE, "a");

    if (!log) {
        return;
    }

    /*
     * Timestamp generated when the user-space reader
     * receives the event from the eBPF ring buffer.
     */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);

    char timestamp[64];

    strftime(
        timestamp,
        sizeof(timestamp),
        "%Y-%m-%d %H:%M:%S",
        &tm_info
    );

    fprintf(
        log,
        "TIME=%s.%03ld | "
        "PID=%u | UID=%u | PROCESS=%s | PATH=%s | "
        "RISK=%s | REASON=%s | ACTION=%s\n",
        timestamp,
        ts.tv_nsec / 1000000L,
        event->pid,
        event->uid,
        event->comm,
        event->filename,
        risk,
        reason,
        action
    );

    fflush(log);

    fclose(log);
}


/* ============================================================
 * Ring buffer event handler
 * ============================================================ */

static int handle_event(
    void *ctx,
    void *data,
    size_t data_sz
)
{
    struct exec_event *event = data;

    char risk[32];
    char reason[256];
    char action[32];


    /* Ignore internal helper/background events */

    if (should_ignore_event(event)) {
        return 0;
    }


    /* Ask dynamic YAML policy engine */

    check_policy(
        event->filename,
        risk,
        sizeof(risk),
        reason,
        sizeof(reason),
        action,
        sizeof(action)
    );


    /* ========================================================
     * Suppress REVIEW events from console
     *
     * REVIEW events are still written to the security log.
     * ======================================================== */

    if (strcmp(risk, "REVIEW") == 0) {

        write_log(
            event,
            risk,
            reason,
            action
        );

        return 0;
    }


    /* ========================================================
     * Display security event
     * ======================================================== */

    printf("\n");

    printf(
        "========================================\n"
    );

    printf(
        "       KERNELGUARD SECURITY EVENT\n"
    );

    printf(
        "========================================\n"
    );


    printf(
        "PID      : %u\n",
        event->pid
    );

    printf(
        "UID      : %u\n",
        event->uid
    );

    printf(
        "PROCESS  : %s\n",
        event->comm
    );

    printf(
        "PATH     : %s\n",
        event->filename
    );


    printf(
        "----------------------------------------\n"
    );


    printf(
        "RISK     : %s\n",
        risk
    );

    printf(
        "REASON   : %s\n",
        reason
    );

    printf(
        "ACTION   : %s\n",
        action
    );


    printf(
        "========================================\n"
    );


    fflush(stdout);


    /* Write displayed events to log */

    write_log(
        event,
        risk,
        reason,
        action
    );


    return 0;
}


/* ============================================================
 * Main
 * ============================================================ */

int main(void)
{
    struct ring_buffer *rb = NULL;

    int map_fd;


    /* ========================================================
     * Open pinned Ring Buffer
     * ======================================================== */

    map_fd = bpf_obj_get(EVENT_MAP);

    if (map_fd < 0) {

        fprintf(
            stderr,
            "[-] Failed to open ring buffer: %s\n",
            EVENT_MAP
        );

        fprintf(
            stderr,
            "[-] Make sure exec_monitor is running.\n"
        );

        return 1;
    }


    printf(
        "[+] Ring buffer connected successfully\n"
    );


    /* ========================================================
     * Create Ring Buffer reader
     * ======================================================== */

    rb = ring_buffer__new(
        map_fd,
        handle_event,
        NULL,
        NULL
    );


    if (!rb) {

        fprintf(
            stderr,
            "[-] Failed to create ring buffer\n"
        );

        close(map_fd);

        return 1;
    }


    /* ========================================================
     * Startup information
     * ======================================================== */

    printf(
        "[+] Dynamic YAML policy engine enabled\n"
    );

    printf("[+] Policy file: %s\n", kg_path("policies/policy.yaml"));

    printf(
        "[+] Self-trigger protection enabled\n"
    );

    printf(
        "[+] Noise filtering enabled\n"
    );

    printf(
        "[+] Security event logging enabled\n"
    );

    printf(
        "[+] Waiting for process execution events...\n"
    );


    /* ========================================================
     * Continuously receive events
     * ======================================================== */

    while (1) {

        int err;

        err = ring_buffer__poll(
            rb,
            100
        );


        if (err < 0) {

            fprintf(
                stderr,
                "[-] Ring buffer polling error: %d\n",
                err
            );

            break;
        }
    }


    /* ========================================================
     * Cleanup
     * ======================================================== */

    ring_buffer__free(rb);

    close(map_fd);

    return 0;
}
