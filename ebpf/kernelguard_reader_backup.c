#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Structure received from eBPF program */
struct exec_event {
    uint32_t pid;
    uint32_t uid;
    char comm[64];
    char filename[256];
};

static volatile sig_atomic_t exiting = 0;

/* Log file */
static FILE *log_file = NULL;


/* Signal handler */
static void sig_handler(int sig)
{
    exiting = 1;
}


/* =====================================================
   NOISE FILTER
   Filters repetitive background system events
   ===================================================== */

static int should_ignore_event(struct exec_event *event)
{
    const char *ignored_paths[] = {
        "/bin/sh",
        "/usr/bin/lesspipe",
        "/usr/bin/basename",
        "/usr/bin/dirname",
        "/usr/bin/dircolors",
        NULL
    };

    for (int i = 0; ignored_paths[i] != NULL; i++) {
        if (strcmp(event->filename, ignored_paths[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


/* =====================================================
   POLICY ENGINE
   ===================================================== */

static void evaluate_policy(struct exec_event *event,
                            const char **risk,
                            const char **reason,
                            const char **action)
{
    /* HIGH RISK - Suspicious execution paths */

    if (strncmp(event->filename, "/tmp/", 5) == 0 ||
        strncmp(event->filename, "/var/tmp/", 9) == 0 ||
        strncmp(event->filename, "/dev/shm/", 9) == 0) {

        *risk = "HIGH";
        *reason = "Execution from high-risk path";
        *action = "ALERT";
    }

    /* MEDIUM RISK - Sensitive commands */

    else if (strcmp(event->filename, "/usr/bin/sudo") == 0 ||
             strcmp(event->filename, "/bin/sudo") == 0 ||
             strcmp(event->filename, "/bin/bash") == 0 ||
             strcmp(event->filename, "/usr/bin/bash") == 0) {

        *risk = "MEDIUM";
        *reason = "Sensitive command detected";
        *action = "WARNING";
    }

    /* LOW RISK - Known safe commands */

    else if (strcmp(event->filename, "/usr/bin/ls") == 0 ||
             strcmp(event->filename, "/bin/ls") == 0 ||
             strcmp(event->filename, "/usr/bin/whoami") == 0 ||
             strcmp(event->filename, "/usr/bin/date") == 0 ||
             strcmp(event->filename, "/bin/date") == 0 ||
             strcmp(event->filename, "/usr/bin/pwd") == 0) {

        *risk = "LOW";
        *reason = "Known standard system command";
        *action = "ALLOW";
    }

    /* UNKNOWN */

    else {

        *risk = "REVIEW";
        *reason = "Executable not found in policy";
        *action = "REVIEW";
    }
}


/* =====================================================
   RING BUFFER EVENT HANDLER
   ===================================================== */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct exec_event *event = data;

    /* Ignore repetitive background events */

    if (should_ignore_event(event)) {
        return 0;
    }

    const char *risk;
    const char *reason;
    const char *action;

    char time_buffer[64];

    time_t now = time(NULL);
    struct tm *time_info = localtime(&now);

    strftime(time_buffer,
             sizeof(time_buffer),
             "%Y-%m-%d %H:%M:%S",
             time_info);


    /* Evaluate security policy */

    evaluate_policy(event,
                    &risk,
                    &reason,
                    &action);


    /* Terminal output */

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
    printf("ACTION   : %s\n", action);

    printf("========================================\n");


    /* Write event to log */

    if (log_file) {

        fprintf(log_file,
                "[%s] %s | PID:%u | UID:%u | PROCESS:%s | PATH:%s | ACTION:%s\n",
                time_buffer,
                risk,
                event->pid,
                event->uid,
                event->comm,
                event->filename,
                action);

        /* Immediately write to disk */

        fflush(log_file);
    }

    return 0;
}


/* =====================================================
   MAIN
   ===================================================== */

int main(void)
{
    const char *map_path = "/sys/fs/bpf/kernelguard_events";

    int map_fd;
    struct ring_buffer *rb;
    int err;


    /* Signal handling */

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    printf("========================================\n");
    printf("     KernelGuard Security Monitor\n");
    printf("========================================\n");


    /* Open security event log */

    log_file = fopen("kernelguard_live.log", "a");

    if (!log_file) {

        fprintf(stderr,
                "Failed to open log file: %s\n",
                strerror(errno));

        return 1;
    }


    /* Open pinned eBPF Ring Buffer */

    map_fd = bpf_obj_get(map_path);

    if (map_fd < 0) {

        fprintf(stderr,
                "Failed to open KernelGuard ring buffer: %s\n",
                strerror(errno));

        fclose(log_file);

        return 1;
    }


    printf("[+] Ring buffer connected successfully\n");
    printf("[+] Policy engine loaded\n");
    printf("[+] Noise filtering enabled\n");
    printf("[+] Security event logging enabled\n");
    printf("[+] Waiting for process execution events...\n");


    /* Create Ring Buffer */

    rb = ring_buffer__new(map_fd,
                          handle_event,
                          NULL,
                          NULL);

    if (!rb) {

        fprintf(stderr,
                "Failed to create ring buffer\n");

        close(map_fd);
        fclose(log_file);

        return 1;
    }


    /* Listen continuously for events */

    while (!exiting) {

        err = ring_buffer__poll(rb, 100);

        if (err < 0 && err != -EINTR) {

            fprintf(stderr,
                    "Ring buffer polling error: %d\n",
                    err);

            break;
        }
    }


    /* Cleanup */

    printf("\nKernelGuard monitor stopped.\n");

    ring_buffer__free(rb);

    close(map_fd);

    fclose(log_file);

    return 0;
}
