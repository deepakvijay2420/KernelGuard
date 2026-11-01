#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../../ebpf/zta/zta_enforcer.skel.h"


static volatile sig_atomic_t running = 1;


static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}


/*
 * ------------------------------------------------------------
 * Check that the Agent PID exists
 * ------------------------------------------------------------
 */
static int agent_exists(uint32_t pid)
{
    char path[128];

    snprintf(
        path,
        sizeof(path),
        "/proc/%u",
        pid
    );

    return access(path, F_OK) == 0;
}


/*
 * ------------------------------------------------------------
 * Register Agent root
 * ------------------------------------------------------------
 */
static int register_agent(
    int map_fd,
    uint32_t agent_pid)
{
    uint8_t value = 1;

    return bpf_map_update_elem(
        map_fd,
        &agent_pid,
        &value,
        BPF_ANY
    );
}


/*
 * ------------------------------------------------------------
 * Enable blocked Zero Trust rule
 * ------------------------------------------------------------
 */
static int enable_rule(
    int map_fd,
    uint32_t rule_id)
{
    uint8_t value = 1;

    return bpf_map_update_elem(
        map_fd,
        &rule_id,
        &value,
        BPF_ANY
    );
}


int main(int argc, char **argv)
{
    struct zta_enforcer_bpf *skel;

    uint32_t agent_pid;

    int agent_map_fd;
    int rules_map_fd;

    int err;


    /*
     * --------------------------------------------------------
     * Arguments
     * --------------------------------------------------------
     */
    if (argc != 2)
    {
        fprintf(
            stderr,
            "\nUsage:\n"
            "  sudo %s <AGENT_PID>\n\n",
            argv[0]
        );

        fprintf(
            stderr,
            "Example:\n"
            "  sudo %s 7217\n\n",
            argv[0]
        );

        return 1;
    }


    agent_pid =
        (uint32_t)strtoul(
            argv[1],
            NULL,
            10
        );


    if (agent_pid == 0)
    {
        fprintf(
            stderr,
            "[ERROR] Invalid Agent PID\n"
        );

        return 1;
    }


    /*
     * --------------------------------------------------------
     * Verify Agent process exists
     * --------------------------------------------------------
     */
    if (!agent_exists(agent_pid))
    {
        fprintf(
            stderr,
            "[ERROR] Agent PID %u does not exist\n",
            agent_pid
        );

        return 1;
    }


    /*
     * --------------------------------------------------------
     * Signal handling
     * --------------------------------------------------------
     */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);


    /*
     * --------------------------------------------------------
     * libbpf configuration
     * --------------------------------------------------------
     */
    libbpf_set_strict_mode(
        LIBBPF_STRICT_ALL
    );


    /*
     * --------------------------------------------------------
     * Open generated BPF skeleton
     * --------------------------------------------------------
     */
    printf("\n");
    printf("==================================================\n");
    printf(" KernelGuard Zero Trust Controller\n");
    printf("==================================================\n");
    printf("\n");

    printf(
        "[+] Agent PID        : %u\n",
        agent_pid
    );

    printf(
        "[+] BPF object       : zta_enforcer.bpf.o\n"
    );

    printf(
        "[+] Policy            : Agent-aware ZTA\n"
    );

    printf("\n");

    skel =
        zta_enforcer_bpf__open();

    if (!skel)
    {
        fprintf(
            stderr,
            "[ERROR] Failed to open BPF skeleton\n"
        );

        return 1;
    }


    /*
     * --------------------------------------------------------
     * Load BPF program into kernel
     * --------------------------------------------------------
     */
    printf(
        "[*] Loading BPF program...\n"
    );

    err =
        zta_enforcer_bpf__load(
            skel
        );

    if (err)
    {
        fprintf(
            stderr,
            "[ERROR] Failed to load BPF program: %d\n",
            err
        );

        zta_enforcer_bpf__destroy(
            skel
        );

        return 1;
    }

    printf(
        "[+] BPF program loaded successfully\n"
    );


    /*
     * --------------------------------------------------------
     * Attach BPF-LSM program
     * --------------------------------------------------------
     */
    printf(
        "[*] Attaching BPF-LSM program...\n"
    );

    err =
        zta_enforcer_bpf__attach(
            skel
        );

    if (err)
    {
        fprintf(
            stderr,
            "[ERROR] Failed to attach BPF-LSM: %d\n",
            err
        );

        zta_enforcer_bpf__destroy(
            skel
        );

        return 1;
    }

    printf(
        "[+] BPF-LSM attached successfully\n"
    );


    /*
     * --------------------------------------------------------
     * Get map file descriptors
     * --------------------------------------------------------
     */
    agent_map_fd =
        bpf_map__fd(
            skel->maps.agent_roots
        );

    rules_map_fd =
        bpf_map__fd(
            skel->maps.blocked_rules
        );


    if (agent_map_fd < 0 ||
        rules_map_fd < 0)
    {
        fprintf(
            stderr,
            "[ERROR] Failed to obtain BPF map FDs\n"
        );

        zta_enforcer_bpf__destroy(
            skel
        );

        return 1;
    }


    /*
     * --------------------------------------------------------
     * Register Agent identity
     * --------------------------------------------------------
     */
    printf(
        "[*] Registering Agent identity...\n"
    );

    if (register_agent(
            agent_map_fd,
            agent_pid) != 0)
    {
        fprintf(
            stderr,
            "[ERROR] Failed to register Agent PID %u: %s\n",
            agent_pid,
            strerror(errno)
        );

        zta_enforcer_bpf__destroy(
            skel
        );

        return 1;
    }

    printf(
        "[+] Agent PID %u registered\n",
        agent_pid
    );


    /*
     * --------------------------------------------------------
     * Enable Zero Trust blocked rules
     * --------------------------------------------------------
     *
     * 1 = sudo
     * 2 = bash
     * 3 = sh
     * 4 = passwd
     */
    printf(
        "[*] Loading Zero Trust blocked rules...\n"
    );


    for (uint32_t rule = 1; rule <= 4; rule++)
    {
        if (enable_rule(
                rules_map_fd,
                rule) != 0)
        {
            fprintf(
                stderr,
                "[ERROR] Failed to enable rule %u: %s\n",
                rule,
                strerror(errno)
            );

            zta_enforcer_bpf__destroy(
                skel
            );

            return 1;
        }

        printf(
            "    [+] Rule %u enabled\n",
            rule
        );
    }


    /*
     * --------------------------------------------------------
     * Display security policy
     * --------------------------------------------------------
     */
    printf("\n");

    printf(
        "--------------------------------------------------\n"
    );

    printf(
        " Zero Trust Policy\n"
    );

    printf(
        "--------------------------------------------------\n"
    );

    printf(
        " Agent PID : %u\n",
        agent_pid
    );

    printf(
        " Rule 1    : /usr/bin/sudo   -> DENY\n"
    );

    printf(
        " Rule 2    : /bin/bash       -> DENY\n"
    );

    printf(
        " Rule 3    : /bin/sh         -> DENY\n"
    );

    printf(
        " Rule 4    : /usr/bin/passwd -> DENY\n"
    );

    printf(
        "--------------------------------------------------\n"
    );


    printf("\n");

    printf(
        "[+] KernelGuard ZTA enforcement ACTIVE\n"
    );

    printf(
        "[+] Waiting for Agent execution events...\n"
    );

    printf(
        "[+] Press Ctrl+C to stop.\n"
    );

    printf("\n");


    /*
     * --------------------------------------------------------
     * Keep BPF program attached
     * --------------------------------------------------------
     */
    while (running)
    {
        sleep(1);

        /*
         * If the Agent exits, keep the controller alive.
         *
         * The identity remains registered until the
         * controller is stopped.
         */
    }


    /*
     * --------------------------------------------------------
     * Shutdown
     * --------------------------------------------------------
     */
    printf("\n");
    printf(
        "[*] Stopping KernelGuard ZTA controller...\n"
    );


    /*
     * Remove Agent identity from map.
     */
    bpf_map_delete_elem(
        agent_map_fd,
        &agent_pid
    );


    printf(
        "[+] Agent identity removed\n"
    );


    /*
     * Destroy skeleton.
     *
     * This detaches the BPF-LSM program.
     */
    zta_enforcer_bpf__destroy(
        skel
    );


    printf(
        "[+] BPF-LSM detached\n"
    );

    printf(
        "[+] KernelGuard ZTA controller stopped\n"
    );

    return 0;
}
