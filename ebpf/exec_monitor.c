#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EVENT_PIN_PATH "/sys/fs/bpf/kernelguard_events"

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
    stop = 1;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *events_map;
    struct bpf_link *link;

    int err;

    /* ---------------------------------------------------- */
    /* Open eBPF object                                     */
    /* ---------------------------------------------------- */

    obj = bpf_object__open_file("./exec_monitor.bpf.o", NULL);

    if (!obj) {
        fprintf(stderr,
                "[-] Failed to open BPF object\n");
        return 1;
    }

    /* ---------------------------------------------------- */
    /* Load eBPF program                                    */
    /* ---------------------------------------------------- */

    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr,
                "[-] Failed to load BPF object: %d\n",
                err);

        bpf_object__close(obj);
        return 1;
    }

    printf("[+] eBPF object loaded successfully\n");

    /* ---------------------------------------------------- */
    /* Find LSM program                                     */
    /* ---------------------------------------------------- */

    prog = bpf_object__find_program_by_name(
        obj,
        "check_exec"
    );

    if (!prog) {
        fprintf(stderr,
                "[-] Could not find BPF program: check_exec\n");

        bpf_object__close(obj);
        return 1;
    }

    printf("[+] LSM program found\n");

    /* ---------------------------------------------------- */
    /* Attach LSM program                                   */
    /* ---------------------------------------------------- */

    link = bpf_program__attach_lsm(prog);

    if (!link) {
        fprintf(stderr,
                "[-] Failed to attach LSM program\n");

        bpf_object__close(obj);
        return 1;
    }

    printf("[+] LSM program attached successfully\n");

    /* ---------------------------------------------------- */
    /* Find ring buffer map                                 */
    /* ---------------------------------------------------- */

    events_map = bpf_object__find_map_by_name(
        obj,
        "events"
    );

    if (!events_map) {
        fprintf(stderr,
                "[-] Could not find events ring buffer map\n");

        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("[+] Ring buffer map found\n");

    /* ---------------------------------------------------- */
    /* Pin ring buffer                                      */
    /* ---------------------------------------------------- */

    err = bpf_map__pin(
        events_map,
        EVENT_PIN_PATH
    );

    if (err) {

        fprintf(stderr,
                "[-] Failed to pin ring buffer at %s: %d\n",
                EVENT_PIN_PATH,
                err);

        bpf_link__destroy(link);
        bpf_object__close(obj);

        return 1;
    }

    printf("[+] Ring buffer pinned at:\n");
    printf("    %s\n", EVENT_PIN_PATH);

    /* ---------------------------------------------------- */
    /* Start monitoring                                    */
    /* ---------------------------------------------------- */

    printf("\n");
    printf("========================================\n");
    printf("       KERNELGUARD eBPF MONITOR\n");
    printf("========================================\n");
    printf("[+] KernelGuard eBPF LSM started\n");
    printf("[+] Monitoring program execution\n");
    printf("[+] Ring buffer ready\n");
    printf("[+] Press Ctrl+C to stop\n");
    printf("========================================\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* ---------------------------------------------------- */
    /* Keep program running                                 */
    /* ---------------------------------------------------- */

    while (!stop)
        sleep(1);

    /* ---------------------------------------------------- */
    /* Cleanup                                              */
    /* ---------------------------------------------------- */

    printf("\n[+] Stopping KernelGuard...\n");

    bpf_link__destroy(link);

    bpf_object__close(obj);

    unlink(EVENT_PIN_PATH);

    printf("[+] KernelGuard stopped.\n");

    return 0;
}
