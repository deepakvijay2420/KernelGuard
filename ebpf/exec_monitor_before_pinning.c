#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
    stop = 1;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;


    obj = bpf_object__open_file("./exec_monitor.bpf.o", NULL);

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(
        obj, "bprm_check_security");

    if (!prog) {
        fprintf(stderr, "Could not find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_lsm(prog);

    if (!link) {
        fprintf(stderr, "Failed to attach LSM program\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("KernelGuard eBPF LSM started successfully!\n");
    printf("Monitoring program execution...\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!stop)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);

    printf("KernelGuard stopped.\n");

    return 0;
}
