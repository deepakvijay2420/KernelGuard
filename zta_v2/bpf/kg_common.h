#ifndef KG_COMMON_H
#define KG_COMMON_H

#define KG_COMM_LEN 16
#define KG_FILENAME_LEN 128

enum kg_event_type {
    KG_EVENT_EXEC = 1,
    KG_EVENT_FILE_OPEN = 2,
    KG_EVENT_SOCKET_CONNECT = 3,
    KG_EVENT_SOCKET_SENDMSG = 4,
    KG_EVENT_BPF = 5,
    KG_EVENT_PTRACE = 6
};

/* KernelGuard policy decisions */
enum kg_policy_decision {
    KG_POLICY_REVIEW = 0,
    KG_POLICY_ALLOW = 1,
    KG_POLICY_DENY = 2
};

/* Policy lookup key */
struct kg_policy_key {
    unsigned long long cgroup_id;
    char filename[KG_FILENAME_LEN];
};

/* Policy lookup value */
struct kg_policy_value {
    unsigned int decision;
};

struct kg_event {
    unsigned int event_type;
    unsigned int tgid;
    unsigned int uid;

    unsigned long long cgroup_id;
    unsigned long long timestamp_ns;

    char comm[KG_COMM_LEN];
    char filename[KG_FILENAME_LEN];
};

#endif
