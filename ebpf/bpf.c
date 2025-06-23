#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BIN_PATH_SIZE 256

struct event {
    __u32 pid;
    __u32 ppid;
    char bin_path[BIN_PATH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&event.bin_path, sizeof(event.bin_path), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";