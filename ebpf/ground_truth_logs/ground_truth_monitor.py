#!/usr/bin/env python3
from bcc import BPF
import time

bpf_text = """
#include <linux/sched.h>

BPF_PERF_OUTPUT(module_events);
BPF_PERF_OUTPUT(process_events);

struct mod_data_t {
    u32 pid;
    u64 ts;
    char comm[16];
};

struct proc_data_t {
    u32 pid;
    u32 ppid;
    u64 ts;
    char comm[16];
    u8 event;   // 0 = fork, 1 = exit
};

int trace_module_load(struct pt_regs *ctx) {
    struct mod_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    module_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct proc_data_t data = {};
    data.pid = args->child_pid;
    data.ppid = args->parent_pid;
    data.ts = bpf_ktime_get_ns();
    data.event = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));  // parent's comm — fine for identification
    process_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct proc_data_t data = {};
    data.pid = args->pid;
    data.ts = bpf_ktime_get_ns();
    data.event = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    process_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="do_init_module", fn_name="trace_module_load")

GROUND_TRUTH_PIDS = set()  # live PIDs as seen by the kernel, not by ps

def handle_module(cpu, data, size):
    e = b["module_events"].event(data)
    print(f"[GROUND TRUTH] module load: pid={e.pid} comm={e.comm.decode()} ts={e.ts}")

def handle_process(cpu, data, size):
    e = b["process_events"].event(data)
    if e.event == 0:
        GROUND_TRUTH_PIDS.add(e.pid)
        print(f"[GROUND TRUTH] fork: pid={e.pid} ppid={e.ppid} comm={e.comm.decode()}")
    else:
        GROUND_TRUTH_PIDS.discard(e.pid)
        print(f"[GROUND TRUTH] exit: pid={e.pid}")

b["module_events"].open_perf_buffer(handle_module)
b["process_events"].open_perf_buffer(handle_process)

print("eBPF ground-truth monitor running. Ctrl+C to stop.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break