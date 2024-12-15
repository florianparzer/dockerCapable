#!/usr/bin/python3
from bcc import BPF

prog = '''
#include <uapi/linux/ptrace.h> //needed? prob because of the task struct
#include <linux/sched.h>
//define the output struct
struct data_t{
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    int retval;
};
BPF_PERF_OUTPUT(events);

int printProcesses(struct pt_regs *ctx){
    struct data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    data.ts = bpf_ktime_get_ns();
    //Is the pid (called in userspace thread-id) or the threadgroupid (called in userspace pid) needed
    //In this case rather the threadgroupid is needed therefore the result is shifted by 32 to the right because the pid is in the lower 32 bit and the threadgroupid in the upper 32 bit
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //write the command of the parent process to data.pcmd
    bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
'''
b = BPF(text=prog)
b.attach_kretprobe(event=b.get_syscall_fnname('execve'), fn_name='printProcesses')
#b.attach_kretprobe(event=b.get_syscall_fnname('fork'), fn_name='printProcesses')
b.attach_kretprobe(event=b.get_syscall_fnname('clone'), fn_name='printProcesses')
containerProcesses = []
# Print a header
print("%-18s %-16s %-6s %-16s %-6s" % ('TIME(s)', 'CMD', 'PID', 'Parent CMD', 'PPID'))

#TODO with execve it only shows new processes that are created with clone + execve, not the ones with only clone
#Can be traced with the retval of clone but this is only shows the pid inside the namespace; this can be converted to the host pid with looking at /proc/<pid>/status |grep NS
#but it would need the pid of the host already, one could try to get the pids via pgrep -P <ppid> or ps --ppid <ppid>, where the ppid is the process that has the pid 1 in the namespace
def printEvent(cpu, data, size):
    event = b['events'].event(data)
    if event.comm == b'containerd-shim' or event.ppid in containerProcesses:
        containerProcesses.append(event.pid)
    #if event.pid in containerProcesses:
    timestamp = event.ts / 1000000000
    print("%-18.9f %-16s %-6d %-16s %-6d %d" % (timestamp, event.comm, event.pid, event.pcomm, event.ppid, event.retval))


b['events'].open_perf_buffer(printEvent)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(containerProcesses)
        exit()