#!/usr/bin/python3
from collections import defaultdict

from bcc import BPF
from bcc.utils import printb

prog = '''
#include <uapi/linux/ptrace.h> //needed? prob because of the task struct
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

//define the output struct
struct data_t{
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    enum event_type type;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char argv[ARGSIZE];
    int retval;
};
BPF_PERF_OUTPUT(events);

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        bpf_probe_read_user(data->argv,sizeof(data->argv), argp);
        events.perf_submit(ctx, data, sizeof(struct data_t));
        return 1;
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp){
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
    data.type = EVENT_ARG;
    
    bpf_probe_read_user(&data.argv, sizeof(data.argv), (void*)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    
    //Submit up to 20 arguments
    #pragma unroll
    for(int i = 1; i < 20; i++){
        if(submit_arg(ctx, (void *)&__argv[i], &data) == 0)
            break;
    }

    return 0;
}

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
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

'''
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname('execve'), fn_name='syscall__execve')
b.attach_kretprobe(event=b.get_syscall_fnname('execve'), fn_name='printProcesses')
#b.attach_kretprobe(event=b.get_syscall_fnname('fork'), fn_name='printProcesses')
b.attach_kretprobe(event=b.get_syscall_fnname('clone'), fn_name='printProcesses')
containerProcesses = []
argv = defaultdict(list)

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

# Print a header
print("%-18s %-16s %-6s %-16s %-6s" % ('TIME(s)', 'CMD', 'PID', 'Parent CMD', 'PPID'))

#TODO with execve it only shows new processes that are created with clone + execve, not the ones with only clone
#Can be traced with the retval of clone but this is only shows the pid inside the namespace; this can be converted to the host pid with looking at /proc/<pid>/status |grep NS
#but it would need the pid of the host already, one could try to get the pids via pgrep -P <ppid> or ps --ppid <ppid>, where the ppid is the process that has the pid 1 in the namespace
#
#Also all global pids of the processes in the namespaces are shown in /sys/fs/cgroup/system.slice/docker-<containerID>.scope/cgroup.procs
#These are also the ones that execute capset or are child-processes of that process
def printEvent(cpu, data, size):
    event = b['events'].event(data)
    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.comm == b'containerd-shim' or event.ppid in containerProcesses:
            containerProcesses.append(event.pid)
        #if event.pid in containerProcesses:
        timestamp = event.ts / 1000000000
        argvText = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
        printb(b"%-18.9f %-16s %-6d %-16s %-6d %d " % (timestamp, event.comm, event.pid, event.pcomm, event.ppid, event.retval), nl='')
        printb(b'%s' % (argvText))
        del(argv[event.pid])


b['events'].open_perf_buffer(printEvent)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(containerProcesses)
        exit()