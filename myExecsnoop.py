#!/usr/bin/python3
from collections import defaultdict
import re
from bcc import BPF
from bcc.utils import printb

class EventType(object):
    EXECVE_CALL = 0
    EXECVE_RET = 1
    CLONE_CALL = 2
    CLONE_RET = 3

class Process:
    pid = None
    command = ''
    argv = ''
    ppid = None
    _capabilities = set()

    def __init__(self, pid:int, ppid:int, command='', arguments=''):
        self.pid = pid
        self.command = command
        self.argv = arguments
        self.ppid = ppid

    def __eq__(self, __value):
        if not isinstance(__value, Process):
            return False
        return self.pid == __value.pid

    def addCap(self, cap:int):
        self._capabilities.add((cap))

    def delCap(self, cap:int):
        self._capabilities.remove(cap)

def getProcessFromDict(pid, containerProcs:dict):
    for containerID, procs in containerProcs.items():
        for proc in procs:
            if proc.pid == pid:
                return containerID, proc
    return None, None

prog = '''
#include <uapi/linux/ptrace.h> //needed? prob because of the task struct
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EXECVE_CALL,
    EXECVE_RET,
    CLONE_CALL,
    CLONE_RET
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

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data){
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        bpf_probe_read_user(data->argv,sizeof(data->argv), argp);
        events.perf_submit(ctx, data, sizeof(struct data_t));
        return 1;
    }
    return 0;
}

static int collect_task_info(struct data_t *data){
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    
    data->ts = bpf_ktime_get_ns();
    //Is the pid (called in userspace thread-id) or the threadgroupid (called in userspace pid) needed
    //In this case rather the threadgroupid is needed therefore the result is shifted by 32 to the right because the pid is in the lower 32 bit and the threadgroupid in the upper 32 bit
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    //write the command of the parent process to data.pcmd
    bpf_probe_read_kernel_str(data->pcomm, sizeof(data->pcomm), task->real_parent->comm);
    
    return 0;
}


int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp){
    struct data_t data = {};
    collect_task_info(&data);
    data.retval = PT_REGS_RC(ctx);
    data.type = EXECVE_CALL;
    
    //Submit Filename as argument
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

int ret_execve(struct pt_regs *ctx){
    struct data_t data = {};
    collect_task_info(&data);
    data.type = EXECVE_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

int ret_clone(struct pt_regs *ctx){
    struct data_t data = {};
    collect_task_info(&data);
    data.type = CLONE_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
'''
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname('execve'), fn_name='syscall__execve')
b.attach_kretprobe(event=b.get_syscall_fnname('execve'), fn_name='ret_execve')
#b.attach_kretprobe(event=b.get_syscall_fnname('fork'), fn_name='ret_clone')
b.attach_kretprobe(event=b.get_syscall_fnname('clone'), fn_name='ret_clone')
containerProcesses = defaultdict(list)
argv = defaultdict(list)

#With execve it only shows new processes that are created with clone + execve, not the ones with only clone
#Can be traced with the retval of clone but this is only shows the pid inside the namespace; this can be converted to the host pid with looking at /proc/<pid>/status |grep NS
#but it would need the pid of the host already, one could try to get the pids via pgrep -P <ppid> or ps --ppid <ppid>, where the ppid is the process that has the pid 1 in the namespace
#
#Also all global pids of the processes in the namespaces are shown in /sys/fs/cgroup/system.slice/docker-<containerID>.scope/cgroup.procs
#These are also the ones that execute capset or are child-processes of that process
def printEvent(cpu, data, size):
    event = b['events'].event(data)
    if event.type == EventType.EXECVE_CALL:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EXECVE_RET:
        proc = Process(event.pid, event.ppid, event.comm.decode('ascii'),
                       b' '.join(argv[event.pid]).replace(b'\n', b'\\n').decode('ascii'))
        del (argv[event.pid])
        timestamp = event.ts / 1000000000
        printb(b"%-18.9f %-16s %-6d %-16s %-6d %-6d " % (
            timestamp, event.comm, event.pid, event.pcomm, event.ppid, event.retval), nl='')
        print('%-50s' % proc.argv)
        containerId, element = getProcessFromDict(event.pid, containerProcesses)
        if element is not None:
            element.command = proc.command
            element.argv = proc.argv
            return
        if event.comm == b'containerd-shim' and (matcher := re.search('-id (\w+)(?:\s|^)', proc.argv)) is not None:
            containerId = matcher.group(1)
            containerProcesses[containerId].append(proc)
            return
        containerId, element = getProcessFromDict(event.ppid, containerProcesses)
        #if (container, element := getProcessFromDict(event.ppid, containerProcesses))[1] is not None:
        if containerId is not None:
            containerProcesses[containerId].append(proc)
    elif event.type == EventType.CLONE_RET:
        timestamp = event.ts / 1000000000
        printb(b"%-18.9f %-16s %-6d %-16s %-6d %-6d " % (
            timestamp, event.comm, event.pid, event.pcomm, event.ppid, event.retval), nl='')
        print('%-50s' % '')
        containerID, pProc = getProcessFromDict(event.pid, containerProcesses)
        if containerID is not None:
            pProc.command = event.comm.decode('ascii')
            pid = getGlobalPID(containerID, retval=event.retval)
            #Check if pid could not be found or if process is already traced
            if pid is None or getProcessFromDict(pid, containerProcesses)[0] is not None:
                return
            proc = Process(pid=pid, ppid=event.pid)
            containerProcesses[containerID].append(proc)


def getGlobalPID(containerID, retval):
    '''
    Returns the global PID for a PID in context of a certain container
    :param containerID: The ContainerID to which the process belongs to
    :param retval: The return value of the clone syscall aka the pid of the new process in context of the pid namespace
    :return: integer value of the global pid
    '''
    try:
        with open(f'/sys/fs/cgroup/system.slice/docker-{containerID}.scope/cgroup.procs') as file:
            for line in file:
                #Check Processes in cgroup.procs file
                proc = getProcessFromDict(int(line.strip()), containerProcesses)[1]
                if proc is not None:
                    #If process is already included in the list of container processes, skip it
                    continue
                pid = int(line.strip())
                try:
                    with open(f'/proc/{pid}/status') as pidStatus:
                        #Look in the status file for the pid in the ns context
                        for line2 in pidStatus:#Problem here?
                            if (matcher := re.match('NStgid:\s+(\d+)\s+(\d+)', line2)) is not None and int(matcher.group(2)) == retval:
                                #Check whether the pid in ns context is the same as the return value of the syscall
                                return pid
                except FileNotFoundError as err:
                    print(f'Status file /proc/{pid}/status not found')
                    return None
        return retval
    except FileNotFoundError as e:
        return retval

# Print a header
print("%-18s %-16s %-6s %-16s %-6s %-6s %-50s" % ('TIME(s)', 'CMD', 'PID', 'Parent CMD', 'PPID', 'RETVAL', 'ARGV'))
b['events'].open_perf_buffer(printEvent)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print('\nTraced container processes:\n')
        for containerID, procs in containerProcesses.items():
            print(f'ContainerID: {containerID}')
            for proc in procs:
                print(f'    {proc.pid}{" ," + proc.command if proc.command != "" else ""}{", " + proc.argv if proc.argv != "" else ""}')
        exit()