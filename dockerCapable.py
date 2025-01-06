#!/usr/bin/python3
from bcc import BPF
from threading import Thread
from threading import Event
from collections import defaultdict
import queue
import time
import re

capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

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
    isTraced = False
    _capabilities = set()

    def __init__(self, pid:int, ppid:int, command='', arguments='', isTraces=False):
        self.pid = pid
        self.command = command
        self.argv = arguments
        self.ppid = ppid
        self.isTraced = isTraces

    def __eq__(self, __value):
        if not isinstance(__value, Process):
            return False
        return self.pid == __value.pid

    def addCap(self, cap:int):
        self._capabilities.add(cap)

    def getCaps(self):
        return self._capabilities.copy()

    def delCap(self, cap:int):
        self._capabilities.remove(cap)

def execsnoop(pidQueue, runEvent):
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
    execBPF = BPF(text=prog)
    execBPF.attach_kprobe(event=execBPF.get_syscall_fnname('execve'), fn_name='syscall__execve')
    execBPF.attach_kretprobe(event=execBPF.get_syscall_fnname('execve'), fn_name='ret_execve')
    execBPF.attach_kretprobe(event=execBPF.get_syscall_fnname('clone'), fn_name='ret_clone')

    argv = defaultdict(list)

    def sendProc(ctx, data, size):
        event = execBPF['events'].event(data)
        if event.type == EventType.EXECVE_CALL:
            argv[event.pid].append(event.argv)
        elif event.type == EventType.EXECVE_RET:
            argvText = b' '.join(argv[event.pid]).replace(b'\n', b'\\n').decode('ascii')
            del (argv[event.pid])
            pidQueue.put(('proc', event.type, event.pid, event.comm.decode('ascii'), event.ppid,
                          event.pcomm.decode('ascii'), argvText))
        elif event.type == EventType.CLONE_RET:
            pidQueue.put(('proc', event.type, event.pid, event.comm.decode('ascii'), event.ppid, event.retval))

    execBPF['events'].open_perf_buffer(sendProc)
    while runEvent.is_set():
        execBPF.perf_buffer_poll()


def capable(pidQueue, runEvent):
    prog = '''
    #include <linux/sched.h>
    //define the output struct
    struct data_t{
        u32 tgid;
        u32 pid;
        u32 uid;
        int cap;
        //int inEffective; //is 0 when cap is in effective set of task; Not possible as function is not called via kretprobe
        char comm[TASK_COMM_LEN];
    };

    BPF_PERF_OUTPUT(events);

    BPF_HASH(isTraces, struct data_t, int);

    int traceCap(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *targ_ns,
        int cap, unsigned int opts){
        //bpf_trace_printk("Cap: %d\\n", cap);
        //return 0;
        struct data_t data = {};

        data.pid = bpf_get_current_pid_tgid();
        data.tgid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.cap = cap;
        //data.inEffective = PT_REGS_RC(ctx);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        if(isTraces.lookup(&data) != NULL){
            return 0;
        }
        isTraces.update(&data, &cap);

        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    '''
    capableBPF = BPF(text=prog)
    capableBPF.attach_kprobe(event='cap_capable', fn_name='traceCap')

    def traceCaps(ctx, data, size):
        event = capableBPF['events'].event(data)
        pidQueue.put(('cap', event.tgid, event.cap))

    capableBPF['events'].open_perf_buffer(traceCaps)
    while runEvent.is_set():
        capableBPF.perf_buffer_poll()
    exit(0)

def getProcessFromDict(pid) -> (str, Process):
    for containerID, procs in containerProcesses.items():
        for proc in procs:
            if proc.pid == pid:
                return containerID, proc
    return None, None

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
                proc = getProcessFromDict(int(line.strip()))[1]
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
    except FileNotFoundError as e:
        return retval
    return retval

def addProc(msg):
    eventType = msg[1]
    if eventType == EventType.EXECVE_RET:
        proc = Process(pid=msg[2], ppid=msg[4], command=msg[3], arguments=msg[6])
        containerId, element = getProcessFromDict(proc.pid)
        if element is not None:
            element.command = proc.command
            element.argv = proc.argv
            return
        if proc.command == 'containerd-shim' and (matcher := re.search('-id (\w+)(?:\s|^)', proc.argv)) is not None:
            containerProcesses[matcher.group(1)].append(proc)
            return
        containerId, element = getProcessFromDict(proc.ppid)
        # if (container, element := getProcessFromDict(event.ppid, containerProcesses))[1] is not None:
        if containerId is not None:
            if element.command == 'runc:[1:CHILD]':
                proc.isTraced = True
            containerProcesses[containerId].append(proc)
    elif eventType == EventType.CLONE_RET:
        retval = msg[5]
        ppid = msg[2]
        pComm = msg[3]
        #Chech wheter the parent process is included in the list
        containerID, pProc = getProcessFromDict(ppid)
        if containerID is not None:
            pProc.command = pComm
            pid = getGlobalPID(containerID, retval=retval)
            if pid is None or getProcessFromDict(pid)[0] is not None:
                return
            proc = Process(pid=pid, ppid=ppid)
            if pProc.isTraced or pProc.command == 'runc:[1:CHILD]':
                proc.isTraced = True
            containerProcesses[containerID].append(proc)

containerProcesses = defaultdict(list)

def printCapabilities():
    for containerID, procs in containerProcesses.items():
        print(f'ContainerID: {containerID}')
        for proc in procs:
            if not proc.isTraced:
                continue
            for cap in proc.getCaps():
                print(f'    {proc.pid}:{proc.command}:{capabilities[cap]}')


if __name__ == '__main__':
    pidQueue = queue.Queue()
    runEvent = Event()
    runEvent.set()
    execsnoopTask = Thread(target=execsnoop, args=(pidQueue,runEvent))
    capableTask = Thread(target=capable, args=(pidQueue,runEvent))

    #Start the execsnoop and capable Threads; Sleep needed as otherwise there is a segmentation fault
    execsnoopTask.start()
    time.sleep(3)
    capableTask.start()

    try:
        while True:
            msg = pidQueue.get()
            if msg[0] == 'proc':
                addProc(msg)
            elif msg[0] == 'cap':
                pid = msg[1]
                cap = msg[2]
                if (proc := getProcessFromDict(pid)[1]) is not None:
                    proc.addCap(cap)
    except KeyboardInterrupt:
        runEvent.clear()
        printCapabilities()
        execsnoopTask.join()
        capableTask.join()
