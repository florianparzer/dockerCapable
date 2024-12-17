#!/usr/bin/python3
from bcc import BPF
from threading import Thread
from threading import Event
import queue
import time

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

def execsnoop(pidQueue, runEvent):
    containerProcesses = []
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
    execBPF = BPF(text=prog)
    execBPF.attach_kretprobe(event=execBPF.get_syscall_fnname('execve'), fn_name='printProcesses')

    def sendPID(ctx, data, size):
        event = execBPF['events'].event(data)
        if event.comm == b'containerd-shim' or event.ppid in containerProcesses:
            containerProcesses.append(event.pid)
            pidQueue.put(event.pid)

    execBPF['events'].open_perf_buffer(sendPID)
    while runEvent.is_set():
        execBPF.perf_buffer_poll()


def capable(pidQueue, runEvent):
    #TODO Dictonary containing pid as key and a list of caps as value
    capablePIDs = {}
    containerProcesses = set()
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
        if event.tgid not in capablePIDs:
            capablePIDs[event.tgid] = set()
        capablePIDs[event.tgid].add(event.cap)
        print(capablePIDs)

    capableBPF['events'].open_perf_buffer(traceCaps)
    while runEvent.is_set():
        capableBPF.perf_buffer_poll()
    try:
        while True:
            pid = pidQueue.get(block=False)
            containerProcesses.add(pid)
    except queue.Empty:
        for pid in containerProcesses:
            print(pid)
            if pid not in capablePIDs:
                continue
            for cap in capablePIDs[pid]:
                print(capabilities[cap])

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
        while 1:
            time.sleep(1)
    except KeyboardInterrupt:
        runEvent.clear()
        execsnoopTask.join()
        capableTask.join()
