#!/usr/bin/python3
from bcc import BPF
from bcc import printb

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


prog = '''
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/uidgid_types.h>

//define the output struct
struct data_t{
    u32 tgid;
    u32 pid;
    u32 uid;
    int cap;
    u64 caps;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

BPF_HASH(isTraces, struct data_t, int);

int traceCap(struct pt_regs *ctx, const struct cred *cred, struct user_namespace *targ_ns,
    int cap, unsigned int opts){
    struct data_t data = {};
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    
    if(cred != task->real_cred){
        return 0;
    }
    
    data.pid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    //data.uid = user_ns_inum;
    data.cap = cap;
    data.caps = cred->cap_permitted.val;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if(isTraces.lookup(&data) != NULL){
        return 0;
    }
    isTraces.update(&data, &cap);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
'''
b = BPF(text=prog)
#b.attach_kretprobe(event='cap_capable', fn_name='traceCap')
b.attach_kprobe(event='cap_capable', fn_name='traceCap')

def printCaps(ctx, data, size):
    event = b['events'].event(data)
    #inEffective = True if event.inEffective == 0 else False
    print("%-16s %-6d %d %d %lx %s" % (event.comm, event.tgid, event.uid, event.cap, event.caps, capabilities[event.cap]))

b['events'].open_perf_buffer(printCaps)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()