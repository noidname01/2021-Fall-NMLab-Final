from __future__ import print_function
from bcc import BPF
import time
import argparse
from subprocess import call
from datetime import datetime


# arguments
examples = """examples:
    ./filetop            # file I/O top, 1 second refresh
    ./filetop -C         # don't clear the screen
    ./filetop -p 181     # PID 181 only
    ./filetop 5          # 5 second summaries
    ./filetop 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="File reads and writes by process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
// the key for the output summary
struct info_t {
    u64 order;
    unsigned long inode;
    u32 pid;
    u32 name_len;
    char comm[4*TASK_COMM_LEN];
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[2*DNAME_INLINE_LEN];
    char type;
};

BPF_ARRAY(order, u64, 1);
BPF_HASH(counts, struct dentry *);
BPF_PERF_OUTPUT(events);

static int do_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count, int is_read)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (TGID_FILTER)
        return 0;
    u32 pid = bpf_get_current_pid_tgid();
    // skip I/O lacking a filename
    struct dentry *de = file->f_path.dentry;
    int mode = file->f_inode->i_mode;
    struct qstr d_name = de->d_name;
    if (d_name.len == 0 || !S_ISREG(mode))
        return 0;
    // store counts and sizes by pid & file
    struct info_t info = {
        .pid = pid,
        .inode = file->f_inode->i_ino,
    };
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.name_len = d_name.len;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);
    info.type = 'W';

    int key = 0;
    u64 *ord;

    ord = order.lookup(&key);
    
    if(ord){
        info.order = *ord;
        bpf_trace_printk("count: %llu, filename: %s", *ord, info.name);
        *ord = *ord + 1;
        events.perf_submit(ctx, &info, sizeof(info));
        return 0;
    }
}
int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    return do_entry(ctx, file, buf, count, 0);
}

// trace file deletion and output details
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (TGID_FILTER)
            return 0;

    struct qstr d_name = dentry->d_name;
    if (d_name.len == 0)
        return 0;

    // store counts and sizes by pid & file
    struct info_t info = {
        .pid = pid,
    };

    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.name_len = d_name.len;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);
    info.type = 'D';

    int key = 0;
    u64 *ord;

    ord = order.lookup(&key);
    if(ord){
        info.order = *ord;
        bpf_trace_printk("count: %llu, filename: %s", *ord, info.name);
        *ord = *ord + 1;
        events.perf_submit(ctx, &info, sizeof(info));
        return 0;
    }
}
"""

if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % args.tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

TASK_COMM_LEN = 32
DNAME_INLINE_LEN = 32  # linux/dcache.h

print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)

def sort_fn(counts):
    return (counts[1].order)

# header
print("%-20s %-7s %-16s %4s %s" % ("TIME" ,"TID", "COMM", "TYPE", "FILE"))

comm_set = set()

# process event
def filter_event(cpu, data, size):
    event = b["events"].event(data)
    name = event.name.decode('utf-8', 'replace')
    if event.name_len > DNAME_INLINE_LEN:
        name = name[:-3] + "..."

    
    # print line
    print("%-20s %-7s %-16s %4s %s" % (
        # datetime.fromtimestamp(v.time // 1000000000).strftime('%Y-%m-%d %H:%M:%S'),   
        event.order,
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        event.type.decode('utf-8', 'replace'), 
        name
    ))

    comm_set.add(event.comm.decode('utf-8', 'replace'))


b["events"].open_perf_buffer(filter_event)

start_time = time.time()
while (time.time() - start_time) < 300:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

print(comm_set)
print()


def print_event(cpu, data, size):
    event = b["events"].event(data)
    name = event.name.decode('utf-8', 'replace')
    if event.name_len > DNAME_INLINE_LEN:
        name = name[:-3] + "..."

    # print line
    if(event.comm.decode('utf-8', 'replace')) not in comm_set:
        print("%-20s %-7s %-16s %4s %s" % (
            event.order,
            event.pid,
            event.comm.decode('utf-8', 'replace'),
            event.type.decode('utf-8', 'replace'), 
            name
        ))
b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()