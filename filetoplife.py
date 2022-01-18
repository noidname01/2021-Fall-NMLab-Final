from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
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
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/sched.h>
// the key for the output summary
struct info_t {
    unsigned long inode;
    dev_t dev;
    u32 pid;
    u32 name_len;
    char comm[TASK_COMM_LEN];
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];
    char type;
};
// the value of the output summary
struct val_t {
    u64 time;
};
BPF_HASH(counts, struct info_t, struct val_t);

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
        .dev = file->f_inode->i_rdev,
    };
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.name_len = d_name.len;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), d_name.name);
    info.type = 'W';

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&info, &zero);
    if(valp){
        valp->time += bpf_ktime_get_ns();
    }


    return 0;
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

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_try_init(&info, &zero);
    if(valp){
        valp->time += bpf_ktime_get_ns();
    }

    return 0;
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
    return (counts[1].time)

# output
exiting = 0
print("%-20s %-7s %-16s %4s %s" % ("TIME" ,"TID", "COMM", "TYPE", "FILE"))

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    
    # by-TID output
    counts = b.get_table("counts")
    line = 0
    for k, v in reversed(sorted(counts.items(),
                                key=sort_fn)):
        name = k.name.decode('utf-8', 'replace')
        if k.name_len > DNAME_INLINE_LEN:
            name = name[:-3] + "..."

        # print line
        print("%-20s %-7s %-16s %4s %s" % (
            datetime.fromtimestamp(v.time // 1000000000).strftime('%Y-%m-%d %H:%M:%S'),   
            k.pid,
            k.comm.decode('utf-8', 'replace'),
            k.type.decode('utf-8', 'replace'), 
            name
        ))

        line += 1
        if line >= maxrows:
            break
    counts.clear()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()