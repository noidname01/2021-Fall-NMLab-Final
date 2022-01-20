from __future__ import print_function
from asyncore import file_wrapper
from bcc import BPF
import time
import argparse
import subprocess

#====== our module ======
from LVM import *

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
parser.add_argument("duration", nargs="?", 
    help="the scanning time duration")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("--size", nargs="?", default=4096,
    help="snapshot size in GB")
parser.add_argument("--debug", action="store_true", 
    help="open debug mode")
args = parser.parse_args()

duration = int(args.duration)
interval = int(args.interval)
size = int(args.size)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = bool(int(args.debug))

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

# initialize BPF
b = BPF(text=bpf_text, )
b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

snapshot = LVM()
# snapshot.createSnapshot(0, size)
print("Mounting...")
mount_path = snapshot.mountSnapshot(0)

command_to_comm = {}
comm_to_command = {}
comm_filename_set = set()
candidators_info = {}

# the path we trust
whilelist = ["/usr", "/lib", "/sbin"]

def print_event(cpu, data, size):
    event = b["events"].event(data)
    name = event.name.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

    # run 'ps aux -L | grep pid' to get the executor
    p = subprocess.Popen(f'ps aux -L | grep " {str(event.pid)} "',shell=True, stdout=subprocess.PIPE)
    command_list = list(map(lambda x:" ".join(x.split("   ")[-1].split(" ")[1:]).strip() ,p.stdout.read().decode('utf-8').splitlines()))
    command_list = list(filter(lambda x: x.replace("grep", "") == x, command_list))

    try:
        command = command_list[0].split(" ")[0]
        # construct comm to command dict, to record the mapping relation ship
        if command not in command_to_comm:
            command_to_comm[command] = set()
        
        command_to_comm[command].add(comm)
        comm_to_command[comm] = command

    except:
        # process has been stopped
        try:
            # if we have seen this comm before, get its command
            command = comm_to_command[comm]
        except:
            # we didn't see it before
            command = "This comm comes from a stopped process"

    finally:
        # if the executor doesn't in the whitelist, record it to be processed
        has_whitepath = list(filter(lambda x: command.replace(x, "") != command, whilelist))
        if debug and len(has_whitepath) == 0:
            if (comm, name) not in comm_filename_set:
                print("%-10d %-7s %-16s %4s %-64s" % (
                            event.order,
                            event.pid,
                            comm,
                            event.type.decode('utf-8', 'replace'), 
                            name,
                ))
                comm_filename_set.add((comm, name))
                candidators_info[str(event.order)] = {
                    "pid":event.pid,
                    "comm":comm,
                    "type": event.type.decode('utf-8', 'replace'), 
                    "filename": name,
                }

        
b["events"].open_perf_buffer(print_event)

# header
if debug:
    print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)
    print("%-10s %-7s %-16s %4s %-64s" % ("ORDER" ,"TID", "COMM", "TYPE", "FILE"))   
else:
    print('Scanning... ')

# run until the duration over
start_time = time.time()
while time.time() - start_time < duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Bye!")
        exit()

# print(candidators_info)


file_recoverer = FileRe('/', mount_path)

print(mount_path)

print("%-10s %-7s %-16s %4s %-64s" % ("ORDER" ,"TID", "COMM", "TYPE", "FILE"))   

count = 0
full_path_filenames = []
for order, info in candidators_info.items():
    all_possibility = file_recoverer.query(info["filename"])
    for possibility in all_possibility:
        print("%5d %-7s %-16s %4s %-64s" % (
                            count,
                            info["pid"],
                            info["comm"],
                            info["type"], 
                            possibility["p"],
            ))
        full_path_filenames.append(possibility["p"])
        count += 1

to_be_recovered = list(map(lambda x : full_path_filenames[int(x)],input("choose the file you want to recover:").split(" ")))
file_recoverer.recovery(to_be_recovered)

print("Congraturation! Recovery Success.")
# snapshot.unmountSnapshot(0)
# snapshot.removeSnapshot(0)