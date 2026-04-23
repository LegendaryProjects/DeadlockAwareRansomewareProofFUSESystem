#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stat.h>

struct event_data_t {
    u32 pid;
    u64 timestamp_ns;
    u64 write_size;
    char process_name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(write_events);

int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {

    umode_t i_mode = file->f_inode->i_mode;
    
    if ((i_mode & S_IFMT) != S_IFREG) {
        return 0; 
    }
    
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.timestamp_ns = bpf_ktime_get_ns(); 
    data.write_size = count;

    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));
    write_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}