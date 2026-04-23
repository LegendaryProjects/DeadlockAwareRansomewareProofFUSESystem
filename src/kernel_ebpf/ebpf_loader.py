from bcc import BPF
import time
import os
from collections import defaultdict

WRITE_THRESHOLD = 100 
TIME_WINDOW_NS = 1_000_000_000
MY_PID = os.getpid()

process_tracker = defaultdict(list)

print("[*] Compiling and injecting eBPF Kernel Probe...")

bpf_program = BPF(src_file=os.path.join(os.path.dirname(__file__), "vfs_monitor.c"), cflags=["-Wno-duplicate-decl-specifier"])

print("[*] eBPF successfully attached to vfs_write. Monitoring whole system...")
print(f"[*] Alert Threshold: >{WRITE_THRESHOLD} writes/sec\n")
print(f"{'PID':<10} | {'PROCESS':<15} | {'BEHAVIORAL VERDICT'}")
print("-" * 50)


def print_event(cpu, data, size):
    event = bpf_program["write_events"].event(data)
    pid = event.pid
    
    if pid == MY_PID:
        return
        
    p_name = event.process_name.decode('utf-8', 'replace')
    current_time = event.timestamp_ns
    
    process_tracker[pid].append(current_time)
    
    process_tracker[pid] = [ts for ts in process_tracker[pid] if (current_time - ts) <= TIME_WINDOW_NS]
    
    if len(process_tracker[pid]) > WRITE_THRESHOLD:
        print(f"{pid:<10} | {p_name:<15} | [CRITICAL] Frantic Write Speed Detected!")
        
        process_tracker[pid].clear()

bpf_program["write_events"].open_perf_buffer(print_event)

try:
    while True:
        bpf_program.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[*] Detaching eBPF monitor and exiting.")