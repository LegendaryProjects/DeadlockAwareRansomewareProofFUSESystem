import socket
import os
import sys
import joblib
import numpy as np
import threading
import signal
from collections import defaultdict
sys.path.append('/usr/lib/python3/dist-packages')
from bcc import BPF

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ml_pipeline/feature_extraction')))
from entropy_calc import (
    calculate_shannon_entropy, calculate_chi_square, calculate_monobit, 
    calculate_poker_test, calculate_cumulative_sums, extract_mac_metadata
)

SOCKET_PATH = "/tmp/ransomware_defense.sock"
BACKING_STORE = "/tmp/backing_store"
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ml_pipeline/saved_models/rf_ransomware_model.pkl'))
EBPF_SRC_PATH = os.path.join(os.path.dirname(__file__), "../kernel_ebpf/vfs_monitor.c")
WRITE_THRESHOLD = 100
TIME_WINDOW_NS = 1_000_000_000
MY_PID = os.getpid()


def fuse_ai_thread(rf_model):
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o777)
    server.listen(5)
    print("[+] Thread 1: FUSE Mathematical ML Bridge Active.")

    while True:
        conn, _ = server.accept()
        try:
            raw_path = conn.recv(512)
            if not raw_path: continue
            fuse_path = raw_path.replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
            
            if fuse_path.startswith("HONEYFILE:"):
                actual_file = fuse_path.split(":", 1)[0]
                print(f"[HONEYFILE TRIPWIRE] Rogue process touched '{actual_file}'!")
                print(f"[MITIGATION] C++ Kernel Driver bypassed ML and executed SIGKILL.")
                continue

            physical_path = os.path.join(BACKING_STORE, fuse_path.lstrip('/'))
            data_buffer = conn.recv(65536)
            if not data_buffer: continue
    
            entropy = calculate_shannon_entropy(data_buffer)
            chi_square = calculate_chi_square(data_buffer)
            monobit_dist = calculate_monobit(data_buffer)
            poker_stat = calculate_poker_test(data_buffer)
            cumul_sums = calculate_cumulative_sums(data_buffer)
            mac_delta = extract_mac_metadata(physical_path)
            
            feature_vector = np.array([[entropy, chi_square, monobit_dist, poker_stat, cumul_sums, mac_delta]])
            prediction = rf_model.predict(feature_vector)[0]
            
            print(f"[*] Scanned: {fuse_path}")
            print(f"[*] Inference -> Entropy: {entropy:.2f} | Chi-Square: {chi_square:.2f} | Monobit: {monobit_dist:.2f} | Poker: {poker_stat:.2f} | Cumulative_sums: {cumul_sums:.2f} | MAC: {mac_delta:.2f} | Verdict: {prediction}")

            if str(prediction).strip() == '1':
                print(f"Ransomware detected. Blocking write")
                conn.send(b'1')
            else:
                conn.send(b'0')

        except Exception as e:
            print(f"IPC Read Error: {e}")

        finally:
            conn.close()



def ebpf_behavioral_thread():
    process_tracker = defaultdict(list)
    bpf_program = BPF(src_file=EBPF_SRC_PATH, cflags=["-Wno-duplicate-decl-specifier"])

    print(f"[+] Thread 2: eBPF Deep-Kernel Monitor Active. Threshold: >{WRITE_THRESHOLD} writes/sec")

    def print_event(cpu, data, size):
        event = bpf_program["write_events"].event(data)
        pid = event.pid
        if pid == MY_PID: return
        p_name = event.process_name.decode('utf-8', 'replace')
        current_time = event.timestamp_ns

        process_tracker[pid].append(current_time)
        process_tracker[pid] = [ts for ts in process_tracker[pid] if (current_time - ts) <= TIME_WINDOW_NS]        

        if len(process_tracker[pid]) > WRITE_THRESHOLD:
            print(f"\n[CRITICAL eBPF] Frantic Write Speed Detected! Program: {p_name} (PID: {pid})")
            print(f"[MITIGATION eBPF] Executing kernel-level SIGKILL to PID {pid}...\n")            

            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

            process_tracker[pid].clear()

    bpf_program["write_events"].open_perf_buffer(print_event)
    while True:
        bpf_program.perf_buffer_poll()


def start_master_daemon():
    print("   INITIALIZING UNIFIED EDR SECURITY DAEMON")

    with open("/tmp/ml_daemon.pid", "w") as f:
        f.write(str(MY_PID))

    print(f"[*] Master Daemon PID: {MY_PID} (Whitelisted against Deadlocks)")

    try:
        rf_model = joblib.load(MODEL_PATH)
        print("[*] 6-Dimensional AI Brain Loaded Successfully.")
    except Exception as e:
        print(f"[ERROR] Could not load model: {e}")
        return

    t1 = threading.Thread(target=fuse_ai_thread, args=(rf_model,), daemon=True)
    t2 = threading.Thread(target=ebpf_behavioral_thread, daemon=True)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()

    except KeyboardInterrupt:
        print("\n[*] Shutting down Unified Master Daemon.")

if __name__ == "__main__":
    start_master_daemon()