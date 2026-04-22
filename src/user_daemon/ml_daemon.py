import socket
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ml_pipeline/feature_extraction')))
from entropy_calc import calculate_shannon_entropy, calculate_chi_square, calculate_monobit, calculate_poker_test, calculate_cumulative_sums, extract_mac_metadata

SOCKET_PATH = "/tmp/ransomware_defense.sock"

def start_daemon():
    with open("/tmp/ml_daemon.pid", "w") as f:
        f.write(str(os.getpid()))
    print(f"[ ] ML Daemon started with pid {os.getpid()}. Whitelisted to prevent deadlock. ") 

    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
        
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)
    print("[*] Listening for FUSE kernel interrupts")  

    while True:
        conn, _ = server.accept()
        try:
            data_buffer = conn.recv(65536)
            if not data_buffer:
                continue

            entropy = calculate_shannon_entropy(data_buffer)
            chi_square = calculate_chi_square(data_buffer)
            monobit_dist = calculate_monobit(data_buffer)
            poker_stat = calculate_poker_test(data_buffer)
            cumul_sums = calculate_cumulative_sums(data_buffer)           
            mac_delta = extract_mac_metadata(filepath)        

            feature_vector = np.array([[entropy, chi_square, monobit_dist, poker_stat, cumul_sums, mac_delta]])         
            prediction = rf_model.predict(feature_vector)

            print(f"[*] Inference -> Entropy: {entropy:.2f} | Chi-Square: {chi_square:.2f} | Monobit: {monobit_dist:.2f} | Verdict: {prediction}")

            if entropy > 7.95 and (150 < chi_square < 350):
                print(f"[Alert] high entropy activity detected! Classifying as malicious.")
                conn.sendall(b"1")
            else:
                conn.sendall(b"0")
        finally:
            conn.close()

if __name__ == "__main__":
    start_daemon()