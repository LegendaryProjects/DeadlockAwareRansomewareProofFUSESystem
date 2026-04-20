import socket
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ml_pipeline/feature_extraction')))
from entropy_calc import calculate_shannon_entropy, calculate_chi_square

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
            
            print(f"[*] Scanned File -> Entropy: {entropy:.2f} | Chi-Square: {chi_square:.2f}")

            if entropy > 7.95 and (150 < chi_square < 350):
                print(f"[Alert] high entropy activity detected! Classifying as malicious.")
                conn.sendall(b"1")
            else:
                conn.sendall(b"0")
        finally:
            conn.close()
            

if __name__ == "__main__":
    start_daemon()