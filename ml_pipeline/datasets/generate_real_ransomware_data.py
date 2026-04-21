import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Define the paths
BASE_DIR = os.path.dirname(__file__)
BENIGN_DIR = os.path.abspath(os.path.join(BASE_DIR, 'benign'))
MALICIOUS_DIR = os.path.abspath(os.path.join(BASE_DIR, 'malicious'))

def generate_raw_encrypted_dataset():
    if not os.path.exists(BENIGN_DIR) or not os.listdir(BENIGN_DIR):
        print(f"[ERROR] No real files found in {BENIGN_DIR}.")
        return

    os.makedirs(MALICIOUS_DIR, exist_ok=True)
    
    # Generate a raw 256-bit (32 byte) AES key and 128-bit (16 byte) IV
    aes_key = os.urandom(32) 
    print(f"[*] Generated Raw AES-256 Key: {aes_key.hex()}")

    print("[*] Simulating Raw Ransomware Attack on Benign Dataset...")
    
    success_count = 0
    for filename in os.listdir(BENIGN_DIR):
        filepath = os.path.join(BENIGN_DIR, filename)
        
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    original_data = f.read()
                
                # AES requires data to be a multiple of the block size (16 bytes)
                # Standard ransomware pads the final block
                padding_length = 16 - (len(original_data) % 16)
                padded_data = original_data + bytes([padding_length] * padding_length)
                
                # Encrypt using raw AES-256 in CBC mode
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                raw_encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                
                malicious_filepath = os.path.join(MALICIOUS_DIR, f"{filename}.encrypted")
                
                # Write the raw IV and Ciphertext to disk (Exactly how ransomware does it)
                with open(malicious_filepath, 'wb') as f:
                    f.write(iv + raw_encrypted_data)
                    
                success_count += 1
                
            except Exception as e:
                print(f"  -> Failed to encrypt {filename}: {e}")

    print(f"[*] Success! {success_count} real files were encrypted to raw binary and saved to {MALICIOUS_DIR}.")

if __name__ == "__main__":
    generate_raw_encrypted_dataset()
