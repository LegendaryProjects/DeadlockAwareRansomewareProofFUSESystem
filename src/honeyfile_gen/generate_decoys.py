import os

BACKING_STORE = "/tmp/backing_store"
HONEYFILE_LIST_PATH = "/tmp/honeyfiles.txt"

# Attractive names that ransomware looks for first
DECOY_NAMES = [
    ".backup_keys.pem",
    "passwords_2024.xlsx",
    ".wallet_backup.dat",
    "tax_returns_final.pdf",
    "secret_config.ini"
]

def generate_honeyfiles():
    if not os.path.exists(BACKING_STORE):
        os.makedirs(BACKING_STORE)

    created_files = []

    print("[*] Deploying Honeyfile Tripwires directly to physical disk")

    for file_name in DECOY_NAMES:
        # Pick a random attractive name
        full_path = os.path.join(BACKING_STORE, file_name)

        try:
            with open(full_path, "w") as f:
                f.write("CONFIDENTIAL: DO NOT STORE.\n" * 10)

            fuse_path = f"/{file_name}"
            created_files.ppend(fuse_path)
            print(f" -> Successfully deployed: {fuse_path}")

        except Exception as e:
            print(f" -> [FAILED] Could not create {file_name}. Error: {e}")

    # Save the list of honeyfiles so the C++ driver can read them
    with open(HONEYFILE_LIST_PATH, "w") as f:
        for path in created_files:
            f.write(path + "\n")
            
    print(f"[*] Saved tripwire map to {HONEYFILE_LIST_PATH} with {len(created_files)} files.")

if __name__ == "__main__":
    generate_honeyfiles()