# DeadlockAwareRansomewareProofFUSESystem

## Overview

This repository implements a Linux user-space FUSE filesystem designed to detect and block ransomware-like behavior while avoiding deadlock conditions. It combines:
- A C++ FUSE layer that exposes a secure mount point and enforces write controls.
- A Python-based ML daemon that performs real-time file-content analysis and eBPF monitoring.
- A honeyfile generator for deploying decoy tripwires on the backing store.
- An ML training pipeline to build a Random Forest model for ransomware detection.

## Key Features

- Deadlock-aware FUSE driver for secure file I/O.
- Machine learning inference over file data and metadata.
- eBPF-based write-rate behavioral monitoring.
- Honeyfile tripwires to trap malicious actors.
- External backing store at `/tmp/backing_store` with mount at `/tmp/secure_mount`.

## Project Structure

- `src/fuse_fs/deadlock_aware_fuse.cpp` - user-space FUSE filesystem driver.
- `src/user_daemon/ml_daemon.py` - Python daemon that loads the trained ML model, serves inference over UNIX socket, and runs eBPF monitoring.
- `src/honeyfile_gen/generate_decoys.py` - writes decoy honeyfiles and records them for the FUSE driver.
- `ml_pipeline/feature_extraction/entropy_calc.py` - calculates features such as entropy, chi-square, monobit, poker test, cumulative sums, and MAC metadata.
- `ml_pipeline/models/train_rf.py` - trains and saves a Random Forest classifier.
- `ml_pipeline/datasets/` - expected datasets for benign, compressed, and malicious sample data.

## Requirements

- Linux environment with FUSE support.
- `g++` compiler.
- `pkg-config` with FUSE support.
- Python 3 with packages: `numpy`, `scikit-learn`, `joblib`, `bcc`.
- Root or sudo access for mounting and eBPF operations.

## Build and Run

From `scripts/`:

```bash
cd scripts
./build_and_run.sh
```

This script does the following:

1. Creates `/tmp/secure_mount` and `/tmp/backing_store`.
2. Compiles `deadlock_aware_fuse.cpp` into `ransomware_fuse`.
3. Starts `ml_daemon.py` in the background.
4. Streams `/tmp/edr_alerts.log` to the terminal.
5. Mounts the FUSE filesystem at `/tmp/secure_mount`.

## Usage

Once mounted, write normal files and attempt suspicious payload writes into `/tmp/secure_mount` to test defenses.

To stop the system:

```bash
fusermount -u /tmp/secure_mount && kill $DAEMON_PROCESS
```

If you run the daemon manually, make sure to unmount the FUSE mount before exiting.

## Honeyfiles

Use `src/honeyfile_gen/generate_decoys.py` to deploy decoy files into the backing store. These files are written to `/tmp/honeyfiles.txt` and monitored by the FUSE driver as tripwires.

```bash
python3 src/honeyfile_gen/generate_decoys.py
```

## ML Training

The ML pipeline expects sample files under:
- `ml_pipeline/datasets/benign`
- `ml_pipeline/datasets/compressed`
- `ml_pipeline/datasets/malicious`

Train a model with:

```bash
python3 ml_pipeline/models/train_rf.py
```

The trained model is saved as `ml_pipeline/saved_models/rf_ransomware_model.pkl`.

## Notes

- The FUSE driver uses a UNIX socket at `/tmp/ransomware_defense.sock` to query the ML daemon.
- The ML daemon also monitors write behavior and kills processes with excessive write rates via eBPF.
- The driver detects honeyfile writes and enforces immediate mitigation.
