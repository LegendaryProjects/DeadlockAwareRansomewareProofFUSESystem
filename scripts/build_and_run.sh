#!/bin/bash

set -e

echo "Building the Fuse System which is aware of deadlock...."

mkdir -p /tmp/secure_mount
mkdir -p /tmp/backing_store

echo "[*] Compiling C++ FUSE Driver."
g++ -Wall ../src/fuse_fs/deadlock_aware_fuse.cpp `pkg-config fuse --cflags --libs` -o ransomware_fuse

echo "[*] Starting User-Mode ML Daemon."

sudo $(which python3) ../src/user_daemon/ml_daemon.py &
DAEMON_PROCESS=$!

sleep 2

rm -f /tmp/edr_alerts.log
touch /tmp/edr_alerts.log

# Stream the log file directly to this terminal!
tail -f /tmp/edr_alerts.log &
TAIL_PID=$!

echo "[*] Mounting FUSE to /tmp/secure_mount..."
./ransomware_fuse -s -o direct_io /tmp/secure_mount

echo "System is now active."
echo "To test: try writing normal file and an encrypted payload to /tmp/secure_mount"
echo "To shut down Type: fusermount -u /tmp/secure_mount && kill $DAEMON_PROCESS"
