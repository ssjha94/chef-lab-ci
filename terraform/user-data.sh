#!/bin/bash
# user-data.sh — Lightweight EC2 first-boot script
# Chef Infra Client is installed by 'knife bootstrap' (not here).
# This script only ensures the instance is SSH-ready and up to date.

set -e

echo "[$(date)] Starting instance preparation..."

# Wait for cloud-init to finish (ensures apt lock is free)
cloud-init status --wait || true

# Update apt cache
echo "[$(date)] Updating apt cache..."
apt-get update -qq

# Ensure sshd is running (usually is by default on Ubuntu, but be safe)
systemctl enable ssh
systemctl start ssh

echo "[$(date)] Instance ready for knife bootstrap."
