#!/usr/bin/env bash
# Linux basis: update, requirements, Docker, kernel modifications for Elasticsearch
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y upgrade
apt-get install -y git curl jq python3 python3-pip ca-certificates cloud-guest-utils

# Increase disk size
growpart /dev/vda 1 || true
resize2fs /dev/vda1
df -h /

# Docker
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
usermod -aG docker vagrant || true
systemctl enable --now docker

# Elasticsearch requires vm.max_map_count >= 262144
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elastic.conf
sysctl --system >/dev/null
