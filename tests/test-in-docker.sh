#!/usr/bin/env bash
# =============================================================================
# tests/test-in-docker.sh
# Runs the NFT Firewall in a privileged container to test logic and ruleset.
# =============================================================================
set -euo pipefail

IMAGE_NAME="nft-firewall-test"
CONTAINER_NAME="nft-firewall-run"

echo "[+] Building test image..."
cat > Dockerfile.test <<EOF
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \\
    nftables wireguard-tools python3 python3-pip curl procps kmod iproute2 iptables sudo \\
    && apt-get clean
# Mock systemctl
RUN echo '#!/bin/bash\\necho "[mock] systemctl \$*"' > /usr/local/bin/systemctl && chmod +x /usr/local/bin/systemctl
WORKDIR /opt/nft-firewall
COPY . .
RUN ls -la src/ systemd/
RUN mkdir -p /etc/wireguard && touch /etc/wireguard/wg0.conf
EOF

docker build -t "$IMAGE_NAME" -f Dockerfile.test .
rm Dockerfile.test

echo "[+] Starting privileged container..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run -d --privileged \
    --name "$CONTAINER_NAME" \
    "$IMAGE_NAME" tail -f /dev/null

echo "[+] Installing firewall inside container..."
docker exec "$CONTAINER_NAME" mkdir -p /tmp/install/config
docker exec "$CONTAINER_NAME" bash -c "cp -r /opt/nft-firewall/* /tmp/install/"
docker exec "$CONTAINER_NAME" bash -c "cat > /tmp/install/config/firewall.ini <<EOF
[network]
phy_if = eth0
vpn_interface = wg0
lan_net = 172.17.0.0/16
vpn_server_ip = 1.2.3.4
vpn_server_port = 51820
ssh_port = 22
lan_full_access = false
lan_allow_ports = 22, 32400

[install]
profile = cosmos-vpn-secure
EOF"

docker exec "$CONTAINER_NAME" bash -c "cd /tmp/install && python3 setup.py install"

echo "[+] Running chaos tests inside container..."
# Mocking networking for Drill 3
docker exec "$CONTAINER_NAME" bash -c "echo '#!/bin/bash\\nexit 0' > /usr/bin/ping && chmod +x /usr/bin/ping"
docker exec "$CONTAINER_NAME" bash /opt/nft-firewall/tests/chaos_test.sh

echo "[+] Cleanup..."
docker rm -f "$CONTAINER_NAME"
