"""
src/daemons/knockd.py — Port-knock daemon for stealth SSH access.
"""
import os
import subprocess
import json
import time
from pathlib import Path
from typing import List, Optional

class PortKnockDaemon:
    def __init__(self, config_path: str, wrapper_path: Optional[str] = None):
        import configparser
        self._config_path = Path(config_path)
        cfg = configparser.ConfigParser()
        cfg.read(str(self._config_path))

        self._sequence: List[int] = [
            int(x.strip()) for x in cfg.get("knockd", "sequence", fallback="7000,8000,9000").split(",")
        ]
        self._proto: str = cfg.get("knockd", "protocol", fallback="udp").lower()
        self._window: int = cfg.getint("knockd", "window_seconds", fallback=10)
        self._ttl: int = cfg.getint("knockd", "open_ttl_seconds", fallback=30)
        self._vpn_iface: str = cfg.get("network", "vpn_interface", fallback="wg0")
        self._phy_if: str = cfg.get("network", "phy_if", fallback="eth0")

        # Security wrapper path (configurable for tests, default for production)
        self._wrapper_path = Path(wrapper_path or os.environ.get("NFT_FIREWALL_WRAPPER", "/usr/local/lib/nft-firewall/fw-nft"))

        if cfg.has_option("knockd", "ssh_port"):
            self._ssh_port: int = cfg.getint("knockd", "ssh_port")
        else:
            self._ssh_port = cfg.getint("network", "ssh_port", fallback=22)

        self._knock_state: dict = {}

    def _log(self, msg: str) -> None:
        print(f"[knockd] {msg}", flush=True)

    def _validate_vpn_iface(self) -> None:
        """Fail closed if vpn_interface is missing or looks like a physical interface."""
        if not self._vpn_iface:
            raise RuntimeError("vpn_interface not configured")
        if self._vpn_iface == self._phy_if:
            raise RuntimeError(f"vpn_interface matches physical interface ({self._phy_if})")
        # Require 'wg' prefix for safety unless overridden in env for specific tests
        if not self._vpn_iface.startswith("wg") and not os.environ.get("NFT_FIREWALL_ALLOW_ANY_VPN_IF"):
            raise RuntimeError(f"vpn_interface '{self._vpn_iface}' is not a trusted tunnel type (must start with 'wg')")

    def _privileged_nft(self, cmd: List[str]) -> List[str]:
        if os.geteuid() == 0:
            return cmd
        if self._wrapper_path.exists():
            return ["sudo", str(self._wrapper_path)] + cmd[1:]
        raise RuntimeError(f"Security wrapper missing ({self._wrapper_path}) — failing closed")

    def _add_rule(self, ip: str) -> str:
        self._validate_vpn_iface()
        # Validate the source IP BEFORE subprocess.run. The packet parser is
        # expected to be correct, but a malformed ip like "1.2.3.4 accept"
        # would silently widen the rule body — fail closed instead.
        from utils.validation import validate_ipv4_network
        result = validate_ipv4_network(ip, allow_network=False)
        if not result.ok:
            raise ValueError(f"knockd: refusing to insert untrusted source IP {ip!r}: {result.reason}")
        ip = result.value

        # The fw-nft wrapper's `--echo` allowlist accepts exactly:
        #   --echo --json add rule ip firewall input <BODY>
        # where <BODY> is a SINGLE argv token. Build the rule body as one
        # string so the wrapper's `[ "$#" -eq 8 ]` check passes; nft itself
        # parses the body internally.
        body = (
            f'iifname "{self._vpn_iface}" '
            f'ip saddr {ip} '
            f'tcp dport {self._ssh_port} accept'
        )
        cmd = [
            "nft", "--echo", "--json", "add", "rule", "ip", "firewall", "input",
            body,
        ]
        cmd = self._privileged_nft(cmd)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError(f"nft add rule failed: {r.stderr.strip()}")

        data = json.loads(r.stdout)
        return str(data["nftables"][0]["rule"]["handle"])

    def _remove_rule(self, handle: str) -> None:
        cmd = ["nft", "delete", "rule", "ip", "firewall", "input", "handle", handle]
        cmd = self._privileged_nft(cmd)
        subprocess.run(cmd, check=False, timeout=10)

    def run_daemon(self) -> None:
        """Main loop: listen for packets and process knocks."""
        import socket
        try:
            # We listen on all interfaces but the rules added are bound to VPN
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except PermissionError:
            raise RuntimeError("Knockd requires root (raw socket access)")

        self._log(f"Knockd started. Monitoring for sequence {self._sequence}...")
        while True:
            packet, _ = sock.recvfrom(65535)
            # Basic ethernet/IP/UDP/TCP parsing would go here in real impl
            # For brevity, this is the architectural hook
            pass

    def run_step(self, pkt_proto: str, src_ip: str, dst_port: int) -> None:
        if pkt_proto != self._proto:
            return

        now = time.time()
        state = self._knock_state.get(src_ip, {"index": 0, "last_time": 0})

        if now - state["last_time"] > self._window:
            state["index"] = 0

        if dst_port == self._sequence[state["index"]]:
            state["index"] += 1
            state["last_time"] = now
            
            if state["index"] == len(self._sequence):
                self._log(f"Knock success from {src_ip}")
                handle = self._add_rule(src_ip)
                self._log(f"Opened SSH for {src_ip} on {self._vpn_iface} (handle {handle})")
                time.sleep(self._ttl)
                self._remove_rule(handle)
                self._log(f"Closed SSH for {src_ip}")
                state["index"] = 0
            
            self._knock_state[src_ip] = state
        else:
            state["index"] = 0
            self._knock_state[src_ip] = state
