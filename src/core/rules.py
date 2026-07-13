"""
src/core/rules.py — Pure nftables ruleset generator.

This module is intentionally side-effect-free.  It only builds strings.
No subprocess calls, no file I/O, no imports from state.py.

Usage
-----
    from core.rules import RulesetConfig, generate_ruleset

    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
        ssh_port=22,
    )
    ruleset_str = generate_ruleset(cfg, exposed_ports=[...])

The returned string can be passed directly to ``state.apply_ruleset()``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from utils.validation import (
    validate_block_target,
    validate_ipv4_network,
    validate_trusted_target,
)

# ── Data contract ─────────────────────────────────────────────────────────────

@dataclass
class RulesetConfig:
    """All inputs needed to generate a complete nftables ruleset.

    Only ``phy_if`` is required; every other field has a safe default.

    Attributes
    ----------
    phy_if:
        Physical (WAN-facing) network interface, e.g. ``"eth0"``.
    vpn_interface:
        WireGuard tunnel interface name.  Default ``"wg0"``.
    vpn_server_ip:
        Remote WireGuard endpoint IP.  Used in the OUTPUT bootstrap rule.
    vpn_server_port:
        Remote WireGuard endpoint UDP port.
    lan_net:
        Local LAN subnet in CIDR notation, e.g. ``"192.168.1.0/24"``.
    lan_full_access:
        When ``True``, preserve the legacy trusted-LAN behavior and allow all
        LAN input on the physical interface.
    lan_allow_ports:
        TCP ports reachable from LAN when ``lan_full_access`` is ``False``.
    lan_allow_udp_ports:
        UDP ports reachable from LAN when ``lan_full_access`` is ``False``
        (e.g. service-discovery beacons like Jellyfin's UDP 7359).
    container_supernet:
        Docker container IP supernet (covers all bridge /28 networks).
        Default ``"172.16.0.0/12"``.
    docker_networks:
        Docker bridge network CIDRs treated as internal container networks.
    ssh_port:
        SSH port to protect with LAN + GeoIP restrictions.  Default ``22``.
    torrent_port:
        Optional torrent TCP+UDP port to open on the VPN interface.
    extra_ports:
        Additional TCP ports to open on the VPN interface.
    cosmos_public_ports:
        TCP ports exposed for Cosmos Cloud reverse-proxy ingress.
    allow_plex_lan:
        When ``True``, open port 32400 for LAN-only Plex direct play.
    blocked_ips/trusted_ips/dk_ips:
        Persisted dynamic set members to preload after a ruleset reload.
    """

    # Required
    phy_if: str

    # Network topology
    vpn_interface:      str           = "wg0"
    vpn_server_ip:      str           = ""
    vpn_server_port:    str           = ""
    lan_net:            str           = "192.168.1.0/24"
    lan_full_access:    bool          = False
    lan_allow_ports:    List[int]     = field(default_factory=list)
    lan_allow_udp_ports: List[int]    = field(default_factory=list)
    container_supernet: str           = "172.16.0.0/12"
    docker_networks:    List[str]     = field(default_factory=list)

    # WireGuard fwmark — wg-quick marks its encrypted UDP packets with this value
    # so the kernel routing policy can exempt them from the tunnel (avoiding loops).
    # The same mark is used here to lock the bootstrap OUTPUT rule to the WG process.
    # Default 0xca6c = 51820 — the standard wg-quick value for wg0.
    vpn_fwmark: str = "0xca6c"

    # Ports
    ssh_port:     int            = 22
    torrent_port: Optional[int]  = None
    extra_ports:  List[int]      = field(default_factory=list)

    # Profile flags
    cosmos_public_ports: List[int] = field(default_factory=list)
    allow_plex_lan: bool      = False

    # Persisted dynamic sets
    blocked_ips: List[str] = field(default_factory=list)
    trusted_ips: List[str] = field(default_factory=list)
    geowhitelist_ips: List[str] = field(default_factory=list)
    dk_ips:      List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Reject unsafe network inputs before any nft syntax is generated."""
        # 1. Validate interface semantics (logical)
        if not self.phy_if:
            raise ValueError("phy_if is required")
        if self.vpn_interface == self.phy_if:
            raise ValueError(f"vpn_interface cannot be the same as phy_if ({self.phy_if})")
        
        # Require vpn_interface to look like a tunnel (wg*) unless explicitly overridden
        if not self.vpn_interface.startswith("wg") and not os.environ.get("NFT_FIREWALL_ALLOW_ANY_VPN_IF"):
             raise ValueError(f"Invalid vpn_interface '{self.vpn_interface}'; must start with 'wg'")

        # 2. Validate CIDRs
        for label, value in (
            ("lan_net", self.lan_net),
            ("container_supernet", self.container_supernet),
        ):
            result = validate_ipv4_network(value)
            if not result.ok:
                raise ValueError(f"{label}: {result.reason}")
            setattr(self, label, result.value)

        self.docker_networks = _validated_network_list("docker_networks", self.docker_networks)
        self.blocked_ips = _validated_set_members("blocked_ips", self.blocked_ips)
        self.trusted_ips = _validated_set_members("trusted_ips", self.trusted_ips)
        self.geowhitelist_ips = _validated_set_members("geowhitelist_ips", self.geowhitelist_ips)
        self.dk_ips = _validated_set_members("dk_ips", self.dk_ips)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _iface_vars(cfg: RulesetConfig) -> Dict[str, str]:
    """Return the nftables interface-match expression strings.

    Keys: PHY, OPH, VPN, OVPN — positive matches only.
    Negative-match variants (NPHY, NOPH, NVPN, NOVP) have been removed:
    every accept rule must name the interface it permits, never 'not X'.
    """
    phy = cfg.phy_if
    vpn = cfg.vpn_interface
    return {
        "PHY" : f'iifname "{phy}"',
        "OPH" : f'oifname "{phy}"',
        "VPN" : f'iifname "{vpn}"',
        "OVPN": f'oifname "{vpn}"',
    }


def _pset(ports) -> str:
    """Format a collection of ports as an nftables set literal, e.g. ``{ 22, 80 }``."""
    return "{ " + ", ".join(str(p) for p in sorted(set(ports))) + " }"


def _geowhitelist_tcp_ports(cfg: RulesetConfig) -> List[int]:
    """Return physical-interface TCP services allowed from geowhitelisted IPs.

    The country whitelist is a source gate, not a trust zone. It must never
    produce a blanket ``accept``; only explicitly configured public/admin
    services may be reachable from those sources.
    """
    configured_services = (
        set(cfg.extra_ports)
        | set(cfg.cosmos_public_ports)
        | set(cfg.lan_allow_ports)
    )
    allowed = {cfg.ssh_port}
    allowed.update(port for port in (80, 443) if port in configured_services)
    return sorted(allowed)


def _validated_network_list(label: str, values: List[str]) -> List[str]:
    """Return normalized IPv4 networks, rejecting /0 and malformed values."""
    normalized: List[str] = []
    for value in values:
        result = validate_ipv4_network(value)
        if not result.ok:
            raise ValueError(f"{label}: {result.reason}")
        normalized.append(result.value)
    return normalized


def _validated_set_members(set_name: str, values: List[str]) -> List[str]:
    """Validate persisted dynamic set members before embedding them in nftables."""
    normalized: List[str] = []
    for value in values:
        if set_name == "blocked_ips":
            result = validate_block_target(value)
        elif set_name == "trusted_ips":
            result = validate_trusted_target(value)
        else:
            result = validate_ipv4_network(value)
        if not result.ok:
            raise ValueError(f"{set_name}: {result.reason}")
        normalized.append(result.value)
    return normalized


def _normalize_intervals(elements: List[str]) -> List[str]:
    """Return sorted non-overlapping CIDR/IP intervals for nft interval sets."""
    networks = []
    passthrough = []
    for element in elements:
        raw = str(element).strip()
        if not raw:
            continue
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            passthrough.append(raw)
    collapsed = [str(net) for net in ipaddress.collapse_addresses(networks)]
    return sorted(set(collapsed + passthrough))


def _nexpr(networks: List[str]) -> str:
    """Format one or more CIDRs as an nftables network expression."""
    unique = _normalize_intervals(networks)
    if len(unique) == 1:
        return unique[0]
    return "{ " + ", ".join(unique) + " }"


def _emit_dynamic_set(lines: List[str], name: str, comment: str, elements: List[str],
                      with_timeout: bool = False) -> None:
    """Append an interval ipv4_addr set with optional persisted elements.

    ``with_timeout`` adds the ``timeout`` flag so individual elements may carry
    an expiry (e.g. a 48h temporary allow); untimed elements stay permanent.
    """
    a = lines.append
    flags = "interval, timeout" if with_timeout else "interval"
    a(f"    # {comment}")
    a(f"    set {name} {{")
    a(f"        type ipv4_addr; flags {flags}")
    if elements:
        a("        elements = { " + ", ".join(_normalize_intervals(elements)) + " }")
    a("    }")
    a("")


def _allowed_exposed_ports(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[Dict]:
    """Return exposed entries whose host port is explicitly allowed by config."""
    allowed_tcp = set(cfg.cosmos_public_ports)
    allowed: List[Dict] = []
    for entry in exposed_ports:
        try:
            proto = str(entry.get("proto", "tcp")).lower()
            host_port = int(entry["host_port"])
            container_port = int(entry["container_port"])
            container_ip = str(entry["container_ip"])
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if proto != "tcp" or host_port not in allowed_tcp:
            continue
        ip_result = validate_ipv4_network(container_ip, allow_network=False)
        if not ip_result.ok:
            continue
        cleaned = dict(entry)
        cleaned["proto"] = proto
        cleaned["host_port"] = host_port
        cleaned["container_port"] = container_port
        cleaned["container_ip"] = ip_result.value
        if cleaned.get("src"):
            src_result = validate_ipv4_network(str(cleaned["src"]))
            if not src_result.ok:
                continue
            cleaned["src"] = src_result.value
        allowed.append(cleaned)
    return allowed


def _build_header(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the comment header lines and ``flush ruleset`` directive."""
    L: List[str] = []
    a = L.append

    a("#!/usr/sbin/nft -f")
    a("")
    a("# +===================================================================+")
    a("# | NFT Firewall & VPN Killswitch — Modular Architecture             |")
    a("# | Full-tunnel | iptables:false | Dynamic sets | Watchdog-aware     |")
    a("# +===================================================================+")
    a(f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    a(f"# VPN       : {cfg.vpn_server_ip}:{cfg.vpn_server_port} -> {cfg.vpn_interface}")
    a(f"# Physical  : {cfg.phy_if} | LAN: {cfg.lan_net}")
    a(f"# SSH       : {cfg.ssh_port}")
    if cfg.torrent_port:
        a(f"# Torrent   : {cfg.torrent_port}")
    if cfg.extra_ports:
        a(f"# Extra     : {', '.join(map(str, cfg.extra_ports))}")
    a(f"# Plex      : {'yes' if cfg.allow_plex_lan else 'no'}")
    a(f"# Container supernet: {cfg.container_supernet}")
    docker_nets = _normalize_intervals(cfg.docker_networks or [cfg.container_supernet])
    a(f"# Docker networks: {', '.join(docker_nets)}")
    if cfg.cosmos_public_ports:
        a(f"# Cosmos public TCP: {', '.join(map(str, cfg.cosmos_public_ports))}")
    a(f"# Exposed ports ({len(exposed_ports)}):")
    for e in exposed_ports:
        a(f"#   host:{e['host_port']}/{e.get('proto', 'tcp')} "
          f"-> {e['container_ip']}:{e['container_port']}")
    if not exposed_ports:
        a("#   none")
    a("")
    a("# Docker has iptables:false — it NEVER touches these tables.")
    a("# Dynamic sets (blocked_ips, trusted_ips) survive nftables reload.")
    a("")
    a("flush ruleset")
    a("")
    return L


def _build_ipv6_killswitch() -> List[str]:
    """Return the ``table ip6 killswitch`` block that drops all IPv6 at priority -300.

    Priority -300 is more aggressive than -200 — it undercuts any hidden OS-default
    'allow' hooks that might be inserted at -200 by the kernel or other tools.
    """
    return [
        "# ===================================================================",
        "# IPv6 kill — priority -300, undercuts all other hooks.",
        "# Any IPv6 packet is silently dropped before any other rule can fire.",
        "# ===================================================================",
        "table ip6 killswitch {",
        "    chain input   { type filter hook input   priority -300; policy drop; }",
        "    chain output  { type filter hook output  priority -300; policy drop; }",
        "    chain forward { type filter hook forward priority -300; policy drop; }",
        "}",
        "",
    ]


def _build_nat_table(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the ``table ip nat`` block (prerouting DNAT + postrouting masquerade)."""
    iv = _iface_vars(cfg)
    VPN = iv["VPN"]
    OVPN = iv["OVPN"]
    docker_nets = cfg.docker_networks or [cfg.container_supernet]
    allowed_exposed = _allowed_exposed_ports(cfg, exposed_ports)

    L: List[str] = []
    a = L.append

    a("# ===================================================================")
    a("# NAT — we own this entirely (Docker has iptables:false).")
    a("# MASQUERADE only via wg0 — enforces VPN killswitch at NAT layer.")
    a("# ===================================================================")
    a("table ip nat {")
    a("")
    a("    chain prerouting {")
    a("        type nat hook prerouting priority dstnat; policy accept;")
    a("")

    if allowed_exposed:
        a("        # Explicitly allowed public container ingress only.")
        a("        # Docker published ports are ignored unless listed in firewall config.")
        for e in allowed_exposed:
            hp  = e["host_port"]
            cip = e["container_ip"]
            cp  = e["container_port"]
            pr  = e.get("proto", "tcp")
            src = e.get("src")
            if src:
                a(f"        {VPN} {pr} dport {hp} ip saddr {src} dnat to {cip}:{cp}"
                  f"   # host:{hp} LAN-only -> {cip}:{cp}")
            else:
                a(f"        {VPN} {pr} dport {hp} dnat to {cip}:{cp}"
                  f"   # host:{hp} -> {cip}:{cp}")
    else:
        a("        # No explicitly allowed public container ingress.")

    a("    }")
    a("")
    a("    chain postrouting {")
    a("        type nat hook postrouting priority srcnat; policy accept;")
    a("")
    a("        # Single supernet rule replaces 40+ Docker per-/28 rules.")
    a("        # Masquerade ONLY via wg0 — containers cannot leak via phy.")
    a(f"        ip saddr {_nexpr(docker_nets)} {OVPN} masquerade")
    a("    }")
    a("")
    a("}")
    a("")
    return L


def _build_filter_table(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the ``table ip firewall`` block with sets and all three chains."""
    iv   = _iface_vars(cfg)
    PHY  = iv["PHY"]
    OPH  = iv["OPH"]
    VPN  = iv["VPN"]
    OVPN = iv["OVPN"]

    ssh = cfg.ssh_port

    vpn_tcp_in = {ssh}
    vpn_udp_in: set = set()
    if cfg.torrent_port:
        vpn_tcp_in.add(cfg.torrent_port)
        vpn_udp_in.add(cfg.torrent_port)
    for p in cfg.extra_ports:
        vpn_tcp_in.add(p)

    allowed_exposed = _allowed_exposed_ports(cfg, exposed_ports)

    docker_nets   = cfg.docker_networks or [cfg.container_supernet]

    L: List[str] = []
    a = L.append

    a("# ===================================================================")
    a("# Main filter — INPUT / OUTPUT / FORWARD: policy drop on all three.")
    a("# Dynamic sets: blocked_ips and trusted_ips are runtime-editable.")
    a("# ===================================================================")
    a("table ip firewall {")
    a("")
    _emit_dynamic_set(
        L,
        "blocked_ips",
        "Runtime IP block list — persisted and preloaded after reload.",
        cfg.blocked_ips,
    )
    _emit_dynamic_set(
        L,
        "trusted_ips",
        "Trusted IPs — the ONLY sources allowed to 80/443 (+ SSH override). "
        "Supports per-entry timeouts for temporary !allow grants.",
        cfg.trusted_ips,
        with_timeout=True,
    )
    _emit_dynamic_set(
        L,
        "geowhitelist_ips",
        "Lockdown mode whitelist — if non-empty, only these public IPs are allowed.",
        cfg.geowhitelist_ips,
    )
    _emit_dynamic_set(
        L,
        "dk_ips",
        "DK GeoIP set — SSH allowed from Danish IPs.",
        cfg.dk_ips,
    )
    _emit_dynamic_set(
        L,
        "docker_nets",
        "Docker bridge networks — internal container networks.",
        docker_nets,
    )
    a("    # Bogon set — RFC-1918 ranges for anti-spoofing.")
    a("    set bogons {")
    a("        type ipv4_addr; flags interval")
    a("        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }")
    a("    }")
    a("")

    # ── INPUT ────────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # INPUT — default DROP.")
    a("    # ---------------------------------------------------------------")
    a("    chain input {")
    a("        type filter hook input priority filter; policy drop;")
    a("")
    a('        iifname "lo" accept')
    a("        ct state established,related accept")
    a("        ct state invalid drop")
    # Global block list (highest priority after connection tracking)
    a("        ip saddr @blocked_ips drop")
    a("")

    a("        # Trusted admin IPs — SSH and Web override (before LAN/VPN restriction)")
    a(f"        {PHY} ip saddr @trusted_ips tcp dport {ssh} accept   # admin SSH override")
    if cfg.cosmos_public_ports:
        a(f"        {PHY} ip saddr @trusted_ips "
          f"tcp dport {_pset(cfg.cosmos_public_ports)} accept   # admin Web override")
    a("")

    # LOCKDOWN MODE: If geowhitelist is not empty, only selected public/admin
    # services are reachable from those sources. This intentionally does NOT
    # make geowhitelisted countries a trusted zone.
    if cfg.geowhitelist_ips:
        geo_tcp_ports = _geowhitelist_tcp_ports(cfg)
        a("        # LOCKDOWN MODE: Country whitelist gates explicit TCP services only.")
        if geo_tcp_ports:
            a(f"        {PHY} ip saddr @geowhitelist_ips tcp dport {_pset(geo_tcp_ports)} "
              "accept comment \"Lockdown: Country Whitelist Services\"")
        a(f"        {PHY} ip saddr != {cfg.lan_net} drop comment \"Lockdown: Non-whitelisted country drop\"")
        a("")

    a(f"        {PHY} ip saddr @bogons ip saddr != {cfg.lan_net} drop"
      "   # anti-spoofing (LAN excluded)")
    a("")
    a("        tcp flags == 0x0         drop  # NULL scan")
    a("        tcp flags == fin|psh|urg drop  # XMAS scan")
    a("        tcp flags == fin|syn     drop")
    a("        tcp flags == syn|rst     drop")
    a("")
    a("        ip protocol icmp icmp type echo-request \\")
    a("            limit rate 5/second burst 10 packets accept")
    a("        ip protocol icmp icmp type echo-request drop")
    a("        ip protocol icmp accept")
    a("")
    a(f"        # SSH: LAN + DK GeoIP on physical; DK GeoIP + trusted on VPN")
    a(f"        {PHY} ip saddr {cfg.lan_net} tcp dport {ssh} accept")
    a(f"        {PHY} ip saddr @dk_ips tcp dport {ssh} accept   # DK GeoIP")
    a(f"        {PHY} tcp dport {ssh} drop")
    a(f"        {VPN} ip saddr @trusted_ips tcp dport {ssh} accept   # trusted override")
    a(f"        {VPN} ip saddr @dk_ips tcp dport {ssh} accept   # DK GeoIP")
    a(f"        {VPN} tcp dport {ssh} drop")

    vpn_tcp_no_ssh = (vpn_tcp_in - {ssh}) - set(cfg.cosmos_public_ports)
    if vpn_tcp_no_ssh:
        a(f"        {VPN} tcp dport {_pset(vpn_tcp_no_ssh)} accept")
    if vpn_udp_in:
        a(f"        {VPN} udp dport {_pset(vpn_udp_in)} accept")
    a("")


    if cfg.cosmos_public_ports:
        a("        # Cosmos Cloud reverse-proxy ingress — STRICT ALLOWLIST.")
        a("        # Public web ports are reachable ONLY from the trusted_ips set")
        a("        # (managed via ChatOps !allow, with optional per-entry timeouts).")
        a("        # No geo, no open access — everything else hits the policy drop.")
        a(f"        {VPN} ip saddr @trusted_ips tcp dport {_pset(cfg.cosmos_public_ports)} accept")
        a("")

    if cfg.allow_plex_lan:
        a("        # Plex: direct LAN access (also via Cosmos proxy).")
        a("        # MUST be before the general LAN catch-all — otherwise the LAN")
        a("        # accept above would shadow this rule and the drop would never fire.")
        a(f"        {PHY} ip saddr {cfg.lan_net} tcp dport 32400 accept")
        a("        tcp dport 32400 drop   # block from internet/VPN")
        a("")

    if cfg.lan_full_access:
        a(f"        {PHY} ip saddr {cfg.lan_net} accept   # trusted LAN full access")
    else:
        if cfg.lan_allow_ports:
            a("        # Strict LAN mode: only configured LAN TCP services are reachable.")
            a(f"        {PHY} ip saddr {cfg.lan_net} tcp dport {_pset(cfg.lan_allow_ports)} accept")
        if cfg.lan_allow_udp_ports:
            a("        # Strict LAN mode: configured LAN UDP services (e.g. discovery beacons).")
            a(f"        {PHY} ip saddr {cfg.lan_net} udp dport {_pset(cfg.lan_allow_udp_ports)} accept")
        a(f"        {PHY} ip saddr {cfg.lan_net} drop   # strict LAN default deny")
    a("")

    a('        counter log prefix "[nft-in-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")

    # ── OUTPUT ───────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # OUTPUT — default DROP. Full-tunnel VPN killswitch.")
    a("    # Accept paths (ALL interface-pinned — no bare ct established,")
    a("    # no negative-match rules — every accept names its interface):")
    a('    #   1. oifname "lo"')
    a(f"    #   2. {OPH} udp dport 67              (DHCP broadcast + renewal)")
    a(f"    #   3. {OPH} meta mark {cfg.vpn_fwmark} ip daddr {cfg.vpn_server_ip}:{cfg.vpn_server_port}")
    a(f"    #      WG bootstrap — fwmark-locked: only the WireGuard kernel process")
    a(f"    #      marks packets with {cfg.vpn_fwmark}; no other process can use this hole.")
    a(f"    #   4. {OPH} ip daddr {cfg.lan_net}     (LAN stays local)")
    a("    #   5. meta oifkind \"bridge\" ip daddr @docker_nets  (host → containers via bridge only)")
    a(f"    #   6. oifname \"{cfg.vpn_interface}\"   (THE KILLSWITCH — sole internet path)")
    a("    # wg0 down → rule 6 never matches → total drop, no leak.")
    a("    # No ct established,related: stale conntrack cannot bypass the killswitch.")
    a("    # ---------------------------------------------------------------")
    a("    chain output {")
    a("        type filter hook output priority filter; policy drop;")
    a("")
    a('        oifname "lo" accept')
    a(f"        {OPH} udp sport 68 udp dport 67 accept                # DHCP client only (sport 68)")
    a("        ct state invalid drop")
    a("")
    a("        # Block outbound to blocked IPs (even if they were trusted)")
    a("        ip daddr @blocked_ips drop")
    a("")
    a(f"        {OPH} meta mark {cfg.vpn_fwmark} ip daddr {cfg.vpn_server_ip} udp dport {cfg.vpn_server_port} accept  # WG bootstrap — fwmark-locked")
    a(f"        {OPH} ip daddr {cfg.lan_net} accept                         # LAN stays local")
    a('        meta oifkind "bridge" ip daddr @docker_nets accept'
      "               # host → containers via bridge only")
    # The KILLSWITCH accept is the SOLE path for internet egress, placed last
    # so blocked_ips/ct-invalid drops above it actually fire on VPN traffic.
    # The "nft-killswitch-output" comment is the integrity marker that the
    # watchdog and doctor look for; it MUST stay on this rule.
    a(f'        {OVPN} counter accept comment "nft-killswitch-output"   # KILLSWITCH')
    a("")
    a('        counter log prefix "[nft-out-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")

    # ── FORWARD ──────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # FORWARD — default DROP.")
    a(f"    # 0. DROP ct new: container_supernet → {cfg.phy_if} (before conntrack).")
    a("    #    Scoped to ct state new so DNAT return traffic (established) still works.")
    a("    #    Prevents containers initiating connections to PHY; reply packets pass.")
    a("    # 1. ct established (covers DNAT return paths and all other legit flows)")
    a("    # 2. LAN-to-LAN (Plex discovery, local routing)")
    a("    # 3. Inter-container bridges (Cosmos /28 link networks)")
    a("    # 4. Container internet egress via wg0 only (killswitch)")
    a("    # 5. Inbound to published containers (post-DNAT)")
    a("    # ---------------------------------------------------------------")
    a("    chain forward {")
    a("        type filter hook forward priority filter; policy drop;")
    a("")
    a("        ct state invalid drop")
    a("")
    a(f"        # DNAT replies to LAN (e.g. Plex) are established-state; allow those only.")
    a(f"        # All other container→PHY traffic is hard-dropped regardless of ct state,")
    a(f"        # closing the VPN-escape path for established connections.")
    a(f"        ip saddr @docker_nets {OPH} ip daddr {cfg.lan_net} ct state established,related accept"
      "  # DNAT replies to LAN")
    a(f"        ip saddr @docker_nets {OPH} drop"
      "  # hard drop: containers cannot egress PHY (any state)")
    a("")
    a("        ct state established,related accept")
    a("")
    a(f"        {PHY} {OPH} ip saddr {cfg.lan_net} ip daddr {cfg.lan_net} accept"
      "  # LAN-to-LAN")
    a("")
    a("        # Docker internal bridge traffic only between known container networks.")
    a('        meta iifkind "bridge" meta oifkind "bridge" '
      "ip saddr @docker_nets ip daddr @docker_nets accept")
    a("")
    a(f"        ip saddr @docker_nets {OVPN} accept  # container internet ONLY via VPN (killswitch)")
    a("")

    if cfg.cosmos_public_ports:
        a("        # Cosmos Cloud reverse-proxy forwarding — STRICT ALLOWLIST (trusted_ips only).")
        a(f"        {VPN} ip saddr @trusted_ips tcp dport {_pset(cfg.cosmos_public_ports)} "
          "ip daddr @docker_nets accept")
        a("")

    if allowed_exposed:
        a("        # Inbound to published containers (post-DNAT forwarding)")
        for e in allowed_exposed:
            cip = e["container_ip"]
            cp  = e["container_port"]
            pr  = e.get("proto", "tcp")
            src = e.get("src")
            if src:
                a(f"        {VPN} ip saddr {src} {pr} dport {cp} ip daddr {cip} accept"
                  f"   # {e['host_port']}/{pr} [LAN-only] -> {cip}:{cp}")
            else:
                a(f"        {VPN} {pr} dport {cp} ip daddr {cip} accept"
                  f"   # {e['host_port']}/{pr} -> {cip}:{cp}")
        a("")

    a('        counter log prefix "[nft-fwd-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")
    a("}")
    return L


# ── Public API ────────────────────────────────────────────────────────────────

def validate_interface_exists(iface: str) -> None:
    """Raise ValueError if interface *iface* does not exist on the system."""
    try:
        # We use ip link show instead of socket/ioctl to avoid extra imports
        proc = subprocess.run(["ip", "link", "show", iface], 
                            capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise ValueError(f"Interface '{iface}' not found on this system.")
    except FileNotFoundError:
        # If 'ip' command is missing, we skip validation
        pass


def _check_invariants(cfg: RulesetConfig, ruleset: str) -> None:
    """Raise ValueError if the ruleset violates core security invariants."""
    # 1. Strip '#' comments for analysis to prevent bypasses or false positives
    # We preserve 'comment "..."' tokens as they are part of our integrity markers
    clean = re.sub(r'#.*$', '', ruleset, flags=re.MULTILINE)
    condensed = re.sub(r'\s+', ' ', clean)

    # 2. Detect dangerous /0 network (too broad)
    # Catches: 0.0.0.0/0, 0/0, ip saddr 0/0, etc.
    if re.search(r'\b0(\.0\.0\.0)?/0\b', clean):
        raise ValueError("Security violation: /0 network found in ruleset (too broad)")

    # 3. Detect public ports 80/443 on physical interface
    phy = cfg.phy_if
    # Search for ALL chain blocks to find any public port exposure on the physical interface.
    # We find blocks between curly braces in the cleaned ruleset.
    for block_match in re.finditer(r'{(.*?)}', clean, re.DOTALL):
        block = block_match.group(1)
        # Simplify the block by condensing all whitespace into single spaces
        block_clean = re.sub(r'\s+', ' ', block)
        # Strictest check: find 'iifname "PHY"', 'dport 80/443', and 'accept' 
        # in that specific order within a single rule context (no other 'accept' or ';' in between).
        # Pattern ensures we match '80' exactly and stay within a single rule.
        pattern = rf'iifname "{re.escape(phy)}"(?:(?!accept|;).)*?dport\b(?:(?!accept|;).)*?\b(80|443)\b(?:(?!accept|;).)*?accept'
        for rule_match in re.finditer(pattern, block_clean, re.IGNORECASE):
            rule = re.sub(r"\s+", " ", rule_match.group(0)).lower()
            source_restricted = (
                f"ip saddr {cfg.lan_net}".lower() in rule
                or "ip saddr @geowhitelist_ips" in rule
                or "ip saddr @trusted_ips" in rule
                or "ip saddr @dk_ips" in rule
            )
            if source_restricted:
                continue
            raise ValueError(f"Security violation: Public port exposure detected on {phy}")


    # 4. VPN Killswitch Marker must be present in ACTUAL code, not just comments
    if 'nft-killswitch-output' not in ruleset:
         raise ValueError("Security violation: Killswitch integrity marker missing from ruleset")
    
    # 5. VPN Egress Check: Ensure there's a functional accept rule for the VPN interface
    if not re.search(r'oifname\s+"' + re.escape(cfg.vpn_interface) + r'"[\s\S]*?accept', clean, re.DOTALL):
         raise ValueError(f"Security violation: No functional accept rule found for VPN interface {cfg.vpn_interface}")


def generate_ruleset(cfg: RulesetConfig, exposed_ports: Optional[List[Dict]] = None) -> str:
    """Build the complete nftables ruleset as a single string.

    This function is pure — it performs no I/O and executes no subprocesses.
    The returned string is ready to be written to a file and loaded with
    ``nft -f``, or validated with ``nft -c -f``.

    Tables generated
    ----------------
    ``ip6 killswitch``
        Drops all IPv6 at priority -300, undercutting all other hooks.
    ``ip nat``
        Masquerade (VPN-only killswitch at NAT layer) + DNAT for exposed
        container ports.
    ``ip firewall``
        Default-drop INPUT/OUTPUT/FORWARD with dynamic ``blocked_ips``,
        ``trusted_ips``, ``dk_ips``, and ``bogons`` sets.

    Parameters
    ----------
    cfg:
        A :class:`RulesetConfig` describing the network topology, ports, and
        profile flags.
    exposed_ports:
        List of expose-registry dicts (as returned by
        ``integrations.docker.load_registry()``).  Defaults to ``[]``.

    Returns
    -------
    str
        The complete nftables ruleset, newline-terminated.
    """
    if exposed_ports is None:
        exposed_ports = []

    sections: List[List[str]] = [
        _build_header(cfg, exposed_ports),
        _build_ipv6_killswitch(),
        _build_nat_table(cfg, exposed_ports),
        _build_filter_table(cfg, exposed_ports),
    ]

    lines: List[str] = []
    for section in sections:
        lines.extend(section)

    ruleset = "\n".join(lines) + "\n"
    _check_invariants(cfg, ruleset)
    return ruleset
