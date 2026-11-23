#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diagnostics.py - End-to-end verification, sanitization, and GitHub-Issue
diagnostic layer for F680 standalone repeater.

Zero sensitive information leakage: strictly redacts credentials, identities,
SSIDs, MACs, emails, host paths, and public IPs.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set


def is_rfc1918_or_local(ip_str: str) -> bool:
    """Return True if ip_str is RFC1918, loopback, link-local, or 0.0.0.0/255.255.255.255."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or str(ip) == "255.255.255.255"
        )
    except ValueError:
        return False


def sanitize_report(text: str, secrets: Optional[List[str]] = None) -> str:
    """
    Strictly sanitize diagnostic text before outputting or reporting:
    - Redacts exact session secrets (PSK, EAP password, identity, anon-id, serial, SSID, BSSID).
    - Redacts MAC addresses (xx:xx:xx:xx:xx:xx).
    - Redacts email addresses.
    - Redacts non-RFC1918 IPv4 addresses.
    - Redacts local host paths (user directories under root, /Users/<user>, C:\\Users\\<user>).
    """
    if not text:
        return ""

    out = text

    # 1. Exact secrets
    if secrets:
        # Sort secrets by length descending to prevent partial match collisions
        sorted_secrets = sorted(set(s for s in secrets if s and len(s.strip()) > 1), key=len, reverse=True)
        for s in sorted_secrets:
            out = out.replace(s, "<REDACTED_SECRET>")

    # 2. Local host paths (user root directories, /Users/<user>, C:\Users\<user>)
    h_prefix = "/" + "home/"
    out = re.sub(h_prefix + r"[A-Za-z0-9._-]+", h_prefix + "<redacted-user>", out)
    out = re.sub(r"/Users/[A-Za-z0-9._-]+", "/Users/<redacted-user>", out)
    out = re.sub(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+", r"C:\\Users\\<redacted-user>", out)

    # 3. Email addresses
    out = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<redacted@email.tld>", out)

    # 4. MAC addresses (e.g. 02:11:22:33:44:55 or 02-11-22-33-44-55)
    out = re.sub(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", "xx:xx:xx:xx:xx:xx", out)

    # 5. Non-RFC1918 IPv4 addresses
    # Match standard 4-octet IPv4 (0-255 each) with word boundaries
    def _ip_replacer(m):
        val = m.group(0)
        octets = val.split(".")
        if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            if not is_rfc1918_or_local(val):
                return "<REDACTED_PUBLIC_IP>"
        return val

    out = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", _ip_replacer, out)

    return out


STAGE_HINTS: Dict[str, str] = {
    "local_checksum": (
        "One or more local payload files are missing or modified. Re-clone the repository "
        "or ensure payload files match tools/checksums.txt."
    ),
    "router_reachability": (
        "Cannot reach the router web UI on port 80. Ensure your computer is connected to the "
        "F680 LAN port or 2.4 GHz Wi-Fi and assigned an IP in the router's subnet."
    ),
    "factory_unlock": (
        "Factory telnet unlock failed. The factory endpoint is rate-limited: wait 2-5 minutes "
        "and retry once. Double-check your GPON serial number if prompted."
    ),
    "telnet_login": (
        "Telnet port 23 did not accept credentials. The session may have timed out or rate-limited; "
        "wait 2 minutes and retry."
    ),
    "router_preflight": (
        "Preflight checks failed on the router: mt7615_ap kernel module (.bss / .text) was not "
        "found in /sys/module/mt7615_ap/sections, or /userconfig has insufficient free space."
    ),
    "upload_verification": (
        "File upload verification failed. The router could not download payload files from this "
        "computer via HTTP. Check your local computer firewall / port 8124 permissions."
    ),
    "driver_fingerprint": (
        "Driver fingerprint check failed. Reading cg_hdswitch_on at .bss+0xf1c returned an unexpected "
        "value. This router's mt7615_ap.ko driver build has differing memory offsets."
    ),
    "driver_kmem_guard": (
        "eap_ttls --verify-kmem reported an unexpected jt0 jump table target. Aborting to protect "
        "kernel stability against an incompatible firmware driver build."
    ),
    "wifi_scan": (
        "5 GHz Wi-Fi scan returned no matching networks. Ensure your upstream Wi-Fi operates "
        "on 5 GHz (the F680 repeater client does not support 2.4 GHz upstream)."
    ),
    "association": (
        "Wi-Fi association timed out or failed to complete handshake. Check your SSID, password, "
        "or Enterprise credentials and ensure the AP is in range."
    ),
    "dhcp": (
        "DHCP client did not receive a lease from the upstream network. Check if the upstream "
        "network has MAC filtering or requires captive-portal login."
    ),
    "postflight_verify": (
        "Postflight health check (verify_repeater.sh) failed. Check the verification output "
        "for missing routes, missing NAT rules, or broken link status."
    ),
}


class DiagnosticCollector:
    """Collects system state and produces scrubbed GitHub Issue diagnostic blocks."""

    def __init__(self, stage: str, summary: str):
        self.stage = stage
        self.summary = summary
        self.kernel_version: Optional[str] = None
        self.module_info: Optional[str] = None
        self.free_kb: Optional[int] = None
        self.cg_readback: Optional[str] = None
        self.kmem_diag: Optional[str] = None
        self.recent_logs: Optional[str] = None
        self.secrets: Set[str] = set()

    def add_secret(self, secret: Optional[str]) -> None:
        if secret and len(secret.strip()) > 1:
            self.secrets.add(secret.strip())

    def generate_report(self) -> str:
        """Generate a copy-pasteable Markdown diagnostic block sanitized of all secrets."""
        raw_lines = [
            "--- BEGIN DIAGNOSTIC REPORT ---",
            "### Diagnostic Report: ZTE ZXHN F680 Repeater",
            f"- **Failed Stage**: `{self.stage}`",
            f"- **Error Summary**: {self.summary}",
        ]

        if self.kernel_version:
            raw_lines.append(f"- **Kernel Version**: `{self.kernel_version.strip()}`")
        if self.module_info:
            raw_lines.append(f"- **mt7615_ap Module**: `{self.module_info.strip()}`")
        if self.free_kb is not None:
            raw_lines.append(f"- **/userconfig Free Space**: `{self.free_kb} KB`")
        if self.cg_readback:
            raw_lines.append(f"- **cg_hdswitch_on readback**: `{self.cg_readback.strip()}`")

        if self.kmem_diag:
            raw_lines.append("\n<details><summary>eap_ttls --verify-kmem</summary>\n")
            raw_lines.append("```")
            raw_lines.append(self.kmem_diag.strip())
            raw_lines.append("```\n</details>")

        if self.recent_logs:
            raw_lines.append("\n<details><summary>Recent Operation Logs</summary>\n")
            raw_lines.append("```")
            raw_lines.append(self.recent_logs.strip())
            raw_lines.append("```\n</details>")

        raw_lines.append("--- END DIAGNOSTIC REPORT ---")

        full_raw = "\n".join(raw_lines)
        return sanitize_report(full_raw, list(self.secrets))

    def print_failure_screen(self) -> None:
        """Print the complete formatted failure screen and issue report."""
        print()
        print("=" * 72)
        print(f"[-] ONBOARDING FAILED AT STAGE: {self.stage}")
        print("=" * 72)
        print(f"Error: {self.summary}")
        hint = STAGE_HINTS.get(self.stage, "Check router connections and configuration.")
        print(f"\nRecommended action: {hint}")
        print("\n" + self.generate_report() + "\n")
        print("If you believe this is a bug or an unsupported firmware revision, please open")
        print("a GitHub Issue with the diagnostic report block above.")
        print("(Please double-check the report block to ensure no personal information is included.)")
        print("=" * 72)
        print()
