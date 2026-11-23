#!/usr/bin/env python3
"""Serve the F680 repeater payload and print copy-paste router commands.

Works on Linux, macOS, and Windows. The payload directory is the HTTP root.
"""
import http.server
import os
import socket
import socketserver
import sys
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = ROOT / "payload"
PORT = int(os.environ.get("PORT", "8124"))


def local_ip() -> str:
    """Best-effort local IP on the F680 LAN, without sending packets."""
    targets = [os.environ.get("ROUTER_IP", ""), "192.168.12.1", "8.8.8.8"]
    for target in targets:
        if not target:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 80))
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            s.close()
    return "127.0.0.1"


def print_commands(ip: str) -> None:
    base = f"http://{ip}:{PORT}"
    print()
    print("=" * 72)
    print("  F680 repeater payload (manual mode)")
    print("=" * 72)
    print(f"  Serving: {PAYLOAD}")
    print(f"  Address: {base}")
    print()
    print("  On the F680 root shell (already unlocked), paste:")
    print()
    print("  cd /userconfig")
    for name in (
        "kmemtool",
        "udhcpc",
        "udhcpc.script",
        "repeater_up.sh",
        "restore_after_boot.sh",
        "verify_repeater.sh",
    ):
        print(f"  wget -q -O {name} {base}/{name}")
    print(f"  wget -q -O upstream.conf {base}/upstream.conf.example")
    print("  chmod +x kmemtool udhcpc udhcpc.script repeater_up.sh restore_after_boot.sh verify_repeater.sh")
    print("  chmod 600 upstream.conf")
    print()
    print("  Optional safe boot wrapper (stock firmware does NOT auto-run it):")
    print("  cp /userconfig/autorun.sh /userconfig/autorun.sh.old 2>/dev/null")
    print(f"  wget -q -O /userconfig/autorun.sh {base}/autorun.sh")
    print("  chmod +x /userconfig/autorun.sh")
    print()
    print("  Edit the upstream credentials, then run:")
    print("  vi /userconfig/upstream.conf")
    print("  sh /userconfig/repeater_up.sh")
    print()
    print("  Ctrl+C stops this server.")
    print("=" * 72)
    print()


def main() -> None:
    if not PAYLOAD.is_dir():
        print(f"payload directory missing: {PAYLOAD}", file=sys.stderr)
        sys.exit(1)
    ip = local_ip()
    print_commands(ip)
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(PAYLOAD))
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")


if __name__ == "__main__":
    main()
