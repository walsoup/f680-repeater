#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F680 guided onboarding: factory unlock -> router-side Wi-Fi scan -> credentials
-> payload install -> repeater bring-up.

License: GNU Affero General Public License v3.0 (AGPL-3.0), because it uses the
FactoryMode handshake adapted from douniwan5788 / zte_modem_tools. The router
payload scripts and documentation are MIT; see NOTICE.
"""
import argparse
import tempfile
import getpass
import hashlib
import http.server
import os
import random
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = ROOT / "payload"
sys.path.insert(0, str(ROOT / "tools"))

try:
    import requests  # noqa: F401
    from Crypto.Cipher import AES  # noqa: F401
    from zte_factorymode import unlock_factory_telnet, DEFAULT_USERS, DEFAULT_PASSWORDS
    from diagnostics import DiagnosticCollector
except Exception as exc:  # pragma: no cover
    print(f"[-] Cannot load the onboarding dependencies: {exc}")
    print("    Install: python3 -m pip install -r requirements.txt")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Minimal Telnet client (works on Python 3.13+, where telnetlib was removed)
# ---------------------------------------------------------------------------
class Telnet:
    IAC = 255
    DONT = 254
    DO = 253
    WONT = 252
    WILL = 251
    SB = 250
    SE = 240

    def __init__(self, ip: str, timeout: float = 10.0, port: int = 23):
        self.sock = socket.create_connection((ip, port), timeout=timeout)
        self.sock.settimeout(0.3)
        self.state = 0
        self.iac_cmd = 0

    def _send_iac(self, cmd: int, opt: int = None) -> None:
        data = bytes([self.IAC, cmd])
        if opt is not None:
            data += bytes([opt])
        try:
            self.sock.sendall(data)
        except OSError:
            pass

    def _feed(self, chunk: bytes) -> bytes:
        out = bytearray()
        for b in chunk:
            if self.state == 0:
                if b == self.IAC:
                    self.state = 1
                else:
                    out.append(b)
            elif self.state == 1:
                if b in (self.WILL, self.WONT, self.DO, self.DONT):
                    self.iac_cmd = b
                    self.state = 2
                elif b == self.SB:
                    self.state = 3
                elif b == self.IAC:
                    out.append(b)
                    self.state = 0
                else:
                    self.state = 0
            elif self.state == 2:
                # Keep the pty echo (needed for the command marker), accept SGA.
                if self.iac_cmd == self.WILL:
                    if b in (1, 3):       # ECHO, SGA
                        self._send_iac(self.DO, b)
                    else:
                        self._send_iac(self.DONT, b)
                elif self.iac_cmd == self.DO:
                    if b in (1, 3):
                        self._send_iac(self.WILL, b)
                    else:
                        self._send_iac(self.WONT, b)
                self.state = 0
            elif self.state == 3:
                if b == self.IAC:
                    self.state = 4
            elif self.state == 4:
                self.state = 0 if b == self.SE else 3
        return bytes(out)

    def read(self, timeout: float = 0.5) -> str:
        end = time.time() + timeout
        out = b""
        while time.time() < end:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            out += self._feed(chunk)
        return out.decode("latin1", errors="replace")

    def read_until(self, needles, timeout: float = 10.0) -> str:
        text = ""
        end = time.time() + timeout
        while time.time() < end:
            text += self.read(0.5)
            low = text.lower()
            if any(n.lower() in low for n in needles):
                return text
        return text

    def drain(self) -> str:
        """Discard any stale unread bytes from the socket in non-blocking mode."""
        self.sock.setblocking(False)
        out = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                out += self._feed(chunk)
        except (BlockingIOError, socket.error):
            pass
        finally:
            self.sock.setblocking(True)
            self.sock.settimeout(0.3)
        return out.decode("latin1", errors="replace")

    def read_until_count(self, marker: str, count: int, timeout: float = 30.0) -> str:
        text = ""
        end = time.time() + timeout
        while time.time() < end:
            text += self.read(0.2)
            if text.count(marker) >= count:
                parts = text.split(marker)
                if "#" in parts[-1] or "$" in parts[-1]:
                    return text
                text += self.read(0.1)
                return text
        return text

    def send(self, line: str) -> None:
        self.sock.sendall(line.encode("latin1", errors="replace") + b"\r\n")

    def login(self, user: str, password: str) -> str:
        prompt = self.read_until(["login:"], 10)
        if "login:" not in prompt.lower():
            raise RuntimeError("no login prompt (port 23 may be closed)")
        self.send(user)
        pw_prompt = self.read_until(["password:"], 10)
        if "password:" not in pw_prompt.lower():
            raise RuntimeError("no password prompt")
        self.send(password)
        shell = self.read_until(["#", "$"], 10)
        if "#" not in shell and "$" not in shell:
            raise RuntimeError("login failed (no root prompt)")
        return shell

    def cmd(self, command: str, timeout: float = 30.0) -> str:
        self.drain()
        # Marker uses letters G-Z so it never contains hex or decimal digits
        marker = "__END_" + "".join(random.choice("GHIJKLMNOPQRSTUVWXYZ") for _ in range(10)) + "__"
        self.send(command)
        self.send("echo %s" % marker)
        raw = self.read_until_count(marker, 2, timeout)
        return clean_cmd_output(raw, command, marker)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Temporary HTTP server for payload + one-time ephemeral files
# ---------------------------------------------------------------------------
class PayloadHandler(http.server.BaseHTTPRequestHandler):
    routes: Dict[str, bytes] = {}
    one_shot: Set[str] = set()

    def do_GET(self) -> None:
        data = None
        path = self.path.split("?")[0]
        if path.startswith("/payload/"):
            name = os.path.basename(path)
            f = PAYLOAD / name
            if f.is_file():
                data = f.read_bytes()
        elif path in self.routes:
            data = self.routes[path]
            if path in self.one_shot:
                # Wipe from memory immediately after serving
                del self.routes[path]

        if data is None:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def shq(value: str) -> str:
    """Single-quote a value for /bin/sh (no newlines allowed)."""
    return "'" + value.replace("'", "'\\''") + "'"


def tcp_ok(ip: str, port: int = 80, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def local_ip(router_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def verify_local_payload_checksums() -> None:
    """Layer A: Verify local payload files against tools/checksums.txt."""
    checksums_file = ROOT / "tools" / "checksums.txt"
    if not checksums_file.is_file():
        raise RuntimeError("Missing tools/checksums.txt in repository")

    for line in checksums_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        expected_hash, rel_path = parts[0], parts[1]
        target_file = ROOT / rel_path
        if not target_file.is_file():
            raise RuntimeError(f"Missing required payload file: {rel_path}")
        computed_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
        if computed_hash.lower() != expected_hash.lower():
            raise RuntimeError(
                f"Payload checksum mismatch for {rel_path}!\n"
                f"  Expected: {expected_hash}\n"
                f"  Computed: {computed_hash}\n"
                "Re-clone the repo or restore original files."
            )


def clean_cmd_output(raw_text: str, command: str, marker: Optional[str] = None) -> str:
    """
    Clean raw telnet session transcript for a command:
    - Normalizes \r\r\n and \r\n to \n.
    - Strips end-of-command marker and trailing shell prompt (/ # , # , etc.),
      even when the command output has no trailing newline (e.g. 01/ #  or 01__MARKER__).
    - Strips leading echoed command line, accounting for leading prompts (/ # )
      and terminal line wrapping across lines.
    - Strips echoed sentinel/marker command line (echo <marker>).
    - Preserves internal stdout newlines and content.
    """
    text = raw_text.replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")

    # 1. End boundary: locate the last occurrence of the marker
    if marker:
        idx = text.rfind(marker)
        if idx != -1:
            text = text[:idx]

    # 2. Strip trailing prompt (/ #, #, $, or [path] #) and trailing whitespace/newlines
    while True:
        prompt_pattern = r"(?:\n)?(?:~|/[\w/.-]*|\b)?\s*[#$]\s*$"
        t_new = re.sub(prompt_pattern, "", text).rstrip("\n")
        if t_new == text:
            break
        text = t_new

    # 3. Helper to strip a single command echo, including terminal line-wraps
    def _strip_one_cmd(t: str, cmd: str) -> str:
        while True:
            t_new = re.sub(r"^(?:~|/[\w/.-]*|\b)?\s*[#$]\s*", "", t.lstrip("\n"))
            if t_new == t:
                break
            t = t_new
        c_clean = cmd.strip()
        if not c_clean:
            return t
        if t.startswith(c_clean):
            t = t[len(c_clean):]
            return t.lstrip("\n")
        # Match character-by-character allowing line-breaks injected by PTY wrapping
        i = 0
        j = 0
        while i < len(c_clean) and j < len(t):
            if t[j] == c_clean[i]:
                i += 1
                j += 1
            elif t[j] in "\n\x00":
                j += 1
            elif c_clean[i] == " " and t[j] == "\n":
                i += 1
                j += 1
            else:
                break
        if i == len(c_clean):
            t = t[j:]
            return t.lstrip("\n")
        return t

    text = _strip_one_cmd(text, command)
    if marker:
        text = _strip_one_cmd(text, f"echo {marker}")

    # Strip any residual prompt before stdout starts
    while True:
        t_new = re.sub(r"^(?:~|/[\w/.-]*|\b)?\s*[#$]\s*", "", text.lstrip("\n"))
        if t_new == text:
            break
        text = t_new

    return text.strip("\n")


def parse_kernel_hex_address(output: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Extract a 0x-prefixed 8-hex-digit kernel address (>= 0x80000000).
    Returns (address_int, error_message).
    """
    found_any = None
    for line in output.splitlines():
        line = line.strip()
        m = re.search(r"\b0x([0-9a-fA-F]{8})\b", line)
        if m:
            val = int(m.group(1), 16)
            if val >= 0x80000000:
                return val, None
            found_any = val
    if found_any is not None:
        return None, f"Address 0x{found_any:08x} outside kernel space (< 0x80000000)"
    return None, "No 0x-prefixed 8-hex-digit address found"


def parse_cg_readback(output: str) -> Tuple[Optional[str], str]:
    """
    Parse cg_hdswitch_on byte from kmemtool read output.
    Returns (hex_byte, raw_or_error_token).
    hex_byte is '00' or '01' if valid 2-hex-digit readback found, else None.
    raw_or_error_token is the exact error code (e.g. Rfffffff2) or cleaned output.
    """
    cg_val = None
    err_token = None
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^[0-9a-fA-F]{2}$", line):
            cg_val = line.lower()
            break
        if re.match(r"^[OLRW][0-9a-fA-F]+", line) and not err_token:
            err_token = line

    raw_token = cg_val or err_token or output.strip() or "<empty>"
    return cg_val, raw_token


def parse_module_info(output: str, module_name: str = "mt7615_ap") -> Optional[str]:
    """Extract kernel module line from /proc/modules output, ignoring echoed commands."""
    prefix = module_name + " "
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            return line
    return None


def parse_kernel_version(output: str) -> Optional[str]:
    """Extract Linux version string from /proc/version output."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Linux version "):
            return line
    return None


def parse_verify_kmem(output: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """
    Parse text and jt0 addresses from eap_ttls --verify-kmem output.
    Returns (text_addr, jt0_addr, error_message).
    """
    m_t = re.search(r"\btext:\s*0x([0-9a-fA-F]{8})\b", output)
    m_j = re.search(r"\bjt0:\s*0x([0-9a-fA-F]{8})\b", output)
    if not m_t or not m_j:
        return None, None, "Could not find text: 0x... or jt0: 0x... in output"
    t_val = int(m_t.group(1), 16)
    j_val = int(m_j.group(1), 16)
    if t_val < 0x80000000 or j_val < 0x80000000:
        return None, None, f"Addresses outside kernel space: text=0x{t_val:08x}, jt0=0x{j_val:08x}"
    return t_val, j_val, None


def parse_df_free_kb(output: str) -> Optional[int]:
    """Parse available free 1K-blocks for /userconfig from BusyBox df -k."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("df ") or line.startswith("Filesystem "):
            continue
        parts = line.split()
        if "/userconfig" in parts:
            idx = parts.index("/userconfig")
            nums = [int(p) for p in parts[:idx] if p.isdigit()]
            if len(nums) >= 3:
                return nums[2]  # Available is 3rd numeric column
            elif len(nums) == 2:
                return nums[1]
            elif len(nums) == 1:
                return nums[0]
    return None


def parse_ls_size(output: str, path: str) -> Optional[int]:
    """Parse file byte size from BusyBox ls -l output."""
    basename = os.path.basename(path)
    for line in output.splitlines():
        line = line.strip()
        if not re.match(r"^[-ldcbps][rwxstST-]{9}\s+", line):
            continue
        if basename in line:
            parts = line.split()
            # -rwxr-xr-x 1 root root 1085536 Jan 1 00:00 /userconfig/eap_ttls
            if len(parts) >= 5 and parts[4].isdigit():
                return int(parts[4])
    return None


def parse_restore_status(restore_out: str, verify_out: str) -> Tuple[bool, str]:
    """
    Validate the execution output of restore_after_boot.sh and verify_repeater.sh.
    Returns (True, "OK") on success, or (False, error_summary).
    """
    # 1. Check repeater_up exit code in restore output
    if "repeater_up_rc=0" not in restore_out:
        m = re.search(r"repeater_up_rc=(\d+)", restore_out)
        rc = m.group(1) if m else "unknown"
        return False, f"restore_after_boot: repeater_up.sh failed with exit code {rc}."

    # 2. Check for STATUS: OK in verify output
    if "STATUS: OK" not in verify_out:
        if "STATUS: FAILED" in verify_out:
            errors = [line.strip() for line in verify_out.splitlines() if line.strip().startswith("ERROR:")]
            if errors:
                return False, f"verify_repeater: {errors[0]}"
            return False, "verify_repeater reported STATUS: FAILED."
        return False, "verify_repeater output missing STATUS: OK."

    # 3. Check for IP and default route failure markers
    if "ERROR: apcli0 has no IPv4 address assigned" in verify_out:
        return False, "verify_repeater: apcli0 has no IPv4 address assigned."
    if "ERROR: default route via apcli0 not found" in verify_out:
        return False, "verify_repeater: default route via apcli0 not found."

    return True, "OK"


def parse_scan(text: str):
    """Parse the fixed-width wlandiagcli scan 1 table."""
    rows = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if len(line) < 80:
            continue
        ssid = line[0:35].rstrip()
        bssid = line[35:60].strip()
        if not re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", bssid):
            continue
        sig = line[60:70].strip()
        ch = line[70:80].strip()
        sec = line[80:].strip().split()[0] if line[80:].strip() else ""
        if not ch.isdigit():
            continue
        if not ssid:
            ssid = "<hidden>"
        rows.append({"ssid": ssid, "bssid": bssid, "signal": sig,
                     "channel": ch, "security": sec})
    return rows


def group_networks(rows):
    """One row per SSID, preferring WPA2-PSK-AES and the strongest signal."""
    best = {}
    for r in rows:
        sec = r["security"]
        try:
            sig = int(re.sub(r"[^0-9-]", "", r["signal"]) or -999)
        except ValueError:
            sig = -999
        pref = 1000 if "WPA2-PSK-AES" in sec else 0
        score = pref + sig
        key = r["ssid"]
        if key not in best or score > best[key][0]:
            best[key] = (score, r)
    return [v[1] for v in best.values()]


def print_networks(nets, enterprise_mode: bool = False) -> None:
    print()
    print(f"  {'#':>3}  {'SSID':<32} {'BSSID':<18} {'Signal':>7}  {'Ch':>3}  Security")
    print("  " + "-" * 86)
    for i, n in enumerate(nets, 1):
        print(f"  {i:>3}  {n['ssid'][:32]:<32} {n['bssid']:<18} "
              f"{n['signal']:>7}  {n['channel']:>3}  {n['security']}")
    print()
    if enterprise_mode:
        print("  [*] Note: ZTE firmware often displays WPA2-Enterprise APs as 'No Security'")
        print("      in the Security column above. Select your network number as normal.\n")


def start_server(port: int, routes: Dict[str, bytes], one_shot: Set[str]):
    PayloadHandler.routes = routes
    PayloadHandler.one_shot = one_shot
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", port), PayloadHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def find_port(start: int = 8124) -> int:
    for port in range(start, start + 20):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free TCP port near 8124")


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        prog="start-repeater",
        description="ZTE ZXHN F680 standalone repeater / bridge onboarding tool."
    )
    ap.add_argument("--ip", default="192.168.12.1",
                    help="router LAN IP (default: 192.168.12.1)")
    ap.add_argument("--serial", default=None,
                    help="GPON serial from the label (ZTEG...); used as a factory/root fallback")
    ap.add_argument("--factory-pass", default=None,
                    help="factorymode backdoor password (defaults to known ZTE keys like nE%%jA@5b)")
    ap.add_argument("--scan-only", action="store_true",
                    help="unlock + print the router-side 5G scan, do not install")
    ap.add_argument("--restore", action="store_true",
                    help="unlock + run /userconfig/restore_after_boot.sh, then exit")
    ap.add_argument("--ssid", default=None, help="non-interactive SSID")
    ap.add_argument("--bssid", default=None, help="non-interactive BSSID")
    ap.add_argument("--channel", default=None, help="non-interactive channel")
    ap.add_argument("--psk", default=None, help="non-interactive PSK (avoid; use interactive prompt)")

    # Enterprise support flags (low-key opt-in)
    ap.add_argument("--enterprise", action="store_true",
                    help="enable WPA2-Enterprise (EAP-TTLS/PAP) client mode")
    ap.add_argument("--eap-identity", default=None,
                    help="WPA2-Enterprise username / inner identity (implies --enterprise)")
    ap.add_argument("--eap-password", default=None,
                    help="WPA2-Enterprise password (optional; securely prompted if omitted)")
    ap.add_argument("--eap-anon-identity", default=None,
                    help="optional outer anonymous identity for EAP-TTLS")
    ap.add_argument("--eap-ca", default=None,
                    help="path to local PEM root CA certificate for RADIUS server verification")
    ap.add_argument("--tls12-only", action="store_true",
                    help="restrict EAP-TTLS strictly to TLS 1.2")

    args = ap.parse_args()

    if args.eap_identity:
        args.enterprise = True

    diag = DiagnosticCollector("init", "Onboarding started")

    print()
    print("ZTE ZXHN F680 Standalone Repeater Onboarding")
    print("============================================")
    if args.enterprise:
        print("[Mode: WPA2-Enterprise (EAP-TTLS/PAP)]")
    print("Connect this computer to the F680's 2.4 GHz Wi-Fi or a LAN port.")
    print("The default LAN here is 192.168.12.1. If your F680 is still on the")
    print("ZTE factory default 192.168.1.1, pass --ip 192.168.1.1 only when you")
    print("are sure it is the F680, not the upstream AP.")
    print()

    # Layer A: Local Pre-Check
    print("[*] Layer A: Verifying local payload integrity (sha256) ...")
    try:
        verify_local_payload_checksums()
        print("[+] Local payload integrity verified.")
    except Exception as exc:
        diag.stage = "local_checksum"
        diag.summary = str(exc)
        diag.print_failure_screen()
        sys.exit(1)

    ip = args.ip
    if not tcp_ok(ip, 80):
        diag.stage = "router_reachability"
        diag.summary = f"No web UI found at http://{ip}/ (port 80 unreachable)."
        diag.print_failure_screen()
        sys.exit(1)

    serial = args.serial
    if serial is None:
        try:
            serial = input("Router GPON serial (ZTEG... on label; Enter if unknown): ").strip()
        except (EOFError, KeyboardInterrupt):
            serial = ""
    serial = serial.strip().upper()
    if serial:
        diag.add_secret(serial)

    print()
    tn = None
    creds_cache_file = Path(tempfile.gettempdir()) / "f680_telnet_creds.txt"
    if tcp_ok(ip, 23):
        candidates = []
        if creds_cache_file.is_file():
            try:
                parts = creds_cache_file.read_text().strip().split()
                if len(parts) >= 2:
                    candidates.append((parts[0], parts[1]))
            except Exception:
                pass
        for cu, cp in candidates:
            try:
                test_tn = Telnet(ip, timeout=3.0)
                test_tn.login(cu, cp)
                tn = test_tn
                creds = (cu, cp)
                print(f"[+] Telnet port 23 already open; logged in with cached credentials (user {cu}).")
                break
            except Exception:
                pass

    if tn is None:
        print(f"[*] Unlocking factory telnet on {ip} ...")
        if args.factory_pass:
            passwords = [args.factory_pass]
        else:
            passwords = list(DEFAULT_PASSWORDS)
            if serial and serial not in passwords:
                passwords.append(serial)

        creds = unlock_factory_telnet(ip, 80, users=DEFAULT_USERS, passwords=passwords, verbose=False)
        if not creds:
            print("[-] Default factory passwords did not work.")
            try:
                factory_pw = getpass.getpass("Factory password (optional; press Enter to skip): ")
            except (EOFError, KeyboardInterrupt):
                factory_pw = ""
            if factory_pw:
                diag.add_secret(factory_pw)
                creds = unlock_factory_telnet(ip, 80, users=DEFAULT_USERS, passwords=[factory_pw], verbose=False)

        if not creds:
            diag.stage = "factory_unlock"
            diag.summary = "FactoryMode telnet unlock failed (timed out, rate-limited, or incorrect password)."
            diag.print_failure_screen()
            sys.exit(1)

        t_user, t_pass = creds
        print(f"[+] Root telnet unlocked (user {t_user}).")
        try:
            creds_cache_file.write_text(f"{t_user} {t_pass}\n")
            creds_cache_file.chmod(0o600)
        except Exception:
            pass

        tn = Telnet(ip)
        try:
            tn.login(t_user, t_pass)
        except Exception as exc:
            diag.stage = "telnet_login"
            diag.summary = f"Telnet login failed: {exc}"
            diag.print_failure_screen()
            sys.exit(1)
    print("[+] Root shell ready.")

    # Layer B: Router Preflight & Free Space Check
    print("[*] Layer B: Checking router kernel modules and flash storage ...")
    v_out = tn.cmd("cat /proc/version", timeout=10)
    k_ver = parse_kernel_version(v_out)
    if k_ver:
        diag.kernel_version = k_ver

    mod_out = tn.cmd("grep mt7615_ap /proc/modules 2>/dev/null", timeout=10)
    m_info = parse_module_info(mod_out, "mt7615_ap")
    if m_info:
        diag.module_info = m_info

    sec_out = tn.cmd("[ -f /sys/module/mt7615_ap/sections/.bss ] && [ -f /sys/module/mt7615_ap/sections/.text ] && echo __SECTIONS_OK__", timeout=10)
    if "__SECTIONS_OK__" not in sec_out:
        diag.stage = "router_preflight"
        diag.summary = "mt7615_ap kernel module sections (.bss / .text) not found. 5 GHz Wi-Fi driver is not active."
        diag.recent_logs = sec_out
        diag.print_failure_screen()
        tn.close()
        sys.exit(1)

    df_out = tn.cmd("df -k /userconfig", timeout=10)
    free_kb = parse_df_free_kb(df_out)
    diag.free_kb = free_kb
    required_kb = 2800 if args.enterprise else 1500
    if free_kb is not None and free_kb < required_kb:
        diag.stage = "router_preflight"
        diag.summary = f"Insufficient flash memory on /userconfig: {free_kb} KB free (required >= {required_kb} KB)."
        diag.recent_logs = df_out
        diag.print_failure_screen()
        tn.close()
        sys.exit(1)

    print(f"[+] Preflight passed: mt7615_ap active, {free_kb} KB available on /userconfig.")

    if args.restore:
        print("[*] Running restore_after_boot.sh ...")
        out = tn.cmd("sh /userconfig/restore_after_boot.sh; echo __RESTORE_RC=$?__; "
                     "cat /userconfig/restore_after_boot.out", timeout=120)
        print(out)
        print("[*] Running verify_repeater.sh post-restore check ...")
        vf_out = tn.cmd("sh /userconfig/verify_repeater.sh; echo __VERIFY_RC=$?__; "
                        "cat /userconfig/verify_repeater.out", timeout=45)
        print(vf_out)
        diag.recent_logs = out + "\n" + vf_out

        ok, err_summary = parse_restore_status(out, vf_out)
        if not ok:
            diag.stage = "restore_verification"
            diag.summary = err_summary
            diag.print_failure_screen()
            tn.close()
            sys.exit(1)

        print("[+] Restore completed successfully: repeater link and NAT confirmed OK.")
        tn.close()
        return

    print("[*] Scanning 5G from the router ...")
    scan_out = tn.cmd("wlandiagcli scan 1", timeout=35)
    rows = parse_scan(scan_out)
    nets = group_networks(rows)
    if not nets:
        print("[-] No parsable 5G networks found. The F680's client radio is 5 GHz only;")
        print("    a 2.4 GHz-only upstream cannot be used.")
        if args.scan_only:
            tn.close()
            return
        if args.ssid:
            chosen = {"ssid": args.ssid, "bssid": args.bssid or "",
                      "channel": args.channel or "", "security": "manual"}
        else:
            print("Enter the network manually (leave BSSID/channel empty to scan):")
            ssid = input("SSID: ").strip()
            if not ssid:
                diag.stage = "wifi_scan"
                diag.summary = "No SSID provided during manual network entry."
                diag.print_failure_screen()
                tn.close()
                sys.exit(1)
            chosen = {"ssid": ssid, "bssid": input("BSSID (optional): ").strip(),
                       "channel": input("Channel (optional): ").strip(),
                       "security": "manual"}
    else:
        print_networks(nets, enterprise_mode=args.enterprise)
        if args.scan_only:
            tn.close()
            return
        if args.ssid:
            chosen = {"ssid": args.ssid, "bssid": args.bssid or "", "channel": args.channel or ""}
            for n in nets:
                if n["ssid"] == args.ssid:
                    chosen = n
                    break
        else:
            while True:
                raw = input("Select network number: ").strip()
                if raw.isdigit() and 1 <= int(raw) <= len(nets):
                    chosen = nets[int(raw) - 1]
                    break
                print("  enter a number from the list")

    diag.add_secret(chosen.get("ssid"))
    diag.add_secret(chosen.get("bssid"))

    # Credential collection
    routes: Dict[str, bytes] = {}
    one_shot: Set[str] = set()

    if args.enterprise:
        eap_identity = args.eap_identity
        if not eap_identity:
            try:
                eap_identity = input(f"Enterprise identity / username for {chosen['ssid']}: ").strip()
            except (EOFError, KeyboardInterrupt):
                eap_identity = ""
        if not eap_identity:
            diag.stage = "association"
            diag.summary = "WPA2-Enterprise identity is required but was left empty."
            diag.print_failure_screen()
            tn.close()
            sys.exit(1)
        diag.add_secret(eap_identity)

        eap_password = args.eap_password
        if eap_password is None:
            try:
                eap_password = getpass.getpass(f"Enterprise password for {eap_identity}: ")
            except (EOFError, KeyboardInterrupt):
                eap_password = ""
        if not eap_password:
            diag.stage = "association"
            diag.summary = "WPA2-Enterprise password is required but was left empty."
            diag.print_failure_screen()
            tn.close()
            sys.exit(1)
        diag.add_secret(eap_password)

        eap_anon_id = args.eap_anon_identity
        if eap_anon_id:
            diag.add_secret(eap_anon_id)

        ca_path = args.eap_ca
        if ca_path is None and not args.eap_identity:
            try:
                ca_path_input = input("Path to root CA certificate (.pem) [press Enter to skip CA verification]: ").strip()
            except (EOFError, KeyboardInterrupt):
                ca_path_input = ""
            ca_path = ca_path_input if ca_path_input else None

        ca_bytes = b""
        if ca_path:
            ca_p = Path(ca_path).expanduser().resolve()
            if not ca_p.is_file():
                diag.stage = "association"
                diag.summary = f"Root CA certificate not found at: {ca_path}"
                diag.print_failure_screen()
                tn.close()
                sys.exit(1)
            ca_text = ca_p.read_text(encoding="utf-8", errors="replace")
            pem_header = "-----BEGIN " + "CERTIFICATE-----"
            if pem_header not in ca_text:
                diag.stage = "association"
                diag.summary = f"Invalid PEM CA certificate: '{ca_path}' lacks '{pem_header}'."
                diag.print_failure_screen()
                tn.close()
                sys.exit(1)
            ca_bytes = ca_p.read_bytes()

        # Ephemeral routes for sensitive enterprise files
        pass_token = secrets.token_hex(16)
        routes[f"/pass-{pass_token}.bin"] = eap_password.encode("utf-8")
        one_shot.add(f"/pass-{pass_token}.bin")

        ca_token = secrets.token_hex(16)
        if ca_bytes:
            routes[f"/ca-{ca_token}.pem"] = ca_bytes
            one_shot.add(f"/ca-{ca_token}.pem")

        cfg_content = (
            f"UP_AUTH='wpa2-eap'\n"
            f"UP_SSID={shq(chosen['ssid'])}\n"
            f"UP_PSK=''\n"
            f"UP_BSSID={shq(chosen['bssid'])}\n"
            f"UP_CHANNEL={shq(chosen['channel'])}\n"
            f"UP_EAP_IDENTITY={shq(eap_identity)}\n"
            f"UP_EAP_ANON_ID={shq(eap_anon_id or '')}\n"
            f"UP_EAP_CA={shq('/userconfig/eap_ca.pem' if ca_bytes else '')}\n"
            f"UP_EAP_TLS12_ONLY={'1' if args.tls12_only else '0'}\n"
        )
    else:
        psk = args.psk
        if psk is None:
            try:
                psk = getpass.getpass(
                    f"Wi-Fi password for {chosen['ssid']} (press Enter for Open AP): ")
            except (EOFError, KeyboardInterrupt):
                psk = ""
        if psk:
            diag.add_secret(psk)
        else:
            sec = str(chosen.get("security", "") or "")
            if "OPEN" in sec.upper() or sec in ("", "manual"):
                print("[*] Empty password: joining as Open / captive-portal (no WPA2 key).")
            else:
                ok = input(f"Security shows '{sec}' but the password is empty; "
                           "join as Open anyway? [y/N]: ").strip().lower()
                if ok != "y":
                    diag.stage = "association"
                    diag.summary = "Empty password provided for encrypted network."
                    diag.print_failure_screen()
                    tn.close()
                    sys.exit(1)

        cfg_content = (
            f"UP_AUTH={'wpa2-psk' if psk else 'open'}\n"
            f"UP_SSID={shq(chosen['ssid'])}\n"
            f"UP_PSK={shq(psk)}\n"
            f"UP_BSSID={shq(chosen['bssid'])}\n"
            f"UP_CHANNEL={shq(chosen['channel'])}\n"
        )

    conf_token = secrets.token_hex(16)
    routes[f"/cfg-{conf_token}.conf"] = cfg_content.encode("utf-8")
    one_shot.add(f"/cfg-{conf_token}.conf")

    port = find_port(8124)
    httpd = start_server(port, routes, one_shot)
    host_ip = local_ip(ip)
    base = f"http://{host_ip}:{port}"
    print(f"[*] Payload server: {base}/")

    # Layer C: Verified Upload & Driver Fingerprint Guard
    print("[*] Layer C: Uploading payload and verifying driver offsets ...")
    base_files = ["kmemtool", "udhcpc", "udhcpc.script", "repeater_up.sh",
                  "restore_after_boot.sh", "verify_repeater.sh"]
    if args.enterprise:
        files = base_files + ["eap_ttls", "f680_rsn_patch.ko"]
    else:
        files = base_files

    def upload_file(remote_path: str, url_token: str, expected_size: int, mode: str = "755") -> bool:
        """Upload data to router via HTTP wget and strictly verify byte size."""
        fname = os.path.basename(remote_path)
        out = tn.cmd(f"ls -l {remote_path} 2>/dev/null", timeout=10)
        actual_size = parse_ls_size(out, remote_path)
        if actual_size == expected_size:
            print(f"    {fname}: verified ({expected_size} bytes)")
            return True

        cmd = f"wget -q -O {remote_path} {base}/{url_token} && chmod {mode} {remote_path}; ls -l {remote_path}"
        out = tn.cmd(cmd, timeout=30)
        actual_size = parse_ls_size(out, remote_path)
        if actual_size == expected_size:
            print(f"    {fname}: uploaded and verified ({actual_size} bytes)")
            return True
        return False

    for fname in files:
        expected_size = (PAYLOAD / fname).stat().st_size
        remote_path = f"/userconfig/{fname}"
        if not upload_file(remote_path, f"payload/{fname}", expected_size, mode="755"):
            diag.stage = "upload_verification"
            diag.summary = f"Byte size mismatch for {fname}."
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)

    # Flush payload binaries and scripts to JFFS2 flash
    tn.cmd("sync", timeout=10)

    # Upload configuration and secrets via HTTP
    conf_bytes = cfg_content.encode("utf-8")
    conf_token = secrets.token_hex(8)
    routes[f"/cfg-{conf_token}.conf"] = conf_bytes
    one_shot.add(f"/cfg-{conf_token}.conf")
    cmd = (f"wget -q -O /userconfig/upstream.conf {base}/cfg-{conf_token}.conf && "
           f"chmod 600 /userconfig/upstream.conf; ls -l /userconfig/upstream.conf")
    out = tn.cmd(cmd, timeout=20)
    actual_size = parse_ls_size(out, "/userconfig/upstream.conf")
    if actual_size != len(conf_bytes):
        diag.stage = "upload_verification"
        diag.summary = "Failed to upload /userconfig/upstream.conf."
        diag.print_failure_screen()
        tn.close()
        httpd.shutdown()
        sys.exit(1)
    print(f"    upstream.conf: verified ({actual_size} bytes)")

    if args.enterprise:
        pass_bytes = eap_password.encode("utf-8")
        pass_token = secrets.token_hex(8)
        routes[f"/pass-{pass_token}.bin"] = pass_bytes
        one_shot.add(f"/pass-{pass_token}.bin")
        cmd = (f"wget -q -O /userconfig/eap_pass {base}/pass-{pass_token}.bin && "
               f"chmod 600 /userconfig/eap_pass; ls -l /userconfig/eap_pass")
        out = tn.cmd(cmd, timeout=20)
        actual_size = parse_ls_size(out, "/userconfig/eap_pass")
        if actual_size != len(pass_bytes):
            diag.stage = "upload_verification"
            diag.summary = "Failed to upload /userconfig/eap_pass."
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)
        print(f"    eap_pass: verified ({actual_size} bytes)")

        if ca_bytes:
            ca_token = secrets.token_hex(8)
            routes[f"/ca-{ca_token}.pem"] = ca_bytes
            one_shot.add(f"/ca-{ca_token}.pem")
            cmd = (f"wget -q -O /userconfig/eap_ca.pem {base}/ca-{ca_token}.pem && "
                   f"chmod 644 /userconfig/eap_ca.pem; ls -l /userconfig/eap_ca.pem")
            out = tn.cmd(cmd, timeout=20)
            actual_size = parse_ls_size(out, "/userconfig/eap_ca.pem")
            if actual_size != len(ca_bytes):
                diag.stage = "upload_verification"
                diag.summary = "Failed to upload /userconfig/eap_ca.pem."
                diag.print_failure_screen()
                tn.close()
                httpd.shutdown()
                sys.exit(1)
            print(f"    eap_ca.pem: verified ({actual_size} bytes)")
    else:
        # Clean any stale enterprise credentials and helper module on PSK/Open
        tn.cmd("rm -f /userconfig/eap_pass /userconfig/eap_ca.pem "
               "/userconfig/f680_rsn_patch.ko 2>/dev/null", timeout=10)

    # Flush configuration, credentials, and CA certificate to JFFS2 flash
    tn.cmd("sync", timeout=10)

    # Driver Fingerprint Guard: verify cg_hdswitch_on offset
    bss_out = tn.cmd("cat /sys/module/mt7615_ap/sections/.bss 2>/dev/null", timeout=10)
    bss_addr, bss_err = parse_kernel_hex_address(bss_out)
    if bss_addr is None:
        diag.stage = "driver_fingerprint"
        diag.summary = f"Failed to read mt7615_ap .bss section base address: {bss_err} (raw: '{bss_out.strip()}')."
        diag.recent_logs = bss_out
        diag.print_failure_screen()
        tn.close()
        httpd.shutdown()
        sys.exit(1)
    bss_hex = f"{bss_addr:08x}"

    cg_out = tn.cmd(f"/userconfig/kmemtool /dev/kmem {bss_hex} f1c r", timeout=10)
    cg_val, cg_token = parse_cg_readback(cg_out)
    diag.cg_readback = cg_token
    if cg_val not in ("00", "01"):
        diag.stage = "driver_fingerprint"
        diag.summary = f"cg_hdswitch_on readback at .bss+0xf1c returned '{cg_token}' (expected '00' or '01'). Unsupported mt7615 driver build."
        diag.recent_logs = cg_out
        diag.print_failure_screen()
        tn.close()
        httpd.shutdown()
        sys.exit(1)

    # In enterprise mode, verify eap_ttls driver structure compatibility before association
    if args.enterprise:
        # WPAMakeRSNIE+0xf8 (0x90e08) and ApCliMlmeAssocReqAction+0x29c (0x4b91c)
        # must hold the stock 0x90 or already-patched 0xd0.
        text_out = tn.cmd("cat /sys/module/mt7615_ap/sections/.text 2>/dev/null", timeout=10)
        text_addr, text_err = parse_kernel_hex_address(text_out)
        if text_addr is None:
            diag.stage = "driver_fingerprint"
            diag.summary = (f"Failed to read mt7615_ap .text section base address: "
                            f"{text_err} (raw: '{text_out.strip()}').")
            diag.recent_logs = text_out
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)
        text_hex = f"{text_addr:08x}"
        rsn1_out = tn.cmd(
            f"/userconfig/kmemtool /dev/kmem {text_hex} 90e08 r", timeout=10)
        rsn1_val, rsn1_token = parse_cg_readback(rsn1_out)
        if rsn1_val not in ("90", "d0"):
            diag.stage = "driver_fingerprint"
            diag.summary = (
                f"WPAMakeRSNIE+0xf8 readback at .text+0x90e08 returned "
                f"'{rsn1_token}' (expected '90' or 'd0'). Unsupported mt7615 "
                f"driver build.")
            diag.recent_logs = rsn1_out
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)
        print(f"[+] WPAMakeRSNIE+0xf8 readback: {rsn1_val} (expected 90 or d0).")

        rsn2_out = tn.cmd(
            f"/userconfig/kmemtool /dev/kmem {text_hex} 4b91c r", timeout=10)
        rsn2_val, rsn2_token = parse_cg_readback(rsn2_out)
        if rsn2_val not in ("90", "d0"):
            diag.stage = "driver_fingerprint"
            diag.summary = (
                f"ApCliMlmeAssocReqAction+0x29c readback at .text+0x4b91c returned "
                f"'{rsn2_token}' (expected '90' or 'd0'). Unsupported mt7615 "
                f"driver build.")
            diag.recent_logs = rsn2_out
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)
        print(f"[+] ApCliMlmeAssocReqAction+0x29c readback: {rsn2_val} (expected 90 or d0).")

        rsn3_out = tn.cmd(
            f"/userconfig/kmemtool /dev/kmem {text_hex} 11ca57 r", timeout=10)
        rsn3_val, rsn3_token = parse_cg_readback(rsn3_out)
        if rsn3_val not in ("1a", "ea"):
            diag.stage = "driver_fingerprint"
            diag.summary = (
                f"PMF_MakeRsnIeGMgmtCipher+0x5b readback at .text+0x11ca57 returned "
                f"'{rsn3_token}' (expected '1a' or 'ea'). Unsupported mt7615 "
                f"driver build.")
            diag.recent_logs = rsn3_out
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)
        print(f"[+] PMF_MakeRsnIeGMgmtCipher+0x5b readback: {rsn3_val} (expected 1a or ea).")

        kmem_ver = tn.cmd("/userconfig/eap_ttls --verify-kmem; echo __VERIFY_KMEM_RC=$?__", timeout=15)
        diag.kmem_diag = kmem_ver
        if "__VERIFY_KMEM_RC=0" not in kmem_ver:
            diag.stage = "driver_kmem_guard"
            diag.summary = "eap_ttls --verify-kmem failed with non-zero exit code."
            diag.recent_logs = kmem_ver
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)

        t_val, j_val, k_err = parse_verify_kmem(kmem_ver)
        if t_val is None or j_val is None:
            diag.stage = "driver_kmem_guard"
            diag.summary = f"Driver compatibility check failed: {k_err}."
            diag.recent_logs = kmem_ver
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)

        exp_from = t_val + 0x902a4
        exp_to = t_val + 0x90244
        if j_val != exp_from and j_val != exp_to:
            diag.stage = "driver_kmem_guard"
            diag.summary = f"Driver compatibility check failed: jt0=0x{j_val:08x} (expected 0x{exp_from:08x} or 0x{exp_to:08x})."
            diag.recent_logs = kmem_ver
            diag.print_failure_screen()
            tn.close()
            httpd.shutdown()
            sys.exit(1)

    print("[+] Layer C passed: payload verified, driver offsets matched.")

    # Safe boot wrapper
    tn.cmd("cp /userconfig/autorun.sh /userconfig/autorun.sh.old 2>/dev/null", timeout=10)
    autorun_bytes = (PAYLOAD / "autorun.sh").read_bytes()
    if not upload_file("/userconfig/autorun.sh", "payload/autorun.sh", len(autorun_bytes), mode="755"):
        diag.stage = "upload_verification"
        diag.summary = "Byte size mismatch for autorun.sh."
        diag.print_failure_screen()
        tn.close()
        httpd.shutdown()
        sys.exit(1)
    tn.cmd("sync", timeout=10)

    # Clean old leases
    tn.cmd("rm -f /userconfig/last_lease /userconfig/lease_ok; echo __LEASE_CLEAN__", timeout=30)

    print("[*] Associating and enabling NAT (this takes ~40 s) ...")
    out = tn.cmd("sh /userconfig/repeater_up.sh; echo __RU_RC=$?__; "
                 "cat /userconfig/repeater_boot.log", timeout=120)
    diag.recent_logs = out
    print(out)
    if "__RU_RC=0" not in out:
        diag.stage = "association"
        diag.summary = "repeater_up.sh returned non-zero exit code."
        diag.print_failure_screen()
        tn.close()
        httpd.shutdown()
        sys.exit(1)

    # Layer D: Postflight Health Check
    print("[*] Layer D: Running postflight verification (verify_repeater.sh) ...")
    vf_out = tn.cmd("sh /userconfig/verify_repeater.sh; echo __VERIFY_RC=$?__; cat /userconfig/verify_repeater.out", timeout=45)
    diag.recent_logs = vf_out
    print(vf_out)
    tn.close()
    httpd.shutdown()

    if "__VERIFY_RC=0" not in vf_out or "STATUS: FAILED" in vf_out:
        diag.stage = "postflight_verify"
        diag.summary = "verify_repeater.sh reported one or more critical check failures."
        diag.print_failure_screen()
        sys.exit(1)

    print("[+] Layer D passed: router link and NAT status confirmed OK.")

    print()
    print("[*] Client-side HTTP test from this computer ...")
    try:
        with urllib.request.urlopen("http://example.com", timeout=10) as r:
            print(f"[+] HTTP {r.status} from the client path.")
    except Exception as exc:
        print(f"[!] Host HTTP test failed: {exc}")
        print("    If this computer is on the F680 Wi-Fi/LAN, check the verify output above.")
        print("    If it is on another network, connect to the F680 and retry the client test.")
    print()
    print("[+] Done. The F680 is now operating as a routed NAT repeater.")
    print("    After a reboot, run: sh /userconfig/restore_after_boot.sh")


if __name__ == "__main__":
    main()
