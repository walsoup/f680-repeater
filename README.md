# F680 Wi-Fi repeater

Turn a ZTE ZXHN F680 (vendor firmware `ZTEGF680606MA`) into a standalone routed NAT Wi-Fi repeater. No Ethernet backhaul, no EasyMesh, no serial console, and no rootfs or raw MTD writes yet. Every runtime file lives in `/userconfig` on JFFS2 `mtd5`.

This repo holds the payloads, source code, onboarding scripts, and reverse-engineering notes.

> **Tested on:** ZTE ZXHN F680 V6.0 (`ZTEGF680V60`), firmware `ZTEGF680606MA`, Linux 4.1.25, MediaTek MT7615E (5 GHz) + MT7603E (2.4 GHz).
>
> **Use only on hardware you own.** Read [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) before touching anything persistent. No vendor firmware binaries are distributed in this repo.

## What this does

```text
upstream Wi-Fi (5 GHz, WPA2-PSK or Open)
        │
        │ apcli0
        ▼
    ZTE F680 ──[routed NAT]──► 2.4 GHz AP (wlan0) / LAN (br0)
                               192.168.12.1/24
```

* The 5 GHz radio (`apcli0`) joins an upstream AP as a normal 3-address client and pulls a DHCP lease.
* The 2.4 GHz AP (`wlan0`) and LAN bridge (`br0`) keep serving clients on `192.168.12.0/24`, so management access stays up the whole time.
* Linux forwards and NATs client traffic out `apcli0`. `apcli0` stays out of `br0`, `br0` keeps its original MAC, and `cspd` stays running.

Verified from a downstream client: DHCP, DNS, HTTP 200, and `ping 8.8.8.8` at 0% packet loss.

## The one-byte trick

The 5 GHz driver (`mt7615_ap.ko`) keeps a per-module flag called `cg_hdswitch_on`. When it is `1`, `RtmpOsPktRcvHandle` sends received APCLI frames through `vlan_rx_process` into `wifihdswitchhandler[idm]`, the IDM hardware-forward path. Because `dev+0x470` (the per-netdev IDM slot) is set to `1` (`idm1`) on AP VAPs and left zero-initialized (`idm0`, WAN/GPON) on `apcli0`, those frames vanish into `idm0` and Linux never sees them.

Writing `0` to `/proc/wifi_hdswitch/on` does nothing for 5 GHz. The 2.4 GHz `mt7603e` module owns that proc entry and only toggles its own copy. The 5 GHz copy sits at:

```text
/sys/module/mt7615_ap/sections/.bss + 0xf1c
```

Zero that byte and `RtmpOsPktRcvHandle` falls through to `skb_pull(14)` and `netif_rx(skb)`, handing `apcli0` packets to the normal Linux network stack.

`kmemtool` (a 1 KB static ARM EABI5 binary with no VFP/NEON) handles the read and write:

```sh
B7=$(cat /sys/module/mt7615_ap/sections/.bss)
/userconfig/kmemtool /dev/kmem "$B7" f1c r   # expect 01
/userconfig/kmemtool /dev/kmem "$B7" f1c w 00
```

The `.bss` base address shifts on every boot, so never hardcode it. Full disassembly, symbols, and captures are in [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md) and [`docs/PHASE12_FINDINGS.md`](docs/PHASE12_FINDINGS.md).

## Requirements and ground rules

* A ZTE F680 on firmware `ZTEGF680606MA` (earlier builds may work, but verify the `.bss` offset first).
* A laptop connected to the F680's LAN or 2.4 GHz Wi-Fi with Python 3 installed.
* An upstream 5 GHz WPA2-PSK or Open AP. A 2.4 GHz-only upstream will not work here.
* **Router IP (`--ip` flag):** The script defaults to `--ip 192.168.12.1`. Most stock F680 units use `192.168.1.1` or `192.168.11.1`. **Always pass `--ip <router-ip>`** to match your router's gateway IP.
* Optional: the router's GPON serial from the bottom label (`ZTEG...`). The script tries known ZTE factory keys first and only uses the serial as a fallback (see [`tools/factory_unlock.md`](tools/factory_unlock.md)).
* Never kill `cspd`, and leave the upstream AP config alone.
* `/userconfig/upstream.conf` is written mode `600`. Keep it out of commits, logs, and issue reports.

## Quick start

1. Clone this repository and enter the directory:

   ```bash
   git clone https://github.com/walsoup/f680-repeater.git
   cd f680-repeater
   ```

2. Connect your laptop to the F680's 2.4 GHz Wi-Fi or an Ethernet LAN port. Check your default gateway IP (usually `192.168.1.1` or `192.168.11.1`).
3. Run the onboarding script using the `--ip` flag pointing to your F680:

   ```bash
   ./start-repeater.sh --ip 192.168.1.1          # Linux/macOS (replace with your router's IP)
   start-repeater.bat --ip 192.168.1.1           # Windows
   ```

   *(Using the `--ip` flag is strongly encouraged to ensure you target the right router gateway).*

4. Enter the GPON serial if prompted (or press Enter to skip). The script unlocks factory telnet automatically using known ZTE keys, falling back to your serial or a custom factory password.
5. Pick a 5 GHz network from the router's `wlandiagcli scan 1` output and enter the Wi-Fi password (or press Enter for an Open AP).
6. The script checks local payload sha256 sums against `tools/checksums.txt`, checks that `mt7615_ap` is loaded and `/userconfig` has enough free flash, serves the payload over HTTP, verifies uploaded sizes with `ls -l`, confirms `cg_hdswitch_on` holds an expected value before poking kernel memory, sends `/userconfig/upstream.conf` over a one-time ephemeral HTTP URL (never over telnet), runs `/userconfig/repeater_up.sh`, and tests HTTP from the laptop.
7. Connect any client to the F680's 2.4 GHz AP and test.

If anything fails mid-run, `start-repeater` prints the likely cause plus a redacted Markdown report (credentials, MACs, emails, and public IPs stripped) you can paste into a GitHub issue.

**Useful flags:** `--ip <router>` (default `192.168.12.1`), `--scan-only`, `--restore` (re-runs `restore_after_boot.sh` after a reboot), `--serve-only` (manual payload server), and `--factory-pass`. Non-interactive runs take `--ssid`, `--bssid`, `--channel`, `--psk`, and `--serial`. Opt-in Enterprise flags: `--enterprise`, `--eap-identity`, `--eap-password`, `--eap-anon-identity`, `--eap-ca`, `--tls12-only`.

### Router IP and subnet management

* **Use the `--ip` flag:**
  Stock ZTE F680 units ship with factory IPs like `192.168.1.1` or `192.168.11.1` (depending on ISP firmware), whereas this development repo used `192.168.12.1`. Always specify `--ip <router-ip>` whenever running the onboarding or recovery tools.

* **Avoiding upstream subnet collisions:**
  Because the repeater operates in routed NAT mode, the F680's local subnet (`br0`) **must not overlap** with the upstream network's subnet. For example, if your upstream Wi-Fi assigns addresses in `192.168.1.0/24`, the F680's LAN cannot also be `192.168.1.0/24`.

* **How to change the F680 LAN IP permanently:**
  If you need to change your F680 subnet (e.g. to `192.168.12.1`):
  1. Open the F680 Web UI in your browser (`http://<router-ip>`, e.g., `http://192.168.1.1`).
  2. Navigate to **Local Network** / **Network** > **LAN** > **IPv4**.
  3. Change the IPv4 Address (e.g. `192.168.12.1`) and update the DHCP pool range (e.g. `192.168.12.100` – `192.168.12.200`).
  4. Click **Apply** and wait for the router to restart DHCP.
  
  > [!IMPORTANT]
  > Never change `br0`'s IP address using raw `ifconfig br0 <ip>` in telnet. The web management services (`cspd`/`httpd`) validate the database-configured IP, and raw `ifconfig` changes will cause `400 Bad Request` errors in the web UI. Always change it through the Web UI or DB commands (`sendcmd 1 DB set IPv4Address 0 IPAddress <ip>`).

## What `repeater_up.sh` does

1. Waits up to 90 s for `mt7615_ap` and `apcli0`, then pins the 5 GHz PCIe IRQ (`wlan4`) to CPU1 (`smp_affinity=2`).
2. Reads the live `.bss` address, checks that `cg_hdswitch_on` is `01` or `00`, and writes `00` only if it was `01`. Any other byte aborts without writing.
3. Scans 5 GHz if `UP_CHANNEL` is empty (retries once).
4. Associates `apcli0` as a 3-address client (`ApCliMWDS=0`), waits for EAPOL M4 (WPA2) or AssocResponse (Open), and retries once.
5. Seeds the previous lease and runs `udhcpc` with a unicast DISCOVER to the last gateway, falling back to broadcast.
6. Enables `ip_forward` and adds `MASQUERADE`, `FORWARD`, and `INPUT` rules.
7. Writes `/userconfig/repeater_boot.log`, verifies state, and leaves `udhcpc` running for renewals.

It never bridges `apcli0`, touches `br0`/`wlan0`, or starts `telnetd`.

## Manual mode and verification

Verify local payload checksums first:

```bash
sha256sum -c tools/checksums.txt
```

If you already have a root shell and want to pull the files yourself, start the local HTTP server with `./start-repeater.sh --serve-only` and run:

```sh
cd /userconfig
wget -q -O kmemtool http://<LAPTOP_IP>:8124/kmemtool
wget -q -O udhcpc http://<LAPTOP_IP>:8124/udhcpc
wget -q -O udhcpc.script http://<LAPTOP_IP>:8124/udhcpc.script
wget -q -O repeater_up.sh http://<LAPTOP_IP>:8124/repeater_up.sh
wget -q -O restore_after_boot.sh http://<LAPTOP_IP>:8124/restore_after_boot.sh
wget -q -O verify_repeater.sh http://<LAPTOP_IP>:8124/verify_repeater.sh
wget -q -O upstream.conf http://<LAPTOP_IP>:8124/upstream.conf.example
chmod +x kmemtool udhcpc udhcpc.script repeater_up.sh restore_after_boot.sh verify_repeater.sh
chmod 600 upstream.conf
vi upstream.conf
sh /userconfig/repeater_up.sh
```

Check router state with:

```sh
sh /userconfig/verify_repeater.sh
cat /userconfig/verify_repeater.out
```

Expected output:

```text
cg_hdswitch_on = 00
apcli0: 198.51.100.x/24, default via <gateway>
brctl show: no apcli0
MASQUERADE ... apcli0
```

Then test from a client on the F680's 2.4 GHz AP:

```sh
ping 8.8.8.8
curl http://example.com
```

## After a reboot

Stock firmware ignores `/userconfig/autorun.sh`. After a reboot, the 2.4 GHz LAN and management come back, while `apcli0` stays down and NAT is gone.

Bring it back from your laptop:

```bash
./start-repeater.sh --restore
```

Or from an existing root shell (takes about 40 seconds):

```sh
sh /userconfig/restore_after_boot.sh
cat /userconfig/restore_after_boot.out
```

Automatic boot persistence would require replacing `/lib/libbbx.so` on a read-only rootfs with no UART recovery, so it stays off by default. `autorun.sh` is already in `payload/` for that path, and I have started looking into it. Read [`docs/BOOT_PERSISTENCE.md`](docs/BOOT_PERSISTENCE.md) before trying a `libbbx.so` swap yourself (if you do, consider sharing).

## Hardware quirks and limitations

* **5 GHz upstream only.** Stock `mt7603e_ap.ko` (2.4 GHz) was compiled without `CONFIG_APCLI_SUPPORT` and only runs in AP mode. Only `mt7615_ap.ko` exposes `apcli0`, so the upstream link has to be 5 GHz while `br0` serves local 2.4 GHz, 5 GHz, and Ethernet clients.
* **Bogus `apcli0` drop counter.** `/proc/net/dev` and `ifconfig apcli0` show an uninitialized `rx_dropped` value around 3.3 billion that fluctuates up and down. That is a `mt7615_ap.ko` driver stats bug, not real packet loss.
* **SMP IRQ contention.** On this dual-core Cortex-A9, both radios and Ethernet default to CPU0. `repeater_up.sh` moves the 5 GHz PCIe interrupt (`wlan4`) to CPU1 (`smp_affinity=2`) so it stops fighting `wlan0` and Ethernet under load.
* **Fixed APCLI MAC.** `ifconfig hw ether` is ignored by the driver.
* **Test from a client, not the router.** Router-origin ICMP and DNS are unreliable.
* **Firmware-specific offsets.** Built for `ZTEGF680606MA` / Linux 4.1.25. Other builds need their symbols and offsets checked first.
* **5 GHz AP SSIDs.** Setting `cg=0` sends all 5 GHz RX through `netif_rx`. Local 5 GHz AP SSIDs should keep working, though you should test them if you rely on them.

Full list in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Troubleshooting

### `cg_hdswitch_on` is neither `01` nor `00`

The module is not ready or the offset does not match your firmware. Do not write to `/dev/kmem`. Check:

```sh
cat /sys/module/mt7615_ap/sections/.bss
cat /proc/modules | grep mt7615
```

### `udhcpc: socket: Address in use`

An older `/userconfig/udhcpc` instance is still holding port 68. Kill it and rerun `repeater_up.sh`, or reboot.

### No DHCP lease on a new AP

Some APs (including the one I tested on) drop broadcast DHCP from `apcli0`'s locally-administered MAC. `repeater_up.sh` tries a unicast DISCOVER using `/userconfig/last_lease` first, then falls back to broadcast. On a brand-new AP that blocks broadcast, seed one lease manually: set a temporary static IP on the upstream subnet, write `/userconfig/last_lease` (`LAST_IP`, `LAST_PREFIX`, `LAST_GATEWAY`, `LAST_BROADCAST`), and run `repeater_up.sh`.

### Client has no internet, router sees upstream

Check:

```sh
brctl show                 # must NOT contain apcli0
ip route                   # default via the upstream gateway
iptables -t nat -nvL POSTROUTING
iptables -nvL FORWARD
iptables -t mangle -nvL PREROUTING   # -i apcli0 should tick
grep -E 'apcli0|idm0' /proc/net/dev  # no exact RX->TX mirror
```

### 5 GHz scan misses the SSID

Set `UP_CHANNEL` and `UP_BSSID` directly in `upstream.conf`, and verify with `wlandiagcli scan 1`.

### Factory unlock fails

That is a rate limit on the router. Wait 2 to 5 minutes and try again. If your unit uses a custom factory password, pass it when prompted or via `--factory-pass`.

## Optional: WPA2-Enterprise (EAP-TTLS/PAP)

<details>
<summary>Click to expand WPA2-Enterprise (eduroam / campus / 802.1X) instructions</summary>

The repeater also supports WPA2-Enterprise using EAP-TTLS with PAP inner auth (standard on campus eduroam networks). A static soft-float ARM binary (`eap_ttls`) runs the TLS tunnel and RADIUS exchange on the router, then injects the derived PMK into `mt7615_ap` kernel memory so the driver finishes the 4-way handshake. (This took longer to crack than the main repeater function.)

Onboard with `--enterprise`:

```bash
./start-repeater.sh --enterprise
```

Or pass flags directly:

```bash
./start-repeater.sh --enterprise --eap-identity "user@example.edu" --eap-ca "/path/to/ca.pem"
```

The script reads your password via `getpass` (nothing goes over telnet or logs) and uploads `eap_pass` mode `600` using a one-time ephemeral HTTP token.

Because some controllers require 802.11w PMF or reject the stock driver's RSN IE in client mode, `--enterprise` also loads `f680_rsn_patch.ko` (<2 KB, built by `src/build_rsn_patch.py`). It verifies the vendor instruction words at three `.text` offsets in `mt7615_ap.ko` (`0x90e08`, `0x4b91c`, `0x11ca54`), patches the capability masks to `0xd0` and inserts a standard BIP cipher under `stop_machine`, then unloads immediately. Any instruction mismatch aborts without writing. The patch lives in RAM only and disappears on reboot. PSK/Open installs never upload it and clean up any leftover copy in `/userconfig`.

</details>

## Repo layout

```text
.
├── README.md
├── start-repeater.sh          # Guided onboarding (Linux/macOS)
├── start-repeater.bat         # Guided onboarding (Windows)
├── requirements.txt           # requests + pycryptodome (factory handshake)
├── payload/
│   ├── kmemtool               # 1 KB static ARM /dev/kmem helper
│   ├── udhcpc                 # 454 KB static soft-float ARM DHCP client
│   ├── eap_ttls               # ~1 MB static soft-float ARM EAP-TTLS authenticator (opt-in)
│   ├── f680_rsn_patch.ko      # <2 KB RSN-IE patch module (enterprise only)
│   ├── udhcpc.script          # lease applier + last_lease/lease_ok
│   ├── repeater_up.sh         # bring-up (poke, scan, associate, DHCP, NAT)
│   ├── restore_after_boot.sh  # post-reboot manual recovery
│   ├── verify_repeater.sh     # read-only state/NAT/DNS check
│   ├── autorun.sh             # non-blocking wrapper (not auto-run on stock fw)
│   ├── upstream.conf.example
│   └── README.md              # payload notes
├── src/
│   ├── build_kmemtool.py      # Keystone builder for kmemtool
│   ├── build_rsn_patch.py     # builder + capstone audit for f680_rsn_patch.ko
│   ├── udhcpc.rs              # Rust DHCP client source
│   └── eap_ttls/              # pure-Rust EAP-TTLS crate
├── docs/
│   ├── TECHNICAL_REPORT.md    # root cause, disassembly, reboot findings
│   ├── PHASE12_FINDINGS.md    # early RE notes
│   ├── HOW_IT_WORKS.md
│   ├── BOOT_PERSISTENCE.md
│   ├── LIMITATIONS.md
│   └── EVIDENCE.md
├── tools/
│   ├── onboard.py             # unlock + router-side scan + install
│   ├── diagnostics.py         # pre/post checks, log sanitization, issue report
│   ├── test_diagnostics.py    # sanitizer unit tests
│   ├── zte_factorymode.py     # FactoryMode handshake (AGPL-3.0, adapted)
│   ├── serve.py               # manual payload server
│   ├── checksums.txt
│   └── factory_unlock.md
├── LICENSES/
│   └── AGPL-3.0.txt
├── PRIVACY.md
├── LICENSE                    # MIT for scripts, source, and docs
├── NOTICE
└── DISCLAIMER.md
```

## Contributing

Contributions are welcome ! pull requests, bug reports, and reverse-engineering notes are all appreciated.

Areas that would especially help:

* **Other firmware builds or F680 hardware revisions:** verifying `.bss` offsets, driver behavior, or factory unlock quirks.
* **Boot persistence & 2.4 GHz upstream:** findings or safe approaches for automatic startup or 2.4 GHz APCLI support.
* **Fixes and docs:** script improvements, Windows/macOS/Linux onboarding fixes, or clearer documentation.

If you open an issue, include the redacted Markdown diagnostic block printed by `start-repeater`. Before submitting an issue or PR, check [`PRIVACY.md`](PRIVACY.md) and make sure no credentials, personal MACs/IPs, or vendor firmware binaries are included.

## Credits, privacy, and license

This started as a reverse-engineering project on a single F680. Maybe one day I will look into adding 2.4 GHz upstream support too.

* Router payload scripts, source code, and docs are MIT-licensed.
* Guided onboarding (`tools/onboard.py`, `tools/zte_factorymode.py`) is AGPL-3.0, adapted from douniwan5788's `zte_modem_tools` (thanks!). See `NOTICE` and `LICENSES/AGPL-3.0.txt`.
* Secret handling and redaction rules are in [`PRIVACY.md`](PRIVACY.md).
* AI tools were used to help iterate on parts of the scripts, code, and documentation.
* Vendor names remain trademarks of their owners. No warranty; use at your own risk.
