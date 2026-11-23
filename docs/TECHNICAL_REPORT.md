# F680 Working Repeater — Complete Findings

**Date:** 2026-11-22
**Status:** The F680 is a **working routed NAT Wi-Fi repeater at runtime**.
LAN clients get DHCP, DNS, HTTP 200, and 0% packet loss to 8.8.8.8 through
`apcli0`. **Automatic boot execution is the one remaining blocker**: the safe
`autorun.sh` is present, but the stock firmware does not load the patched
`libbbx.so` that would run it. Manual recovery after a reboot is one command and
is documented in §12–§14.
**Scope:** ZTE ZXHN F680 V6.0 (`ZTEGF680V60`), vendor firmware
`ZTEGF680606MA`, Linux 4.1.25, mt7615 5 GHz + mt7603e 2.4 GHz.
**Safety:** No raw MTD/flash writes. The RX fix is a one-byte RAM poke. The
only persistent artifacts are files in `/userconfig` (JFFS2 mtd5).

---

## 1. Executive summary

The 5G APCLI (`apcli0`) never reached Linux because the mt7615 driver handed
every received frame to the **IDM hardware-forward callback for `idm0`**
(WAN/GPON), not to `netif_rx()`. The switch was not upstream and not the
switch/tm WLAN→IDM map table.

The actual gate is a **per-module** byte:

- `/proc/wifi_hdswitch/on` is created by **mt7603e only** and writes the
  **2.4 GHz** `cg_hdswitch_on` at mt7603e `.bss+0x764`.
- The **5G mt7615** module has its **own** `cg_hdswitch_on` at
  **`.bss+0xf1c`**, default `1`, which no `/proc` file controls.

Writing **`00`** to mt7615 `cg_hdswitch_on` makes `RtmpOsPktRcvHandle` take the
`netif_rx()` branch for APCLI. The result:

```
static ARP ping 198.51.100.1:  5/5, 0% loss
dynamic ARP ping 198.51.100.1: 5/5, 0% loss
mangle PREROUTING -i apcli0:   13 packets / 1092 bytes
idm0 TX:                       3228090/23770 before AND after (frozen)
client:                        HTTP 200, DNS NOERROR, ping 8.8.8.8 0% loss
```

---

## 2. Root cause — exact code path

`mt7615_ap.ko`, `RtmpOsPktRcvHandle` @ `0x1491d8`:

```
skb_push(skb, 14)
if skb->protocol == 0x888e          -> netif_rx
else if cg_hdswitch_on == 0         -> netif_rx
else
    idx = *(u32 *)(skb->dev + 0x470)
    handler = wifihdswitchhandler[idx]
    idm     = idmdev[idx]
    handler(skb, idm)
```

- AP VAPs (`wlan4..7`) set `dev+0x470 = 1` in `MBSS_Init` → `idm1` (LAN/CPU).
- APCLI (`apcli0`) is zero-initialized and never written → `0` → `idm0`
  (WAN/GPON), where the frames disappeared.
- `skb->dev` is at `skb+0x18`; `skb->protocol` at `skb+0xbc` (set by
  `eth_type_trans` in `RtmpOsPktProtocolAssign`).
- Before `netif_rx`, the function does `skb_pull(skb, 14)`.
- The IDM path stores `*(u16 *)(skb+0xca) = *(u32 *)(skb->dev+0x474)` (ESSID ID).

`wlan_hardforward_init` (mt7603e `0x6c42c`, mt7615 `0xc45ac`) resolves `idm0`
and `idm1` by name, reads `netdev_priv(idm)+0x10` (the IDM driver callback),
stores:
- `wifihdswitchhandler[0]` = idm0 callback, `idmdev[0]` = idm0
- `wifihdswitchhandler[1]` = idm1 callback, `idmdev[1]` = idm1
and sets the **module’s own** `cg_hdswitch_on = 1`.

`/proc/wifi_hdswitch/attach_function` was also decoded:
- `1` → `idm_skb_recv = wlan_xmit_idm_hook`
- `0` → `idm_skb_recv = NULL` (kernel global at `0xc071c82c`)

This is the Linux→IDM **TX** hook; setting it to 0 freezes APCLI RX, which is
why that escalation failed.

---

## 3. The one-byte fix

### 3.1 Address

The module `.bss` base is exposed by sysfs and moves every boot:

```sh
B7=$(cat /sys/module/mt7615_ap/sections/.bss)
# this boot: 0xbf7de920
# cg_hdswitch_on = B7 + 0xf1c = 0xbf7df83c
```

The `0xf1c` offset comes from the unstripped `mt7615_ap.ko` symbol table:

```
00000f1c 1 OBJECT GLOBAL 36 cg_hdswitch_on
```

Never hardcode the address across a reboot.

### 3.2 `kmemtool`

A 1,048-byte static ARM EABI5 helper, built by `src/build_kmemtool.py` with
Keystone:

- 181 real integer instructions; **zero VFP/NEON** (audited).
- Syscalls: `open=5`, `read=3`, `write=4`, `_llseek=140`, `exit=1`.
- `_llseek` uses `offset_high=0`, `offset_low=target` (zero-extended; never
  sign-extended).
- Usage: `kmemtool PATH BASE OFFSET r|w [VAL]`
- QEMU-tested at `0x1000` and `0xbf7df82c`; errors print the exact return,
  e.g. `Offfffffe` for open ENOENT.

### 3.3 Calibration

`/dev/kmem` on this build is `crw-rw-rw-`. Calibration against the mt7603e
`cg_hdswitch_on` at `.bss+0x764`, while toggling `/proc/wifi_hdswitch/on`:

```
proc on before: 1   kmem: 01
proc on zero:   0   kmem: 00
proc on restore:1   kmem: 01
CAL_PASS
```

This proved `/dev/kmem` module-space addressing before touching the 5G byte.

### 3.4 The poke

```sh
B7=$(cat /sys/module/mt7615_ap/sections/.bss)
/userconfig/kmemtool /dev/kmem "$B7" f1c r   # expect 01
/userconfig/kmemtool /dev/kmem "$B7" f1c w 00
```

Read-back must be `00`. If it is not `01`, do not write.

---

## 4. DHCP — what works and what the test AP blocks

The router needs dynamic DHCP for dorm Wi-Fi. The upstream used for testing
is documented below with sanitized TEST-NET-2 addresses.

### 4.1 Broadcast DHCP is blocked for the APCLI

The custom DHCP client sends 4 DISCOVERs; mangle `OUTPUT udp dport 67` counts
them, but `PREROUTING udp dport 68` stays **0** and no OFFER arrives. The
laptop's broadcast DHCP works; the APCLI's locally-administered MAC does not.
Changing the APCLI MAC with
`ifconfig apcli0 hw ether …` is **ignored by the driver**; there is no APCLI
MAC setter in mt7615.

### 4.2 Unicast DHCP works

With `.112/24` assigned, sending a **unicast** DISCOVER to `198.51.100.1:67`
works immediately:

```
udhcpc: OFFER 198.51.100.112 server 198.51.100.1
udhcpc: ACK   198.51.100.112 router 198.51.100.1
              dns 198.51.100.1 lease 86400
```

### 4.3 Boot strategy

`repeater_up.sh` uses:

1. `/userconfig/last_lease` (persisted from the previous ACK) to seed
   `apcli0` IP/prefix/broadcast/gateway.
2. `udhcpc --server-ip <last_gateway>` for a **unicast DISCOVER**.
3. If no last lease, or unicast fails, fall back to **broadcast** DHCP (works
   on APs that do not block it).
4. A `lease_ok` flag is written only by a successful DHCP script, so a seeded
   IP alone is not mistaken for a fresh lease.

The DHCP client is `/userconfig/udhcpc`, built from `src/udhcpc.rs` for
`armv7-unknown-linux-musleabi`:

- ELF32 ARM, EABI5, **soft-float** (`e_flags=0x5000200`), statically linked,
  stripped (no symbol table), built with `-C panic=abort`.
- 454 KB; contains 6 unreachable LLVM libunwind VFP save/restore words
  (`vstmia`/`vldmia`); the soft-float ABI is unaffected and the unwinder is
  dead code under `panic=abort`.
- Implements DISCOVER/OFFER/REQUEST/ACK, option 53/61/55/50/54/1/3/6/28/51.
- Writes the BusyBox-`udhcpc`-compatible environment and runs
  `/bin/sh /userconfig/udhcpc.script bound`.
- Supports `-i`, `-s`, `-n`, `-q`, `-f`; `-q` one-shot, otherwise renews at
  lease/2.
- Local mock-server test passed at unprivileged ports; the ARM build passed
  under QEMU against the same mock.

`/userconfig/udhcpc.script`:

- `ip addr flush`, adds `$ip/$prefix` with `brd $broadcast`, default route via
  `$router`.
- Writes upstream `nameserver` lines to `/var/tmp/default_resolv*.conf` and
  HUPs dnsmasq.
- Saves `LAST_IP/LAST_PREFIX/LAST_GATEWAY/LAST_BROADCAST` to
  `/userconfig/last_lease`, and writes `/userconfig/lease_ok`.
- Never touches `br0` or `wlan0`.

---

## 5. Working NAT rules

The exact rules that produced working client traffic:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -t nat -D POSTROUTING -o apcli0 -j MASQUERADE 2>/dev/null
iptables -t nat -A POSTROUTING -o apcli0 -j MASQUERADE

iptables -D FORWARD -i br0 -o apcli0 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i apcli0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -I FORWARD 1 -i br0 -o apcli0 -j ACCEPT
iptables -I FORWARD 2 -i apcli0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -D INPUT -i apcli0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -D INPUT -i apcli0 -p udp --dport 68 -j ACCEPT 2>/dev/null
iptables -I INPUT 1 -i apcli0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -i apcli0 -p udp --dport 68 -j ACCEPT
```

Do **not** add `apcli0` to `br0`; do **not** clone `br0`’s MAC.

---

## 6. Verified results

### 6.1 RX fix (2026-11-22 14:48)

```
calibration mt7603e: 01 -> 00 -> 01   (CAL_PASS)
mt7615 cg:           01 -> 00, readback 00
static ARP ping .1:  5/5, 0% loss
dynamic ARP ping .1: 5/5, 0% loss
mangle -i apcli0:    13 packets / 1092 bytes
idm0 TX:             3228090/23770 before AND after (frozen)
apcli0 RX/TX:        23932/788 -> 23951/802 (+19/+14)
```

### 6.2 Client path

```
DHCP: 192.168.12.50/24 via 192.168.12.1
dig @192.168.12.1 example.com -> NOERROR
  A 172.66.147.243 / 104.20.23.154
getent hosts example.com -> resolves
curl http://example.com -> HTTP=200
ping 8.8.8.8 -> 0% loss
NAT: MASQUERADE 113/23835; FORWARD 400/928
```

### 6.3 Boot-script dry run (2026-11-22 15:35)

```
cg_before=01 -> cg_after=00 -> cg_final=00
scan_choice=02:00:00:00:00:03 60 WPA2-PSK-AES
assoc_last=... TX_EAPOL_PAIR_MSG_4 ... -> association M4 seen
udhcpc: ACK 198.51.100.112 router [198.51.100.1] dns [198.51.100.1] lease 86400
udhcpc: script bound ok; renew in 43200s
brctl show: no apcli0
client test: INTERNET WORKS
```

The client path is the authoritative test and works.

### 6.4 Current state (2026-11-22 15:40)

- `cg_hdswitch_on = 00`
- `apcli0` 198.51.100.112/24, default via .1
- NAT MASQUERADE/FORWARD counters moving
- `brctl show` contains no `apcli0`
- `last_lease` .112/24 gw .1 brd .255
- client on 192.168.12.50 has internet

Note: a manual rerun of `repeater_up.sh` can hit `udhcpc: socket: Address in
use` because the previous background DHCP client still holds port 68. At boot
there is no previous client. If rerunning manually, kill the old
`/userconfig/udhcpc` first.

---

## 7. What did NOT work (do not repeat)

- `/proc/wifi_hdswitch/on = 0`: only mt7603e; 5G kept mirroring to idm0.
- `/proc/wifi_hdswitch/attach_function = 0`: NULLs the global `idm_skb_recv`
  TX hook; freezes APCLI RX instead of falling back to `netif_rx`.
- `br1` containing `apcli0`: `br1` RX was actually TX 938 B/13 pkts; no
  upstream MAC learned; no ping.
- `ip link set idm0 down`, `on=0`+idm0 down, `promisc`: no change.
- FFE/NPU off, multiapd STOP, `MapEnable`/`MWDS` toggles: no change.
- `switchtst`: only eth0–eth3; `-getacl` segfaults; its ACL is the GPON
  forward ACL, not the WLAN→IDM map.
- WLAN→IDM map setters: `aclWLANToIDMEssidCfg2`/`aclWlanToIdmReset` are
  exported but have no in-kernel caller in the dump; cspd only queries.
- `ifconfig apcli0 hw ether 14:00:…`: driver ignored it; the APCLI MAC
  was unchanged.
- Broadcast DHCP from the APCLI: no reply; unicast works.

---

## 8. Boot persistence

### 8.1 Safe autorun wrapper

The old `/userconfig/autorun.sh` was harmful:
- `brctl addif br0 apcli0` (bridge mode)
- `telnetd -l /bin/sh -p 2323` (unauthenticated backdoor)

It was backed up to `/userconfig/autorun.sh.old` and replaced with:

```sh
#!/bin/sh
( sleep 25; /userconfig/repeater_up.sh ) >/userconfig/repeater_boot.log 2>&1 &
exit 0
```

`repeater_up.sh`:
- polls up to 90 s for `/sys/module/mt7615_ap/sections/.bss` and `apcli0`;
- reads the live `.bss`, verifies `cg` is `01` or `00`, writes `00` only from
  `01`, aborts on any other value;
- sources `/userconfig/upstream.conf` (`UP_SSID`, `UP_PSK`, optional
  `UP_BSSID`, `UP_CHANNEL`);
- if `UP_CHANNEL` is empty, runs `wlandiagcli scan 1` with a fixed-width parser,
  prefers `WPA2-PSK-AES`, picks the strongest matching SSID/BSSID, and extracts
  the channel;
- associates 3-address (`MWDS=0`), waits for EAPOL M4, retries once;
- seeds the last lease and runs unicast DHCP, with broadcast fallback;
- applies NAT/INPUT, logs, and verifies;
- never bridges `apcli0`, never touches `br0`/`wlan0`, never starts telnetd.

### 8.2 Loader status — resolved negative

A patched **same-size drop-in replacement for `/lib/libbbx.so`**
(12,591 bytes) with an `.init_array` constructor that runs
`/bin/sh /userconfig/autorun.sh` would be the loader trigger. No such vendor
binary is distributed in this repo. It is **not** loaded from `/userconfig/cfg`:
`pc` maps the stock `/lib/libbbx.so`, has no RPATH/RUNPATH, and
`/etc/ld.so.preload` is empty. The confirmed reboot test showed
`repeater_boot.log` stayed stale, `cg=01`, `apcli0` down, and NAT absent.

The exact trigger must be “make `pc` load the patched `libbbx.so` before
`pc&`” (replace/bind-mount `/lib/libbbx.so`, or `LD_PRELOAD` it). There is no
userland hook to do that. See §13–§14. The safe wrapper and `repeater_up.sh` are
correct; the automatic trigger is the remaining blocker.

---

## 9. Exact file set

Router (`/userconfig`, all persistent on mtd5):

| File | Purpose |
| :--- | :--- |
| `kmemtool` | 1 KB static ARM `/dev/kmem` helper |
| `udhcpc` | 454 KB static soft-float ARM DHCP client |
| `udhcpc.script` | lease applier + last_lease/lease_ok writer |
| `repeater_up.sh` | boot bring-up (poke, scan, associate, DHCP, NAT) |
| `autorun.sh` | safe non-blocking wrapper |
| `autorun.sh.old` | backup of the old harmful script |
| `upstream.conf` | `UP_SSID`, `UP_PSK`, optional BSSID/channel (mode 600) |
| `last_lease` | last IP/prefix/gateway/broadcast (mode 600) |
| `lease_ok` | written only by a successful DHCP script |
| `repeater_boot.log` | boot log |
| `repeater_boot.log.failed_boot` | preserved evidence of the failed auto-boot |
| `restore_after_boot.sh` | post-reboot manual recovery wrapper |

Repo (laptop):

| File | Purpose |
| :--- | :--- |
| `src/build_kmemtool.py` | Keystone builder for `kmemtool` |
| `src/udhcpc.rs` | Rust DHCP client source |
| `payload/` | files served to `/userconfig` (see `payload/README.md`) |
| `tools/onboard.py` | guided unlock + router-side scan + install |
| `tools/serve.py` | manual payload server + command printer |
| `tools/zte_factorymode.py` | FactoryMode handshake (AGPL-3.0, adapted) |
| `tools/checksums.txt` | payload hashes |
| `start-repeater.sh` / `start-repeater.bat` | guided onboarding launchers |

Logs: raw bench session logs are intentionally excluded from the public repo;
sanitized evidence is in `docs/EVIDENCE.md`.

---

## 10. Reproduction checklist

1. Associate `apcli0` to the upstream SSID:
   ```sh
   iwpriv apcli0 set ApCliEnable=0
   iwpriv wlan4 set Channel=<ch>
   iwpriv apcli0 set ApCliMWDS=0
   iwpriv apcli0 set ApCliAuthMode=WPA2PSK
   iwpriv apcli0 set ApCliEncrypType=AES
   iwpriv apcli0 set ApCliSsid="<SSID>"
   iwpriv apcli0 set ApCliWPAPSK="<PSK>"
   iwpriv apcli0 set ApCliEnable=1
   ```
2. Read the live mt7615 `.bss` and write `00` at `+0xf1c`:
   ```sh
   B7=$(cat /sys/module/mt7615_ap/sections/.bss)
   /userconfig/kmemtool /dev/kmem "$B7" f1c r
   /userconfig/kmemtool /dev/kmem "$B7" f1c w 00
   ```
3. Seed/obtain the upstream IP (DHCP unicast or static), set the default
   route, and apply the NAT/INPUT rules in §5.
4. Verify:
   ```sh
   ping -c 5 -T 1 -I 198.51.100.112 198.51.100.1
   iptables -t mangle -nvL PREROUTING    # -i apcli0 must tick
   grep -E 'apcli0|idm0' /proc/net/dev   # no exact RX->TX mirror
   ```
5. From a client on the 2.4 GHz AP: DHCP, `dig`, `curl`, ping.

---

## 11. Caveats / next steps

- The RX fix is RAM-only; the `.bss` address changes on reboot. The boot script
  re-reads it.
- The test AP blocks broadcast DHCP from the APCLI MAC; the boot path uses the
  last lease + unicast DISCOVER, with broadcast fallback for normal APs. A fresh
  install on an AP that also blocks broadcast DHCP still needs a one-time
  static/unicast seed.
- The APCLI’s MAC is fixed by the driver; `ifconfig hw ether` is ignored.
- Router-origin ICMP/DNS is unreliable; use the client path.
- `/userconfig/upstream.conf` contains the PSK in mode 600. Never print it in
  logs or commits.
- The old bridge/telnetd script is backed up but not active.

---

## 12. Controlled reboot verification — automatic boot did NOT run

Reboot issued 2026-11-22 15:43:36. The router came back with the 2.4 GHz AP,
LAN `192.168.12.1`, and DHCP working (laptop got `192.168.12.50`). But:

```
repeater_boot.log:  stale (still the 15:40 manual run)
cg_hdswitch_on:     01   (boot default; not poked)
apcli0:             down, no IP, RX/TX 0
NAT/INPUT:          absent (only stock ZTE rules)
client internet:    failed
```

So `autorun.sh` was **not executed at boot**. The safe wrapper is correct, but
the loader does not run it. The exact boot-hook findings are in §13.

Manual recovery then succeeded:

```sh
sh /userconfig/restore_after_boot.sh   # copies failed log, runs repeater_up.sh
```

Result:

```
repeater_up_rc=0
cg=00
lease_ok: present
apcli0: 198.51.100.112/24, default via .1
brctl: no apcli0
client test: INTERNET WORKS
```

This proves **repeater_up.sh itself works after a real reboot**; only the
automatic trigger is missing.

---

## 13. Exact boot-hook findings

### 13.1 What the boot chain actually does

- `/etc/init.d/rcS` mounts `/userconfig` (mtd5), `/usr/local/ct` (mtd6),
  `/wlan` (mtd4), `/usercustom` (mtd9).
- It runs `/etc/rcS.d/S31emacs`, `S40network`, `S43BSPDriver`, `S99modules`.
- `S99modules` loads `optical`, `zx_ponreg`, `tm`, `netdriver`, `zte_gpon`,
  `gpondrv`, `zte_xgmii`, `switch`, `kudp`, `voip_codec`, `dsp_dev`,
  `ptpdrv`, `y1731drv`, then `ifconfig idm0/idm1 up`.
- At the end of `rcS` it runs `pc&`.
- `/etc/ld.so.preload` is empty.
- There is **no** `autorun`, `/userconfig` script, or patched-library reference
  in `/etc/init.d`, `/etc/rcS.d`, or `/etc/profile`.
- `/usr/local/ct` and `/usercustom` are empty; `/wlan` contains only
  calibration data.
- `/userconfig/ttyredir.cfg` is a `redir` (printk/printf to file) hook, not an
  execute hook.
- `sendcmd 1 DB all` shows only `OMCICFG`/`OMCIPARA` for the search terms; there
  is no user-script/auto-run DB object.

### 13.2 The real loader is `libbbx.so`, not `autorun.sh`

`pc` (PID 604) maps:

```
/lib/libbbx.so
```

`pc` has `NEEDED libbbx.so` and **no RPATH/RUNPATH**. `/etc/ld.so.conf` is
empty, so the loader resolves `libbbx.so` from `/lib`.

The investigated trigger was a **drop-in patched `libbbx.so`**: exactly the
same size as `/lib/libbbx.so` (12,591 bytes), exporting the same `libbbx` API
(`OssUserBbxInit`, `OssGetBbxAddr`, `bbxUserSetKeyParam`, `bbxGetMagic`,
`Omci_Iot_Test_Init`, …), with an `INIT_ARRAY` constructor whose strings
include:

```
/bin/sh
/userconfig/autorun.sh
```

No vendor binary is distributed in this repo. When loaded, its constructor runs
`/bin/sh /userconfig/autorun.sh`. The previous assumption that such a drop-in
is loaded from `/userconfig/cfg` is false: no process maps it, and the stock
`/lib/libbbx.so` is what `pc` uses.

`cspd`’s `usrcfgExt`/`dlopen` strings are not a library loader; the
`usrcfgExt` context is LAN DHCP source/rule handling, not plugin loading.

### 13.3 Exact trigger needed

Before `pc&` starts, one of these must happen:

1. `/lib/libbbx.so` must be a patched drop-in (replace or bind-mount it),
   **or**
2. `pc` must be started with the patched library preloaded (e.g.
   `LD_PRELOAD=<patched-libbbx.so>`, or `LD_LIBRARY_PATH=<dir>` with a
   `libbbx.so` name).

There is **no userland hook** in this firmware to do either before `pc&`.
`/etc/rcS.d/S99modules` and `/etc/ld.so.preload` are on the read-only rootfs.

---

## 14. Options for reboot persistence

**A. Rootfs change (only real zero-assistance fix).**
Remount `/` rw (or otherwise modify the jffs2 rootfs) and either replace
`/lib/libbbx.so` with a patched drop-in or add a bind-mount/`LD_PRELOAD` line
before `pc&`. This is **outside the project’s no-rootfs-write / no-raw-MTD
rules**, has no UART recovery, and needs explicit approval plus a rollback plan.
Not done.

**B. Kernel/module hook.**
Would need a module loaded before `pc`; `/kmodule` and the boot scripts are
read-only, and there is no build tree on the router. Not practical without the
same rootfs change.

**C. Manual re-apply after each reboot (current safe workaround).**
From the laptop (on the router's 2.4 GHz AP or LAN):

```sh
cd f680-repeater
./start-repeater.sh --restore
```

or, from an existing root shell on the router:

```sh
sh /userconfig/restore_after_boot.sh
cat /userconfig/restore_after_boot.out
```

`restore_after_boot.sh` preserves the failed boot log and runs
`repeater_up.sh` (cg 01→00, scan, associate, DHCP, NAT). Takes ~40 s. This
restores the full client path and was verified immediately after the reboot.

**D. Keep the F680 as an AP on Ethernet/GPON, or use a dedicated travel
router/repeater.** The F680’s runtime fix is real but the firmware’s boot
chain is vendor-locked.

---

## 15. Current recovery state (after §12)

- `cg_hdswitch_on = 00`
- `apcli0` 198.51.100.112/24, default via .1
- `lease_ok` present; `last_lease` .112/24 gw .1 brd .255
- NAT/INPUT active; `brctl show` has no `apcli0`
- client test: internet works
- Failed-boot evidence preserved at
  `/userconfig/repeater_boot.log.failed_boot`

---

## 16. WPA2-Enterprise (802.1X / EAP-TTLS) Architecture & Kernel Disassembly

### 16.1. The 3-Site Kernel Driver Gate (mt7615_ap.ko)
The stock MediaTek `mt7615_ap.ko` (Linux 4.1.25) restricts client-mode association (`ApCli`) exclusively to WPA2-PSK and Open networks. When connecting to WPA2-Enterprise (802.1X) and Protected Management Frames (PMF / 802.11w) networks, association requests are rejected across three distinct gating sites in `.text`:

1. **Site 1: RSN IE Capability Bit Gate (`WPAMakeRSNIE + 0xf8` @ `0x90e08`)**:
   ```arm
   0x90e04: e5943000   ldr  r3, [r4]          @ r4 = &RSN IE capability word
   0x90e08: e3130090   tst  r3, #0x90         @ gates capability bit 0x40
   0x90e0c: 0afffffa   beq  0x90dfc
   ```
   *Stock instruction:* `0xe3130090` (`tst r3, #0x90`).
   *Patched instruction:* `0xe31300d0` (`tst r3, #0xd0`).
   *Effect:* Unblocks capability bit `0x40` required for WPA2-Enterprise RSN IE generation.

2. **Site 2: Association Request AKM Mask Gate (`ApCliMlmeAssocReqAction + 0x29c` @ `0x4b91c`)**:
   ```arm
   0x4b918: e3062e08   movw r2, #0x6e08
   0x4b91c: e3a03090   mov  r3, #0x90         @ constructs 0x00100090 AKM mask
   0x4b920: e340201f   movt r2, #0x1f
   0x4b924: e0842002   add  r2, r4, r2
   0x4b928: e3403010   movt r3, #0x10
   0x4b92c: e5922af0   ldr  r2, [r2, #0xaf0]
   0x4b930: e0033002   and  r3, r3, r2        @ tests (AKMMap & 0x00100090) != 0
   ```
   *Stock instruction:* `0xe3a03090` (`mov r3, #0x90`).
   *Patched instruction:* `0xe3a030d0` (`mov r3, #0xd0`).
   *Effect:* Constructs the AKM mask `0x001000d0`, allowing the MLME state machine to transmit association requests containing the 802.1X AKM suite (`00-0F-AC:1`).

3. **Site 3: PMF Group Management Cipher Gate (`PMF_MakeRsnIeGMgmtCipher + 0x58` @ `0x11ca54`)**:
   ```arm
   0x11ca48: 02005ce3   cmp  ip, #2            @ BIP-128 cipher check
   0x11ca4c: 0200000a   beq  #0x11ca5c
   0x11ca50: 0140a0e3   mov  r4, #1
   0x11ca54: 0400a0e1   mov  r0, r4
   0x11ca58: 3880bde8   pop  {r3, r4, r5, pc}
   0x11ca5c: e043d3e5   ldrb r4, [r3, #0x3e0]  @ r4 = ApCliCfg.PmfCfg.MFPC
   0x11ca60: 010054e3   cmp  r4, #1
   0x11ca64: f9ffff1a   bne  #0x11ca50        @ if MFPC == 0 -> exits early returning 1
   0x11ca7c: 020c12e3   tst  r2, #0x200        @ tests igtk_cipher (uninitialized in STA)
   0x11ca54: 1a000021   bne  #0x11cae0        @ Stock branch fails!
   ```
   *Why it fails:* In STA (`ApCli`) mode, `igtk_cipher` is uninitialized prior to association (`r2 & 0x200 == 0`). `bne 0x11cae0` (`0x1a000021`) fails to branch, falling through to `printk("insert fail, IGTK cipher is wrong")` and returning 0.
   *Patched instruction:* `0xea000021` (`b 0x11cae0`).
   *Effect:* Unconditionally branches to `0x11cae0`, successfully appending the BIP-128 (`00-0F-AC:6`) management cipher suite into the RSN IE.
   *Non-PMF Safety:* When `MFPC=0` (WPA2-PSK or Open networks), offset `0x11ca64: bne #0x11ca50` exits immediately returning 1; Site 3 is never evaluated, confirming zero regression on non-PMF networks.

### 16.2. The Deterministic Patch Module (`payload/f680_rsn_patch.ko`)
All three sites are patched atomically in RAM using `f680_rsn_patch.ko` (1,960 bytes):
- **Verification Invariants:** Validates all 3 sites before modifying any byte (all-or-nothing pre-check). Returns `-EINVAL` (`-22`) on mismatch.
- **Safety:** Runs under kernel `stop_machine()`, executes `dsb sy` and `v7_coherent_kern_range()`, and verifies immediate readback. Returns `-EIO` (`-5`) on readback failure.
- **ABI Compliance:** Pure ARMv7 soft-float ABI (`EF_ARM_EABI_VER5`), 0 VFP/NEON instructions, 8-byte stack alignment. Unloaded immediately after execution (`rmmod`).

---

## 17. EAP-TTLS Authentication & EAPOL Framing Daemon (`payload/eap_ttls`)

To perform 802.1X authentication without pulling heavy userspace dependencies (`wpa_supplicant`, `openssl`), `eap_ttls` runs as a standalone static daemon:
1. **RX EAPOL Framing Hook (`jt0`):**
   The mt7615 receive vector is intercepted at `.text + 0x902a4` (or `+ 0x90244`) to pass EtherType `0x888e` packets directly to user-space through an `AF_PACKET` raw socket.
2. **Inner Authentication:**
   Negotiates EAP-TTLS with inner PAP over TLS 1.3/1.2. Supports CA certificate verification using PEM trust anchors.
3. **1970 System Clock Adaptation:**
   At boot time, the F680 has no RTC or NTP sync and initializes to January 1, 1970. The TLS engine accommodates the pre-epoch clock so certificates within their valid period are not falsely rejected.
4. **Hardware Key Installation:**
   Upon successful inner authentication, `eap_ttls` derives the Pairwise Master Key (PMK) and writes it into the mt7615 driver structure via `/dev/kmem`. The native driver then automatically completes the 4-Way Handshake (M1 through M4) and installs the PTK/GTK via `WPAInstallKey`.

---

## 18. Transparent DNS Netfilter Redirection (`F680_DNS`)

Institutional and university networks frequently filter or drop outbound UDP/TCP port 53 traffic directed to public resolvers (`8.8.8.8:53` or `1.1.1.1:53`). To ensure seamless client connectivity without manual client DNS reconfiguration:
1. **Dynamic Upstream Discovery:**
   `payload/udhcpc.script` extracts upstream DNS servers dynamically from the DHCP lease (`$dns`).
2. **Local Resolver SIGHUP:**
   Writes dynamic resolvers to `/var/tmp/default_resolv.conf`, `/var/tmp/default_resolv_proxy.conf`, and `/var/tmp/resolv.conf`, and reloads `dnsmasq` via `killall -HUP dnsmasq`.
3. **Idempotent PREROUTING Netfilter Chain:**
   Creates a dedicated `F680_DNS` chain in the `nat` table applied strictly to LAN client ingress (`-i br0`):
   ```sh
   iptables -t nat -N F680_DNS 2>/dev/null || true
   iptables -t nat -F F680_DNS
   iptables -t nat -D PREROUTING -i br0 -j F680_DNS 2>/dev/null
   iptables -t nat -I PREROUTING 1 -i br0 -j F680_DNS
   iptables -t nat -A F680_DNS -p udp --dport 53 -j DNAT --to-destination "${first_dns}:53"
   iptables -t nat -A F680_DNS -p tcp --dport 53 -j DNAT --to-destination "${first_dns}:53"
   ```
4. **Flash Wear Elimination:**
   DHCP pool DNS options are updated in the runtime configuration DB using `sendcmd 1 DB set DHCP4sPool ...` without ever calling `sendcmd 1 DB save`. This keeps the change RAM-only, avoiding JFFS2 flash wear on DHCP lease renewals and preventing stale DNS persistence across reboots.

---

## 19. Wireless Interface Queue Latency Tuning

The client interface is tuned to `ifconfig apcli0 txqueuelen 100` upon association. The default queue depth caused excessive bufferbloat and latency spikes on the Cortex-A9 SoC under concurrent wireless repeater traffic. Setting `txqueuelen 100` keeps transmission buffering bounded and stabilizes forwarding latency under load.
