# F680 RE — Phase 1/2 Findings (2026-11-22)

> Historical Phase 1/2 snapshot. Boot-persistence conclusions here were
> superseded by the controlled reboot; see
> [`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md) for the confirmed findings.

## 1. Module ABI

- `mt7615_ap.ko`: ELF32 ARM, EABI5, relocatable, not stripped.
- `vermagic`: `4.1.25 SMP mod_unload ARMv7 ` (trailing space).
- ELF flags: `0x5000000` = `EF_ARM_EABI_VER5`.
- `.ARM.attributes`: CPU v7-A, Application profile, Thumb-2, **no `Tag_ABI_VFP_args`** (soft-float ABI), 8-byte alignment, unaligned access v6.
- Live module file size `/kmodule/mt7615_ap.ko` = 3,600,276 bytes, matches the dump.
- `mt7603e_ap.ko` has the same vermagic/EABI.

## 2. The real RX decision (mt7615)

`RtmpOsPktRcvHandle` @ `0x1491d8`:

- `skb->dev` at `skb+0x18`, `skb->protocol` at `skb+0xbc` (set by `eth_type_trans` in `RtmpOsPktProtocolAssign`).
- `skb_push(skb, 14)` on entry; `skb_pull(skb, 14)` before `netif_rx`.
- If `skb->protocol == 0x888e` (EAPOL) → `netif_rx`.
- Else if `cg_hdswitch_on == 0` → `netif_rx(skb)`.
- Else:
  - `vlan_rx_process(skb->dev, skb)` (returns skb or a copy; 0 means drop).
  - `idx = *(u32 *)(skb->dev + 0x470)`.
  - `handler = wifihdswitchhandler[idx]`, `idm = idmdev[idx]`.
  - calls `handler(skb, idm)` (IDM hardware-forward receive callback).
  - stores `*(u16 *)(skb + 0xca) = *(u32 *)(skb->dev + 0x474)` (ESSID ID) before the call.

`dev+0x470` is the IDM slot:

- AP VAPs (`wlan4..7`) set it to `1` in `MBSS_Init` → `idm1`.
- APCLI (`apcli0`) is zero-initialized, never written → `0` → `idm0`.

This is the exact APCLI→idm0 classification.

## 3. handler registration

`wlan_hardforward_init` (mt7603e `0x6c42c`, mt7615 `0xc45ac`):

- `__dev_get_by_name(init_net, "idm0")`, `__dev_get_by_name(init_net, "idm1")`.
- Reads `netdev_priv(idm)+0x10` (the IDM driver's RX callback).
- Stores:
  - `wifihdswitchhandler[0]` = idm0 callback, `idmdev[0]` = idm0
  - `wifihdswitchhandler[1]` = idm1 callback, `idmdev[1]` = idm1
- Sets **the module's own** `cg_hdswitch_on = 1` if the idm1 callback exists.

Per-module addresses:

- mt7615 `cg_hdswitch_on` = `.bss + 0xf1c`.
- mt7603e `cg_hdswitch_on` = `.bss + 0x764`.

`/proc/wifi_hdswitch/on` is created by **mt7603e only** and reads/writes mt7603e's `.bss+0x764`. It does **not** control the 5G module. That is why every `on=0` test still mirrored `apcli0 RX` into `idm0 TX`.

`/proc/wifi_hdswitch/attach_function` writes the **kernel global** `idm_skb_recv` hook (UND symbol, live at `0xc071c82c`):

- `1` → `idm_skb_recv = wlan_xmit_idm_hook`
- `0` → `idm_skb_recv = NULL`

That is the Linux→IDM TX hook, not an RX fallback; NULLing it froze APCLI RX.

## 4. switch/tm WLAN→IDM map

- `s_aclWlanToIdmEssidMap` in `tm.ko` is 16 × 19-byte entries:
  - `wlan_id` (0..15), `idm_port`, `essid_id`, 15-byte ESSID.
  - Static defaults: wlan 0–7 → idm_port 7 (essid 0x18–0x1f); wlan 8–15 → idm_port 6 (essid 0x10–0x17).
- `aclWLANToIDMEssidMap(wlan_id, *idm, *essid_id)` getter.
- `aclEssidToWlanIDMMap(essid_id, *wlan_id, *idm)` getter.
- `aclWLANToIDMEssidCfg2(wlan_id, idm, essid_id, essid_str)` setter.
- `aclWlanToIdmReset()` clears the table.
- `switch.ko` registers PTL commands `0x413/0x414/0x415` via `fuc_table_node_create` for `sw_wlan_idmessid_map`, `sw_wlanname_idmessid_map`, `sw_essid_wlanidm_map` — these are **getters**.
- `cspd` has ioctl strings `wlan_idmessid_map` / `essid_wlanidm_map` and logs `tIdm_port = %x` (queries).
- No in-kernel caller of `aclWLANToIDMEssidCfg2`/`aclWlanToIdmReset` was found in the dumped modules. `netdriver.ko` uses `aclEssidToWlanIDMMap` in `pdt_ethdrv_recv` to map ESSID ID→`wlanN`.
- The map's `idm_port` values are switch/hardware port numbers, not the `idm0`/`idm1` netdev indices. The driver-level selector is `dev+0x470`.

## 5. F680 live capability

From the bench session log (raw logs are excluded from the public repo):

- `insmod`, `rmmod`, `lsmod` present; no `modprobe`, no gcc/make, no `/lib/modules` build tree.
- `modules_disabled = 0`; `kptr_restrict = 0`.
- `/dev/kmem` exists and is `crw-rw-rw-`.
- `/dev/mem` and `/dev/port` exist.
- `/proc/kallsyms`:
  - `netif_rx = 0xc0336d70`
  - `idm_skb_recv = 0xc071c82c`
  - module data symbols (`cg_hdswitch_on`, `wifihdswitchhandler`, `idmdev`) are **not** listed.
- `/sys/module/.../sections` exposes:
  - `mt7615_ap .bss = 0xbf7de920`
  - `mt7603e_ap .bss = 0xbf4cb32c`
  - `mt7615_ap .text = 0xbf55d000`, `.data = 0xbf740100`
- Module load ranges from `/proc/modules`:
  - `mt7615_ap` at `0xbf55d000`, file `/kmodule/mt7615_ap.ko` = 3,600,276 bytes.
  - `mt7603e_ap` at `0xbf3a6000`, file 1,528,304 bytes.
- `/proc/mtd`: mtd5 `usercfg` 8 MB; `/userconfig` is rw jffs2; `/` is ro jffs2.
- `/kmodule` is on the ro rootfs.
- Boot scripts: `/etc/init.d/rcS`, `/etc/rcS.d/S31emacs`, `S40network`, `S43BSPDriver`, `S99modules`.
- `/userconfig/autorun.sh` exists; boot execution was later disproven by the controlled reboot (see `BOOT_PERSISTENCE.md`).

## 6. Exact 5G flag address

- `mt7615 .bss = 0xbf7de920`
- `cg_hdswitch_on` offset = `0xf1c`
- **`cg_hdswitch_on` = 0xbf7df83c** (current boot)
- `mt7603e .bss = 0xbf4cb32c` + `0x764` = `0xbf4cba90` (the `/proc` copy).

If the byte at `0xbf7df83c` reads `01`, writing `00` makes `RtmpOsPktRcvHandle` take the `netif_rx` branch for APCLI.

## 7. br1 correction

In the bench session log, the `br1` line was:

```
br1: 0 0 0 0 0 0 0 0 938 13 ...
```

`/proc/net/dev` columns are RX bytes/packets first, then TX. So `br1` received **0** and transmitted 938 B / 13 packets. The only mangle hit was `-s 198.51.100.0/24` = 3 packets / 336 B, which therefore arrived through another skb->dev (likely `idm0`/`sw`), not through `br1` or `apcli0`. No upstream MAC was learned and no ICMP completed.

## 8. The one-byte RAM test — SUCCEEDED (2026-11-22 14:48)

`kmemtool` was built with Keystone as a 1,048-byte static ARM EABI5 ELF
(181 real integer instructions, zero VFP/NEON; `_llseek` with `offset_high=0`
and the 32-bit target in `offset_low`). It was QEMU-tested at offset `0x1000`
and at `0xbf7df82c` before deployment.

Calibration against mt7603e (`/sys/module/mt7603e_ap/sections/.bss` + `0x764`):

```
proc on before: 1   kmem: 01
proc on zero:   0   kmem: 00
proc on restore:1   kmem: 01
CAL_PASS
```

mt7615 (`/sys/module/mt7615_ap/sections/.bss` + `0xf1c`):

```
before:   01
write 00: 00
readback: 00
```

Result:

```
static ARP ping 198.51.100.1: 5/5, 0% loss
dynamic ARP ping 198.51.100.1: 5/5, 0% loss
mangle PREROUTING -i apcli0: 13 packets / 1092 bytes
idm0 TX: 3228090 packets / 23770 bytes before AND after (frozen)
apcli0 RX: 23932 -> 23951 (+19), TX: 788 -> 802 (+14)
```

Client side while parked on the repeater’s 2.4 GHz Wi-Fi:

```
DHCP: 192.168.12.50/24 via 192.168.12.1
dig @192.168.12.1 example.com -> NOERROR, A 172.66.147.243 / 104.20.23.154
getent hosts example.com -> resolves
curl http://example.com -> HTTP=200
ping 8.8.8.8 -> 2/2, 0% loss
NAT: MASQUERADE 113 packets / 23835 bytes; FORWARD 400/928 packets
```

## 9. Persistence / caveats

- The fix is **RAM-only**. On reboot, the mt7615 `.bss` base changes and
  `cg_hdswitch_on` returns to `1`. Re-read
  `/sys/module/mt7615_ap/sections/.bss` and write `00` at offset `0xf1c` again.
- `/proc/wifi_hdswitch/on` is **not** the 5G control; it writes only mt7603e’s
  `.bss+0x764`.
- The old `/userconfig/autorun.sh` was **harmful**: it contained
  `brctl addif br0 apcli0` and a `telnetd -p 2323` backdoor. The installer now
  backs it up as `autorun.sh.old` and installs a safe wrapper. A patched
  `libbbx.so` drop-in was investigated for the rootfs boot path (not
  distributed in this repo); no running process maps such a library. See
  `BOOT_PERSISTENCE.md` for the confirmed boot-hook findings.
- The router’s own resolver (`/etc/resolv.conf -> /var/tmp/default_resolv.conf`)
  contains the literal placeholders `wancid`/`IPMode`, so router-origin DNS fails.
  Clients do not depend on it: DHCP hands out `8.8.8.8`/`1.1.1.1`, which work
  through NAT; dnsmasq itself answers `dig @192.168.12.1` correctly.
- The exact working scripts are `payload/repeater_up.sh`
  (poke/scan/associate/DHCP/NAT), `payload/verify_repeater.sh` (read-only
  state/DNS check), and `src/build_kmemtool.py`.
