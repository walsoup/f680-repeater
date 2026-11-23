# How it works

This is the short technical version. The full disassembly and evidence are in
[`TECHNICAL_REPORT.md`](TECHNICAL_REPORT.md) and
[`PHASE12_FINDINGS.md`](PHASE12_FINDINGS.md).

## The receive path

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

- `skb->dev` is at `skb+0x18`; `skb->protocol` at `skb+0xbc`.
- Before `netif_rx`, the function does `skb_pull(skb, 14)`.
- AP VAPs (`wlan4..7`) set `dev+0x470 = 1` in `MBSS_Init` → `idm1` (LAN/CPU).
- APCLI (`apcli0`) is zero-initialized and never written → `0` → `idm0`
  (WAN/GPON).

`wlan_hardforward_init` resolves `idm0`/`idm1` by name, reads
`netdev_priv(idm)+0x10` (the IDM driver callback), and fills
`wifihdswitchhandler[0/1]` and `idmdev[0/1]`. It sets the **module’s own**
`cg_hdswitch_on = 1`.

## Why `/proc/wifi_hdswitch/on` was a red herring

The proc file is created by **mt7603e only**. It reads/writes the 2.4 GHz copy
at mt7603e `.bss+0x764`. The 5G module has a separate copy at
**mt7615 `.bss+0xf1c`**. Setting the proc file to `0` never touched the 5G
copy, so APCLI RX kept going to `idm0`.

The calibration in the original investigation tracked the mt7603e copy while
toggling the proc file (`01 -> 00 -> 01`), proving `/dev/kmem` access; the 5G
copy was then poked separately.

## The one-byte fix

```sh
B7=$(cat /sys/module/mt7615_ap/sections/.bss)
/userconfig/kmemtool /dev/kmem "$B7" f1c r   # 01
/userconfig/kmemtool /dev/kmem "$B7" f1c w 00
```

`kmemtool` is a 1,048-byte static ARM EABI5 ELF, built with Keystone:

- 181 real integer instructions; zero VFP/NEON.
- `open=5`, `read=3`, `write=4`, `_llseek=140`, `exit=1`.
- `_llseek` uses `offset_high=0`, `offset_low=target` (zero-extended).

The `.bss` base changes every boot; read it from sysfs first.

## DHCP

The client (`udhcpc`, Rust `armv7-unknown-linux-musleabi`, static, soft-float)
sends DISCOVER/OFFER/REQUEST/ACK and runs `/bin/sh udhcpc.script bound`
with the BusyBox-compatible environment.

The test upstream drops **broadcast** DHCP from the APCLI's
locally-administered MAC, but accepts **unicast** DHCP from
an existing `.112` to the gateway. `repeater_up.sh` therefore:

1. seeds the last lease from `/userconfig/last_lease`;
2. runs `udhcpc --server-ip <last_gateway>` (unicast DISCOVER);
3. falls back to broadcast if there is no last lease or unicast fails;
4. writes `/userconfig/lease_ok` only when the DHCP script succeeds.

## NAT

Ordinary Linux forwarding:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o apcli0 -j MASQUERADE
iptables -I FORWARD 1 -i br0 -o apcli0 -j ACCEPT
iptables -I FORWARD 2 -i apcli0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 1 -i apcli0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -i apcli0 -p udp --dport 68 -j ACCEPT
```

`apcli0` is never added to `br0`; this is routed NAT, not a bridge.

## Transparent DNS DNAT (F680_DNS)

On institutional networks that block public DNS (e.g. `8.8.8.8:53`), client DNS queries are intercepted and redirected to the dynamic upstream DNS server discovered by DHCP:

```sh
iptables -t nat -N F680_DNS 2>/dev/null || true
iptables -t nat -F F680_DNS
iptables -t nat -D PREROUTING -i br0 -j F680_DNS 2>/dev/null
iptables -t nat -I PREROUTING 1 -i br0 -j F680_DNS
iptables -t nat -A F680_DNS -p udp --dport 53 -j DNAT --to-destination "${first_dns}:53"
iptables -t nat -A F680_DNS -p tcp --dport 53 -j DNAT --to-destination "${first_dns}:53"
```

DNS pool settings are simultaneously pushed to local DHCP clients using RAM-only `sendcmd 1 DB set DHCP4sPool ...` (without `sendcmd 1 DB save` to protect JFFS2 flash life).

## WPA2-Enterprise (802.1X / EAP-TTLS) Path

When operating in enterprise mode:
1. **Driver 3-Site Kernel Patch (`payload/f680_rsn_patch.ko`):**
   - Site 1 (`0x90e08`): enables bit `0x40` in RSN IE capability mask.
   - Site 2 (`0x4b91c`): updates MLME association request mask to `0x001000d0`.
   - Site 3 (`0x11ca54`): forces unconditional branch to insert BIP-128 cipher `00-0F-AC:6` (bypassing uninitialized `igtk_cipher` in STA mode).
2. **EAP-TTLS Authenticator (`payload/eap_ttls`):**
   - Intercepts raw EAPOL packets via `jt0` hook at `.text + 0x902a4` / `0x90244`.
   - Establishes TLS tunnel and completes inner PAP credential exchange.
   - Injects the computed PMK into the driver via `/dev/kmem`. The native mt7615 driver then handles the 4-Way Handshake and installs PTK/GTK hardware keys.
3. **Queue Depth Tuning:**
   - Client interface queue length is set to `ifconfig apcli0 txqueuelen 100` to prevent bufferbloat and latency spikes on the Cortex-A9 SoC.

## Boot

The safe `autorun.sh` wrapper is installed, but the stock firmware does not
execute it. `pc` maps the stock `/lib/libbbx.so`; only a patched drop-in
(not distributed in this repo) with a constructor could run the wrapper, and
nothing loads one. See [`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md).
