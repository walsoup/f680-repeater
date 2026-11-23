# Evidence

Sanitized outputs from the working test. Full disassembly:
[`TECHNICAL_REPORT.md`](TECHNICAL_REPORT.md) and
[`PHASE12_FINDINGS.md`](PHASE12_FINDINGS.md).

## Calibration against mt7603e

Toggling `/proc/wifi_hdswitch/on` while reading mt7603e `.bss+0x764`:

```
proc on before: 1   kmem: 01
proc on zero:   0   kmem: 00
proc on restore:1   kmem: 01
CAL_PASS
```

This proved `/dev/kmem` module-space addressing before touching the 5G byte.

## The 5G poke

```
mt7615 .bss = 0xbf7de920
cg_hdswitch_on = .bss + 0xf1c = 0xbf7df83c
before: 01
write 00: 00
readback: 00
```

## RX fix

```
static ARP ping 198.51.100.1:  5/5, 0% loss
dynamic ARP ping 198.51.100.1: 5/5, 0% loss
mangle PREROUTING -i apcli0:   13 packets / 1092 bytes
idm0 TX:                       3228090/23770 before AND after (frozen)
apcli0 RX: 23932 -> 23951 (+19)
apcli0 TX: 788 -> 802 (+14)
```

## DHCP

```
udhcpc: OFFER 198.51.100.112 server 198.51.100.1
udhcpc: ACK   198.51.100.112 router 198.51.100.1
              dns 198.51.100.1 lease 86400
udhcpc: script /userconfig/udhcpc.script bound ok
udhcpc: renew in 43200s
```

## Client path

```
DHCP: 192.168.12.50/24 via 192.168.12.1
dig @192.168.12.1 example.com -> NOERROR
  A 172.66.147.243 / 104.20.23.154
getent hosts example.com -> resolves
curl http://example.com -> HTTP=200
ping 8.8.8.8 -> 2/2, 0% loss
NAT: MASQUERADE 113/23835; FORWARD 400/928
```

## Boot-script dry run

```
cg_before=01 -> cg_after=00 -> cg_final=00
scan_choice=02:00:00:00:00:03 60 WPA2-PSK-AES
assoc_last=... TX_EAPOL_PAIR_MSG_4 ... -> association M4 seen
udhcpc: ACK 198.51.100.112 ... lease 86400
udhcpc: script bound ok; renew in 43200s
brctl show: no apcli0
client test: INTERNET WORKS
```

## Controlled reboot

```
2.4 GHz AP / LAN / DHCP: up
repeater_boot.log: stale
cg_hdswitch_on: 01
apcli0: down, no IP
NAT: absent
client internet: failed
```

This is why `restore_after_boot.sh` exists. It was run immediately after the
reboot and restored `cg=00`, the lease, NAT, and the client path.

## WPA2-Enterprise 3-Site Kernel Driver Patch Evidence

```
mt7615 .text = 0xbf55d000
Site 1 (WPAMakeRSNIE+0xf8 @ .text+0x90e08):
  before: e3130090 (byte: 90) -> after: e31300d0 (byte: d0)
Site 2 (ApCliMlmeAssocReqAction+0x29c @ .text+0x4b91c):
  before: e3a03090 (byte: 90) -> after: e3a030d0 (byte: d0)
Site 3 (PMF_MakeRsnIeGMgmtCipher+0x58 @ .text+0x11ca54):
  before: 1a000021 (byte: 1a) -> after: ea000021 (byte: ea)
readback verification: PASS (d0:d0:ea)
f680_rsn_patch: unloaded cleanly after RAM patch execution
```

## EAP-TTLS Authentication & PMK Export

```
eap_ttls: binding AF_PACKET raw socket on apcli0
eap_ttls: hooked jt0 receive vector at mt7615 .text+0x902a4
eap_ttls: received EAP-Request/Identity -> sent EAP-Response/Identity
eap_ttls: TLS 1.3 tunnel established (CA verification: OK)
eap_ttls: inner EAP-TTLS-PAP exchange -> Access-Accept
eap_ttls: derived PMK -> exported to mt7615 driver structure via /dev/kmem
mt7615: processing 4-Way Handshake -> TX_EAPOL_PAIR_MSG_4
mt7615: WPAInstallKey installed PTK and GTK hardware cipher keys
```

## Transparent DNS DNAT (F680_DNS)

```
Chain F680_DNS (1 references)
 pkts bytes target     prot opt in     out     source               destination         
   42  2856 DNAT       udp  --  *      *       0.0.0.0/0            0.0.0.0/0           udp dpt:53 to:198.51.100.1:53
    0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:53 to:198.51.100.1:53
```

## What failed

- `/proc/wifi_hdswitch/on = 0`: only mt7603e; 5G kept mirroring.
- `/proc/wifi_hdswitch/attach_function = 0`: NULLs the global `idm_skb_recv`
  TX hook; freezes APCLI RX.
- `br1` containing `apcli0`: no upstream MAC learned, no ping.
- `ip link set idm0 down`, promisc, FFE/NPU off, multiapd STOP,
  `MapEnable`/`MWDS` toggles: no change.
- `switchtst`: only eth0–eth3; `-getacl` segfaults.
- `ifconfig apcli0 hw ether ...`: ignored.
- Broadcast DHCP on the test upstream: no reply; unicast works.
