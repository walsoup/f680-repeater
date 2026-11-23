# Limitations

These are the real constraints found on the test unit. Read this before
expecting a perfect zero-touch repeater.

## 1. Boot persistence is not automatic

The stock firmware does not execute `/userconfig/autorun.sh`. `pc` loads the
stock `/lib/libbbx.so`; only a patched same-size drop-in (not distributed in
this repo) with a constructor could run the wrapper, but there is no userland
hook to load one before `pc&`.

- Safe path: run `/userconfig/restore_after_boot.sh` after every reboot.
- Zero-assistance path: replace `/lib/libbbx.so` on the rootfs. This is a
  read-only jffs2 rootfs write, outside the project’s `/userconfig`-only rule,
  and there is **no UART recovery**. It is not the default.

See [`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md).

## 2. Broadcast DHCP is blocked on the test upstream

The test upstream is a wireless router. It drops **broadcast** DHCP from the APCLI's
locally-administered MAC:

- 4 DISCOVERs counted in `OUTPUT udp dport 67`
- `PREROUTING udp dport 68` stayed at 0
- no OFFER

**Unicast** DHCP from an existing `.112/24` to `198.51.100.1:67` works
immediately:

```
OFFER 198.51.100.112 server 198.51.100.1
ACK   198.51.100.112 router 198.51.100.1
      dns 198.51.100.1 lease 86400
```

`repeater_up.sh` therefore uses the saved `last_lease` + unicast DISCOVER first,
with broadcast fallback. On a brand-new AP that also blocks broadcast DHCP, you
need a one-time static/unicast seed, or a different AP.

## 3. The APCLI MAC is fixed

The driver assigns a locally-administered APCLI MAC (derived from the 5G radio). There is no
APCLI MAC setter in `mt7615_ap.ko`; `ifconfig apcli0 hw ether ...` is ignored.
This is likely why the upstream’s DHCP snooping treats it differently from a
normal laptop.

## 4. Transparent DNS Redirection on Institutional Networks

Institutional and corporate networks frequently drop external UDP/TCP port 53 traffic to public resolvers (`8.8.8.8` / `1.1.1.1`). The repeater automatically intercepts client DNS queries on `br0` via the `F680_DNS` netfilter chain and transparently redirects them to the dynamic upstream DNS server discovered via DHCP.

## 5. The 5G AP VAPs also switch to `netif_rx`

Setting `cg_hdswitch_on=0` affects the whole 5G RX path, not only APCLI. AP VAPs
(`wlan4..7`) will use `netif_rx` instead of the IDM/idm1 callback. In practice
this is the normal Linux path and should work, but if you rely on the 5G AP
SSIDs, test them. The 2.4 GHz AP (`wlan0`) is untouched.

## 6. Firmware-specific

This work targets:

- ZTE ZXHN F680 V6.0 (`ZTEGF680V60`)
- vendor firmware `ZTEGF680606MA`
- Linux 4.1.25, MediaTek MT7615E + MT7603E
- soft-float EABI, no VFP/NEON

Other firmware builds may have different symbols, offsets, or boot scripts.
Re-check `mt7615_ap.ko`/`mt7603e_ap.ko` before reusing the offset.

## 7. No raw MTD, no `br0` MAC clone, no `cspd` kill

- Never write raw `/dev/mtd*`; no UART recovery.
- Never clone `br0`’s MAC to `apcli0`’s MAC; it kills TCP management.
- Never kill `cspd`.
- Keep persistent files in `/userconfig` unless you explicitly accept the
  rootfs risk.

## 8. The old bridge/telnetd script is harmful

The original `/userconfig/autorun.sh` contained:

- `brctl addif br0 apcli0` (L2 bridge; breaks NAT/management)
- `telnetd -l /bin/sh -p 2323` (unauthenticated backdoor)

The installer preserves it as `autorun.sh.old` and installs the safe wrapper.
Do not restore the old one.

## 9. Upstream is read-only

Do not modify the upstream AP. No config changes, no reboots, no writes. The
fix is entirely on the F680.

## 10. Legal / ethical

Use this only on hardware you own and networks you are authorized to use.
Respect your ISP/dorm’s terms of service. No vendor firmware binary is
distributed in this repo.

## 11. Uninitialized 1970 System Clock on TLS Validation

At cold boot, the F680 clock initializes to January 1, 1970 (no RTC or NTP prior to network connection). The standalone `eap_ttls` daemon accommodates the pre-epoch clock so CA certificate validity periods (`notBefore` / `notAfter`) are handled gracefully without false validation rejections.

## 12. Reverse HTTP Uploads Require Direct LAN / Wi-Fi

During full onboarding (`start-repeater.sh`), the router downloads payload files from the host computer using HTTP `wget`. If connected via a one-way loopback proxy (such as an ESP32 serial bridge with `192.168.12.1/32 dev lo`), the router attempts to fetch from its own address and fails (`upload_verification`). Full onboarding uploads require the host computer to be connected directly to the F680's Wi-Fi (`La_Fibre_dOrange_2.4G_C9F6` or `5G_C9F6`) or Ethernet LAN. Post-boot recovery (`--restore`) avoids HTTP downloads entirely.
