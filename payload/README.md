# Payload

These are the files served to the F680. They are designed to live in
`/userconfig` (JFFS2 mtd5) and survive a reboot.

| File | What it is |
| :--- | :--- |
| `kmemtool` | 1 KB static ARM EABI5 helper for `/dev/kmem` read/write. Source: `src/build_kmemtool.py`. |
| `udhcpc` | 454 KB static soft-float ARM DHCP client. Source: `src/udhcpc.rs`. |
| `eap_ttls` | ~1 MB static soft-float ARM WPA2-Enterprise (EAP-TTLS/PAP) authenticator and kernel PMK injector. Source: `src/eap_ttls/`. |
| `f680_rsn_patch.ko` | ~1.9 KB Linux 4.1.25 ARM module: unblocks WPA2-Enterprise RSN IE and PMF BIP cipher at 3 sites in `mt7615_ap.ko` under `stop_machine`. Enterprise only. Source: `src/build_rsn_patch.py`. |
| `udhcpc.script` | Lease applier; writes `last_lease` and `lease_ok`. |
| `repeater_up.sh` | Bring-up: wait, SMP IRQ balancing, `cg` poke, enterprise RSN patch + EAP, scan, associate, DHCP, NAT. |
| `restore_after_boot.sh` | Post-reboot recovery; preserves the failed boot log and reruns `repeater_up.sh`. |
| `verify_repeater.sh` | Read-only state/NAT/DNS/IRQ check. |
| `autorun.sh` | Safe non-blocking wrapper: `( sleep 25; repeater_up.sh ) &`. |
| `upstream.conf.example` | Credentials template. Copy to `/userconfig/upstream.conf`, fill, `chmod 600`. |

## Important

The prebuilt `eap_ttls` is stripped; its embedded Rust panic-location strings
were rewritten to neutral `/tmp/rust/...` paths so no developer home directory
is published. Rebuilding it locally may embed your own paths.

No vendor firmware binary is distributed in this repo. The stock firmware
loads `/lib/libbbx.so` for `pc`; only a patched drop-in (not shipped) could
hook the rootfs boot path, and there is no userland hook for that on the
stock rootfs. Do not replace `/lib/libbbx.so` unless you have read
`docs/BOOT_PERSISTENCE.md` and accept the no-UART risk.

The `autorun.sh` wrapper is harmless to install; the stock firmware simply
never executes it. The safe workflow after a reboot is:

```sh
sh /userconfig/restore_after_boot.sh
```

## Confirmed Hardware Quirks

When maintaining or debugging router scripts, keep these verified findings in mind:

- **5 GHz upstream only:** Stock `mt7603e_ap.ko` (2.4 GHz) is compiled without `CONFIG_APCLI_SUPPORT`, operating strictly in Access Point mode. Only the 5 GHz `mt7615_ap.ko` driver exposes `apcli0`. All client/repeater connections must be made via `apcli0` on 5 GHz, leaving `wlan0` dedicated to serving local 2.4 GHz clients.
- **Bogus `apcli0` rx_dropped counter:** `/proc/net/dev` and `ifconfig apcli0` report an uninitialized drop count (~3.3 billion) that fluctuates up and down. This is a stock `mt7615_ap.ko` driver statistics bug, not real packet loss. Forwarded client traffic operates with 0% real drop.
- **SMP IRQ balancing:** The dual-core Cortex-A9 SoC routes hardware interrupts to CPU0 by default. Under heavy Wi-Fi traffic, concurrent 5 GHz RX/TX, 2.4 GHz (`wlan0`), and Ethernet softirqs cause CPU0 starvation. `repeater_up.sh` dynamically routes the 5 GHz PCIe interrupt (`wlan4`) to CPU1 (`smp_affinity=2`) while CPU0 handles 2.4 GHz and Ethernet.
