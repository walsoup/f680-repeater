# Disclaimer

This project modifies the runtime behavior of a ZTE ZXHN F680. It is provided
for educational and personal use on hardware you own.

- **No warranty.** The authors are not responsible for bricked routers, lost
  data, ISP violations, or any other damage.
- **No UART recovery.** The F680 has no exposed UART in this setup. A bad
  persistent change can leave it unreachable.
- **Read-only upstream.** Do not modify, reboot, or write to the upstream AP.
- **Credentials.** The factory unlock password is device/firmware-specific and
  is not included. The upstream Wi-Fi PSK belongs in
  `/userconfig/upstream.conf` (mode 600), never in this repo.
- **Firmware-specific.** The offsets, symbols, and boot scripts were verified
  on `ZTEGF680606MA` / Linux 4.1.25. Other builds may differ.
- **Legal.** Use only on networks you are authorized to use, and follow your
  ISP/dorm’s terms of service.

If you are not comfortable with a no-UART, rootfs-level risk, stop at the
runtime fix and use the manual recovery path in
[`docs/BOOT_PERSISTENCE.md`](docs/BOOT_PERSISTENCE.md).
