# Boot persistence

## The short version

The stock firmware does **not** run `/userconfig/autorun.sh`. The controlled
reboot proved it. After a reboot:

```
repeater_boot.log: stale
cg_hdswitch_on:    01
apcli0:            down, no IP
NAT:               absent
client internet:   failed
```

The 2.4 GHz AP, LAN `192.168.12.1`, and DHCP come back, so management is fine.
Only the repeater bring-up is missing.

Run this from the router root shell after a reboot:

```sh
sh /userconfig/restore_after_boot.sh
cat /userconfig/restore_after_boot.out
```

It preserves the failed boot log and reruns `repeater_up.sh` (cg 01→00, scan,
associate, DHCP, NAT). Takes ~40 seconds. Verified immediately after the
controlled reboot.

## Why autorun.sh does not run

The real loader is not `/userconfig/autorun.sh`:

- `pc` (PID 604) maps the stock **`/lib/libbbx.so`**.
- `pc` has `NEEDED libbbx.so` and **no RPATH/RUNPATH**.
- `/etc/ld.so.preload` is empty.
- `/etc/ld.so.conf` is empty; the loader resolves `libbbx.so` from `/lib`.

The investigated trigger was a **drop-in patched `libbbx.so`**: exactly the
same size as `/lib/libbbx.so` (12,591 bytes), exporting the same `libbbx` API
(`OssUserBbxInit`, `OssGetBbxAddr`, `bbxUserSetKeyParam`, `bbxGetMagic`,
`Omci_Iot_Test_Init`, …), with an `INIT_ARRAY` constructor whose strings
include:

```
/bin/sh
/userconfig/autorun.sh
```

No vendor binary is distributed in this repo (an earlier draft named such a
file `libomcipatch.so`; it has been removed). When loaded, its constructor runs
`/bin/sh /userconfig/autorun.sh`. Nothing loads it at boot on the stock
firmware, so the wrapper never runs.

`cspd`’s `usrcfgExt`/`dlopen` strings are not a library loader; the
`usrcfgExt` context is LAN DHCP source/rule handling.

## What the boot chain does

- `/etc/init.d/rcS` mounts `/userconfig`, `/usr/local/ct`, `/wlan`,
  `/usercustom`.
- It runs `/etc/rcS.d/S31emacs`, `S40network`, `S43BSPDriver`, `S99modules`.
- `S99modules` loads `optical`, `zx_ponreg`, `tm`, `netdriver`, `zte_gpon`,
  `gpondrv`, `zte_xgmii`, `switch`, `kudp`, `voip_codec`, `dsp_dev`,
  `ptpdrv`, `y1731drv`.
- At the end of `rcS` it runs `pc&`.
- There is no user-script hook. `/usr/local/ct` and `/usercustom` are empty;
  `/wlan` is calibration only. `/userconfig/ttyredir.cfg` is a `redir`
  (printk/printf to file) hook, not an execute hook. `sendcmd 1 DB all` has no
  user-script/auto-run object.

## The exact trigger needed

Before `pc&` starts, one of these must happen:

1. `/lib/libbbx.so` must be a patched drop-in (replace or bind-mount it),
   **or**
2. `pc` must be started with the patched library preloaded (e.g.
   `LD_PRELOAD=<patched-libbbx.so>`, or `LD_LIBRARY_PATH=<dir>` with a
   `libbbx.so` name).

There is **no userland hook** to do either on the stock read-only rootfs.

## Options

### A. Rootfs replacement (true zero-assistance, risky)

Replace `/lib/libbbx.so` with a patched drop-in on the jffs2
rootfs. Requires remounting `/` rw (or an equivalent rootfs write). This is
outside the project’s “persistent files only in `/userconfig`” rule and has
**no UART recovery**. It is not the default; no patched library is shipped,
so this path is research-only unless you build your own. Back up the stock
file first.

### B. Manual recovery (safe, default)

After each reboot:

```sh
sh /userconfig/restore_after_boot.sh
```

or from the laptop:

```sh
cd f680-repeater
./start-repeater.sh --restore
```

### C. External travel router / F680 as AP

If you need true zero-touch boot, a dedicated travel router is the lower-risk
option. The F680’s runtime fix is real, but its boot chain is vendor-locked.

## Current state after the controlled reboot

- 2.4 GHz AP / LAN / DHCP: up
- `cg_hdswitch_on`: `01` (boot default)
- `apcli0`: down
- NAT: absent
- manual `restore_after_boot.sh`: restores everything
- failed log preserved at `/userconfig/repeater_boot.log.failed_boot`
