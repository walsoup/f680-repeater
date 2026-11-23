# Factory unlock

The guided onboarding script (`start-repeater.sh` / `start-repeater.bat`) performs the factory unlock
for you. It includes the `webFac` handshake in `tools/onboard.py` +
`tools/zte_factorymode.py`.

What it asks for:

1. **Router LAN IP** — default `192.168.12.1` (the project’s documented LAN).
   If your F680 is still on its factory LAN IP, pass `--ip <that-ip>` only
   when you are sure it is the F680, not the upstream AP.
2. **Known Factory Passwords** — the script automatically tests standard
   ZTE factory backdoor keys (`factorymode` / `nE%jA@5b` and variants adapted from
   `douniwan5788/zte_modem_tools`).
3. **GPON serial** — `ZTEG...` on the label. It is optional and used as a fallback.
4. **Custom Factory password** — only if default candidates fail, or supplied via
   `--factory-pass`.

The handshake is rate-limited. If it fails with `facStep 3: info error`, wait
2–5 minutes and try once. Do not hammer it.

Once unlocked, the installer logs into the Mode 2 (`#`) root telnet, runs the
router-side 5G scan, installs the payload, and enables NAT. It never touches the
upstream AP.

The serial is also the standard root-telnet password on many F680s. The guided
flow uses the factory handshake’s dynamic login; the serial is a fallback
candidate, not a guarantee.
