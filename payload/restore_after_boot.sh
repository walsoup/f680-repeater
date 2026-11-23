#!/bin/sh
# restore_after_boot.sh -- preserve failed-boot log, then run repeater_up.
trap '' HUP
exec > /userconfig/restore_after_boot.out 2>&1

cp /userconfig/repeater_boot.log /userconfig/repeater_boot.log.failed_boot 2>/dev/null
echo "=== running repeater_up.sh ==="
sh /userconfig/repeater_up.sh
echo "repeater_up_rc=$?"

B7=$(cat /sys/module/mt7615_ap/sections/.bss 2>/dev/null)
echo "bss=$B7"
echo -n "cg="; /userconfig/kmemtool /dev/kmem "$B7" f1c r
echo "=== lease_ok ==="
ls -l /userconfig/lease_ok /userconfig/last_lease 2>/dev/null
echo "=== apcli0 ==="
ifconfig apcli0 2>/dev/null | sed -n '1,8p'
ip route show 2>/dev/null | sed -n '1,8p'
echo "=== brctl ==="
brctl show 2>/dev/null
echo "DONE"
