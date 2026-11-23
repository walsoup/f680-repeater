#!/bin/sh
# verify_repeater.sh -- read-only post-fix verification + DNS diagnostics.

exec > /userconfig/verify_repeater.out 2>&1
K=/userconfig/kmemtool
B7=$(cat /sys/module/mt7615_ap/sections/.bss 2>/dev/null)
. /userconfig/last_lease 2>/dev/null
. /userconfig/upstream.conf 2>/dev/null

if [ -z "$UP_AUTH" ]; then
    if [ -n "$UP_PSK" ]; then
        UP_AUTH='wpa2-psk'
    else
        UP_AUTH='open'
    fi
fi

CRITICAL_FAIL=0

echo "=== 1. FIX STATE ==="
echo "mt7615 .bss = $B7"
if [ -z "$B7" ]; then
    echo "ERROR: mt7615_ap .bss not found"
    CRITICAL_FAIL=1
fi

echo -n "cg_hdswitch_on = "
CG=$("$K" /dev/kmem "$B7" f1c r 2>/dev/null)
echo "$CG"
if [ "$CG" != "00" ]; then
    echo "ERROR: cg_hdswitch_on is '$CG' (expected 00)"
    CRITICAL_FAIL=1
fi

echo -n "proc mt7603e on = "
cat /proc/wifi_hdswitch/on 2>/dev/null

WLAN4_IRQ=$(awk -F: '/wlan4/{print $1+0;exit}' /proc/interrupts 2>/dev/null)
if [ -n "$WLAN4_IRQ" ] && [ "$WLAN4_IRQ" -gt 0 ] 2>/dev/null; then
    WLAN4_AFF=$(cat "/proc/irq/$WLAN4_IRQ/smp_affinity" 2>/dev/null)
    echo "wlan4 irq = $WLAN4_IRQ (smp_affinity=${WLAN4_AFF:-unknown})"
else
    echo "wlan4 irq = not found"
fi

echo "=== 1b. RSN IE CAPABILITY, MLME ASSOC & PMF BIP MASKS ==="
TXT=$(cat /sys/module/mt7615_ap/sections/.text 2>/dev/null)
if [ -z "$TXT" ]; then
    echo "ERROR: mt7615_ap .text section not found"
    CRITICAL_FAIL=1
else
    RSN1_BYTE=$("$K" /dev/kmem "$TXT" 90e08 r 2>/dev/null)
    RSN2_BYTE=$("$K" /dev/kmem "$TXT" 4b91c r 2>/dev/null)
    RSN3_BYTE=$("$K" /dev/kmem "$TXT" 11ca57 r 2>/dev/null)
    echo "wpamakersnie+0xf8 = $RSN1_BYTE"
    echo "apclimassoc+0x29c = $RSN2_BYTE"
    echo "pmf_bip+0x5b = $RSN3_BYTE"
    case "$UP_AUTH:$RSN1_BYTE:$RSN2_BYTE:$RSN3_BYTE" in
        wpa2-eap:d0:d0:ea)
            echo "rsn_patch = applied (capability and assoc masks 0xd0, pmf bip 0xea)"
            ;;
        wpa2-eap:*)
            echo "ERROR: enterprise mode expects WPAMakeRSNIE+0xf8 == d0, ApCliMlmeAssocReqAction+0x29c == d0, PMF_MakeRsnIeGMgmtCipher+0x5b == ea (got site1='$RSN1_BYTE' site2='$RSN2_BYTE' site3='$RSN3_BYTE')"
            CRITICAL_FAIL=1
            ;;
        *:d0:d0:ea)
            echo "NOTE: driver text still patched from an earlier enterprise run (RAM only)"
            ;;
        *:90:90:1a)
            echo "rsn_patch = not applied (normal for PSK/Open)"
            ;;
        *)
            echo "WARNING: unexpected driver patch state site1='$RSN1_BYTE' site2='$RSN2_BYTE' site3='$RSN3_BYTE'"
            CRITICAL_FAIL=1
            ;;
    esac
    if grep -q '^f680_rsn_patch ' /proc/modules 2>/dev/null; then
        echo "WARNING: f680_rsn_patch is still loaded"
        CRITICAL_FAIL=1
    else
        echo "rsn_patch module = not loaded"
    fi
fi

echo "=== 2. AUTH & SECURITY CONFIG ==="
echo "auth_mode = $UP_AUTH"
if [ "$UP_AUTH" = "wpa2-eap" ]; then
    echo "identity = $UP_EAP_IDENTITY"
    if [ -x /userconfig/eap_ttls ]; then
        echo "eap_ttls binary = PRESENT (executable)"
    else
        echo "ERROR: /userconfig/eap_ttls missing or not executable"
        CRITICAL_FAIL=1
    fi
    if [ -n "$UP_EAP_CA" ]; then
        if [ -f "$UP_EAP_CA" ]; then
            echo "ca_certificate = PRESENT ($UP_EAP_CA)"
        else
            echo "ERROR: CA certificate file '$UP_EAP_CA' not found"
            CRITICAL_FAIL=1
        fi
    fi
    echo "--- eap_ttls --verify-kmem ---"
    /userconfig/eap_ttls --verify-kmem 2>&1
    if [ $? -ne 0 ]; then
        echo "ERROR: eap_ttls --verify-kmem failed"
        CRITICAL_FAIL=1
    fi
elif [ "$UP_AUTH" = "wpa2-psk" ]; then
    if [ -z "$UP_PSK" ]; then
        echo "WARNING: UP_PSK is empty for wpa2-psk"
        CRITICAL_FAIL=1
    fi
fi

echo "=== 3. APCLI0 & ROUTING ==="
ifconfig apcli0 2>/dev/null
if ! ifconfig apcli0 2>/dev/null | grep -q 'inet addr:'; then
    echo "ERROR: apcli0 has no IPv4 address assigned"
    CRITICAL_FAIL=1
fi

ip route show 2>/dev/null | sed -n '1,12p'
if ! ip route show 2>/dev/null | grep -q 'default.*apcli0'; then
    echo "ERROR: default route via apcli0 not found"
    CRITICAL_FAIL=1
fi
ip neigh show dev apcli0 2>/dev/null

echo "=== 4. COUNTERS ==="
grep -E 'apcli0|idm0' /proc/net/dev

echo "=== 5. MANGLE ==="
iptables -t mangle -nvL PREROUTING 2>/dev/null | sed -n '1,12p'

echo "=== 6. NAT & FORWARDING ==="
iptables -t nat -nvL POSTROUTING 2>/dev/null | sed -n '1,15p'
if ! iptables -t nat -nvL POSTROUTING 2>/dev/null | grep -q 'MASQUERADE.*apcli0'; then
    echo "ERROR: MASQUERADE rule for apcli0 missing in nat table"
    CRITICAL_FAIL=1
fi
iptables -nvL FORWARD 2>/dev/null | sed -n '1,15p'

echo "=== 7. RESOLV FILES ==="
ls -l /etc/resolv.conf /var/tmp/default_resolv* 2>/dev/null
for f in /var/tmp/default_resolv*; do
    [ -f "$f" ] || continue
    echo "-- $f"
    sed -n '1,20p' "$f" 2>/dev/null
done

echo "=== 8. DNSMASQ ==="
ps 2>/dev/null | grep -i dnsmasq | sed -n '1,10p'
echo "=== 8b. F680_DNS CHAIN ==="
iptables -t nat -L F680_DNS -n 2>/dev/null

echo "=== 9. ROUTER PING & REACHABILITY ==="
SRC=$(ifconfig apcli0 2>/dev/null | awk '/inet addr/ {print $2}' | sed 's/addr://')
GW=$(ip route show dev apcli0 2>/dev/null | awk '/default/ {print $3}')
[ -n "$GW" ] || GW="$LAST_GATEWAY"
[ -n "$SRC" ] || SRC="$LAST_IP"

if [ -n "$SRC" ] && [ -n "$GW" ]; then
    ping -c 2 -T 1 -I "$SRC" "$GW"
    GW_PING=$?
    ping -c 2 -T 1 -I "$SRC" 1.1.1.1
    P1_PING=$?
    if [ "$GW_PING" = "0" ] && [ "$P1_PING" != "0" ]; then
        echo "NOTE: upstream gateway reachable, but external ICMP to 1.1.1.1 not reachable (perhaps no internet access or ICMP blocked)"
    fi
else
    echo "ERROR: missing IP address or default gateway for ping test (src='$SRC' gw='$GW')"
    CRITICAL_FAIL=1
fi

if [ "$CRITICAL_FAIL" -eq 1 ]; then
    echo "STATUS: FAILED"
    exit 1
fi

echo "STATUS: OK"
exit 0
