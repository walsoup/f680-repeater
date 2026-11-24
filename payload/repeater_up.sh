#!/bin/sh
# repeater_up.sh -- boot-time standalone repeater bring-up.
# Never bridges apcli0, never touches br0/wlan0, never starts telnetd.
trap '' HUP

if ! mkdir /tmp/f680_repeater_up.lock 2>/dev/null; then
    echo "repeater_up is already running; abort"
    exit 1
fi
trap 'rmdir /tmp/f680_repeater_up.lock 2>/dev/null' EXIT INT TERM

LOG=/userconfig/repeater_boot.log
exec > "$LOG" 2>&1

echo "=== repeater_up start ==="
date

killall -9 udhcpc eap_ttls 2>/dev/null
sleep 1
iwpriv apcli0 set ApCliEnable=0 2>/dev/null

# 0. Never leave apcli0 bridged into br0.
brctl delif br0 apcli0 2>/dev/null

# 1. Wait up to 90 s for mt7615 .bss + apcli0.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45; do
    if [ -f /sys/module/mt7615_ap/sections/.bss ] && grep -q 'apcli0' /proc/net/dev 2>/dev/null; then
        break
    fi
    sleep 2
done
if [ ! -f /sys/module/mt7615_ap/sections/.bss ]; then
    echo "timeout: mt7615_ap .bss missing"
    exit 1
fi
if ! grep -q 'apcli0' /proc/net/dev 2>/dev/null; then
    echo "timeout: apcli0 missing"
    exit 1
fi
echo "module + apcli0 ready"
sleep 5
ps 2>/dev/null | grep -E 'cspd|wlan_mgr' | sed -n '1,10p'

# 1b. Pin 5 GHz PCIe IRQ (wlan4) to CPU1 so softirqs do not contend on CPU0.
WLAN4_IRQ=$(awk -F: '/wlan4/{print $1+0;exit}' /proc/interrupts 2>/dev/null)
if [ -n "$WLAN4_IRQ" ] && [ "$WLAN4_IRQ" -gt 0 ] 2>/dev/null; then
    echo 2 > "/proc/irq/$WLAN4_IRQ/smp_affinity" 2>/dev/null
    WLAN4_AFF=$(cat "/proc/irq/$WLAN4_IRQ/smp_affinity" 2>/dev/null)
    echo "wlan4_irq=$WLAN4_IRQ smp_affinity=${WLAN4_AFF:-none}"
else
    echo "wlan4_irq=none smp_affinity=none"
fi

# 2. Verify and clear mt7615 cg_hdswitch_on.
B7=$(cat /sys/module/mt7615_ap/sections/.bss 2>/dev/null)
echo "bss=$B7"
CG=$(/userconfig/kmemtool /dev/kmem "$B7" f1c r)
echo "cg_before=$CG"
case "$CG" in
    01)
        /userconfig/kmemtool /dev/kmem "$B7" f1c w 00
        CG2=$(/userconfig/kmemtool /dev/kmem "$B7" f1c r)
        echo "cg_after=$CG2"
        if [ "$CG2" != "00" ]; then
            echo "cg write failed; abort"
            exit 1
        fi
        ;;
    00)
        echo "cg already 00"
        ;;
    *)
        echo "cg unexpected: $CG; abort without writing"
        exit 1
        ;;
esac

# 3. Upstream credentials.
if [ ! -f /userconfig/upstream.conf ]; then
    echo "no /userconfig/upstream.conf; abort"
    exit 1
fi
. /userconfig/upstream.conf
if [ -z "$UP_SSID" ]; then
    echo "UP_SSID empty; abort"
    exit 1
fi
if [ -z "$UP_AUTH" ]; then
    if [ -n "$UP_PSK" ]; then
        UP_AUTH='wpa2-psk'
    else
        UP_AUTH='open'
    fi
fi
if [ "$UP_AUTH" = "wpa2-eap" ]; then
    if [ -z "$UP_EAP_IDENTITY" ]; then
        echo "UP_EAP_IDENTITY empty for wpa2-eap; abort"
        exit 1
    fi
    if [ ! -f /userconfig/eap_pass ]; then
        echo "no /userconfig/eap_pass; abort"
        exit 1
    fi
    if [ ! -f /userconfig/eap_ttls ]; then
        echo "no /userconfig/eap_ttls binary; abort"
        exit 1
    fi
    chmod +x /userconfig/eap_ttls 2>/dev/null
    echo "auth=wpa2-eap identity=$UP_EAP_IDENTITY bssid=$UP_BSSID channel=$UP_CHANNEL"
elif [ "$UP_AUTH" = "wpa2-psk" ]; then
    echo "auth=wpa2-psk ssid=$UP_SSID psk_len=${#UP_PSK} bssid=$UP_BSSID channel=$UP_CHANNEL"
else
    echo "auth=open ssid=$UP_SSID bssid=$UP_BSSID channel=$UP_CHANNEL"
fi

# 4. Live 5 GHz Scan (BSSID-First, Same-SSID Fallback).
scan_resolve() {
    wlandiagcli scan 1 2>/dev/null | awk -v target_ssid="$UP_SSID" -v target_bssid="$UP_BSSID" '
        BEGIN {
            found_bssid = 0
            found_ssid = 0
            best_rssi = -9999
        }
        {
            for (i = 1; i <= NF; i++) {
                if (length($i) == 17 && split($i, oct, ":") == 6) {
                    bssid = $i
                    idx = index($0, bssid)
                    ssid = substr($0, 1, idx - 1)
                    sub(/[ \t]+$/, "", ssid)
                    rssi = $(i+1) + 0
                    ch = $(i+2) + 0

                    if (target_bssid != "" && tolower(bssid) == tolower(target_bssid)) {
                        exact_bssid = bssid
                        exact_ch = ch
                        found_bssid = 1
                    }
                    if (target_ssid != "" && ssid == target_ssid) {
                        if (found_ssid == 0 || rssi > best_rssi) {
                            best_rssi = rssi
                            best_bssid = bssid
                            best_ch = ch
                            found_ssid = 1
                        }
                    }
                    break
                }
            }
        }
        END {
            if (found_bssid) {
                print exact_bssid " " exact_ch
            } else if (found_ssid) {
                print best_bssid " " best_ch
            }
        }'
}

echo "scanning 5G for live channel and bssid (target_ssid=$UP_SSID target_bssid=$UP_BSSID) ..."
SCAN_RES=$(scan_resolve)
if [ -z "$SCAN_RES" ]; then
    echo "scan did not match target; retrying after 2s"
    sleep 2
    SCAN_RES=$(scan_resolve)
fi

if [ -n "$SCAN_RES" ]; then
    RESOLVED_BSSID=$(echo "$SCAN_RES" | awk '{print $1}')
    RESOLVED_CH=$(echo "$SCAN_RES" | awk '{print $2}')
    echo "scan resolved: bssid=$RESOLVED_BSSID channel=$RESOLVED_CH"
    BSSID="$RESOLVED_BSSID"
    CH="$RESOLVED_CH"
else
    echo "scan found nothing; falling back to saved bssid=$UP_BSSID channel=$UP_CHANNEL"
    BSSID="$UP_BSSID"
    CH="$UP_CHANNEL"
fi

if [ -z "$CH" ]; then
    echo "target channel unresolved; abort"
    exit 1
fi
echo "target bssid=$BSSID channel=$CH"

# 5. Associate (3-address client, MWDS=0).
TARGET_BSSID="$BSSID"
if [ "$UP_AUTH" = "wpa2-eap" ]; then
    echo "initiating wpa2-eap association on channel $CH bssid $TARGET_BSSID"
    ifconfig apcli0 up
    ifconfig apcli0 txqueuelen 100
    iwpriv apcli0 set ApCliEnable=0
    sleep 1
    iwpriv wlan4 set Channel="$CH"
    iwpriv apcli0 set ApCliMWDS=0
    iwpriv apcli0 set ApCliAuthMode=WPA2
    iwpriv apcli0 set ApCliEncrypType=AES
    iwpriv apcli0 set "ApCliSsid=$UP_SSID"
    [ -n "$TARGET_BSSID" ] && iwpriv apcli0 set "ApCliBssid=$TARGET_BSSID"
    iwpriv apcli0 set ApCliPMFMFPC=1
    iwpriv apcli0 set ApCliPMFMFPR=0
    iwpriv apcli0 set ApCliPMFSHA256=1

    # 5a. RSN-IE capability mask (0x90e08), MLME Assoc mask (0x4b91c),
    # and PMF BIP cipher insertion (0x11ca54).
    # Some EAP networks only accept an RSN IE that advertises management-frame
    # protection as required, and the driver gates RSN IE generation during
    # ApCliMlmeAssocReqAction when AKMMap == 0x40. Furthermore, STA mode does
    # not initialize igtk_cipher, so PMF_MakeRsnIeGMgmtCipher must unconditionally
    # append the standard BIP cipher (00-0F-AC:6).
    # f680_rsn_patch.ko validates vendor sites before writing, patches them
    # under stop_machine, flushes the I-cache and is unloaded immediately.
    # PSK/Open never reaches this branch.
    TXT=$(cat /sys/module/mt7615_ap/sections/.text 2>/dev/null)
    if [ -z "$TXT" ]; then
        echo "mt7615_ap .text section missing; abort"
        exit 1
    fi
    RSN1_BYTE=$(/userconfig/kmemtool /dev/kmem "$TXT" 90e08 r 2>/dev/null)
    RSN2_BYTE=$(/userconfig/kmemtool /dev/kmem "$TXT" 4b91c r 2>/dev/null)
    RSN3_BYTE=$(/userconfig/kmemtool /dev/kmem "$TXT" 11ca57 r 2>/dev/null)
    echo "wpamakersnie_byte=$RSN1_BYTE apclimassoc_byte=$RSN2_BYTE pmf_bip_byte=$RSN3_BYTE text=$TXT"
    case "$RSN1_BYTE" in
        90|d0) ;;
        *)
            echo "unsupported mt7615 driver: WPAMakeRSNIE+0xf8 is '$RSN1_BYTE' (expected 90 or d0); abort"
            exit 1
            ;;
    esac
    case "$RSN2_BYTE" in
        90|d0) ;;
        *)
            echo "unsupported mt7615 driver: ApCliMlmeAssocReqAction+0x29c is '$RSN2_BYTE' (expected 90 or d0); abort"
            exit 1
            ;;
    esac
    case "$RSN3_BYTE" in
        1a|ea) ;;
        *)
            echo "unsupported mt7615 driver: PMF_MakeRsnIeGMgmtCipher+0x58 is '$RSN3_BYTE' (expected 1a or ea); abort"
            exit 1
            ;;
    esac

    if [ "$RSN1_BYTE" = "d0" ] && [ "$RSN2_BYTE" = "d0" ] && [ "$RSN3_BYTE" = "ea" ]; then
        echo "all three rsn/pmf sites already patched (d0, d0, ea); skipping insmod"
    else
        if [ ! -f /userconfig/f680_rsn_patch.ko ]; then
            echo "f680_rsn_patch.ko missing (onboard with --enterprise); abort"
            exit 1
        fi
        rmmod f680_rsn_patch 2>/dev/null
        insmod /userconfig/f680_rsn_patch.ko
        INS_RC=$?
        rmmod f680_rsn_patch 2>/dev/null
        RSN1_AFTER=$(/userconfig/kmemtool /dev/kmem "$TXT" 90e08 r 2>/dev/null)
        RSN2_AFTER=$(/userconfig/kmemtool /dev/kmem "$TXT" 4b91c r 2>/dev/null)
        RSN3_AFTER=$(/userconfig/kmemtool /dev/kmem "$TXT" 11ca57 r 2>/dev/null)
        echo "rsn_patch_insmod_rc=$INS_RC site1_after=$RSN1_AFTER site2_after=$RSN2_AFTER site3_after=$RSN3_AFTER"
        if [ "$INS_RC" -ne 0 ]; then
            echo "rsn patch insmod failed (rc=$INS_RC); abort"
            exit 1
        fi
        if [ "$RSN3_AFTER" = "1a" ]; then
            echo "site3 not patched by module; applying kmemtool fallback"
            /userconfig/kmemtool /dev/kmem "$TXT" 11ca57 w ea
            RSN3_AFTER=$(/userconfig/kmemtool /dev/kmem "$TXT" 11ca57 r 2>/dev/null)
        fi
        if [ "$RSN1_AFTER" != "d0" ] || [ "$RSN2_AFTER" != "d0" ] || [ "$RSN3_AFTER" != "ea" ]; then
            echo "rsn patch readback failed: site1='$RSN1_AFTER' site2='$RSN2_AFTER' site3='$RSN3_AFTER'; abort"
            exit 1
        fi
    fi

    iwpriv apcli0 set ApCliEnable=1

    echo "waiting for L2 association..."
    l2_ok=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if /userconfig/eap_ttls --verify-kmem 2>/dev/null | grep -q '0x00004001'; then
            l2_ok=1
            break
        fi
        sleep 1
    done
    if [ "$l2_ok" -ne 1 ]; then
        echo "L2 association failed (0x00004001 not reached)"
        wlandiagcli show assochistory 1 2>/dev/null | awk '{ l[NR]=$0 } END { s=NR-11; if (s<1) s=1; for (i=s; i<=NR; i++) print l[i] }'
        exit 1
    fi
    echo "L2 association OK"

    EAP_CMD="/userconfig/eap_ttls --iface apcli0 --bssid $TARGET_BSSID --identity $UP_EAP_IDENTITY --password-file /userconfig/eap_pass"
    if [ -n "$UP_EAP_CA" ]; then
        EAP_CMD="$EAP_CMD --ca $UP_EAP_CA"
    fi
    if [ -n "$UP_EAP_ANON_ID" ]; then
        EAP_CMD="$EAP_CMD --anon-identity $UP_EAP_ANON_ID"
    fi
    if [ "$UP_EAP_TLS12_ONLY" = "1" ]; then
        EAP_CMD="$EAP_CMD --tls12-only"
    fi

    echo "running eap_ttls authentication..."
    $EAP_CMD
    EAP_RC=$?
    if [ "$EAP_RC" -ne 0 ] && [ "$UP_EAP_TLS12_ONLY" != "1" ]; then
        echo "eap_ttls failed (rc=$EAP_RC); attempting fallback with --tls12-only"
        iwpriv apcli0 set ApCliEnable=0
        sleep 1
        iwpriv apcli0 set ApCliEnable=1
        l2_ok=0
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            if /userconfig/eap_ttls --verify-kmem 2>/dev/null | grep -q '0x00004001'; then
                l2_ok=1
                break
            fi
            sleep 1
        done
        if [ "$l2_ok" -ne 1 ]; then
            echo "L2 association failed on retry (0x00004001 not reached)"
            wlandiagcli show assochistory 1 2>/dev/null | awk '{ l[NR]=$0 } END { s=NR-11; if (s<1) s=1; for (i=s; i<=NR; i++) print l[i] }'
            exit 1
        fi
        echo "L2 association OK on retry"
        $EAP_CMD --tls12-only
        EAP_RC=$?
    fi

    if [ "$EAP_RC" -ne 0 ]; then
        echo "eap_ttls authentication failed (rc=$EAP_RC); abort"
        exit 1
    fi
    echo "eap_ttls authentication succeeded"

    echo "waiting for 4-way handshake (M4)..."
    for i in 1 2 3 4 5 6 7 8 9 10; do
        LAST=$(wlandiagcli show assochistory 1 2>/dev/null | sed -n '$p')
        case "$LAST" in
            *EAPOL_PAIR_MSG_4*) echo "association M4 seen: $LAST"; break ;;
        esac
        sleep 1
    done
else
    assoc() {
        ifconfig apcli0 up
    ifconfig apcli0 txqueuelen 100
        iwpriv apcli0 set ApCliEnable=0
        iwpriv wlan4 set Channel="$CH"
        iwpriv apcli0 set ApCliMWDS=0
        if [ "$UP_AUTH" = "wpa2-psk" ]; then
            iwpriv apcli0 set ApCliAuthMode=WPA2PSK
            iwpriv apcli0 set ApCliEncrypType=AES
            iwpriv apcli0 set ApCliWPAPSK="$UP_PSK"
        else
            iwpriv apcli0 set ApCliAuthMode=OPEN
            iwpriv apcli0 set ApCliEncrypType=NONE
        fi
        iwpriv apcli0 set "ApCliSsid=$UP_SSID"
        [ -n "$TARGET_BSSID" ] && iwpriv apcli0 set "ApCliBssid=$TARGET_BSSID"
        iwpriv apcli0 set ApCliEnable=1
    }
    assoc
    sleep 9
    LAST=$(wlandiagcli show assochistory 1 2>/dev/null | sed -n '$p')
    echo "assoc_last=$LAST"
    if [ "$UP_AUTH" = "wpa2-psk" ]; then
        case "$LAST" in
            *EAPOL_PAIR_MSG_4*) echo "association M4 seen" ;;
            *) echo "no M4 yet; retry once"; assoc; sleep 9 ;;
        esac
    else
        case "$LAST" in
            *RX_AssocResponse*) echo "open association confirmed" ;;
            *) echo "no AssocResponse yet; retry once"; assoc; sleep 9 ;;
        esac
    fi
fi

# 6. DHCP: last-lease unicast first, broadcast fallback.
if [ ! -r /userconfig/udhcpc.script ]; then
    echo "ERROR: /userconfig/udhcpc.script missing"
    exit 1
fi
killall -9 udhcpc eap_ttls 2>/dev/null
sleep 1
rm -f /userconfig/lease_ok
if [ -f /userconfig/last_lease ]; then
    . /userconfig/last_lease
fi
IP_OK=0
if [ -n "$LAST_IP" ] && [ -n "$LAST_GATEWAY" ]; then
    echo "using last lease $LAST_IP/$LAST_PREFIX gw $LAST_GATEWAY"
    ip addr flush dev apcli0
    if [ -n "$LAST_BROADCAST" ]; then
        ip addr add "$LAST_IP/$LAST_PREFIX" brd "$LAST_BROADCAST" dev apcli0
    else
        ip addr add "$LAST_IP/$LAST_PREFIX" dev apcli0
    fi
    ip route replace default via "$LAST_GATEWAY" dev apcli0
    /userconfig/udhcpc -i apcli0 -s /userconfig/udhcpc.script -n -f --server-ip "$LAST_GATEWAY" &
    DHC_PID=$!
else
    echo "no last lease; broadcast DHCP"
    /userconfig/udhcpc -i apcli0 -s /userconfig/udhcpc.script -n -f &
    DHC_PID=$!
fi
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if [ -f /userconfig/lease_ok ]; then IP_OK=1; break; fi
    sleep 2
done
if [ "$IP_OK" -eq 0 ]; then
    echo "DHCP attempt failed; broadcast fallback"
    killall -9 udhcpc eap_ttls 2>/dev/null
    kill "$DHC_PID" 2>/dev/null
    ip addr flush dev apcli0 2>/dev/null
    rm -f /userconfig/lease_ok
    sleep 1
    /userconfig/udhcpc -i apcli0 -s /userconfig/udhcpc.script -n -f &
    DHC_PID=$!
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if [ -f /userconfig/lease_ok ]; then IP_OK=1; break; fi
        sleep 2
    done
fi
echo "ip_ok=$IP_OK"
ifconfig apcli0 2>/dev/null | sed -n '1,8p'
ip route show 2>/dev/null | sed -n '1,8p'

# 7. NAT + INPUT (idempotent).
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -D POSTROUTING -o apcli0 -j MASQUERADE 2>/dev/null
iptables -t nat -A POSTROUTING -o apcli0 -j MASQUERADE
iptables -D FORWARD -i br0 -o apcli0 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i apcli0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -I FORWARD 1 -i br0 -o apcli0 -j ACCEPT
iptables -I FORWARD 2 -i apcli0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D INPUT -i apcli0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -D INPUT -i apcli0 -p udp --dport 68 -j ACCEPT 2>/dev/null
iptables -I INPUT 1 -i apcli0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 2 -i apcli0 -p udp --dport 68 -j ACCEPT

# 7b. Re-read the fresh lease; DHCP may have replaced the seeded one.
if [ -f /userconfig/last_lease ]; then
    . /userconfig/last_lease
fi

# 8. Verify/log.
echo "=== brctl show ==="
brctl show 2>/dev/null
echo "=== nat ==="
iptables -t nat -nvL POSTROUTING 2>/dev/null | sed -n '1,10p'
echo "=== forward ==="
iptables -nvL FORWARD 2>/dev/null | sed -n '1,8p'
SRC=$(ifconfig apcli0 2>/dev/null | awk '/inet addr/ {print $2}' | sed 's/addr://')
echo "src=$SRC"

GW=$(ip route show dev apcli0 2>/dev/null | awk '/default/ {print $3}')
[ -n "$GW" ] || GW="$LAST_GATEWAY"

if [ "$IP_OK" != "1" ] || [ -z "$SRC" ]; then
    echo "ERROR: DHCP did not configure apcli0 (ip_ok=$IP_OK)"
    exit 1
fi

if ! ip route show dev apcli0 2>/dev/null | grep -q 'default'; then
    echo "ERROR: DHCP did not configure apcli0 (no default route)"
    exit 1
fi

GW_RC=1
if [ -n "$SRC" ] && [ -n "$GW" ]; then
    ping -c 2 -T 1 -I "$SRC" "$GW"
    GW_RC=$?
    echo "ping_gw_rc=$GW_RC"
    ping -c 2 -T 1 -I "$SRC" 8.8.8.8
    P8_RC=$?
    echo "ping_8888_rc=$P8_RC"
    if [ "$GW_RC" = "0" ] && [ "$P8_RC" != "0" ]; then
        echo "note: upstream gateway reachable, but external ICMP to 8.8.8.8 not reachable (perhaps no internet access or ICMP blocked)"
    fi
fi

# 9. Auto-reconnect watchdog (background, RAM only).
if [ -f /tmp/f680_watchdog.pid ]; then
    OLD_WD_PID=$(cat /tmp/f680_watchdog.pid 2>/dev/null)
    if [ -n "$OLD_WD_PID" ]; then
        kill "$OLD_WD_PID" 2>/dev/null
    fi
fi

(
    trap - EXIT INT TERM
    f=""
    while :; do
        sleep 45
        ok=1

        if [ "$UP_AUTH" = "wpa2-eap" ]; then
            if ! /userconfig/eap_ttls --verify-kmem 2>/dev/null | grep -q '0x00004001'; then
                ok=0
            fi
        fi

        if [ "$ok" = "1" ]; then
            if ! ifconfig apcli0 2>/dev/null | grep -q 'inet addr:'; then
                ok=0
            fi
        fi

        if [ "$ok" = "1" ]; then
            GW=$(route -n 2>/dev/null | awk '$1=="0.0.0.0" && $8=="apcli0" {print $2; exit}')
            [ -n "$GW" ] || GW=$(ip route show dev apcli0 2>/dev/null | awk '/default/ {print $3}')
            [ -n "$GW" ] || GW="$LAST_GATEWAY"
            if [ -n "$GW" ]; then
                if ! ping -c 1 -W 3 "$GW" >/dev/null 2>&1; then
                    ok=0
                fi
            else
                ok=0
            fi
        fi

        if [ "$ok" = "1" ]; then
            f=""
        else
            f="${f}x"
            echo "$(date): health check failed ($f)" >> /tmp/f680_watchdog.log
            if [ "$f" = "xxx" ]; then
                echo "$(date): 3 consecutive failures; reconnecting via repeater_up.sh" >> /tmp/f680_watchdog.log
                f=""
                sh /userconfig/repeater_up.sh
            fi
        fi

        if [ -f /tmp/f680_watchdog.log ]; then
            awk '{ l[NR]=$0 } END { s=NR-99; if (s<1) s=1; for (i=s; i<=NR; i++) print l[i] }' /tmp/f680_watchdog.log > /tmp/f680_watchdog.tmp 2>/dev/null
            mv /tmp/f680_watchdog.tmp /tmp/f680_watchdog.log 2>/dev/null
        fi
    done
) >/dev/null 2>&1 &

echo $! > /tmp/f680_watchdog.pid
echo "watchdog started pid=$(cat /tmp/f680_watchdog.pid)"

echo "=== repeater_up done ==="
exit 0
