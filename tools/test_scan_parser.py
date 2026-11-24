#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_scan_parser.py - Unit tests for wlandiagcli scan 1 awk parser in repeater_up.sh.
Tests:
(a) Space-containing SSID + BSSID channel hop (e.g. DFS 56 -> 64)
(b) Missing pinned BSSID falling back to strongest same-SSID AP
"""

import subprocess
import unittest
from pathlib import Path


def get_awk_parser_script() -> str:
    script_path = Path(__file__).resolve().parent.parent / "payload" / "repeater_up.sh"
    content = script_path.read_text(encoding="utf-8")
    marker = 'awk -v target_ssid="$UP_SSID" -v target_bssid="$UP_BSSID" \''
    start_idx = content.find(marker)
    if start_idx == -1:
        raise ValueError("scan_resolve awk parser not found in repeater_up.sh")
    start_idx += len(marker)
    end_idx = content.find("'\n}", start_idx)
    if end_idx == -1:
        end_idx = content.find("' }", start_idx)
    return content[start_idx:end_idx].strip()


def run_awk_scan_parser(scan_output: str, target_ssid: str, target_bssid: str):
    awk_script = get_awk_parser_script()
    cmd = [
        "awk",
        "-v",
        f"target_ssid={target_ssid}",
        "-v",
        f"target_bssid={target_bssid}",
        awk_script,
    ]
    proc = subprocess.run(
        cmd,
        input=scan_output,
        capture_output=True,
        text=True,
        check=True,
    )
    out = proc.stdout.strip()
    if not out:
        return None, None
    parts = out.split()
    if len(parts) >= 2:
        return parts[0], int(parts[1])
    return None, None


class TestWlanDiagScanParser(unittest.TestCase):

    def setUp(self):
        # Sample scan table output with space-containing SSIDs, multiple APs, and formatting
        self.mock_scan_output = (
            "[Get 5G  scanned result:]\n"
            "The total number of surrounding AP=5\n"
            "SSID                               BSSID                    Signal    Channel   Security                      Mode           SGIEnabledNSI  SNR  BeaconIntervel ChannelOffset  BandWidth DeviceModeDTIMPeriod\n"
            "Campus Wi-Fi 5G                    02:11:22:33:44:AA        -65dBm    64        WPA2-EAP-AES                  a,n,ac         1         -95  0    100            upper          80MHz     ap        1\n"
            "Campus Wi-Fi 5G                    02:11:22:33:44:01        -75dBm    36        WPA2-EAP-AES                  a,n,ac         1         -95  0    100            upper          80MHz     ap        1\n"
            "Campus Wi-Fi 5G                    02:11:22:33:44:02        -45dBm    44        WPA2-EAP-AES                  a,n,ac         1         -95  0    100            upper          80MHz     ap        1\n"
            "Campus Wi-Fi 5G                    02:11:22:33:44:03        -55dBm    52        WPA2-EAP-AES                  a,n,ac         1         -95  0    100            upper          80MHz     ap        1\n"
            "Other Visitor Network              02:11:22:33:44:99        -40dBm    40        WPA2-PSK-AES                  a,n,ac         1         -95  0    100            upper          80MHz     ap        1\n"
        )

    def test_space_containing_ssid_and_bssid_channel_hop(self):
        """
        Test case (a): Pinned BSSID matches case-insensitively, adopting live channel
        even if the AP has hopped (e.g. from DFS 56 to 64) and even if other APs with
        the same space-containing SSID have stronger RSSI.
        """
        # Configured BSSID is 02:11:22:33:44:aa (lowercase), originally on channel 56
        target_ssid = "Campus Wi-Fi 5G"
        target_bssid = "02:11:22:33:44:aa"

        resolved_bssid, resolved_ch = run_awk_scan_parser(
            self.mock_scan_output,
            target_ssid=target_ssid,
            target_bssid=target_bssid,
        )

        self.assertEqual(resolved_bssid.lower(), "02:11:22:33:44:aa")
        self.assertEqual(resolved_ch, 64)

    def test_missing_pinned_bssid_fallback_to_strongest_same_ssid(self):
        """
        Test case (b): Pinned BSSID is absent from scan, parser matches configured SSID
        and picks the AP with the highest numeric RSSI (-45dBm on channel 44),
        adopting both its BSSID and live Channel.
        """
        target_ssid = "Campus Wi-Fi 5G"
        target_bssid = "02:99:99:99:99:99"  # Absent BSSID

        resolved_bssid, resolved_ch = run_awk_scan_parser(
            self.mock_scan_output,
            target_ssid=target_ssid,
            target_bssid=target_bssid,
        )

        self.assertEqual(resolved_bssid.lower(), "02:11:22:33:44:02")
        self.assertEqual(resolved_ch, 44)

    def test_scan_finds_nothing_returns_empty(self):
        """
        Test case (c): Unmatched SSID and BSSID returns empty result,
        triggering script fallback to saved upstream.conf parameters.
        """
        target_ssid = "NonExistent Network"
        target_bssid = "02:88:88:88:88:88"

        resolved_bssid, resolved_ch = run_awk_scan_parser(
            self.mock_scan_output,
            target_ssid=target_ssid,
            target_bssid=target_bssid,
        )

        self.assertIsNone(resolved_bssid)
        self.assertIsNone(resolved_ch)


if __name__ == "__main__":
    unittest.main()
