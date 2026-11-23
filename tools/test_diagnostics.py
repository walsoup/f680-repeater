#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_diagnostics.py - Unit tests for sanitize_report and DiagnosticCollector.
"""

import unittest
from diagnostics import DiagnosticCollector, sanitize_report, is_rfc1918_or_local


class TestDiagnosticsSanitizer(unittest.TestCase):

    def test_exact_secrets_redaction(self):
        secrets = [
            "SuperSecretWiFiKey99!",
            "EAPSecretPass456",
            "student@campus.edu",
            "anon@campus.edu",
            "ZTEGTEST1234",
            "DormNetwork_5G",
            "02:11:22:33:44:55",
        ]
        text = (
            "Connecting to SSID DormNetwork_5G (BSSID 02:11:22:33:44:55) with PSK SuperSecretWiFiKey99! "
            "or Enterprise user student@campus.edu (anon: anon@campus.edu) pass EAPSecretPass456 "
            "serial ZTEGTEST1234"
        )
        cleaned = sanitize_report(text, secrets=secrets)
        for s in secrets:
            self.assertNotIn(s, cleaned)
        self.assertIn("<REDACTED_SECRET>", cleaned)

    def test_mac_redaction(self):
        text = "Client MAC 02:11:22:33:44:66 associated with AP 20:aa:bb:cc:dd:ee (alt format 02-11-22-33-44-66)"
        cleaned = sanitize_report(text)
        self.assertNotIn("02:11:22:33:44:66", cleaned)
        self.assertNotIn("20:aa:bb:cc:dd:ee", cleaned)
        self.assertNotIn("02-11-22-33-44-66", cleaned)
        self.assertIn("xx:xx:xx:xx:xx:xx", cleaned)

    def test_email_redaction(self):
        text = "Contact admin at operator.support@example.edu or test.user+label@domain.org for info."
        cleaned = sanitize_report(text)
        self.assertNotIn("operator.support@example.edu", cleaned)
        self.assertNotIn("test.user+label@domain.org", cleaned)
        self.assertIn("<redacted@email.tld>", cleaned)

    def test_host_paths_redaction(self):
        h_dir = "/" + "home/"
        text = (
            f"Logs saved to {h_dir}alice/project/run.log and /Users/john_doe/Downloads/ca.pem "
            "and C:\\Users\\Administrator\\Desktop\\output.txt"
        )
        cleaned = sanitize_report(text)
        self.assertNotIn(f"{h_dir}alice", cleaned)
        self.assertNotIn("/Users/john_doe", cleaned)
        self.assertNotIn("Administrator", cleaned)
        self.assertIn(f"{h_dir}<redacted-user>", cleaned)
        self.assertIn("/Users/<redacted-user>", cleaned)
        self.assertIn("C:\\Users\\<redacted-user>", cleaned)

    def test_ipv4_rfc1918_preservation_and_public_redaction(self):
        # RFC1918, loopback, and broadcast should be preserved
        rfc1918_text = "Router IP is 192.168.12.1, gateway is 10.150.1.1, sub is 172.16.5.10, loopback 127.0.0.1, 0.0.0.0"
        cleaned_rfc1918 = sanitize_report(rfc1918_text)
        self.assertIn("192.168.12.1", cleaned_rfc1918)
        self.assertIn("10.150.1.1", cleaned_rfc1918)
        self.assertIn("172.16.5.10", cleaned_rfc1918)
        self.assertIn("127.0.0.1", cleaned_rfc1918)
        self.assertIn("0.0.0.0", cleaned_rfc1918)

        # Public IPs should be redacted
        public_text = "DNS servers: 8.8.8.8 and 1.1.1.1, upstream IP is 197.230.12.45"
        cleaned_public = sanitize_report(public_text)
        self.assertNotIn("8.8.8.8", cleaned_public)
        self.assertNotIn("1.1.1.1", cleaned_public)
        self.assertNotIn("197.230.12.45", cleaned_public)
        self.assertIn("<REDACTED_PUBLIC_IP>", cleaned_public)

    def test_versions_and_hex_not_mangled(self):
        text = "BusyBox v1.17.2, Linux version 2.6.36, text base 0xbf800000, offset 0x90244, hex 0xdeadbeef"
        cleaned = sanitize_report(text)
        self.assertIn("1.17.2", cleaned)
        self.assertIn("2.6.36", cleaned)
        self.assertIn("0xbf800000", cleaned)
        self.assertIn("0x90244", cleaned)
        self.assertIn("0xdeadbeef", cleaned)

    def test_diagnostic_collector_block_structure(self):
        h_dir = "/" + "home/"
        dc = DiagnosticCollector("driver_fingerprint", "cg_hdswitch_on readback at .bss+0xf1c was 0xff")
        dc.kernel_version = "Linux version 2.6.36 (root@build-server) (gcc 4.4.6) #1 SMP"
        dc.module_info = "mt7615_ap 1425408 1 - Live 0xbf800000"
        dc.free_kb = 4296
        dc.cg_readback = "0xff"
        dc.recent_logs = f"Checking kmem at {h_dir}alice/dump\nBSSID: 02:11:22:33:44:66\nDNS: 8.8.8.8"
        dc.add_secret("SecretSSID123")
        dc.add_secret("SecretPasswordXYZ")

        report = dc.generate_report()
        self.assertTrue(report.startswith("--- BEGIN DIAGNOSTIC REPORT ---"))
        self.assertTrue(report.endswith("--- END DIAGNOSTIC REPORT ---"))
        self.assertIn("- **Failed Stage**: `driver_fingerprint`", report)
        self.assertIn("cg_hdswitch_on readback at .bss+0xf1c was 0xff", report)
        self.assertIn("Linux version 2.6.36", report)
        self.assertIn("4296 KB", report)
        # Check sanitization in logs
        self.assertNotIn(f"{h_dir}alice", report)
        self.assertNotIn("02:11:22:33:44:66", report)
        self.assertNotIn("8.8.8.8", report)
        self.assertIn("<REDACTED_PUBLIC_IP>", report)
        self.assertIn("xx:xx:xx:xx:xx:xx", report)


if __name__ == "__main__":
    unittest.main()
