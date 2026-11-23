#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_onboard_parsing.py - Unit tests for telnet command echo stripping,
prompt handling, and hardened output parsers in onboard.py.
"""

import unittest
from onboard import (
    clean_cmd_output,
    parse_kernel_hex_address,
    parse_cg_readback,
    parse_module_info,
    parse_kernel_version,
    parse_df_free_kb,
    parse_ls_size,
    parse_verify_kmem,
    parse_restore_status,
)


class TestTelnetEchoAndOutputCleaning(unittest.TestCase):

    def test_clean_standard_echo(self):
        marker = "__END_ABCDEFGHIJ__"
        raw = (
            f"/ # cat /proc/version\r\n"
            f"echo {marker}\r\n"
            f"Linux version 2.6.36 (root@build-server) (gcc 4.4.6) #1 SMP Fri Nov 20 18:32:10 CST 2020\r\n"
            f"/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, "cat /proc/version", marker)
        expected = "Linux version 2.6.36 (root@build-server) (gcc 4.4.6) #1 SMP Fri Nov 20 18:32:10 CST 2020"
        self.assertEqual(cleaned, expected)

    def test_clean_no_trailing_newline_with_prompt(self):
        # Case where a tool prints without a trailing newline, causing the shell prompt to land on the same line
        marker = "__END_KLMNOPQRST__"
        raw = (
            f"/ # /userconfig/kmemtool /dev/kmem bf7de920 f1c r\r\n"
            f"echo {marker}\r\n"
            f"01/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, "/userconfig/kmemtool /dev/kmem bf7de920 f1c r", marker)
        self.assertEqual(cleaned, "01")

    def test_clean_no_trailing_newline_before_marker(self):
        # Case where output without trailing newline is immediately followed by marker
        marker = "__END_UVWXYZABCD__"
        raw = (
            f"/userconfig/kmemtool /dev/kmem bf7de920 f1c r\r\n"
            f"01{marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, "/userconfig/kmemtool /dev/kmem bf7de920 f1c r", marker)
        self.assertEqual(cleaned, "01")

    def test_clean_wrapped_command_echo(self):
        marker = "__END_QWERTYUIOP__"
        cmd = "wget -q -O /userconfig/field_ops.sh http://192.168.12.100:8124/field_ops.sh && chmod +x /userconfig/field_ops.sh; ls -l /userconfig/field_ops.sh"
        # Terminal wrapping injecting \r\n across lines
        raw = (
            f"/ # wget -q -O /userconfig/field_ops.sh http://192.168.12.100:8124/field\r\n"
            f"_ops.sh && chmod +x /userconfig/field_ops.sh; ls -l /userconfig/field\r\n"
            f"_ops.sh\r\n"
            f"echo {marker}\r\n"
            f"-rwxr-xr-x    1 root     root         21501 Jan  1 00:05 /userconfig/field_ops.sh\r\n"
            f"/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, cmd, marker)
        self.assertEqual(cleaned, "-rwxr-xr-x    1 root     root         21501 Jan  1 00:05 /userconfig/field_ops.sh")

    def test_clean_empty_command_output(self):
        marker = "__END_ASDFGHJKLZ__"
        cmd = "rm -f /userconfig/stale_file 2>/dev/null"
        raw = (
            f"/ # {cmd}\r\n"
            f"echo {marker}\r\n"
            f"/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, cmd, marker)
        self.assertEqual(cleaned, "")

    def test_clean_multiline_output_with_internal_hash(self):
        marker = "__END_ZXCVBNMLKJ__"
        raw = (
            f"/ # cat /proc/version\r\n"
            f"echo {marker}\r\n"
            f"Linux version 2.6.36 (build@host) #1 SMP PREEMPT 2020\r\n"
            f"Additional line with hash #42 details\r\n"
            f"/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, "cat /proc/version", marker)
        self.assertIn("Linux version 2.6.36", cleaned)
        self.assertIn("#1 SMP", cleaned)
        self.assertIn("#42 details", cleaned)
        self.assertFalse(cleaned.endswith("/ #"))

    def test_clean_multiple_leading_prompts(self):
        marker = "__END_POIUYTREWQ__"
        raw = (
            f"/ # / # grep mt7615_ap /proc/modules 2>/dev/null\r\n"
            f"echo {marker}\r\n"
            f"mt7615_ap 1425408 1 - Live 0xbf800000\r\n"
            f"/ # {marker}\r\n"
            f"/ # "
        )
        cleaned = clean_cmd_output(raw, "grep mt7615_ap /proc/modules 2>/dev/null", marker)
        self.assertEqual(cleaned, "mt7615_ap 1425408 1 - Live 0xbf800000")


class TestHardenedParsers(unittest.TestCase):

    def test_bss_valid_kernel_address(self):
        output = "0xbf7de920"
        val, err = parse_kernel_hex_address(output)
        self.assertIsNone(err)
        self.assertEqual(val, 0xbf7de920)
        self.assertEqual(f"{val:08x}", "bf7de920")

    def test_bss_ignores_decimal_marker_noise(self):
        # Reproduces the live Router B failure where __ONBOARD_42345039__ was in raw output
        raw_with_noise = (
            "/ # cat /sys/module/mt7615_ap/sections/.bss 2>/dev/null\n"
            "echo __ONBOARD_42345039__\n"
            "0xbf7de920\n"
            "/ # __ONBOARD_42345039__\n"
            "/ # "
        )
        val, err = parse_kernel_hex_address(raw_with_noise)
        self.assertIsNone(err)
        self.assertEqual(val, 0xbf7de920)
        # Verify 42345039 was not matched
        self.assertNotEqual(val, 42345039)

    def test_bss_rejects_bare_hex_without_0x(self):
        bare_output = "42345039"
        val, err = parse_kernel_hex_address(bare_output)
        self.assertIsNone(val)
        self.assertIn("No 0x-prefixed", err)

    def test_bss_rejects_user_space_address(self):
        user_space = "0x00400000"
        val, err = parse_kernel_hex_address(user_space)
        self.assertIsNone(val)
        self.assertIn("outside kernel space", err)

    def test_cg_readback_parsing(self):
        cg_val, token = parse_cg_readback("01")
        self.assertEqual(cg_val, "01")
        self.assertEqual(token, "01")

        cg_val, token = parse_cg_readback("00")
        self.assertEqual(cg_val, "00")
        self.assertEqual(token, "00")

        # WPAMakeRSNIE+0xf8 and ApCliMlmeAssocReqAction+0x29c bytes (90 stock, d0 patched)
        # PMF_MakeRsnIeGMgmtCipher+0x5b condition byte (1a stock bne, ea patched b)
        for byte in ("90", "d0", "1a", "ea"):
            cg_val, token = parse_cg_readback(byte)
            self.assertEqual(cg_val, byte)
            self.assertEqual(token, byte)

    def test_cg_readback_rejects_echoed_command(self):
        echo_line = "/userconfig/kmemtool /dev/kmem 42345039 f1c r"
        cg_val, token = parse_cg_readback(echo_line)
        self.assertIsNone(cg_val)
        self.assertEqual(token, echo_line)

    def test_cg_readback_captures_error_token(self):
        # Read error from kmemtool
        cg_val, token = parse_cg_readback("Rfffffff2")
        self.assertIsNone(cg_val)
        self.assertEqual(token, "Rfffffff2")

        # Seek error from kmemtool
        cg_val, token = parse_cg_readback("Lffffffed")
        self.assertIsNone(cg_val)
        self.assertEqual(token, "Lffffffed")

        # Open error from kmemtool
        cg_val, token = parse_cg_readback("Offfffffe")
        self.assertIsNone(cg_val)
        self.assertEqual(token, "Offfffffe")

        # Empty output
        cg_val, token = parse_cg_readback("")
        self.assertIsNone(cg_val)
        self.assertEqual(token, "<empty>")

    def test_module_info_ignores_echo(self):
        raw_grep = (
            "grep mt7615_ap /proc/modules 2>/dev/null\n"
            "mt7615_ap 1425408 1 - Live 0xbf800000"
        )
        mod = parse_module_info(raw_grep, "mt7615_ap")
        self.assertEqual(mod, "mt7615_ap 1425408 1 - Live 0xbf800000")

    def test_kernel_version_ignores_echo(self):
        raw_v = (
            "cat /proc/version\n"
            "Linux version 2.6.36 (root@build) (gcc 4.4.6) #1 SMP"
        )
        k_ver = parse_kernel_version(raw_v)
        self.assertEqual(k_ver, "Linux version 2.6.36 (root@build) (gcc 4.4.6) #1 SMP")

    def test_df_free_kb_ignores_echo(self):
        raw_df = (
            "df -k /userconfig\n"
            "Filesystem           1K-blocks      Used Available Use% Mounted on\n"
            "/dev/mtdblock5            6144      1848      4296  30% /userconfig"
        )
        free_kb = parse_df_free_kb(raw_df)
        self.assertEqual(free_kb, 4296)

    def test_ls_size_ignores_echo(self):
        raw_ls = (
            "wget -q -O /userconfig/kmemtool http://192.168.12.100:8124/kmemtool && chmod +x /userconfig/kmemtool; ls -l /userconfig/kmemtool\n"
            "-rwxr-xr-x    1 root     root          1084 Jan  1 00:00 /userconfig/kmemtool"
        )
        size = parse_ls_size(raw_ls, "/userconfig/kmemtool")
        self.assertEqual(size, 1084)

    def test_verify_kmem_parsing(self):
        output = (
            "/userconfig/eap_ttls --verify-kmem\n"
            "mt7615_ap module info:\n"
            "  text: 0xbf800000\n"
            "  jt0:  0xbf8902a4\n"
            "__VERIFY_KMEM_RC=0__"
        )
        t_val, j_val, err = parse_verify_kmem(output)
        self.assertIsNone(err)
        self.assertEqual(t_val, 0xbf800000)
        self.assertEqual(j_val, 0xbf8902a4)

    def test_verify_kmem_rejects_user_space(self):
        bad_output = "text: 0x00400000\njt0:  0x004902a4"
        t_val, j_val, err = parse_verify_kmem(bad_output)
        self.assertIsNone(t_val)
        self.assertIsNone(j_val)
        self.assertIn("outside kernel space", err)


class TestRestoreParsing(unittest.TestCase):

    def test_restore_success(self):
        restore_out = "=== running repeater_up.sh ===\nrepeater_up_rc=0\nbss=0xbf800000\nDONE\n"
        verify_out = "=== 1. FIX STATE ===\nSTATUS: OK\n"
        ok, summary = parse_restore_status(restore_out, verify_out)
        self.assertTrue(ok)
        self.assertEqual(summary, "OK")

    def test_restore_repeater_up_failure(self):
        restore_out = "=== running repeater_up.sh ===\nERROR: DHCP did not configure apcli0\nrepeater_up_rc=1\nDONE\n"
        verify_out = "=== 1. FIX STATE ===\nSTATUS: OK\n"
        ok, summary = parse_restore_status(restore_out, verify_out)
        self.assertFalse(ok)
        self.assertIn("repeater_up.sh failed with exit code 1", summary)

    def test_restore_verify_status_failed(self):
        restore_out = "repeater_up_rc=0\nDONE\n"
        verify_out = "=== 3. APCLI0 & ROUTING ===\nERROR: apcli0 has no IPv4 address assigned\nSTATUS: FAILED\n"
        ok, summary = parse_restore_status(restore_out, verify_out)
        self.assertFalse(ok)
        self.assertIn("apcli0 has no IPv4 address assigned", summary)

    def test_restore_verify_missing_default_route(self):
        restore_out = "repeater_up_rc=0\nDONE\n"
        verify_out = "=== 3. APCLI0 & ROUTING ===\nERROR: default route via apcli0 not found\nSTATUS: FAILED\n"
        ok, summary = parse_restore_status(restore_out, verify_out)
        self.assertFalse(ok)
        self.assertIn("default route via apcli0 not found", summary)

    def test_restore_verify_missing_status_ok(self):
        restore_out = "repeater_up_rc=0\nDONE\n"
        verify_out = "=== 1. FIX STATE ===\nIncomplete truncated output"
        ok, summary = parse_restore_status(restore_out, verify_out)
        self.assertFalse(ok)
        self.assertIn("missing STATUS: OK", summary)


if __name__ == "__main__":
    unittest.main()
