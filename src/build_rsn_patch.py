#!/usr/bin/env python3
"""build_rsn_patch.py - emit a tiny Linux 4.1.25 ARM module that unblocks
WPA2-Enterprise (0x40) AKM and RSN-IE generation in mt7615_ap.ko by patching
WPAMakeRSNIE (0x90e08), ApCliMlmeAssocReqAction (0x4b91c), and PMF_MakeRsnIeGMgmtCipher (0x11ca54).

What it patches
---------------
mt7615_ap.ko (ZTEGF680606MA, kernel 4.1.25) gates RSN IE generation and
WPA2-Enterprise association at three sites in .text:

  1. Site 1: WPAMakeRSNIE + 0xf8 (T + 0x90e08):
       0x90e04: e5943000   ldr  r3, [r4]      @ r4 = &RSN IE capability word
       0x90e08: e3130090   tst  r3, #0x90     @ gates extra capability bits
       0x90e0c: 0afffffa   beq  0x90dfc
     Patched to:
       0x90e08: e31300d0   tst  r3, #0xd0     @ enables PMF / capability bit 0x40

  2. Site 2: ApCliMlmeAssocReqAction + 0x29c (T + 0x4b91c = WPAMakeRSNIE - 0x453f4):
       0x4b918: e3062e08   movw r2, #0x6e08
       0x4b91c: e3a03090   mov  r3, #0x90     @ constructs 0x00100090 AKM mask
       0x4b920: e340201f   movt r2, #0x1f
       0x4b924: e0842002   add  r2, r4, r2
       0x4b928: e3403010   movt r3, #0x10
       0x4b92c: e5922af0   ldr  r2, [r2, #0xaf0]
       0x4b930: e0033002   and  r3, r3, r2    @ tests (AKMMap & 0x00100090) != 0
     Patched to:
       0x4b91c: e3a030d0   mov  r3, #0xd0     @ constructs 0x001000d0, unblocking 0x40

  3. Site 3: PMF_MakeRsnIeGMgmtCipher + 0x58 (T + 0x11ca54 = WPAMakeRSNIE + 0x8bd44):
       0x11ca50: e0830000   add  r0, r3, r0
       0x11ca54: 1a000021   bne  0x11cae0     @ tests igtk_cipher (uninitialized in STA)
       0x11ca58: e3120b01   tst  r2, #1024
     Patched to:
       0x11ca54: ea000021   b    0x11cae0     @ unconditionally appends BIP cipher

The module rewrites all three sites in RAM only under stop_machine().  It is lost
on reboot and never touches flash.

Safety and Paranoia:
  * init_module resolves WPAMakeRSNIE through kallsyms_lookup_name(), then
    runs patch_worker under stop_machine() so no CPU is executing the code
    while it is rewritten.
  * patch_worker validates ALL THREE sites before writing a single byte
    (all-or-nothing pre-check):
      - Site 1: *(u32 *)(site1 - 4) == 0xe5943000 and *(u32 *)site1 in {0xe3130090, 0xe31300d0}
      - Site 2: *(u32 *)(site2 + 0x0c) == 0xe3403010 and *(u32 *)(site2 + 4) == 0xe340201f
                and *(u32 *)site2 in {0xe3a03090, 0xe3a030d0}
      - Site 3: *(u32 *)(site3 - 4) == 0xe0830000 and *(u32 *)(site3 + 4) == 0xe3120b01
                and *(u32 *)site3 in {0x1a000021, 0xea000021}
    On any mismatch it returns -EINVAL (-22) immediately without writing anything.
  * Each site is patched only if currently unpatched.  After each store, it executes
    dsb sy and v7_coherent_kern_range(site, site + 4), then verifies readback.
    If readback fails, it returns -EIO (-5).
  * Returns 0 on success (idempotent if already patched).
  * cleanup_module is a single bx lr; the caller unloads the module immediately
    after init so nothing stays resident.

Reference evidence (read-only, taken from dump/kmodule):
  * mt7615_ap.ko .text file offset 0x34, WPAMakeRSNIE st_value 0x90d10:
      0x90d10 = 0xe92d4ff0  push {r4, r5, r6, r7, r8, sb, sl, fp, lr}
      0x90e04 = 0xe5943000  ldr r3, [r4]
      0x90e08 = 0xe3130090  tst r3, #0x90
      0x90e0c = 0x0afffffa  beq 0x90dfc
  * mt7615_ap.ko .text offset 0x4b918 - 0x4b928:
      0x4b918 = 0xe3062e08  movw r2, #0x6e08
      0x4b91c = 0xe3a03090  mov r3, #0x90
      0x4b920 = 0xe340201f  movt r2, #0x1f
      0x4b924 = 0xe0842002  add r2, r4, r2
      0x4b928 = 0xe3403010  movt r3, #0x10
  * mt7615_ap.ko .text offset 0x11ca50 - 0x11ca58:
      0x11ca50 = 0xe0830000  add r0, r3, r0
      0x11ca54 = 0x1a000021  bne 0x11cae0
      0x11ca58 = 0xe3120b01  tst r2, #1024

Output
------
A deterministic ELF32 ARM ET_REL object of ~1.6 KB, hand-encoded with the
Python standard library only.  No compiler, linker, keystone, or kernel tree
is used; every run emits byte-identical output.

Usage:
  python3 src/build_rsn_patch.py                 # build + self-verify + dump
  python3 src/build_rsn_patch.py --quiet         # build + verify only
  python3 src/build_rsn_patch.py --no-verify     # build only (no capstone)
  python3 src/build_rsn_patch.py --verify-only payload/f680_rsn_patch.ko
  python3 src/build_rsn_patch.py --reference ../dump/kmodule/mt7615_ap.ko
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "payload" / "f680_rsn_patch.ko"

# ---------------------------------------------------------------------------
# Target facts (Linux 4.1.25 / ZTE ZXHN F680 V6.0)
# ---------------------------------------------------------------------------
MODULE_NAME = "f680_rsn_patch"
KERNEL_RELEASE = "4.1.25"
VERMAGIC = b"4.1.25 SMP mod_unload ARMv7 "          # trailing space is required
MODINFO = (b"license=GPL\x00"                       # GPL: resolves GPL symbols
           b"depends=\x00"
           b"vermagic=" + VERMAGIC + b"\x00")

TARGET_SYMBOL = "WPAMakeRSNIE"

# Site 1: WPAMakeRSNIE + 0xf8 (0x90e08)
SITE1_ADDEND = 0xF8
SITE1_PRE_WORD = 0xE5943000                         # ldr r3, [r4]
SITE1_ORIG_WORD = 0xE3130090                        # tst r3, #0x90
SITE1_PATCH_WORD = 0xE31300D0                       # tst r3, #0xd0

# Site 2: WPAMakeRSNIE - 0x453f4 (0x4b91c)
SITE2_OFFSET = 0x453F4
SITE2_MOVT3_WORD = 0xE3403010                       # movt r3, #0x10 at 0x4b928 (site2 + 0x0c)
SITE2_MOVT2_WORD = 0xE340201F                       # movt r2, #0x1f at 0x4b920 (site2 + 0x04)
SITE2_ORIG_WORD = 0xE3A03090                        # mov r3, #0x90 at 0x4b91c
SITE2_PATCH_WORD = 0xE3A030D0                       # mov r3, #0xd0 at 0x4b91c

# Site 3: PMF_MakeRsnIeGMgmtCipher + 0x58 (T + 0x11ca54 = WPAMakeRSNIE + 0x8bd44)
SITE3_OFFSET = 0x8BD44
SITE3_PRE_WORD = 0xE0830000                          # add r0, r3, r0 at 0x11ca50 (site3 - 4)
SITE3_POST_WORD = 0xE3120B01                         # tst r2, #1024 at 0x11ca58 (site3 + 4)
SITE3_ORIG_WORD = 0x1A000021                         # bne 0x11cae0 at 0x11ca54
SITE3_PATCH_WORD = 0xEA000021                        # b 0x11cae0 at 0x11ca54

MODULE_STRUCT_SIZE = 336                             # 0x150, sizeof(struct module)
MODULE_NAME_OFF = 0x0C                               # offsetof(struct module, name)
MODULE_INIT_OFF = 0xC0                               # offsetof(struct module, init)
MODULE_EXIT_OFF = 0x148                              # offsetof(struct module, exit)

# Reference instruction words (vaddr inside mt7615_ap.ko .text).
REFERENCE_WORDS = {
    0x4B918: 0xE3062E08,  # movw r2, #0x6e08
    0x4B91C: 0xE3A03090,  # mov r3, #0x90
    0x4B920: 0xE340201F,  # movt r2, #0x1f
    0x4B924: 0xE0842002,  # add r2, r4, r2
    0x4B928: 0xE3403010,  # movt r3, #0x10
    0x90D10: 0xE92D4FF0,  # push {r4, r5, r6, r7, r8, sb, sl, fp, lr}
    0x90E04: 0xE5943000,  # ldr r3, [r4]
    0x90E08: 0xE3130090,  # tst r3, #0x90
    0x90E0C: 0x0AFFFFFA,  # beq 0x90dfc
    0x11CA50: 0xE0830000, # add r0, r3, r0
    0x11CA54: 0x1A000021, # bne 0x11cae0
    0x11CA58: 0xE3120B01, # tst r2, #1024
}

# ---------------------------------------------------------------------------
# Minimal ARM (A32) encoders.  Pure integer instructions only.
# ---------------------------------------------------------------------------
COND_EQ = 0x0
COND_NE = 0x1

REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6, REG_LR, REG_PC = (
    0, 1, 2, 3, 4, 5, 6, 14, 15)


def enc_b(cond: int, insn_off: int, target_off: int) -> int:
    """B <label> (ARM state, 24-bit signed word offset)."""
    delta = target_off - (insn_off + 8)
    if delta % 4:
        raise ValueError("unaligned branch target")
    imm24 = (delta >> 2) & 0xFFFFFF
    return (cond << 28) | 0x0A000000 | imm24


def enc_ldr_pc(rd: int, insn_off: int, literal_off: int) -> int:
    """ldr rd, [pc, #imm] (U=1)."""
    delta = literal_off - (insn_off + 8)
    if delta < 0 or delta % 4 or delta >= 0x1000:
        raise ValueError("literal out of range at 0x%x: %d" % (insn_off, delta))
    return 0xE59F0000 | (rd << 12) | delta


def enc_ldr_imm(rd: int, rn: int, imm: int) -> int:
    """ldr rd, [rn, #+/-imm] (P=1, B=0, W=0)."""
    if not -0xFFF <= imm <= 0xFFF:
        raise ValueError("ldr offset out of range")
    up = 0x00800000 if imm >= 0 else 0
    return 0xE5100000 | up | (rn << 16) | (rd << 12) | abs(imm)


def enc_str_imm(rd: int, rn: int, imm: int) -> int:
    """str rd, [rn, #+/-imm] (P=1, B=0, W=0)."""
    if not -0xFFF <= imm <= 0xFFF:
        raise ValueError("str offset out of range")
    up = 0x00800000 if imm >= 0 else 0
    return 0xE5000000 | up | (rn << 16) | (rd << 12) | abs(imm)


def enc_mov_reg(rd: int, rm: int) -> int:
    return 0xE1A00000 | (rd << 12) | rm


def enc_mov_imm(rd: int, imm8: int) -> int:
    if not 0 <= imm8 <= 0xFF:
        raise ValueError("mov immediate must fit imm8")
    return 0xE3A00000 | (rd << 12) | imm8


def enc_add_imm(rd: int, rn: int, imm8: int) -> int:
    if not 0 <= imm8 <= 0xFF:
        raise ValueError("add immediate must fit imm8")
    return 0xE2800000 | (rn << 16) | (rd << 12) | imm8


def enc_sub_reg(rd: int, rn: int, rm: int) -> int:
    """sub rd, rn, rm."""
    return 0xE0400000 | (rn << 16) | (rd << 12) | rm


def enc_add_reg(rd: int, rn: int, rm: int) -> int:
    """add rd, rn, rm."""
    return 0xE0800000 | (rn << 16) | (rd << 12) | rm


def enc_cmp_reg(rn: int, rm: int) -> int:
    return 0xE1500000 | (rn << 16) | rm


def enc_cmp_imm(rn: int, imm8: int) -> int:
    if not 0 <= imm8 <= 0xFF:
        raise ValueError("cmp immediate must fit imm8")
    return 0xE3500000 | (rn << 16) | imm8


def enc_mvn_imm(rd: int, imm8: int) -> int:
    """mvn rd, #imm8 (ARM A32: rd = ~imm8 = -(imm8 + 1))."""
    if not 0 <= imm8 <= 0xFF:
        raise ValueError("mvn immediate must fit imm8")
    return 0xE3E00000 | (rd << 12) | imm8


def enc_blx_reg(rm: int) -> int:
    return 0xE12FFF30 | rm


ENC_BX_LR = 0xE12FFF1E
ENC_DSB_SY = 0xF57FF04F                  # dsb sy (CP15 barrier, not VFP)
ENC_PUSH_R4_LR = 0xE92D4010              # push {r4, lr}        -> 8-byte aligned (2 regs)
ENC_POP_R4_PC = 0xE8BD8010               # pop  {r4, pc}
ENC_PUSH_R4_R5_R6_LR = 0xE92D4070        # push {r4, r5, r6, lr} -> 8-byte aligned (4 regs)
ENC_POP_R4_R5_R6_PC = 0xE8BD8070         # pop  {r4, r5, r6, pc}


# ---------------------------------------------------------------------------
# .text builder: two passes over symbolic branches and PC-relative literals
# ---------------------------------------------------------------------------
class TextBuilder:
    def __init__(self) -> None:
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple] = []
        self.relocs: list[tuple[int, str]] = []

    @property
    def off(self) -> int:
        return len(self.words) * 4

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError("duplicate label %s" % name)
        self.labels[name] = self.off

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def branch(self, cond: int, label: str) -> None:
        self.fixups.append(("b", self.off, cond, label))
        self.words.append(0)

    def ldr_literal(self, rd: int, label: str) -> None:
        self.fixups.append(("ldr", self.off, rd, label))
        self.words.append(0)

    def literal(self, label: str, word: int = 0, symbol: str | None = None) -> None:
        self.label(label)
        if symbol:
            self.relocs.append((self.off, symbol))
        self.words.append(word & 0xFFFFFFFF)

    def assemble(self) -> bytes:
        for kind, off, a, b in self.fixups:
            if kind == "b":
                self.words[off // 4] = enc_b(a, off, self.labels[b])
            elif kind == "ldr":
                self.words[off // 4] = enc_ldr_pc(a, off, self.labels[b])
            else:  # pragma: no cover
                raise AssertionError(kind)
        return b"".join(struct.pack("<I", w) for w in self.words)


def build_text() -> tuple[bytes, dict, list[tuple[int, str]]]:
    """Emit cleanup_module, patch_worker and init_module plus one literal pool."""
    t = TextBuilder()

    # --- cleanup_module(void): nothing to undo ---------------------------------
    t.label("cleanup_module")
    t.emit(ENC_BX_LR)                          # bx lr

    # --- patch_worker(void *data) ---------------------------------------------
    # r0 = base = pointer to WPAMakeRSNIE (T + 0x90d10)
    t.label("patch_worker")
    t.emit(ENC_PUSH_R4_R5_R6_LR)               # push {r4, r5, r6, lr} -> 16 bytes (8-byte aligned)
    # site1 = base + 0xf8
    t.emit(enc_add_imm(REG_R4, REG_R0, SITE1_ADDEND))  # add r4, r0, #0xf8
    # site2 = base - 0x453f4
    t.ldr_literal(REG_R1, "lit_site2_off")     # ldr r1, =0x453f4
    t.emit(enc_sub_reg(REG_R5, REG_R0, REG_R1))# sub r5, r0, r1
    # site3 = base + 0x8bd44
    t.ldr_literal(REG_R1, "lit_site3_off")     # ldr r1, =0x8bd44
    t.emit(enc_add_reg(REG_R6, REG_R0, REG_R1))# add r6, r0, r1

    # === PRE-CHECK: validate ALL THREE sites before writing a single byte ===
    # Site 1 pre-target: *(u32 *)(site1 - 4) == 0xe5943000 (ldr r3, [r4])
    t.emit(enc_ldr_imm(REG_R3, REG_R4, -4))    # ldr r3, [r4, #-4]
    t.ldr_literal(REG_R2, "lit_site1_pre")     # ldr r2, =0xe5943000
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval

    # Site 1 target: *(u32 *)site1 in {0xe3130090, 0xe31300d0}
    t.emit(enc_ldr_imm(REG_R3, REG_R4, 0))     # ldr r3, [r4]
    t.ldr_literal(REG_R2, "lit_site1_orig")    # ldr r2, =0xe3130090
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_EQ, "site1_ok")              # beq site1_ok
    t.ldr_literal(REG_R2, "lit_site1_patch")   # ldr r2, =0xe31300d0
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval
    t.label("site1_ok")

    # Site 2 + 0x0c: *(u32 *)(site2 + 0x0c) == 0xe3403010 (movt r3, #0x10)
    t.emit(enc_ldr_imm(REG_R3, REG_R5, 12))    # ldr r3, [r5, #12]
    t.ldr_literal(REG_R2, "lit_site2_movt3")   # ldr r2, =0xe3403010
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval

    # Site 2 + 4: *(u32 *)(site2 + 4) == 0xe340201f (movt r2, #0x1f)
    t.emit(enc_ldr_imm(REG_R3, REG_R5, 4))     # ldr r3, [r5, #4]
    t.ldr_literal(REG_R2, "lit_site2_movt2")   # ldr r2, =0xe340201f
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval

    # Site 2 target: *(u32 *)site2 in {0xe3a03090, 0xe3a030d0}
    t.emit(enc_ldr_imm(REG_R3, REG_R5, 0))     # ldr r3, [r5]
    t.ldr_literal(REG_R2, "lit_site2_orig")    # ldr r2, =0xe3a03090
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_EQ, "site2_ok")              # beq site2_ok
    t.ldr_literal(REG_R2, "lit_site2_patch")   # ldr r2, =0xe3a030d0
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval
    t.label("site2_ok")

    # Site 3 - 4: *(u32 *)(site3 - 4) == 0xe0830000 (add r0, r3, r0)
    t.emit(enc_ldr_imm(REG_R3, REG_R6, -4))    # ldr r3, [r6, #-4]
    t.ldr_literal(REG_R2, "lit_site3_pre")     # ldr r2, =0xe0830000
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval

    # Site 3 + 4: *(u32 *)(site3 + 4) == 0xe3120b01 (tst r2, #1024)
    t.emit(enc_ldr_imm(REG_R3, REG_R6, 4))     # ldr r3, [r6, #4]
    t.ldr_literal(REG_R2, "lit_site3_post")    # ldr r2, =0xe3120b01
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval

    # Site 3 target: *(u32 *)site3 in {0x1a000021, 0xea000021}
    t.emit(enc_ldr_imm(REG_R3, REG_R6, 0))     # ldr r3, [r6]
    t.ldr_literal(REG_R2, "lit_site3_orig")    # ldr r2, =0x1a000021
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_EQ, "site3_ok")              # beq site3_ok
    t.ldr_literal(REG_R2, "lit_site3_patch")   # ldr r2, =0xea000021
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_inval")           # bne patch_inval
    t.label("site3_ok")

    # === PATCH SITE 1 if == 0xe3130090 ===
    t.emit(enc_ldr_imm(REG_R3, REG_R4, 0))     # ldr r3, [r4]
    t.ldr_literal(REG_R2, "lit_site1_orig")    # ldr r2, =0xe3130090
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "site1_skip")            # bne site1_skip (already patched)
    t.ldr_literal(REG_R2, "lit_site1_patch")   # ldr r2, =0xe31300d0
    t.emit(enc_str_imm(REG_R2, REG_R4, 0))     # str r2, [r4]
    t.emit(ENC_DSB_SY)                         # dsb sy
    t.emit(enc_mov_reg(REG_R0, REG_R4))        # mov r0, r4 (site1)
    t.emit(enc_add_imm(REG_R1, REG_R4, 4))     # add r1, r4, #4 (site1 + 4)
    t.ldr_literal(REG_R3, "lit_flush")         # ldr r3, =v7_coherent_kern_range
    t.emit(enc_blx_reg(REG_R3))                # blx r3
    t.emit(enc_ldr_imm(REG_R3, REG_R4, 0))     # ldr r3, [r4] (readback)
    t.ldr_literal(REG_R2, "lit_site1_patch")   # ldr r2, =0xe31300d0
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_eio")             # bne patch_eio
    t.label("site1_skip")

    # === PATCH SITE 2 if == 0xe3a03090 ===
    t.emit(enc_ldr_imm(REG_R3, REG_R5, 0))     # ldr r3, [r5]
    t.ldr_literal(REG_R2, "lit_site2_orig")    # ldr r2, =0xe3a03090
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "site2_skip")            # bne site2_skip (already patched)
    t.ldr_literal(REG_R2, "lit_site2_patch")   # ldr r2, =0xe3a030d0
    t.emit(enc_str_imm(REG_R2, REG_R5, 0))     # str r2, [r5]
    t.emit(ENC_DSB_SY)                         # dsb sy
    t.emit(enc_mov_reg(REG_R0, REG_R5))        # mov r0, r5 (site2)
    t.emit(enc_add_imm(REG_R1, REG_R5, 4))     # add r1, r5, #4 (site2 + 4)
    t.ldr_literal(REG_R3, "lit_flush")         # ldr r3, =v7_coherent_kern_range
    t.emit(enc_blx_reg(REG_R3))                # blx r3
    t.emit(enc_ldr_imm(REG_R3, REG_R5, 0))     # ldr r3, [r5] (readback)
    t.ldr_literal(REG_R2, "lit_site2_patch")   # ldr r2, =0xe3a030d0
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_eio")             # bne patch_eio
    t.label("site2_skip")

    # === PATCH SITE 3 if == 0x1a000021 ===
    t.emit(enc_ldr_imm(REG_R3, REG_R6, 0))     # ldr r3, [r6]
    t.ldr_literal(REG_R2, "lit_site3_orig")    # ldr r2, =0x1a000021
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "site3_skip")            # bne site3_skip (already patched)
    t.ldr_literal(REG_R2, "lit_site3_patch")   # ldr r2, =0xea000021
    t.emit(enc_str_imm(REG_R2, REG_R6, 0))     # str r2, [r6]
    t.emit(ENC_DSB_SY)                         # dsb sy
    t.emit(enc_mov_reg(REG_R0, REG_R6))        # mov r0, r6 (site3)
    t.emit(enc_add_imm(REG_R1, REG_R6, 4))     # add r1, r6, #4 (site3 + 4)
    t.ldr_literal(REG_R3, "lit_flush")         # ldr r3, =v7_coherent_kern_range
    t.emit(enc_blx_reg(REG_R3))                # blx r3
    t.emit(enc_ldr_imm(REG_R3, REG_R6, 0))     # ldr r3, [r6] (readback)
    t.ldr_literal(REG_R2, "lit_site3_patch")   # ldr r2, =0xea000021
    t.emit(enc_cmp_reg(REG_R3, REG_R2))        # cmp r3, r2
    t.branch(COND_NE, "patch_eio")             # bne patch_eio
    t.label("site3_skip")

    # Success: return 0
    t.emit(enc_mov_imm(REG_R0, 0))             # mov r0, #0
    t.emit(ENC_POP_R4_R5_R6_PC)                # pop {r4, r5, r6, pc}

    t.label("patch_inval")
    t.emit(enc_mvn_imm(REG_R0, 21))            # mvn r0, #21 -> r0 = ~21 = -22 (-EINVAL)
    t.emit(ENC_POP_R4_R5_R6_PC)                # pop {r4, r5, r6, pc}

    t.label("patch_eio")
    t.emit(enc_mvn_imm(REG_R0, 4))             # mvn r0, #4 -> r0 = ~4 = -5 (-EIO)
    t.emit(ENC_POP_R4_R5_R6_PC)                # pop {r4, r5, r6, pc}

    # --- init_module(void) -----------------------------------------------------
    t.label("init_module")
    t.emit(ENC_PUSH_R4_LR)                     # push {r4, lr}
    t.ldr_literal(REG_R3, "lit_kallsyms")      # ldr r3, =kallsyms_lookup_name
    t.ldr_literal(REG_R0, "lit_name")          # ldr r0, ="WPAMakeRSNIE"
    t.emit(enc_blx_reg(REG_R3))                # blx r3
    t.emit(enc_cmp_imm(REG_R0, 0))             # cmp r0, #0
    t.branch(COND_EQ, "init_noent")            # beq init_noent
    t.emit(enc_mov_reg(REG_R1, REG_R0))        # mov r1, r0 (data = base)
    t.ldr_literal(REG_R0, "lit_worker")        # ldr r0, =patch_worker
    t.emit(enc_mov_imm(REG_R2, 0))             # mov r2, #0 (NULL / all online CPUs)
    t.ldr_literal(REG_R3, "lit_stop")          # ldr r3, =stop_machine
    t.emit(enc_blx_reg(REG_R3))                # blx r3
    t.emit(ENC_POP_R4_PC)                      # return stop_machine()'s value

    t.label("init_noent")
    t.emit(enc_mvn_imm(REG_R0, 1))             # mvn r0, #1 -> r0 = ~1 = -2 (-ENOENT)
    t.emit(ENC_POP_R4_PC)                      # pop {r4, pc}

    # --- literal pool (unreachable: every path above returns) ------------------
    t.label("pool")
    t.literal("lit_site1_pre", SITE1_PRE_WORD)       # 0xe5943000
    t.literal("lit_site1_orig", SITE1_ORIG_WORD)     # 0xe3130090
    t.literal("lit_site1_patch", SITE1_PATCH_WORD)   # 0xe31300d0
    t.literal("lit_site2_off", SITE2_OFFSET)         # 0x000453f4
    t.literal("lit_site2_movt3", SITE2_MOVT3_WORD)   # 0xe3403010
    t.literal("lit_site2_movt2", SITE2_MOVT2_WORD)   # 0xe340201f
    t.literal("lit_site2_orig", SITE2_ORIG_WORD)     # 0xe3a03090
    t.literal("lit_site2_patch", SITE2_PATCH_WORD)   # 0xe3a030d0
    t.literal("lit_site3_off", SITE3_OFFSET)         # 0x0008bd44
    t.literal("lit_site3_pre", SITE3_PRE_WORD)       # 0xe0830000
    t.literal("lit_site3_post", SITE3_POST_WORD)     # 0xe3120b01
    t.literal("lit_site3_orig", SITE3_ORIG_WORD)     # 0x1a000021
    t.literal("lit_site3_patch", SITE3_PATCH_WORD)   # 0xea000021
    t.literal("lit_flush", symbol="v7_coherent_kern_range")
    t.literal("lit_kallsyms", symbol="kallsyms_lookup_name")
    t.literal("lit_name", symbol="rsn_name")
    t.literal("lit_worker", symbol="patch_worker")
    t.literal("lit_stop", symbol="stop_machine")

    text = t.assemble()
    meta = {
        "labels": t.labels,
        "pool_off": t.labels["pool"],
        "literal_labels": [name for name in t.labels if name.startswith("lit_")],
    }
    return text, meta, t.relocs


# ---------------------------------------------------------------------------
# ELF32 ARM ET_REL writer
# ---------------------------------------------------------------------------
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_REL = 9
SHT_ARM_ATTRIBUTES = 0x70000003
STB_LOCAL, STB_GLOBAL = 0, 1
STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION = 0, 1, 2, 3
R_ARM_ABS32 = 2


def build_arm_attributes() -> bytes:
    """Minimal EABI attributes: ARMv7-A, no FP/SIMD tags at all."""
    def uleb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    payload = bytearray()
    payload += uleb(5) + b"7-A\x00"      # Tag_CPU_name
    payload += uleb(6) + uleb(10)        # Tag_CPU_arch = v7
    payload += uleb(7) + uleb(ord("A"))  # Tag_CPU_arch_profile = A
    payload += uleb(8) + uleb(1)         # Tag_ARM_ISA_use
    payload += uleb(9) + uleb(2)         # Tag_THUMB_ISA_use = Thumb-2
    payload += uleb(15) + uleb(1)        # Tag_ABI_PCS_RW_data = PC-relative
    payload += uleb(16) + uleb(1)        # Tag_ABI_PCS_RO_data = PC-relative
    payload += uleb(18) + uleb(4)        # Tag_ABI_PCS_wchar_t
    payload += uleb(24) + uleb(1)        # Tag_ABI_align_needed = 8-byte
    payload += uleb(25) + uleb(1)        # Tag_ABI_align_preserved = 8-byte
    payload += uleb(26) + uleb(1)        # Tag_ABI_enum_size = int
    # No Tag_FP_arch (10), no Tag_ABI_VFP_args: this object is integer-only.

    file_sub = b"\x01" + struct.pack("<I", len(payload) + 5) + bytes(payload)
    vendor = b"aeabi\x00" + file_sub
    return b"A" + struct.pack("<I", len(vendor) + 4) + vendor


class Section:
    def __init__(self, name, sh_type, flags, data=b"", align=1, entsize=0,
                 link=0, info=0):
        self.name = name
        self.type = sh_type
        self.flags = flags
        self.data = data
        self.align = align
        self.entsize = entsize
        self.link = link
        self.info = info
        self.offset = 0


def build_elf() -> tuple[bytes, dict]:
    text, text_meta, text_relocs = build_text()

    rodata = TARGET_SYMBOL.encode() + b"\x00"
    rodata += b"\x00" * ((4 - len(rodata) % 4) % 4)

    this_module = bytearray(MODULE_STRUCT_SIZE)
    encoded_name = MODULE_NAME.encode() + b"\x00"
    if len(encoded_name) > 56:
        raise ValueError("module name too long")
    this_module[MODULE_NAME_OFF:MODULE_NAME_OFF + len(encoded_name)] = encoded_name

    # Section indices in the table built below.
    SEC_TEXT, SEC_RELTEXT, SEC_MODINFO, SEC_RODATA, SEC_THIS_MODULE = 1, 2, 3, 4, 5
    SEC_SYMTAB, SEC_STRTAB = 9, 10

    # Symbol table: locals first, then globals, then undefined imports.
    sym_defs = [
        # (name, info, shndx, value, size)
        ("", STB_LOCAL << 4 | STT_NOTYPE, 0, 0, 0),           # 0 null
        ("", STB_LOCAL << 4 | STT_SECTION, SEC_TEXT, 0, 0),   # 1 .text
        ("", STB_LOCAL << 4 | STT_SECTION, SEC_RODATA, 0, 0),  # 2 .rodata
        ("patch_worker", STB_LOCAL << 4 | STT_FUNC, SEC_TEXT,
         text_meta["labels"]["patch_worker"],
         text_meta["labels"]["init_module"] - text_meta["labels"]["patch_worker"]),
        ("rsn_name", STB_LOCAL << 4 | STT_OBJECT, SEC_RODATA, 0,
         len(TARGET_SYMBOL) + 1),
        ("init_module", STB_GLOBAL << 4 | STT_FUNC, SEC_TEXT,
         text_meta["labels"]["init_module"],
         text_meta["labels"]["pool"] - text_meta["labels"]["init_module"]),
        ("cleanup_module", STB_GLOBAL << 4 | STT_FUNC, SEC_TEXT,
         text_meta["labels"]["cleanup_module"], 4),
        ("__this_module", STB_GLOBAL << 4 | STT_OBJECT, SEC_THIS_MODULE, 0,
         MODULE_STRUCT_SIZE),
        ("kallsyms_lookup_name", STB_GLOBAL << 4 | STT_NOTYPE, 0, 0, 0),
        ("stop_machine", STB_GLOBAL << 4 | STT_NOTYPE, 0, 0, 0),
        ("v7_coherent_kern_range", STB_GLOBAL << 4 | STT_NOTYPE, 0, 0, 0),
    ]
    sym_index = {name: i for i, (name, *_rest) in enumerate(sym_defs) if name}
    first_global = 5  # index of init_module

    strtab = bytearray(b"\x00")
    sym_offsets = {}
    for name, *_rest in sym_defs:
        if not name:
            sym_offsets[name] = 0
            continue
        if name in sym_offsets:
            continue
        sym_offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"

    symtab = bytearray()
    for name, info, shndx, value, size in sym_defs:
        symtab += struct.pack("<IIIBBH", sym_offsets[name], value, size,
                              info, 0, shndx)

    def rel_entries(entries, symbol_table):
        raw = bytearray()
        for off, symbol in sorted(entries):
            raw += struct.pack("<II", off, (symbol_table[symbol] << 8) | R_ARM_ABS32)
        return bytes(raw)

    rel_text = rel_entries(text_relocs, sym_index)
    rel_module = rel_entries(
        [(MODULE_INIT_OFF, "init_module"), (MODULE_EXIT_OFF, "cleanup_module")],
        sym_index)

    # Sections in link order.  Indices are used by sh_link/sh_info below.
    sections = [
        Section("", 0, 0),
        Section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text, 4),
        Section(".rel.text", SHT_REL, 0, rel_text, 4, 8, link=9, info=1),
        Section(".modinfo", SHT_PROGBITS, SHF_ALLOC, MODINFO, 4),
        Section(".rodata", SHT_PROGBITS, SHF_ALLOC, rodata, 4),
        Section(".gnu.linkonce.this_module", SHT_PROGBITS,
                SHF_WRITE | SHF_ALLOC, bytes(this_module), 4),
        Section(".rel.gnu.linkonce.this_module", SHT_REL, 0, rel_module, 4, 8,
                link=9, info=5),
        Section(".ARM.attributes", SHT_ARM_ATTRIBUTES, 0, build_arm_attributes(), 1),
        Section(".shstrtab", SHT_STRTAB, 0, b"", 1),
        Section(".symtab", SHT_SYMTAB, 0, bytes(symtab), 4, 16,
                link=10, info=first_global),
        Section(".strtab", SHT_STRTAB, 0, bytes(strtab), 1),
    ]

    shstrtab = bytearray(b"\x00")
    name_offsets = {}
    for sec in sections[1:]:
        name_offsets[sec.name] = len(shstrtab)
        shstrtab += sec.name.encode() + b"\x00"
    sections[8].data = bytes(shstrtab)

    # File layout: ELF header, section payloads, then the section header table.
    blob = bytearray(b"\x00" * 52)
    for sec in sections[1:]:
        if sec.align > 1:
            blob += b"\x00" * ((sec.align - len(blob) % sec.align) % sec.align)
        sec.offset = len(blob)
        blob += sec.data
    blob += b"\x00" * ((4 - len(blob) % 4) % 4)
    shoff = len(blob)

    for sec in sections:
        blob += struct.pack(
            "<IIIIIIIIII",
            name_offsets.get(sec.name, 0), sec.type, sec.flags, 0, sec.offset,
            len(sec.data), sec.link, sec.info, sec.align, sec.entsize)

    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    blob[0:52] = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        1,                       # e_type = ET_REL
        40,                      # e_machine = EM_ARM
        1,                       # e_version
        0,                       # e_entry
        0,                       # e_phoff
        shoff,                   # e_shoff
        0x05000000,              # e_flags = EF_ARM_EABI_VER5
        52,                      # e_ehsize
        0,                       # e_phentsize
        0,                       # e_phnum
        40,                      # e_shentsize
        len(sections),           # e_shnum
        8,                       # e_shstrndx
    )
    meta = {
        "text": text,
        "text_meta": text_meta,
        "rel_text": text_relocs,
        "rel_module": [(MODULE_INIT_OFF, "init_module"),
                       (MODULE_EXIT_OFF, "cleanup_module")],
        "sections": sections,
        "shoff": shoff,
        "symtab": sym_defs,
    }
    return bytes(blob), meta


# ---------------------------------------------------------------------------
# ELF parser (independent of the builder)
# ---------------------------------------------------------------------------
def parse_elf(blob: bytes) -> dict:
    if blob[:4] != b"\x7fELF" or blob[4] != 1 or blob[5] != 1:
        raise AssertionError("not a little-endian ELF32 file")
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", blob, 16)

    secs = []
    for i in range(e_shnum):
        (name_off, sh_type, flags, addr, off, size, link, info, align,
         entsize) = struct.unpack_from("<IIIIIIIIII", blob, e_shoff + i * 40)
        secs.append(dict(index=i, name_off=name_off, type=sh_type, flags=flags,
                          addr=addr, offset=off, size=size, link=link, info=info,
                          align=align, entsize=entsize, data=blob[off:off + size]))
    shstr = secs[e_shstrndx]["data"]

    def string_at(table, off):
        end = table.index(b"\x00", off)
        return table[off:end].decode("latin-1")

    for sec in secs:
        sec["name"] = string_at(shstr, sec["name_off"])
    sec_by_name = {sec["name"]: sec for sec in secs if sec["name"]}

    symtab_sec = sec_by_name[".symtab"]
    strtab = secs[symtab_sec["link"]]["data"]
    syms = []
    for off in range(0, symtab_sec["size"], 16):
        st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
            "<IIIBBH", symtab_sec["data"], off)
        syms.append(dict(name=string_at(strtab, st_name), value=st_value,
                         size=st_size, info=st_info, shndx=st_shndx))

    relocs = {}
    for sec in secs:
        if sec["type"] != SHT_REL:
            continue
        entries = []
        for off in range(0, sec["size"], 8):
            r_offset, r_info = struct.unpack_from("<II", sec["data"], off)
            sym = syms[r_info >> 8]
            addend = struct.unpack_from("<I", blob,
                                        secs[sec["info"]]["offset"] + r_offset)[0]
            entries.append(dict(offset=r_offset, sym=sym["name"],
                                type=r_info & 0xFF,
                                sym_index=r_info >> 8, addend=addend))
        relocs[sec["name"]] = entries

    return dict(e_type=e_type, e_machine=e_machine, e_version=e_version,
                e_entry=e_entry, e_phoff=e_phoff, e_shoff=e_shoff,
                e_flags=e_flags, e_ehsize=e_ehsize, e_shnum=e_shnum,
                e_shstrndx=e_shstrndx, sections=secs, sec_by_name=sec_by_name,
                syms=syms, relocs=relocs, blob=blob)


# ---------------------------------------------------------------------------
# Self-verification
# ---------------------------------------------------------------------------
def _require_capstone(version: str = "5.") -> tuple:
    try:
        import capstone
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("[-] capstone is required for self-verification "
                         "(pip install capstone==5.0.7): %s" % exc)
    if not capstone.__version__.startswith(version):
        raise SystemExit("[-] capstone %s found; the audit is pinned to 5.x"
                         % capstone.__version__)
    return capstone, Cs, CS_ARCH_ARM, CS_MODE_ARM


def verify_blob(blob: bytes, verbose: bool = True) -> dict:
    capstone, Cs, CS_ARCH_ARM, CS_MODE_ARM = _require_capstone()
    from capstone.arm import ARM_OP_REG, ARM_OP_MEM, ARM_REG_PC

    elf = parse_elf(blob)
    problems: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            problems.append(msg)

    # --- ELF header --------------------------------------------------------
    check(elf["e_type"] == 1, "e_type is not ET_REL")
    check(elf["e_machine"] == 40, "e_machine is not EM_ARM")
    check(elf["e_flags"] == 0x05000000,
          "e_flags is 0x%08x, expected 0x05000000" % elf["e_flags"])
    check(len(blob) < 4096, "file is unexpectedly large")
    check(len(blob) >= 1024, "file is unexpectedly small")

    sec = elf["sec_by_name"]
    text = sec[".text"]
    text_bytes = text["data"]

    # --- .modinfo ----------------------------------------------------------
    modinfo = sec[".modinfo"]
    check(modinfo["flags"] & SHF_ALLOC != 0, ".modinfo is not SHF_ALLOC")
    check(modinfo["align"] == 4, ".modinfo align is not 4")
    check(MODINFO in modinfo["data"], ".modinfo does not contain the expected tags")
    check(b"vermagic=" + VERMAGIC + b"\x00" in modinfo["data"],
          "vermagic does not match '4.1.25 SMP mod_unload ARMv7 ' (trailing space)")
    check(KERNEL_RELEASE.encode() in modinfo["data"], "kernel release missing")

    # --- __this_module -----------------------------------------------------
    mod = sec[".gnu.linkonce.this_module"]
    check(mod["flags"] == (SHF_WRITE | SHF_ALLOC),
          ".gnu.linkonce.this_module flags are not SHF_WRITE|SHF_ALLOC")
    check(mod["align"] == 4, "this_module align is not 4")
    check(mod["size"] == MODULE_STRUCT_SIZE,
          "sizeof(struct module) is %d, expected %d" % (mod["size"], 336))
    check(mod["data"][MODULE_NAME_OFF:MODULE_NAME_OFF + len(MODULE_NAME) + 1]
          == MODULE_NAME.encode() + b"\x00",
          "module name at offset 0x0c is wrong")
    rel_mod = {r["offset"]: r["sym"] for r in elf["relocs"][".rel.gnu.linkonce.this_module"]}
    check(rel_mod.get(MODULE_INIT_OFF) == "init_module",
          "this_module+0xc0 is not init_module")
    check(rel_mod.get(MODULE_EXIT_OFF) == "cleanup_module",
          "this_module+0x148 is not cleanup_module")
    for r in elf["relocs"][".rel.gnu.linkonce.this_module"]:
        check(r["type"] == R_ARM_ABS32, "this_module reloc is not R_ARM_ABS32")
        check(r["addend"] == 0, "this_module reloc addend is not zero")

    # --- .rodata ----------------------------------------------------------
    rodata = sec[".rodata"]
    check(rodata["data"].startswith(TARGET_SYMBOL.encode() + b"\x00"),
          ".rodata does not start with the target symbol name")

    # --- symbols ----------------------------------------------------------
    sym_by_name = {s["name"]: s for s in elf["syms"] if s["name"]}
    for required in ("cleanup_module", "patch_worker", "init_module",
                     "__this_module", "kallsyms_lookup_name", "stop_machine",
                     "v7_coherent_kern_range", "rsn_name"):
        check(required in sym_by_name, "missing symbol %s" % required)
    for required in ("kallsyms_lookup_name", "stop_machine",
                     "v7_coherent_kern_range"):
        check(sym_by_name.get(required, {}).get("shndx") == 0,
              "%s is not an undefined import" % required)
        check(sym_by_name.get(required, {}).get("info", 0) >> 4 == STB_GLOBAL,
              "%s is not STB_GLOBAL" % required)
    for name in ("init_module", "cleanup_module", "patch_worker"):
        s = sym_by_name[name]
        check(s["shndx"] == 1, "%s is not defined in .text" % name)
        check(s["info"] & 0xF == STT_FUNC, "%s is not STT_FUNC" % name)
    check(sym_by_name["rsn_name"]["shndx"] == sec[".rodata"]["index"],
          "rsn_name does not live in .rodata")
    check(sym_by_name["__this_module"]["shndx"] == mod["index"],
          "__this_module does not live in .gnu.linkonce.this_module")

    # Function ranges must tile .text from 0 to the literal pool without gaps.
    funcs = sorted(
        [(s["value"], s["size"], name) for name, s in sym_by_name.items()
         if s["shndx"] == 1 and s["info"] & 0xF == STT_FUNC and name != "init_module"],
        key=lambda item: item[0])
    funcs.append((sym_by_name["init_module"]["value"],
                  sym_by_name["init_module"]["size"], "init_module"))
    funcs.sort(key=lambda item: item[0])
    check(funcs[0][0] == 0, "first function does not start at .text+0")
    cursor = 0
    for start, size, name in funcs:
        check(start == cursor, "gap/overlap before %s" % name)
        cursor = start + size
    pool_start = cursor
    check(pool_start % 4 == 0, "literal pool is not word-aligned")
    check(pool_start < len(text_bytes), "no literal pool found")
    # Literal pool: 13 constants + 5 relocations = 18 words
    check(len(text_bytes) - pool_start == 18 * 4,
          "expected 18 literal-pool words (13 constants + 5 relocs), found %d bytes after functions"
          % (len(text_bytes) - pool_start))

    # --- disassembly -------------------------------------------------------
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    md.skipdata = False
    forbidden_mnemonic = {"mcr", "mrc", "cdp", "ldc", "stc", "mcrr", "mrrc"}
    literal_loads: list[dict] = []   # ldr rX, [pc, #imm]
    instruction_rows = []
    fp_insns = []
    for start, size, name in funcs:
        for insn in md.disasm(text_bytes[start:start + size], start):
            instruction_rows.append((insn.address, insn, name, None))
            mnem = insn.mnemonic
            if mnem.startswith(("v", "f")) or mnem in forbidden_mnemonic:
                fp_insns.append((insn.address, mnem, insn.op_str))
            for op in insn.operands:
                if op.type == ARM_OP_REG:
                    regname = insn.reg_name(op.reg)
                    if regname and regname[0] in "qds" and regname[1:].isdigit():
                        fp_insns.append((insn.address, mnem, insn.op_str))
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    target = insn.address + 8 + op.mem.disp
                    dest = insn.reg_name(insn.operands[0].reg)
                    literal_loads.append(dict(insn=insn.address, reg=dest,
                                              target=target, func=name))
    check(not fp_insns, "VFP/NEON/coprocessor instructions found: %r" % fp_insns)

    for item in literal_loads:
        check(pool_start <= item["target"] < len(text_bytes),
              "ldr at 0x%x targets 0x%x outside the literal pool"
              % (item["insn"], item["target"]))
        check(item["target"] % 4 == 0,
              "ldr at 0x%x targets an unaligned literal" % item["insn"])
    loaded_targets = {item["target"] for item in literal_loads}
    rel_text = elf["relocs"].get(".rel.text", [])
    rel_offsets = {r["offset"] for r in rel_text}
    for r in rel_text:
        check(r["type"] == R_ARM_ABS32, ".rel.text has a non-ABS32 relocation")
        check(r["offset"] >= pool_start,
              "relocation 0x%x is outside the literal pool" % r["offset"])
        check((r["offset"] - pool_start) % 4 == 0,
              "relocation 0x%x is not word-aligned" % r["offset"])
        check(r["addend"] == 0,
              "relocation 0x%x has a non-zero addend (ABS32 would add twice)"
              % r["offset"])
        check(r["offset"] in loaded_targets,
              "relocation 0x%x is never loaded by an ldr" % r["offset"])
    check(rel_offsets <= loaded_targets, "unloaded relocation targets")
    check(len(rel_text) == 5, "expected 5 .text relocations, found %d" % len(rel_text))

    # Every pool word is either a known constant or a relocation target.
    pool_words = {}
    for off in range(pool_start, len(text_bytes), 4):
        word = struct.unpack_from("<I", text_bytes, off)[0]
        pool_words[off] = word

    expected_consts = {
        pool_start + 0: SITE1_PRE_WORD,
        pool_start + 4: SITE1_ORIG_WORD,
        pool_start + 8: SITE1_PATCH_WORD,
        pool_start + 12: SITE2_OFFSET,
        pool_start + 16: SITE2_MOVT3_WORD,
        pool_start + 20: SITE2_MOVT2_WORD,
        pool_start + 24: SITE2_ORIG_WORD,
        pool_start + 28: SITE2_PATCH_WORD,
        pool_start + 32: SITE3_OFFSET,
        pool_start + 36: SITE3_PRE_WORD,
        pool_start + 40: SITE3_POST_WORD,
        pool_start + 44: SITE3_ORIG_WORD,
        pool_start + 48: SITE3_PATCH_WORD,
    }
    for off, word in pool_words.items():
        if off in rel_offsets:
            check(word == 0, "relocated literal at 0x%x is not zero" % off)
        else:
            check(expected_consts.get(off) == word,
                  "unexpected literal at 0x%x: 0x%08x (expected 0x%08x)"
                  % (off, word, expected_consts.get(off, 0)))
        check(off in loaded_targets, "literal at 0x%x is never loaded" % off)

    # ----------------------------------------------------------------
    # SP alignment: walk every basic block from each function entry.
    # ----------------------------------------------------------------
    def sp_walk(start: int, size: int, name: str) -> list[str]:
        insns = {i.address: i for i in md.disasm(text_bytes[start:start + size], start)}
        errors = []
        pending = [(start, 0)]
        seen = {}
        while pending:
            addr, delta = pending.pop()
            while True:
                if addr in seen:
                    if seen[addr] != delta:
                        errors.append("%s: 0x%x reached with sp%+d and sp%+d"
                                      % (name, addr, seen[addr], delta))
                    break
                seen[addr] = delta
                insn = insns.get(addr)
                if insn is None:
                    errors.append("%s: fell out of function at 0x%x" % (name, addr))
                    break
                writes_pc = (("pc" in insn.op_str and insn.mnemonic.startswith("pop"))
                             or insn.mnemonic == "bx")
                if insn.mnemonic in ("push", "pop"):
                    regs = [r.strip() for r in insn.op_str.strip("{}").split(",")]
                    count = len(regs)
                    if insn.mnemonic == "push":
                        delta += 4 * count
                    else:
                        delta -= 4 * count
                if insn.mnemonic in ("add", "sub") and insn.op_str.startswith("sp"):
                    errors.append("%s: unsupported sp arithmetic at 0x%x" % (name, addr))
                if insn.mnemonic == "blx":
                    if delta % 8:
                        errors.append("%s: blx at 0x%x with sp%+d (not 8-byte aligned)"
                                      % (name, addr, delta))
                if insn.mnemonic in ("b", "bne", "beq", "bx", "bgt", "blt",
                                     "bls", "bhi", "bge", "ble"):
                    mnem = insn.mnemonic
                    if mnem == "bx":
                        break
                    if mnem == "b":
                        target = insn.operands[0].imm
                        addr = target
                        continue
                    pending.append((insn.operands[0].imm, delta))
                if writes_pc:
                    break
                addr = insn.address + insn.size
        return errors

    sp_errors = []
    for start, size, name in funcs:
        sp_errors.extend(sp_walk(start, size, name))
    check(not sp_errors, "stack alignment errors: %r" % sp_errors)

    # --- simulate Linux 4.1.25 simplify_symbols() + apply_relocate() ------
    def simulate_load():
        cursor = 0x1000
        bases = {}
        for section in elf["sections"]:
            if not section["flags"] & SHF_ALLOC:
                continue
            align = max(section["align"], 1)
            cursor = (cursor + align - 1) & ~(align - 1)
            bases[section["name"]] = cursor
            cursor += section["size"]
        undefined = {"kallsyms_lookup_name": 0xA000,
                     "stop_machine": 0xA100,
                     "v7_coherent_kern_range": 0xA200}
        sym_values = {}
        for index, sym in enumerate(elf["syms"]):
            if sym["shndx"] == 0:
                sym_values[index] = undefined.get(sym["name"], 0)
            else:
                secname = elf["sections"][sym["shndx"]]["name"]
                sym_values[index] = bases.get(secname, 0) + sym["value"]
        images = {s["name"]: bytearray(s["data"]) for s in elf["sections"]
                  if s["flags"] & SHF_ALLOC}
        for relname, entries in elf["relocs"].items():
            target = elf["sections"][sec[relname]["info"]]
            image = images[target["name"]]
            for r in entries:
                current = struct.unpack_from("<I", image, r["offset"])[0]
                struct.pack_into("<I", image, r["offset"],
                                 (current + sym_values[r["sym_index"]]) & 0xFFFFFFFF)
        return images, bases, sym_values

    images, bases, sym_values = simulate_load()
    sim_text = images[".text"]
    sim_module = images[".gnu.linkonce.this_module"]

    def sim_lit(off: int) -> int:
        return struct.unpack_from("<I", sim_text, off)[0]

    check(sim_lit(pool_start + 0) == SITE1_PRE_WORD, "simulated literal 0 mismatch")
    check(sim_lit(pool_start + 4) == SITE1_ORIG_WORD, "simulated literal 1 mismatch")
    check(sim_lit(pool_start + 8) == SITE1_PATCH_WORD, "simulated literal 2 mismatch")
    check(sim_lit(pool_start + 12) == SITE2_OFFSET, "simulated literal 3 mismatch")
    check(sim_lit(pool_start + 16) == SITE2_MOVT3_WORD, "simulated literal 4 mismatch")
    check(sim_lit(pool_start + 20) == SITE2_MOVT2_WORD, "simulated literal 5 mismatch")
    check(sim_lit(pool_start + 24) == SITE2_ORIG_WORD, "simulated literal 6 mismatch")
    check(sim_lit(pool_start + 28) == SITE2_PATCH_WORD, "simulated literal 7 mismatch")
    check(sim_lit(pool_start + 32) == SITE3_OFFSET, "simulated literal 8 mismatch")
    check(sim_lit(pool_start + 36) == SITE3_PRE_WORD, "simulated literal 9 mismatch")
    check(sim_lit(pool_start + 40) == SITE3_POST_WORD, "simulated literal 10 mismatch")
    check(sim_lit(pool_start + 44) == SITE3_ORIG_WORD, "simulated literal 11 mismatch")
    check(sim_lit(pool_start + 48) == SITE3_PATCH_WORD, "simulated literal 12 mismatch")
    check(sim_lit(pool_start + 52) == 0xA200,
          "v7_coherent_kern_range did not relocate to its symbol value")
    check(sim_lit(pool_start + 56) == 0xA000,
          "kallsyms_lookup_name did not relocate to its symbol value")
    check(sim_lit(pool_start + 60) == bases[".rodata"],
          "rsn_name did not relocate into .rodata")
    check(sim_lit(pool_start + 64) == bases[".text"] + sym_by_name["patch_worker"]["value"],
          "patch_worker literal did not relocate into .text")
    check(sim_lit(pool_start + 68) == 0xA100,
          "stop_machine did not relocate to its symbol value")
    check(struct.unpack_from("<I", sim_module, MODULE_INIT_OFF)[0]
          == bases[".text"] + sym_by_name["init_module"]["value"],
          "struct module init does not relocate to init_module")
    check(struct.unpack_from("<I", sim_module, MODULE_EXIT_OFF)[0]
          == bases[".text"] + sym_by_name["cleanup_module"]["value"],
          "struct module exit does not relocate to cleanup_module")

    # --- exact contract checks --------------------------------------------
    def word_at(off: int) -> int:
        return struct.unpack_from("<I", text_bytes, off)[0]

    pw = sym_by_name["patch_worker"]["value"]
    check(word_at(pw) == ENC_PUSH_R4_R5_R6_LR, "patch_worker does not push {r4, r5, r6, lr}")
    
    pw_words = [word_at(o) for o in range(pw, sym_by_name["init_module"]["value"], 4)]
    check(0xE5143004 in pw_words, "patch_worker does not verify [r4, #-4]")
    check(0xE595300C in pw_words, "patch_worker does not verify [r5, #12]")
    check(0xE5953004 in pw_words, "patch_worker does not verify [r5, #4]")
    check(0xE5163004 in pw_words, "patch_worker does not verify [r6, #-4]")
    check(0xE5963004 in pw_words, "patch_worker does not verify [r6, #4]")
    check(0xE5842000 in pw_words, "patch_worker has no str r2, [r4]")
    check(0xE5852000 in pw_words, "patch_worker has no str r2, [r5]")
    check(0xE5862000 in pw_words, "patch_worker has no str r2, [r6]")

    im = sym_by_name["init_module"]["value"]
    check(word_at(im) == ENC_PUSH_R4_LR, "init_module does not push {r4, lr}")
    check(word_at(0) == ENC_BX_LR, "cleanup_module is not a single bx lr")

    # Contract check: exact errno return values (ARM A32 mvn rd, #imm: rd = ~imm)
    check(enc_mvn_imm(REG_R0, 21) in pw_words,
          "patch_worker patch_inval does not return -22 (-EINVAL)")
    check(enc_mvn_imm(REG_R0, 4) in pw_words,
          "patch_worker patch_eio does not return -5 (-EIO)")
    im_words = [word_at(o) for o in range(im, pool_start, 4)]
    check(enc_mvn_imm(REG_R0, 1) in im_words,
          "init_module init_noent does not return -2 (-ENOENT)")

    # --- report ------------------------------------------------------------
    if verbose:
        print("[verify] capstone %s" % capstone.__version__)
        print("[verify] ELF32 LE ET_REL EM_ARM e_flags=0x%08x size=%d bytes"
              % (elf["e_flags"], len(blob)))
        print("[verify] vermagic=%r" % VERMAGIC.decode())
        print("[verify] sizeof(struct module)=%d name@0x%02x init@0x%02x exit@0x%02x"
              % (mod["size"], MODULE_NAME_OFF, MODULE_INIT_OFF, MODULE_EXIT_OFF))
        print("[verify] .text=%d bytes, %d real instructions, %d literal words"
              % (len(text_bytes), sum(1 for _r in instruction_rows),
                 len(pool_words)))
        print("[verify] relocations: .rel.text=%d ABS32, .rel.this_module=%d ABS32"
              % (len(rel_text), len(elf["relocs"][".rel.gnu.linkonce.this_module"])))
        print("[verify] kernel apply_relocate simulation: 7 ABS32 relocations resolve "
              "(init/exit + 5 literals)")
        print("[verify] VFP/NEON/coprocessor instructions: 0")
        print("[verify] stack: 8-byte aligned at every call site "
              "(walked %d instructions in %d functions)"
              % (sum(1 for _r in instruction_rows), len(funcs)))

    if problems:
        print("\n[verify] FAILED (%d problem(s)):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        raise SystemExit(1)
    if verbose:
        print("[verify] PASS")

    return dict(elf=elf, text_bytes=text_bytes, funcs=funcs,
                pool_start=pool_start, instruction_rows=instruction_rows,
                pool_words=pool_words, literal_loads=literal_loads)


# ---------------------------------------------------------------------------
# Human-readable dump (task 4 evidence)
# ---------------------------------------------------------------------------
def print_report(blob: bytes, result: dict) -> None:
    elf = result["elf"]
    text_bytes = result["text_bytes"]
    sec = elf["sec_by_name"]
    rel_text = {r["offset"]: r for r in elf["relocs"][".rel.text"]}

    print("\n== section headers ==")
    print("%-32s %-10s %-6s %-8s %-8s %-6s %s"
          % ("name", "type", "flags", "offset", "size", "align", "link/info"))
    for s in elf["sections"]:
        flag_str = ""
        if s["flags"] & SHF_WRITE:
            flag_str += "W"
        if s["flags"] & SHF_ALLOC:
            flag_str += "A"
        if s["flags"] & SHF_EXECINSTR:
            flag_str += "X"
        print("%-32s %-10d %-6s 0x%06x 0x%06x %-6d %d/%d"
              % (s["name"] or "<null>", s["type"], flag_str, s["offset"],
                 s["size"], s["align"], s["link"], s["info"]))

    print("\n== symbols ==")
    print("%-24s %-6s %-8s %-10s %-10s %s"
          % ("name", "bind", "type", "shndx", "value", "size"))
    for s in elf["syms"]:
        bind = "LOCAL" if (s["info"] >> 4) == STB_LOCAL else "GLOBAL"
        typ = {STT_NOTYPE: "NOTYPE", STT_OBJECT: "OBJECT", STT_FUNC: "FUNC",
               STT_SECTION: "SECTION"}.get(s["info"] & 0xF, "UNKNOWN")
        print("%-24s %-6s %-8s %-10d 0x%08x 0x%x"
              % (s["name"] or "<section>", bind, typ, s["shndx"],
                 s["value"], s["size"]))

    print("\n== .rel.text (R_ARM_ABS32 = type 2) ==")
    for r in elf["relocs"][".rel.text"]:
        print("  offset 0x%08x  type=%d  sym[%d]=%-24s addend=0x%08x"
              % (r["offset"], r["type"], r["sym_index"], r["sym"], r["addend"]))
    print("== .rel.gnu.linkonce.this_module ==")
    for r in elf["relocs"][".rel.gnu.linkonce.this_module"]:
        print("  offset 0x%08x  type=%d  sym[%d]=%-24s addend=0x%08x"
              % (r["offset"], r["type"], r["sym_index"], r["sym"], r["addend"]))

    print("\n== .text disassembly (every instruction; later words are literals) ==")
    func_names = {start: name for start, size, name in result["funcs"]}
    printed_func = None
    for addr, insn, name, _dummy in result["instruction_rows"]:
        if name != printed_func:
            print("\n  -- %s --" % name)
            printed_func = name
        print("  0x%04x  %08x  %-8s %s"
              % (addr, int.from_bytes(insn.bytes, "little"),
                 insn.mnemonic, insn.op_str))
    pool = result["pool_start"]
    print("\n  -- literal pool --")
    for off in range(pool, len(text_bytes), 4):
        word = struct.unpack_from("<I", text_bytes, off)[0]
        rel = rel_text.get(off)
        note = ("-> %s" % rel["sym"]) if rel else "constant"
        print("  0x%04x  %08x  .word       0x%08x  (%s)" % (off, word, word, note))

    print("\n== literal loads (PC-relative) ==")
    for item in result["literal_loads"]:
        note = ""
        rel = rel_text.get(item["target"])
        if rel:
            note = "-> %s (R_ARM_ABS32)" % rel["sym"]
        elif item["target"] in result["pool_words"]:
            note = "constant 0x%08x" % result["pool_words"][item["target"]]
        print("  0x%04x  ldr %-2s, [pc] -> 0x%04x  %s"
              % (item["insn"], item["reg"], item["target"], note))

    print("\n== sections with SHF_ALLOC ==")
    for s in elf["sections"]:
        if s["flags"] & SHF_ALLOC:
            print("  %-32s size=0x%x" % (s["name"], s["size"]))


# ---------------------------------------------------------------------------
# Optional reference check against the vendor dump
# ---------------------------------------------------------------------------
def check_reference(path: Path) -> None:
    blob = path.read_bytes()
    if blob[:4] != b"\x7fELF":
        raise SystemExit("[-] %s is not an ELF file" % path)
    elf = parse_elf(blob)
    text = elf["sec_by_name"][".text"]
    for vaddr, expected in sorted(REFERENCE_WORDS.items()):
        off = text["offset"] + vaddr
        actual = struct.unpack_from("<I", blob, off)[0]
        status = "OK" if actual == expected else "MISMATCH"
        print("[ref] mt7615_ap.ko .text+0x%05x = 0x%08x (expected 0x%08x) %s"
              % (vaddr, actual, expected, status))
        if actual != expected:
            raise SystemExit("[-] reference instruction check failed")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build the deterministic f680_rsn_patch.ko helper module.")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="output path (default: payload/f680_rsn_patch.ko)")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip the capstone self-verification")
    parser.add_argument("--verify-only", metavar="PATH", default=None,
                        help="only verify an existing .ko")
    parser.add_argument("--reference", metavar="MT7615_KO", default=None,
                        help="read-only check of mt7615_ap.ko instruction words")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the disassembly and relocation dump")
    args = parser.parse_args(argv)

    if args.reference:
        check_reference(Path(args.reference))

    if args.verify_only:
        blob = Path(args.verify_only).read_bytes()
        result = verify_blob(blob, verbose=not args.quiet)
        if not args.quiet:
            print_report(blob, result)
        return 0

    blob, _meta = build_elf()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)

    sha = hashlib.sha256(blob).hexdigest()
    print("[build] wrote %s (%d bytes, sha256 %s)" % (out, len(blob), sha))

    if not args.no_verify:
        result = verify_blob(blob, verbose=not args.quiet)
        if not args.quiet:
            print_report(blob, result)
    else:
        print("[build] self-verification skipped (--no-verify)")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
