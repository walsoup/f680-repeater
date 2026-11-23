#!/usr/bin/env python3
"""build_kmemtool.py - assemble a tiny static ARM EABI5 /dev/kmem peek-poke tool.

Usage:
  kmemtool <path> <hex_base> <hex_offset> r
  kmemtool <path> <hex_base> <hex_offset> w <hex_byte>

Pure ARM integer instructions only (no VFP/NEON). Uses ARM EABI syscalls:
open=5, read=3, write=4, _llseek=140, exit=1. For _llseek, offset_high is
always 0 and offset_low is the zero-extended 32-bit target address.
"""
import re
import struct
import sys

from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM

ASM = r"""
.syntax unified
.arm

@ ---------------------------------------------------------------
@ _start: branch over the data block, then code
@ ---------------------------------------------------------------
_start:
    b       real_start

.align 2
byte_buf:
    .byte 0, 0, 0, 0
char_buf:
    .byte 0, 0, 0, 0
seek_res:
    .space 8
nl:
    .byte 10, 0, 0, 0
msg_usage:
    .asciz "usage: kmemtool PATH BASE OFF r|w [VAL]\n"
.align 2

real_start:
@   argv[1] = path
@   argv[2] = hex base
@   argv[3] = hex offset
@   argv[4] = "r" or "w"
@   argv[5] = hex byte value (write only)
@ ---------------------------------------------------------------
    ldr     r0, [sp]            @ argc
    cmp     r0, #5
    blt     usage

    ldr     r10, [sp, #8]       @ path
    ldr     r0, [sp, #12]       @ base string
    bl      parse_hex
    mov     r8, r0
    ldr     r0, [sp, #16]       @ offset string
    bl      parse_hex
    add     r8, r8, r0          @ target address

    ldr     r0, [sp, #20]       @ mode string
    ldrb    r9, [r0]
    mov     r11, #0             @ write value
    cmp     r9, #119            @ 'w'
    bne     open_it
    ldr     r0, [sp]            @ argc
    cmp     r0, #6
    blt     usage
    ldr     r0, [sp, #24]       @ value string
    bl      parse_hex
    and     r11, r0, #255

open_it:
    mov     r0, r10
    mov     r1, #2              @ O_RDWR
    mov     r2, #0
    mov     r7, #5              @ __NR_open
    svc     #0
    cmp     r0, #0
    blt     err_open
    mov     r6, r0              @ fd

seek1:
    mov     r0, r6
    mov     r1, #0              @ offset_high = 0 (never sign-extended)
    mov     r2, r8              @ offset_low = target
    adr     r3, seek_res
    mov     r4, #0              @ SEEK_SET
    mov     r7, #140            @ __NR__llseek
    svc     #0
    cmp     r0, #0
    blt     err_seek

    cmp     r9, #119            @ 'w'
    beq     do_write

do_read:
    mov     r0, r6
    adr     r1, byte_buf
    mov     r2, #1
    mov     r7, #3              @ __NR_read
    svc     #0
    cmp     r0, #1
    bne     err_read
    b       print_byte

do_write:
    adr     r1, byte_buf
    strb    r11, [r1]
    mov     r0, r6
    mov     r1, r1              @ keep buffer pointer
    mov     r2, #1
    mov     r7, #4              @ __NR_write
    svc     #0
    cmp     r0, #1
    bne     err_write

    @ seek back and read-verify
    mov     r0, r6
    mov     r1, #0
    mov     r2, r8
    adr     r3, seek_res
    mov     r4, #0
    mov     r7, #140
    svc     #0
    cmp     r0, #0
    blt     err_seek

    mov     r0, r6
    adr     r1, byte_buf
    mov     r2, #1
    mov     r7, #3
    svc     #0
    cmp     r0, #1
    bne     err_read

print_byte:
    adr     r1, byte_buf
    ldrb    r0, [r1]
    bl      print_hex8
    adr     r1, nl
    ldrb    r0, [r1]
    bl      putc
    mov     r0, #0
    mov     r7, #1              @ __NR_exit
    svc     #0

usage:
    adr     r1, msg_usage
usage_loop:
    ldrb    r0, [r1], #1
    cmp     r0, #0
    beq     usage_exit
    bl      putc
    b       usage_loop
usage_exit:
    mov     r0, #2
    mov     r7, #1
    svc     #0

err_open:
    mov     r5, r0
    mov     r0, #79             @ 'O'
    b       err_common
err_seek:
    mov     r5, r0
    mov     r0, #76             @ 'L'
    b       err_common
err_read:
    mov     r5, r0
    mov     r0, #82             @ 'R'
    b       err_common
err_write:
    mov     r5, r0
    mov     r0, #87             @ 'W'
err_common:
    bl      putc
    mov     r0, r5
    bl      print_hex32
    adr     r1, nl
    ldrb    r0, [r1]
    bl      putc
    mov     r0, #1
    mov     r7, #1
    svc     #0

@ ---------------------------------------------------------------
@ putc: r0 = char, writes to stdout
@ ---------------------------------------------------------------
putc:
    adr     r1, char_buf
    strb    r0, [r1]
    mov     r0, #1              @ stdout
    mov     r2, #1
    mov     r7, #4              @ __NR_write
    svc     #0
    bx      lr

@ ---------------------------------------------------------------
@ print_nibble: r0 = 0..15
@ ---------------------------------------------------------------
print_nibble:
    cmp     r0, #9
    addle   r0, r0, #48         @ '0'
    addgt   r0, r0, #87         @ 'a' - 10
    b       putc

@ ---------------------------------------------------------------
@ print_hex8: r0 = byte
@ ---------------------------------------------------------------
print_hex8:
    push    {r4, lr}
    mov     r4, r0
    lsr     r0, r4, #4
    and     r0, r0, #15
    bl      print_nibble
    and     r0, r4, #15
    bl      print_nibble
    pop     {r4, pc}

@ ---------------------------------------------------------------
@ print_hex32: r0 = 32-bit value
@ ---------------------------------------------------------------
print_hex32:
    push    {r4, r5, lr}
    mov     r4, r0
    mov     r5, #8
ph32_loop:
    mov     r0, r4, lsr #28
    and     r0, r0, #15
    bl      print_nibble
    lsl     r4, r4, #4
    subs    r5, r5, #1
    bne     ph32_loop
    pop     {r4, r5, pc}

@ ---------------------------------------------------------------
@ parse_hex: r0 = string, returns value in r0
@ accepts optional 0x / 0X prefix; stops at NUL/CR/LF
@ ---------------------------------------------------------------
parse_hex:
    mov     r1, r0
    ldrb    r2, [r1]
    cmp     r2, #48             @ '0'
    bne     ph_loop
    ldrb    r2, [r1, #1]
    cmp     r2, #120            @ 'x'
    beq     ph_skip
    cmp     r2, #88             @ 'X'
    bne     ph_loop
ph_skip:
    add     r1, r1, #2

ph_loop:
    mov     r0, #0
ph_next:
    ldrb    r2, [r1], #1
    cmp     r2, #0
    beq     ph_done
    cmp     r2, #10
    beq     ph_done
    cmp     r2, #13
    beq     ph_done
    cmp     r2, #48             @ '0'
    blt     ph_bad
    cmp     r2, #57             @ '9'
    ble     ph_digit
    cmp     r2, #97             @ 'a'
    blt     ph_upper
    cmp     r2, #102            @ 'f'
    bgt     ph_bad
    sub     r2, r2, #87         @ 'a' - 10
    b       ph_accum
ph_upper:
    cmp     r2, #65             @ 'A'
    blt     ph_bad
    cmp     r2, #70             @ 'F'
    bgt     ph_bad
    sub     r2, r2, #55         @ 'A' - 10
    b       ph_accum
ph_digit:
    sub     r2, r2, #48         @ '0'
ph_accum:
    lsl     r0, r0, #4
    orr     r0, r0, r2
    b       ph_next
ph_done:
    bx      lr
ph_bad:
    mov     r0, #0
    bx      lr

"""

BASE = 0x00010000
CODE_OFF = 0x100


def build(out_path):
    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    encoding, count = ks.asm(ASM, addr=BASE + CODE_OFF)
    code = bytes(encoding)
    filesz = CODE_OFF + len(code)

    e_ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,          # ET_EXEC
        40,         # EM_ARM
        1,          # EV_CURRENT
        BASE + CODE_OFF,  # e_entry
        52,         # e_phoff
        0,          # e_shoff
        0x05000000, # EF_ARM_EABI_VER5
        52,         # e_ehsize
        32,         # e_phentsize
        1,          # e_phnum
        0,          # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,          # PT_LOAD
        0,          # p_offset
        BASE,       # p_vaddr
        BASE,       # p_paddr
        filesz,     # p_filesz
        filesz,     # p_memsz
        7,          # PF_R|PF_W|PF_X
        0x1000,     # p_align
    )
    blob = ehdr + phdr
    blob += b"\x00" * (CODE_OFF - len(blob))
    blob += code
    with open(out_path, "wb") as f:
        f.write(blob)

    print("assembled %d instructions, code=%d bytes, file=%d bytes" % (count, len(code), len(blob)))
    print("entry=0x%x  segment=0x%x..0x%x" % (BASE + CODE_OFF, BASE, BASE + filesz))

    # VFP/NEON audit: follow the initial branch over the data block, then
    # disassemble the real code body and reject any FP/SIMD mnemonic.
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    first = next(md.disasm(code[:4], BASE + CODE_OFF))
    code_start = BASE + CODE_OFF
    if first.mnemonic == "b" and first.operands and first.operands[0].type == ARM_OP_IMM:
        code_start = first.operands[0].imm
    bad = []
    audited = 0
    for insn in md.disasm(code[code_start - (BASE + CODE_OFF):], code_start):
        audited += 1
        if re.match(r"^(v|f)[a-z]", insn.mnemonic):
            bad.append((insn.address, insn.mnemonic, insn.op_str))
    print("audited %d real code instructions from 0x%x" % (audited, code_start))
    if bad:
        print("VFP/NEON INSTRUCTIONS FOUND:")
        for a, m, o in bad:
            print("  0x%x %s %s" % (a, m, o))
    else:
        print("VFP/NEON audit: none (integer ARM only)")

    return blob


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "kmemtool"
    build(out)
