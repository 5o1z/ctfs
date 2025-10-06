#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./main', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input("Please press ENTER to send your payload")

# ==================== EXPLOIT ====================

def exploit():

  sla(b'Input: ', cyclic(0x200))

  interactive()

if __name__ == '__main__':
  exploit()


