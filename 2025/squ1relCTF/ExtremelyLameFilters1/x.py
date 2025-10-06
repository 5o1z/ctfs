with open("exec_shell.elf", "wb") as f:
    f.write(
        b"\x7fELF" +                     # ELF magic
        b"\x02\x01\x01\x00" +           # 64-bit, little endian, version
        b"\x00" * 8 +                   # padding
        b"\x02\x00" +                   # ET_EXEC
        b"\x3e\x00" +                   # EM_X86_64
        b"\x01\x00\x00\x00" +           # EV_CURRENT
        b"\x78\x00\x40\x00\x00\x00\x00\x00" +  # e_entry = 0x400078
        b"\x40\x00\x00\x00\x00\x00\x00\x00" +  # e_phoff = 0x40
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +  # e_shoff = 0
        b"\x00\x00\x00\x00" +                 # e_flags
        b"\x40\x00" +                   # e_ehsize
        b"\x38\x00" +                   # e_phentsize
        b"\x01\x00" +                   # e_phnum
        b"\x00\x00" +                   # e_shentsize
        b"\x00\x00" +                   # e_shnum
        b"\x00\x00" +                   # e_shstrndx

        # Program header
        b"\x01\x00\x00\x00" +           # p_type = PT_LOAD
        b"\x05\x00\x00\x00" +           # p_flags = RX
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +  # p_offset
        b"\x00\x00\x40\x00\x00\x00\x00\x00" +  # p_vaddr = 0x400000
        b"\x00\x00\x40\x00\x00\x00\x00\x00" +  # p_paddr
        b"\x78\x00\x00\x00\x00\x00\x00\x00" +  # p_filesz
        b"\x78\x00\x00\x00\x00\x00\x00\x00" +  # p_memsz
        b"\x00\x10\x00\x00\x00\x00\x00\x00" +  # p_align

        # Shellcode: execve("/bin/sh", 0, 0)
        b"\x48\x31\xd2" +                          # xor    rdx, rdx
        b"\x48\x31\xf6" +                          # xor    rsi, rsi
        b"\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00" +  # movabs rdi, "/bin/sh"
        b"\x57" +                                  # push   rdi
        b"\x48\x89\xe7" +                          # mov    rdi, rsp
        b"\x48\x31\xc0" +                          # xor    rax, rax
        b"\xb0\x3b" +                              # mov    al, 59
        b"\x0f\x05"                                # syscall
    )
