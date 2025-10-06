global _start

section .text

babyasm:
    push    ebp
    mov     ebp, esp
    xor     eax, eax
    mov     ah, byte [ebp+0xb]
    shl     ax, 0x10
    sub     al, byte [ebp+0xd]
    add     ah, byte [ebp+0xc]
    xor     ax, word [ebp+0x12]
    nop
    pop     ebp
    ret

_start:
    push    dword 0x68686868
    push    dword 0xdfed7768
    push    dword 0xabcd1456
    call    babyasm
    mov     ebx, eax
    mov     eax, 1
    int     0x80
