section .text
global _start

    _start:
        mov     edx, 0x4321fedc
        mov     esi, 0x28121969
        mov     edi, 0xfee1dead
        mov     al,  0xa9
        syscall