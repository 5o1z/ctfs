section .data
    filename db '/flag.txt', 0

section .text
    global _start

_start:
    ; open
    xor eax, eax
    mov ebx, filename
    xor ecx, ecx
    mov al, 5
    int 0x80

    ; read
    mov ebx, eax
    xor eax, eax
    mov ecx, esp
    mov edx, 100
    mov al, 3
    int 0x80

    ; write
    mov eax, 4
    mov ebx, 1
    int 0x80

    xor eax, eax
    mov al, 1
    xor ebx, ebx
    int 0x80

end
