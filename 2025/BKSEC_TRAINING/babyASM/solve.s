global main

section .text

; Hàm babyasm:
; Thực hiện các phép toán dựa trên các byte trong đối số.
; Các offset trên stack (theo cdecl, little-endian):
;   Arg1 = 0xabcd1456:
;       [ebp+8]  = 0x56
;       [ebp+9]  = 0x14
;       [ebp+10] = 0xcd
;       [ebp+11] = 0xab
;   Arg2 = 0xdfed7768:
;       [ebp+12] = 0x68
;       [ebp+13] = 0x77
;       [ebp+14] = 0xed
;       [ebp+15] = 0xdf
;   Arg3 = 0x68686868:
;       [ebp+16] = 0x68
;       [ebp+17] = 0x68
;       [ebp+18] = 0x68
;       [ebp+19] = 0x68
;   => WORD tại [ebp+0x12] (tức [ebp+18]) là 0x6868.
babyasm:
    push    ebp
    mov     ebp, esp
    xor     eax, eax             ; eax = 0, ax = 0x0000
    mov     ah, byte [ebp+0xb]     ; ah = 0xab (byte thứ 4 của Arg1)
    shl     ax, 0x10             ; dịch ax sang trái 16 bit (không thay đổi vì ax 16-bit)
    sub     al, byte [ebp+0xd]     ; al = 0x00 - 0x77 = 0x89 (underflow mod 256)
    add     ah, byte [ebp+0xc]     ; ah = 0xab + 0x68 = 0x113 -> chỉ lấy byte thấp: 0x13
    xor     ax, word [ebp+0x12]    ; ax = 0x1389 XOR 0x6868 = 0x7BE1
    nop
    pop     ebp
    ret

; Hàm main:
; Gọi babyasm với các đối số: 0xabcd1456, 0xdfed7768, 0x68686868.
; Kết quả trả về từ babyasm nằm trong eax và được dùng làm exit code.
main:
    push    dword 0x68686868   ; Arg3
    push    dword 0xdfed7768   ; Arg2
    push
