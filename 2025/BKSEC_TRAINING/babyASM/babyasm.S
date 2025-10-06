babyasm:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	xor    eax,eax
	<+5>:	mov    ah,BYTE PTR [ebp+0xb] ; 0xab
	<+8>:	shl    ax,0x10				 ; 0xab00
	<+12>:	sub    al,BYTE PTR [ebp+0xd] ; 0xab00 - 0x77 = 0xaaff89 -> take lobyte -> 0x89 -> ax = 0xab89
	<+15>:	add    ah,BYTE PTR [ebp+0xc] ; 0xab + 0x68 = 0x113 -> take lobyte (overflow so just take lobye) -> ah = 0x13 -> ax = 0x1389
	<+18>:	xor    ax,WORD PTR [ebp+0x12]; 0x1389 ^ 0x6868 = 0x7BE1
	<+22>:	nop
	<+23>:	pop    ebp
	<+24>:	ret    


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

; --->> Result: BKSEC{7BE1}