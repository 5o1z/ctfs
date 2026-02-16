`checkout` stack frame
```sh
pwndbg> tele
00:0000│ esp 0xffa36950 —▸ 0x8049028 ◂— push edi /* 'Want to checkout? Maybe next time!' */
01:0004│-034 0xffa36954 ◂— 0x1c07
02:0008│-030 0xffa36958 —▸ 0x8049013 ◂— imul edx, dword ptr [eax + 0x68], 0x20656e6f /* 'iPhone 8' */
03:000c│-02c 0xffa3695c —▸ 0x80487c0 (my_read+39) ◂— mov dword ptr [ebp - 0xc], eax
04:0010│-028 0xffa36960 ◂— 0x1c07  # <------------------------ total
05:0014│-024 0xffa36964 ◂— 1
06:0018│-020 0xffa36968 —▸ 0x85b4bd0 ◂— 'iPhone 8' # <------------------------ name
07:001c│-01c 0xffa3696c ◂— 1 # <------------------------ prize
pwndbg>
08:0020│-018 0xffa36970 —▸ 0xffa369a6 ◂— 0xdd000a35 /* '5\n' */ # <-------------------- fd
09:0024│-014 0xffa36974 —▸ 0x85b4ba0 —▸ 0x85b4bc0 ◂— 'iPhone 6' # <-------------------- bk
0a:0028│-010 0xffa36978 ◂— 0xa /* '\n' */
0b:002c│-00c 0xffa3697c ◂— 0x84ddb100
0c:0030│-008 0xffa36980 —▸ 0x8048d00 (__libc_csu_init) —▸ 0xff315755 ◂— 0
0d:0034│-004 0xffa36984 —▸ 0xf7fcab60 (_rtld_global_ro) ◂— 0
0e:0038│ ebp 0xffa36988 —▸ 0xffa369c8 —▸ 0xffa369e8 ◂— 0
0f:003c│+004 0xffa3698c —▸ 0x8048c54 (handler+129) ◂— jmp handler+144
pwndbg>
10:0040│+008 0xffa36990 —▸ 0xffa369a6 ◂— 0xdd000a35 /* '5\n' */
11:0044│+00c 0xffa36994 ◂— 0x15
12:0048│+010 0xffa36998 —▸ 0xffa369b4 ◂— 6
13:004c│+014 0xffa3699c ◂— 0
14:0050│+018 0xffa369a0 ◂— 5
15:0054│+01c 0xffa369a4 ◂— 0xa35ba20
16:0058│+020 0xffa369a8 —▸ 0xf7d9dd00 (__isoc99_vsscanf) ◂— endbr32
17:005c│+024 0xffa369ac —▸ 0x80486f7 (menu+138) ◂— leave
```

`delete` stack frame

```sh
pwndbg> tele
00:0000│ esp 0xffa36940 —▸ 0xffa36966 ◂— 0xbd9ffa3
01:0004│-044 0xffa36944 ◂— 0x15
02:0008│-040 0xffa36948 ◂— 0xa /* '\n' */
03:000c│-03c 0xffa3694c ◂— 0
04:0010│-038 0xffa36950 ◂— 1
05:0014│-034 0xffa36954 —▸ 0x85b45b0 —▸ 0x85b45d0 ◂— 'iPhone 6 Plus'
06:0018│-030 0xffa36958 —▸ 0xf7fcab60 (_rtld_global_ro) ◂— 0
07:001c│-02c 0xffa3695c —▸ 0x80487c0 (my_read+39) ◂— mov dword ptr [ebp - 0xc], eax
pwndbg>
08:0020│-028   0xffa36960 ◂— 0
09:0024│ eax-2 0xffa36964 —▸ 0xffa369a6 ◂— 0xdd000a33 /* '3\n' */
0a:0028│-020   0xffa36968 —▸ 0xf7d90bd9 (__isoc23_strtol+9) ◂— add eax, 0x1e625b # <--------------- padding 2 bytes to reach name
0b:002c│-01c   0xffa3696c —▸ 0xf7d83884 (atoi+20) ◂— add esp, 0x1c
0c:0030│-018   0xffa36970 —▸ 0xffa369a6 ◂— 0xdd000a33 /* '3\n' */
0d:0034│-014   0xffa36974 ◂— 0
0e:0038│-010   0xffa36978 ◂— 0xa /* '\n' */
0f:003c│-00c   0xffa3697c ◂— 0x84ddb100
pwndbg>
10:0040│-008 0xffa36980 —▸ 0x8048d00 (__libc_csu_init) —▸ 0xff315755 ◂— 0
11:0044│-004 0xffa36984 —▸ 0xf7fcab60 (_rtld_global_ro) ◂— 0
12:0048│ ebp 0xffa36988 —▸ 0xffa369c8 —▸ 0xffa369e8 ◂— 0
13:004c│+004 0xffa3698c —▸ 0x8048c46 (handler+115) ◂— jmp handler+144
14:0050│+008 0xffa36990 —▸ 0xffa369a6 ◂— 0xdd000a33 /* '3\n' */
15:0054│+00c 0xffa36994 ◂— 0x15
16:0058│+010 0xffa36998 —▸ 0xffa369b4 ◂— 6
17:005c│+014 0xffa3699c ◂— 0
```
