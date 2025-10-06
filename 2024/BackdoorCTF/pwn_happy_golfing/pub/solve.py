from pwn import *

# you can compile your raw binary with the command given below. Also use "wc -c solve" to get the size

# run("nasm -f bin solve.asm -o solve", shell=True, check=True)

p=process('./chal')
# p=remote("localhost",8001)

data=open("./solve","rb").read()
print(data)
p.send(data)

p.interactive()