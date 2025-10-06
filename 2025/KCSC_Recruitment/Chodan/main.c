#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define __USE_MISC  
#include <sys/mman.h>
#include <fcntl.h>
#define CODE_SIZE 0x100
#define NAME_SIZE 0x10

void (*code)();


void setup()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    code = mmap(NULL, CODE_SIZE, PROT_READ | PROT_READ | PROT_EXEC | PROT_WRITE, \
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(!code)
    {
        perror("Init code failed");
        exit(-1);
    }
}

int main()
{
    setup();
    printf("Your shellcode: ");
    read(0, code, CODE_SIZE);
    close(0);
    uint8_t *cur = (uint8_t*)code + 8;
    while(cur + 8 < code + CODE_SIZE)
    {
        memset(cur, 0, 8);
        cur += 16;
    }
    asm volatile(
        ".intel_syntax noprefix;"
        "mov rax, 0xdededede;"
        "mov rdi, 0xcafebabe;"
        "mov rdx, 0xdcdcdcdc;"
        "mov rbx, 0xaaaaaaaaaa;"
        "mov rcx, 0xcccc;"
        "mov rsi, 0xccacaaaaac;"
        ".att_syntax prefix;"
    );
    code();
    return 0;
}

