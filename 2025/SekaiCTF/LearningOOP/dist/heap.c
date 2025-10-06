#include <stdio.h>
#include <stdlib.h>

int main()
{
    long long *chunk1, chunk2, chunk3;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    chunk1 = malloc(0x100);
    chunk2 = malloc(0x50);
    chunk3 = malloc(0x20);

    free(chunk1);

    malloc(0x100);

    return 0;
}
