#include <stdio.h>
#include <unistd.h>

int main() {

    char buf[0x100];
    ssize_t r = read(0, buf, 0x010101010101010101);
    printf("r = %zd\n", r);
}
