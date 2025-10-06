#include <stdio.h>

unsigned int __ROL4__(unsigned int value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

unsigned int obscure_key(int a1) {
return (4919 * __ROL4__(a1 ^ 0xA5A5A5A5, 3)) ^ 0x5A5A5A5A;
}

unsigned int generate_2fa_code(int a1) {
int i;
unsigned int v3, v4;

v4 = 48879 * a1;
v3 = 48879 * a1;
for (i = 0; i <= 9; ++i) {
v4 = obscure_key(v4);
v3 = ((v4 >> (i % 5)) ^ (v4 << (i % 7))) + __ROL4__(v4 ^ v3, 5);
v3 &= 0xFFFFFFFF;
}
return v3 & 0xFFFFFF;
}

int main() {
int a1 = 1337;
unsigned int code = generate_2fa_code(a1);
printf("Generated 2FA code: %u\n", code);
return 0;
}