# include <stdio.h>

// gcc demo.c -o demo -no-pie -fno-stack-protector

int main(){

	char buf[0x20];
	puts("Just test!!");
	gets(buf);

	return 0;

}
