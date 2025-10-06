#include <stdio.h>
#include <limits.h>

int main() {
    int a = INT_MAX; // Maximum value of int type
    int b = INT_MIN; // Minimum value of int type
    
    printf("Maximum value of int: %d\n", a);
    printf("Minimum value of int: %d\n", b);
    
    // Positive overflow
    a = a + 1;
    printf("After exceeding INT_MAX: %d\n", a);
    
    // Negative overflow
    b = b - 1;
    printf("After going below INT_MIN: %d\n", b);
    
    return 0;
}