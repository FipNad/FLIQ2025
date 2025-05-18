#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("Hello world from C!");

    void *ptr = malloc(1);
    printf("Allocated memory at %p\n", ptr);
    return 0;
}