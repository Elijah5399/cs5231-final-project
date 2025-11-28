#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <0|1>\n", argv[0]);
        return 1;
    }

    int trigger = atoi(argv[1]);  // 1 -> double free, 0 -> safe

    int *p = malloc(sizeof(int));
    *p = 42;

    if (trigger == 1) {
        free(p);            // free the memory
        free(p);            // double free vulnerability
    } else {
        free(p);            // free once
    }

    return 0;
}
