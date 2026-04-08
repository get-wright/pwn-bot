#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    puts("Input:");
    read(0, buf, 256);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
