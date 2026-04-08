#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buf[128];
    puts("Input:");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);  // format string vulnerability
    puts("Again:");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
