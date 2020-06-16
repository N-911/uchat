#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main (int argc, char **argv) {
    int a = 0;

    while (a < 750) {
        char name[100];
        snprintf(name, 100, "bot00%d", rand() * 32);
        char *ar[] = {"1", "10.111.7.10", "4444", name, NULL};
        pid_t pid;
        pid = fork();
        if (pid < 0)
            exit(1);
         else if (pid == 0)
            execvp("./bot", ar);
        a++;
    }
    return 0;
}

