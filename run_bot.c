#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main (int argc, char **argv) {
    int a = 0;

    while (a < 200) {
        char name[100];
        snprintf(name, 100, "bot00%d", rand() * 32);
        printf("name =%s\n", name);


        char *ar[] = {"1", "10.111.7.8", "8000", name, NULL};
//        char *ar[] = {NULL, " NULL};
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

