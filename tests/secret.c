#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: secret <SECRET>\n");
        return -1;
    }

    int secret = atoi(argv[1]);

    printf("I'm process %d and my secret is at %p\n", getpid(), &secret);
    printf("%d %p\n", getpid(), &secret);

    for (;;)
        sleep(1);

    return 0;
}