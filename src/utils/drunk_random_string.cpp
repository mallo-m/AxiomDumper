#include <time.h>
#include "Glibc.h"

char* drunk_random_string(SIZE_T len)
{
    char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";
    int charsetSize = sizeof(charset) - 1;
    char* randomString;

    randomString = (char*)malloc(len + 1);

    srand((unsigned int)time(NULL));
    for (SIZE_T i = 0; i < len; i++) {
        int key = rand() % charsetSize;
        randomString[i] = charset[key];
    }

    randomString[len] = '\0';
    return (randomString);
}

