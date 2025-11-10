#include "Glibc.h"

const char* drunk_strcat(char* dest, const char* src)
{
    int i;
    int j;

    i = 0;
    while (dest[i] != '\0')
        i++;
    j = 0;
    while (src[j] != '\0')
    {
        dest[i + j] = src[j];
        j++;
    }
    dest[i + j] = '\0';
    return (dest);
}

