#include "Glibc.h"

uint64_t drunk_atoi_hex(const char* str)
{
    uint64_t result;

    result = 0;
    while (*str)
    {
        char c = *str++;

        int value;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        }
        else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        }
        else {
            break;  // Invalid character, stop parsing
        }

        result = result * 16 + value;
    }
    return (result);
}

