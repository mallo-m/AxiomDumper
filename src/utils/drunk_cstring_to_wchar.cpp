#include "Glibc.h"
#include <string>

LPWSTR drunk_cstring_to_wchar(char* str)
{
    wchar_t* tmp = new wchar_t[4096];

    MultiByteToWideChar(CP_ACP, 0, str, -1, tmp, 4096);
    return (tmp);
}

