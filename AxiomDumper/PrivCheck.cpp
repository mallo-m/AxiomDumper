#include "AxiomDumper.h"

BOOL AXIOM_PrivCheck()
{
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (hToken) CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        if (hToken) CloseHandle(hToken);
        return FALSE;
    }

    return (elevation.TokenIsElevated);
}
