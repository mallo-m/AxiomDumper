#include "dm_structs.h"
#include <stdio.h>

void DM_GetKrnlVersion(char* buffer, SIZE_T bufferLen, CHAR* filename)
{
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSizeA(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            *buffer = '\0';
            return;
        }

        if (GetFileVersionInfoA(filename, 0, verSize, verData)) {
            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                        snprintf(buffer, bufferLen, "%ld-%ld", majorVersion, minorVersion);
                        // _tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}

