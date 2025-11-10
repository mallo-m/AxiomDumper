#include "dm_structs.h"
#include <psapi.h>

static PVOID _g_baseaddress = NULL;

void DM_SetNtoskrnlBaseAddress(PVOID address)
{
    _g_baseaddress = address;
}

DWORD64 DM_FindNtoskrnlBaseAddress(void)
{
    DWORD cbNeeded = 0;
    LPVOID drivers[1024] = { 0 };

    if (_g_baseaddress != NULL)
        return ((DWORD64)_g_baseaddress);

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        _g_baseaddress = drivers[0];
        return ((DWORD64)_g_baseaddress);
    }
    else {
        return (0x00);
    }
}

