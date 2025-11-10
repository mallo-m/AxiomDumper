#include "dm.h"

# define RTL_REGISTRY_ABSOLUTE 0

NTSTATUS DM_AddDriverViaRegistry(const char* drv_name)
{
    HMODULE hNtdll = LoadLibraryA(XorStr("ntdll.dll\0"));
    WCHAR ServiceName[MAX_PATH + 1];
    WCHAR DriverNtPath[MAX_PATH + 1];
    _C_RtlCreateRegistryKey CreateRegistryKey;
    _C_RtlWriteRegistryValue RtlWriteRegistryValue;
    CreateRegistryKey = (_C_RtlCreateRegistryKey)(void*)GetProcAddress(hNtdll, XorStr("RtlCreateRegistryKey"));
    RtlWriteRegistryValue = (_C_RtlWriteRegistryValue)(void*)GetProcAddress(hNtdll, XorStr("RtlWriteRegistryValue"));

    _snwprintf(ServiceName, MAX_PATH, XorStrW(L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\%S"), drv_name);
    _snwprintf(DriverNtPath, MAX_PATH, XorStrW(L"\\??\\C:\\Windows\\System32\\Drivers\\%S.sys"), drv_name);

    NTSTATUS Status = CreateRegistryKey(RTL_REGISTRY_ABSOLUTE, ServiceName);
    if (!NT_SUCCESS(Status))
    {
        printf("[!] Failed to create registry key\n");
        return (Status);
    }
    printf("[+] Registry key added successfully\n");

    ULONG ServiceType = SERVICE_KERNEL_DRIVER;
    ULONG StartType = 0x00000003;
    ULONG ErrorControlType = 0x00000001;

    Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        ServiceName,
        L"ImagePath",
        REG_SZ,
        (LPVOID)DriverNtPath,
        (wcslen(DriverNtPath) + 1) * sizeof(wchar_t)
    );
    if (!NT_SUCCESS(Status)) {
        return (Status);
    }

    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        ServiceName,
        L"Type",
        REG_DWORD,
        &ServiceType,
        sizeof(ServiceType)
    );

    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        ServiceName,
        L"Start",
        REG_DWORD,
        &StartType,
        sizeof(StartType)
    );

    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        ServiceName,
        L"ErrorControl",
        REG_DWORD,
        &ErrorControlType,
        sizeof(ErrorControlType)
    );

    return (Status);
}

